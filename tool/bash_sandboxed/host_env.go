package bash_sandboxed

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
)

// serverOnlyHostEnv names the variables a command allowed with no_sandbox
// must run with as the server has them, not as the agent set them: ones that
// make a program (or a shell, loader, or language runtime it starts) load
// code or config from where they point, before any of the user's code runs.
// A no_sandbox entry trusts a program, not the agent's choice of what that
// program loads, so `HOME=$PWD/h git status` (git reads core.fsmonitor from
// $HOME/.gitconfig) or `NODE_OPTIONS=--require=./x.js node` must not run the
// agent's code on the host. The list is best-effort: a program may act on a
// variable it doesn't name, and the rest of the environment is still the
// agent's to set. See checkHostEnv.
var serverOnlyHostEnv = map[string]bool{
	// Where programs find their config, and the commands they run.
	"HOME": true, "PATH": true, "SHELL": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true, "BROWSER": true,
	"SSH_ASKPASS": true, "SUDO_ASKPASS": true,
	// Shell startup: a native shell sources or runs these first.
	"ZDOTDIR": true, "SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "BASH_XTRACEFD": true,
	// The dynamic loader and libraries it loads by name.
	"GCONV_PATH": true, "OPENSSL_CONF": true, "OPENSSL_ENGINES": true, "OPENSSL_MODULES": true,
	// Node.js.
	"NODE_OPTIONS": true, "NODE_PATH": true,
	// JVM tools.
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "CLASSPATH": true,
	"MAVEN_OPTS": true, "MAVEN_ARGS": true, "GRADLE_OPTS": true, "GRADLE_USER_HOME": true,
	// Go (GOFLAGS can set -toolexec; GOTOOLCHAIN and GOROOT pick the
	// toolchain that runs) and C compilers (a flag can load a plugin).
	"GOFLAGS": true, "GOENV": true, "GOROOT": true, "GOTOOLCHAIN": true,
	"CC": true, "CXX": true, "CFLAGS": true, "CXXFLAGS": true, "CPPFLAGS": true, "LDFLAGS": true,
	"CGO_CFLAGS": true, "CGO_CPPFLAGS": true, "CGO_CXXFLAGS": true, "CGO_FFLAGS": true, "CGO_LDFLAGS": true,
	// Rust (wrappers and the linker run as programs).
	"RUSTC": true, "RUSTC_WRAPPER": true, "RUSTC_WORKSPACE_WRAPPER": true, "RUSTDOC": true,
	"RUSTFLAGS": true, "RUSTDOCFLAGS": true,
	// Cloud and container CLIs whose config can name a program to run
	// (credential_process, exec auth plugins, credential helpers).
	"DOCKER_CONFIG": true, "DOCKER_HOST": true, "KUBECONFIG": true,
	"AWS_CONFIG_FILE": true, "AWS_SHARED_CREDENTIALS_FILE": true,
	"TF_CLI_CONFIG_FILE": true, "TERRAFORM_CONFIG": true,
	"GH_BROWSER": true, "GH_PAGER": true, "GH_EDITOR": true, "GH_CONFIG_DIR": true,
	"KUBE_EDITOR": true, "MANPAGER": true, "GNUPGHOME": true, "HELM_PLUGINS": true,
	// Apple's /usr/bin shims (git, clang, ...) run the developer tools
	// these select.
	"DEVELOPER_DIR": true, "SDKROOT": true, "TOOLCHAINS": true,
	// More programs Go and the tools above run, or where they find them.
	"GOCACHEPROG": true, "GOAUTH": true, "PKG_CONFIG": true, "AR": true, "FC": true, "GCCGO": true,
	"KUBECTL_EXTERNAL_DIFF": true, "AWS_PAGER": true, "JAVA_HOME": true,
}

// hostEnvExempt names members of serverOnlyHostEnvPrefixes' families that
// name no program or file to load, so the agent may still set them: git's
// identity and dates (as gitIdentityEnv passes to a scoped git) and prompt
// switch, and cargo's output and incremental settings.
var hostEnvExempt = map[string]bool{
	"GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_AUTHOR_DATE": true,
	"GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true, "GIT_COMMITTER_DATE": true,
	"GIT_TERMINAL_PROMPT": true, "CARGO_INCREMENTAL": true,
}

// serverOnlyHostEnvPrefixes are name prefixes serverOnlyHostEnv covers as a
// family: each has members that load code (GIT_CONFIG_*, GIT_SSH_COMMAND,
// PYTHONSTARTUP, PERL5OPT, RUBYOPT, CARGO_TARGET_*_RUNNER, XDG_CONFIG_HOME,
// exported bash functions, ...).
var serverOnlyHostEnvPrefixes = []string{
	"LD_", "DYLD_", "BASH_FUNC_", "XDG_",
	"GIT_", "PYTHON", "PERL", "RUBY", "GEM_", "BUNDLE_", "YARN_",
	"CARGO_", "RUSTUP_", "CLOUDSDK_",
}

// isServerOnlyHostEnv reports whether a command allowed with no_sandbox takes
// the variable from the server's environment (see serverOnlyHostEnv). The
// variables the sandbox refuses to assign anywhere (blockedEnvVars) are
// included: a name only known at runtime (`export "$n=..."`) gets past that
// static check. npm reads its config variables case-insensitively.
func isServerOnlyHostEnv(name string) bool {
	if hostEnvExempt[name] || strings.HasPrefix(name, "CARGO_TERM_") {
		return false
	}
	if serverOnlyHostEnv[name] {
		return true
	}
	if _, ok := blockedEnvVars[name]; ok {
		return true
	}
	for _, p := range serverOnlyHostEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return strings.HasPrefix(strings.ToUpper(name), "NPM_CONFIG_")
}

// checkHostEnv refuses a run on the host of a command allowed with no_sandbox
// (a script allowed with it included) when env, the command's environment, sets
// a variable isServerOnlyHostEnv names to anything but the server's own
// value, or sets one the server doesn't. Replacing the agent's value silently
// would run the command against something other than what it asked for
// (GIT_DIR=../other git reset), so the agent is told to drop it instead.
//
// Unsetting one the server has is refused too: the user may harden a host
// program through it (GIT_CONFIG_* turning core.fsmonitor off). The
// comparison is with the server's whole environment, credentials included,
// not the scrubbed one commands start from (commandBaseEnv): which variables
// are scrubbed follows the config, which can change while an interpreter
// built from the old one runs. So a credential-named variable
// (config.CredentialEnvVar) missing from env is not refused, and one the
// interpreter kept is still the server's.
func checkHostEnv(env map[string]string) error {
	server := envSliceToMap(os.Environ())
	var changed []string
	for name, v := range env {
		if isServerOnlyHostEnv(name) {
			if sv, ok := server[name]; !ok || sv != v {
				changed = append(changed, name)
			}
		}
	}
	for name := range server {
		if _, ok := env[name]; !ok && isServerOnlyHostEnv(name) && !config.CredentialEnvVar(name) {
			changed = append(changed, name)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	sort.Strings(changed)
	return fmt.Errorf("a command allowed with no_sandbox runs on the host with the server's %s, which this command line changes (a program loads code or config from it); unset or restore it for this command", strings.Join(changed, ", "))
}

// serverPath is the PATH a command allowed with no_sandbox is looked up in:
// the server's, without empty or relative entries, which would look it up in
// the working directory the agent writes.
func serverPath() string {
	var keep []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(dir) {
			keep = append(keep, dir)
		}
	}
	return strings.Join(keep, string(filepath.ListSeparator))
}

// checkHostEnvAssigns refuses a no_sandbox host run whose argv changes, through
// env at any wrapper depth, a variable isServerOnlyHostEnv names: env acts
// after checkHostEnv has looked. That is a NAME=VALUE operand (`env HOME=...
// git`), -u/--unset of one, and -i (or -), which clears them all. Also
// refused: BSD env's -P, which names the directories env looks the command
// up in in place of the server's PATH, and env under xargs, whose -I can
// build an assignment's name from its input (`echo HOME | xargs -I X env
// X=... git`).
func checkHostEnvAssigns(args []string) error {
	underXargs := false
	for guard := 0; guard <= maxBashDepth && len(args) > 0; guard++ {
		switch args[0] {
		case "xargs":
			underXargs = true
		case "env":
			if underXargs {
				return fmt.Errorf("env under xargs is not allowed for a command allowed with no_sandbox: xargs can build the variable it sets")
			}
			idx, operands, rejected := wrapperSpecs["env"].layout(args, args)
			if rejected != nil {
				return rejected
			}
			if idx < 0 {
				return nil
			}
			if err := checkHostEnvOptions(args[1:operands]); err != nil {
				return err
			}
			for _, a := range args[operands:idx] {
				name, _, _ := strings.Cut(a, "=")
				if isServerOnlyHostEnv(name) {
					return fmt.Errorf("env %s=... is not allowed for a command allowed with no_sandbox: it runs on the host with the server's %s", name, name)
				}
			}
		}
		unwrap := lookupCommand(args[0]).unwrap
		if unwrap == nil {
			return nil
		}
		args = unwrap(args)
	}
	return nil
}

// checkHostEnvOptions checks env's options (the words before its first
// operand) for checkHostEnvAssigns: -P, -i/-/--ignore-environment, and
// -u/--unset naming a variable isServerOnlyHostEnv names, alone or in a
// cluster. A letter that takes a value (wrapperSpecs["env"]) ends its
// cluster, its value the rest of the word or the next word.
func checkHostEnvOptions(opts []string) error {
	const prefix = "for a command allowed with no_sandbox, which runs on the host with the server's environment"
	unset := func(name string) error {
		if isServerOnlyHostEnv(name) {
			return fmt.Errorf("env -u %s is not allowed %s", name, prefix)
		}
		return nil
	}
	valued := wrapperSpecs["env"].opts.short
	for i := 0; i < len(opts); i++ {
		w := opts[i]
		next := func() string {
			if i+1 < len(opts) {
				i++
				return opts[i]
			}
			return ""
		}
		switch {
		case w == "--":
			return nil
		case w == "-" || w == "--ignore-environment" || (strings.HasPrefix(w, "--i") && strings.HasPrefix("--ignore-environment", w)):
			return fmt.Errorf("env -i is not allowed %s", prefix)
		case strings.HasPrefix(w, "--"):
			name, val, hasVal := strings.Cut(w[2:], "=")
			if len(name) >= 3 && strings.HasPrefix("unset", name) {
				if !hasVal {
					val = next()
				}
				if err := unset(val); err != nil {
					return err
				}
			} else if !hasVal && slices.ContainsFunc(wrapperSpecs["env"].opts.long, func(l string) bool { return strings.HasPrefix(l, name) }) {
				next()
			}
		case strings.HasPrefix(w, "-") && len(w) >= 2:
			for j := 1; j < len(w); j++ {
				c := w[j]
				switch c {
				case 'P':
					return fmt.Errorf("env -P is not allowed %s: the command is looked up in the server's PATH", prefix)
				case 'i':
					return fmt.Errorf("env -i is not allowed %s", prefix)
				}
				if strings.IndexByte(valued, c) >= 0 {
					val := w[j+1:]
					if val == "" {
						val = next()
					}
					if c == 'u' {
						if err := unset(val); err != nil {
							return err
						}
					}
					break
				}
			}
		}
	}
	return nil
}

// checkNoSandboxEnv is checkHostEnvAssigns and checkHostEnv for one run on
// the host of a command allowed with no_sandbox: args is its argv, env the
// environment it gets.
func checkNoSandboxEnv(args []string, env map[string]string) error {
	if err := checkHostEnvAssigns(args); err != nil {
		return err
	}
	return checkHostEnv(env)
}

// withoutTrustedScript returns ctx without the mark of a trusted script
// (withTrustedScript), for a check that holds even where its rules are
// lifted: trustedScriptFrom finds no trustedScript in it.
func withoutTrustedScript(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustedScriptKey{}, nil)
}
