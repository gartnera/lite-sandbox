package bash_sandboxed

import (
	"fmt"

	"mvdan.cc/sh/v3/syntax"
)

// profileHooks are the parser hooks of the profiles (config/profiles.go): the
// argument validators of the commands a profile whitelists. The sandbox never
// asks which profile is enabled — it is handed one commands list with each
// enabled profile's commands already in it (config.Config.Effective) — so a
// hook runs whenever its command runs, whitelisted or not: in denylist mode an
// unlisted `go run pkg@latest` is still refused.
//
// Commands with nothing to validate (gofmt, rustc, flutter/dart/fvm, uvx) have
// no hook: gofmt is a pure formatter, rustc compiles what it is given, the
// Flutter tools and uvx run code the OS sandbox confines like `go test`.
var profileHooks = map[string]func(s *Sandbox, args []*syntax.Word) error{
	// go generate runs the shell commands in //go:generate directives.
	"go": func(s *Sandbox, args []*syntax.Word) error {
		return validateGoArgs(args, s.extraAllowsTokens("go", "generate"))
	},
	"pnpm": func(s *Sandbox, args []*syntax.Word) error {
		return validatePnpmArgs(args, s.extraAllowsTokens("pnpm", "publish"))
	},
	"cargo": func(s *Sandbox, args []*syntax.Word) error {
		return validateCargoArgs(args, s.extraAllowsTokens("cargo", "publish"))
	},
	"deno": func(s *Sandbox, args []*syntax.Word) error {
		return validateDenoArgs(args, s.extraAllowsTokens("deno", "publish"), s.getConfig().ProfileOption("deno", "allow_import"))
	},
	"uv": func(s *Sandbox, args []*syntax.Word) error {
		return validateUvArgs(args, s.extraAllowsTokens("uv", "publish"))
	},
	"python":  validatePythonArgs,
	"python3": validatePythonArgs,
}

func init() {
	for name, hook := range profileHooks {
		if _, dup := commandArgValidators[name]; dup {
			panic(fmt.Sprintf("profile hook for %q collides with a built-in validator", name))
		}
		commandArgValidators[name] = hook
	}
}

// publishGate refuses a registry-publishing subcommand unless the config has
// an allow for exactly it ("cargo publish"). Publishing changes shared state
// no sandbox can confine, so it takes its own commands entry beyond the
// profile that whitelists the tool.
func publishGate(tool string, allowed bool) error {
	if !allowed {
		return fmt.Errorf("%s publish is not allowed; the user can allow it with `lite-sandbox config commands allow %q`", tool, tool+" publish")
	}
	return nil
}

// getWhitelistedCommands returns a snapshot of the commands the config's
// commands list whitelists (the enabled profiles' commands).
func (s *Sandbox) getWhitelistedCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.whitelistedCommands
}

// commandWhitelisted reports whether name is on the whitelist: the built-in
// allowedCommands or a command the config's commands list whitelists. Either
// way it is validated like any whitelisted command, unlike an allow.
func (s *Sandbox) commandWhitelisted(name string) bool {
	return allowedCommands[name] || s.getWhitelistedCommands()[name]
}

// extraAllowsTokens reports whether the config's allows admit cmdName invoked
// with the leading non-flag arguments tokens: a bare allow of the command, or
// a restricted one ("cargo publish") whose arguments are a prefix of them.
func (s *Sandbox) extraAllowsTokens(cmdName string, tokens ...string) bool {
	return s.extraAllowsArgs(cmdName, tokens)
}

// extraAllowsArgs is the runtime form of the static inExtra check: whether an
// allow admits cmdName invoked with the expanded arguments args (argv[1:]). A
// restricted allow only admits the invocations it names, so `cargo publish`
// allowed leaves `cargo build` to the whitelist and cargo's validator at the
// runtime layer too — not just when the name is a literal the static pass saw.
func (s *Sandbox) extraAllowsArgs(cmdName string, args []string) bool {
	if !s.getExtraCommands()[cmdName] {
		return false
	}
	if s.getBareExtraCommands()[cmdName] {
		return true
	}
	restrictions, ok := s.getExtraSubCommands()[cmdName]
	return ok && argsMatchSubCommand(restrictions, args)
}
