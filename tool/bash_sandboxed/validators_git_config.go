package bash_sandboxed

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// gitProgramKeys lists, by section, the config keys that name a program for
// git to run, a config file for it to include, or a path outside the
// repository for it to write: "*" for every key of the section. Section and
// key are lowercase (git compares them case-insensitively), and a key matches
// whatever its subsection (diff.<driver>.textconv, remote.<name>.uploadpack).
//
// Setting one is refused whatever the git levels. git writes the repository's
// config itself, past the sandbox's block on .git, and the git the user later
// runs outside the sandbox reads it: a hook path, pager, or filter driver set
// from inside would run there, on the host. The OS sandbox can't help, since
// the program it names can live in the working directory or /tmp.
var gitProgramKeys = map[string][]string{
	"core": {
		"hookspath", "fsmonitor", "pager", "editor", "sshcommand", "askpass",
		"gitproxy", "alternaterefscommand",
		// Where git checks files out, which can be outside the repository.
		"worktree",
	},
	"diff":        {"external", "textconv", "command"},
	"merge":       {"driver"},
	"remote":      {"uploadpack", "receivepack", "vcs"},
	"submodule":   {"update"}, // "!command"
	"tar":         {"command"},
	"sequence":    {"editor"},
	"interactive": {"difffilter"},
	"web":         {"browser"},
	"help":        {"browser"},
	"init":        {"templatedir"}, // hooks copied into new repositories
	"uploadpack":  {"packobjectshook"},
	"http":        {"cookiefile", "savecookies"},
	// alias.x = "!command"; include.path and includeIf.<cond>.path pull in
	// a file of any keys; filter.<driver>.clean/smudge/process,
	// credential.helper, pager.<cmd>, hook.<name>.command, gpg.program,
	// sendemail.*cmd, imap.tunnel, <tool>.cmd, trace2 targets (files it
	// appends to), and protocol.ext.allow (ext:: remotes run a command).
	"alias":      {"*"},
	"include":    {"*"},
	"includeif":  {"*"},
	"filter":     {"*"},
	"credential": {"*"},
	"pager":      {"*"},
	"hook":       {"*"},
	"gpg":        {"*"},
	"sendemail":  {"*"},
	"imap":       {"*"},
	"difftool":   {"*"},
	"mergetool":  {"*"},
	"guitool":    {"*"},
	"browser":    {"*"},
	"man":        {"*"},
	"instaweb":   {"*"},
	"trace2":     {"*"},
	"protocol":   {"*"},
}

// gitKeyRunsProgram reports whether setting the config key name (section.key
// or section.subsection.key) is refused; see gitProgramKeys.
func gitKeyRunsProgram(name string) bool {
	section, rest, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}
	keys := gitProgramKeys[strings.ToLower(section)]
	key := strings.ToLower(rest[strings.LastIndexByte(rest, '.')+1:])
	return slices.Contains(keys, "*") || slices.Contains(keys, key)
}

// gitSectionRunsProgram reports whether a section (section or
// section.subsection), as git config rename-section takes its new name, can
// hold a key of gitProgramKeys.
func gitSectionRunsProgram(name string) bool {
	section, _, _ := strings.Cut(name, ".")
	_, ok := gitProgramKeys[strings.ToLower(section)]
	return ok
}

// gitConfigSubcommands are the subcommands of git config (git 2.46+). git
// takes one only as the first argument; after an option, the arguments are
// the deprecated action form (git config --get name).
var gitConfigSubcommands = []string{"list", "get", "set", "unset", "rename-section", "remove-section", "edit"}

// gitConfigModes maps the action options of the deprecated form to the
// subcommand each stands for.
var gitConfigModes = map[string]string{
	"--list": "list", "-l": "list",
	"--get": "get", "--get-all": "get", "--get-regexp": "get", "--get-urlmatch": "get",
	"--get-color": "get", "--get-colorbool": "get",
	"--add": "set", "--replace-all": "set",
	"--unset": "unset", "--unset-all": "unset",
	"--rename-section": "rename-section",
	"--remove-section": "remove-section",
	"--edit":           "edit", "-e": "edit",
}

// gitConfigLongOpts are git config's long options, the subcommands' and the
// deprecated form's, against which an abbreviated one (--ed) is expanded.
var gitConfigLongOpts = []string{
	"global", "system", "local", "worktree", "file", "blob",
	"get", "get-all", "get-regexp", "get-urlmatch", "get-color", "get-colorbool",
	"replace-all", "add", "unset", "unset-all", "rename-section", "remove-section",
	"list", "edit", "fixed-value", "type", "bool", "int", "bool-or-int",
	"bool-or-str", "path", "expiry-date", "null", "name-only", "includes",
	"show-origin", "show-scope", "show-names", "default", "comment", "all",
	"regexp", "value", "url", "append",
}

// gitConfigValueOpts are the options of gitConfigLongOpts (and the short
// ones) that take a value.
var gitConfigValueOpts = optSpec{short: "ft", long: []string{"file", "blob", "type", "default", "comment", "value", "url"}}

// gitConfigAction returns what git config does with args (the arguments
// after "config"): one of gitConfigSubcommands, or "" when the deprecated
// form names more than one action (which git refuses). It also returns the
// operands: the names and values, without the subcommand.
func gitConfigAction(args []string) (string, []string) {
	if len(args) > 0 && slices.Contains(gitConfigSubcommands, args[0]) {
		_, operands := scanGitConfigArgs(args[1:])
		return args[0], operands
	}
	opts, operands := scanGitConfigArgs(args)
	action := ""
	for _, opt := range opts {
		mode, ok := gitConfigModes[opt]
		switch {
		case !ok || mode == action:
		case mode == "edit" || action == "edit":
			action = "edit" // whatever else is given
		case action != "":
			return "", operands
		default:
			action = mode
		}
	}
	if action == "" {
		// git config name reads it; git config name value sets it.
		action = "set"
		if len(operands) == 1 {
			action = "get"
		}
	}
	return action, operands
}

// scanGitConfigArgs splits git config's arguments into the options (a long
// one expanded, as "--name"; short ones as "-x") and the operands.
func scanGitConfigArgs(args []string) (opts, operands []string) {
	all := optSpec{long: gitConfigLongOpts}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return opts, append(operands, args[i+1:]...)
		case strings.HasPrefix(a, "--"):
			name, _, hasVal := strings.Cut(a[2:], "=")
			name = all.longName(name)
			opts = append(opts, "--"+name)
			if !hasVal && slices.Contains(gitConfigValueOpts.long, name) {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				opts = append(opts, "-"+string(a[j]))
				if strings.IndexByte(gitConfigValueOpts.short, a[j]) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		default:
			operands = append(operands, a)
		}
	}
	return opts, operands
}

// validateGitConfigArgs allows git config only to read when local_write is
// disabled: list and get, as subcommands of newer git (git config get
// user.name) or as the deprecated form's options (--list, --get, ...). With
// local_write it refuses git config edit, whose edits the sandbox can't see,
// and setting a key of gitProgramKeys, whichever operand names it: values
// that look like such a key are refused too, which is rare and can be set
// another way.
func validateGitConfigArgs(rest []*syntax.Word, cfg *config.GitConfig) error {
	action, operands := gitConfigAction(wordTexts(rest))
	if action == "list" || action == "get" {
		return nil
	}
	if !cfg.GitLocalWrite() {
		return fmt.Errorf("git config is only allowed with list, get, --list, --get, --get-all, --get-regexp, or --get-urlmatch (local_write is disabled)")
	}
	switch action {
	case "edit":
		return fmt.Errorf("git config edit is not allowed: the editor's changes to the config can't be checked; set keys with git config set")
	case "unset", "remove-section":
		return nil // removing a key never names a program
	case "rename-section":
		for _, op := range operands {
			if gitSectionRunsProgram(op) {
				return fmt.Errorf("git config rename-section to or from %q is not allowed: the section can hold keys that name a program for git to run", op)
			}
		}
		return nil
	}
	for _, op := range operands {
		if err := gitProgramKeyError(op); err != nil {
			return err
		}
	}
	return nil
}

// validateGitCloneConfig refuses git clone -c/--config setting a key of
// gitProgramKeys in the new repository's config. It reads the option in any
// of git's spellings (-ckey=value, -qc key=value, --conf key=value), and a
// short option bundle holding a c anywhere, as if the c were the option.
func validateGitCloneConfig(rest []*syntax.Word, _ *config.GitConfig) error {
	args := wordTexts(rest)
	for i := 0; i < len(args); i++ {
		a := args[i]
		val, ok := "", false
		switch {
		case a == "--":
			return nil
		case strings.HasPrefix(a, "--"):
			name, v, hasVal := strings.Cut(a, "=")
			if len(name) < len("--con") || !strings.HasPrefix("--config", name) {
				continue
			}
			val, ok = v, true
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
		case strings.HasPrefix(a, "-"):
			c := strings.IndexByte(a, 'c')
			if c < 0 {
				continue
			}
			val, ok = a[c+1:], true
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
		}
		if !ok {
			continue
		}
		key, _, _ := strings.Cut(val, "=")
		if err := gitProgramKeyError(key); err != nil {
			return err
		}
	}
	return nil
}

// gitProgramKeyError returns the error for setting the config key name, or
// nil when it may be set.
func gitProgramKeyError(name string) error {
	if !gitKeyRunsProgram(name) {
		return nil
	}
	return fmt.Errorf("setting git config key %q is not allowed: it names a program for git to run (or a file to include or write), which a git run outside the sandbox would use", name)
}

// gitTemplateFlag is git init and clone's --template, whose directory's
// hooks git copies into .git/hooks (also when git init re-runs in an
// existing repository), where a git run outside the sandbox runs them.
var gitTemplateFlag = gitFlag{gitBlocked, "copies the template directory's hooks into .git, where git outside the sandbox runs them"}
