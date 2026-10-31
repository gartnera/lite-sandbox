package bash_sandboxed

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The gh profile (config/profiles.go) grants gh its config dir and the system
// keyring scoped to gh: gh runs in an OS sandbox worker of its own that holds
// the token, which every other command's worker hides. validateGhArgs keeps
// that token where it is:
//
//   - nothing prints it: gh auth token, gh auth status --show-token, and
//     gh auth git-credential are refused (the first two unless the profile's
//     allow_token option is on), as are the auth subcommands that rewrite the
//     credentials or git's config (login, logout, refresh, switch, setup-git);
//   - nothing the agent or a sandboxed program wrote runs in gh's worker.
//     Only gh's built-in commands are allowed — an extension or an alias is
//     whatever program is installed under its name — and neither the
//     extension manager nor copilot, which downloads and runs the Copilot CLI.
//     gh runs git in the working directory, and git runs the hooks, filters,
//     fsmonitor and ssh commands the project's .git configures, which
//     sandboxed commands can write. So every invocation that makes gh run
//     such a git (status, checkout, fetch, pull, push, clone, ref updates) is
//     refused (ghGitError) unless the profile's allow_git option is on, which
//     trades that away for gh's git workflows; the git gh runs to read the
//     remotes, the branch and its config (remote -v, config --get-regexp,
//     symbolic-ref, rev-parse, log, show -s) runs nothing the project
//     configures. Every scoped worker also runs git with what git lets the
//     environment switch off switched off (scopedGitEnv), which narrows what
//     allow_git exposes but cannot close it.
//
// Everything else gh does goes through the GitHub API with the user's token:
// gh can do whatever the token allows (gh api reaches every endpoint).
func validateGhArgs(args []*syntax.Word, o ghOptions) error {
	argv := make([]string, len(args))
	for i, w := range args {
		v, ok := wordLiteral(w)
		if !ok {
			// A word known only after expansion (--body "$(cat notes.md)"):
			// the runtime layer re-runs this validator on the expanded argv.
			return nil
		}
		argv[i] = v
	}
	return checkGhArgv(argv, o)
}

// ghOptions are the gh profile's options the validator reads.
type ghOptions struct {
	allowToken bool // allow_token: gh auth token, gh auth status --show-token
	allowGit   bool // allow_git: the invocations that make gh run git
}

// ghGitError is the refusal of an invocation that makes gh run git, which the
// allow_git option lifts.
type ghGitError struct{ what string }

func (e *ghGitError) Error() string {
	return fmt.Sprintf("%s is not allowed: it makes gh run git in the working directory, where the hooks and config sandboxed commands can write would run with gh's token; the user can allow it with `lite-sandbox config profiles set gh allow_git true`, which gives up that protection", e.what)
}

// ghCommandAliases and ghSubcommandAliases map the built-in aliases of gh's
// commands and subcommands to their names.
var (
	ghCommandAliases = map[string]string{
		"cs":         "codespace",
		"ext":        "extension",
		"extensions": "extension",
	}
	ghSubcommandAliases = map[string]string{
		"co":  "checkout", // gh pr co
		"ls":  "list",
		"new": "create", // gh pr new, gh repo new, ...
	}
)

// ghCommands are gh's built-in top-level commands, each with the check its
// arguments (after the command name) go through; nil allows every
// invocation.
var ghCommands = map[string]func(rest []string, o ghOptions) error{
	"accessibility": nil,
	"agent-task":    nil,
	"alias":         ghOnly("alias", "list"),
	"api":           nil, // its paths are checked by ghAPIPaths
	"attestation":   nil,
	"auth":          checkGhAuth,
	"browse":        nil,
	"cache":         nil,
	"codespace":     ghRefuse("codespace", "ssh", "cp", "code", "jupyter", "ports", "logs"),
	"completion":    nil,
	"config":        ghOnly("config", "get", "list"),
	"copilot":       ghRefuseAll("copilot", "it downloads and runs the Copilot CLI"),
	"extension":     ghRefuseAll("extension", "extensions are programs gh runs with its token"),
	"gist":          ghRefuse("gist", "clone"),
	"gpg-key":       nil,
	"issue":         checkGhIssue,
	"label":         nil,
	"licenses":      nil,
	"org":           nil,
	"pr":            checkGhPr,
	"preview":       nil,
	"project":       nil,
	"release":       checkGhRelease,
	"repo":          checkGhRepo,
	"ruleset":       nil,
	"run":           nil,
	"search":        nil,
	"secret":        nil,
	"ssh-key":       nil,
	"status":        nil,
	"variable":      nil,
	"version":       nil,
	"workflow":      nil,
}

func checkGhArgv(argv []string, o ghOptions) error {
	rest := argv[1:]
	if len(rest) == 0 || ghOnlyHelp(rest) || slices.Equal(rest, []string{"--version"}) {
		return nil
	}
	name := rest[0]
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("gh: put the command first (gh pr list -R owner/repo, not gh %s ...)", name)
	}
	if alias, ok := ghCommandAliases[name]; ok {
		name = alias
	}
	check, ok := ghCommands[name]
	if !ok {
		return fmt.Errorf("gh %s is not allowed: only gh's built-in commands run, since an extension or alias runs with gh's token", name)
	}
	if check == nil {
		return nil
	}
	err := check(rest[1:], o)
	if gitErr := (*ghGitError)(nil); o.allowGit && errors.As(err, &gitErr) {
		return nil
	}
	return err
}

// ghOnlyHelp reports whether args are only help flags, which print the usage
// of the command they follow and run nothing.
func ghOnlyHelp(args []string) bool {
	for _, a := range args {
		if a != "-h" && a != "--help" {
			return false
		}
	}
	return len(args) > 0
}

// ghSubcommand splits the arguments of a command group (gh pr ...) into its
// subcommand and the arguments around it. Before the subcommand only the
// group's -R/--repo is accepted, since another flag there could hide a value
// that reads as the subcommand. A built-in alias (ls, co) is resolved.
func ghSubcommand(group string, rest []string) (string, []string, error) {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "-R" || a == "--repo":
			i++
		case strings.HasPrefix(a, "--repo=") || (strings.HasPrefix(a, "-R") && len(a) > 2):
		case a == "-h" || a == "--help":
		case strings.HasPrefix(a, "-"):
			return "", nil, fmt.Errorf("gh %s: put the subcommand before %s", group, a)
		default:
			sub := a
			if alias, ok := ghSubcommandAliases[sub]; ok {
				sub = alias
			}
			return sub, append(slices.Clone(rest[:i]), rest[i+1:]...), nil
		}
	}
	return "", nil, nil
}

// ghOnly allows only the named subcommands of group (and the group's help).
func ghOnly(group string, allowed ...string) func([]string, ghOptions) error {
	return func(rest []string, _ ghOptions) error {
		sub, others, err := ghSubcommand(group, rest)
		if err != nil || sub == "" {
			return err
		}
		if slices.Contains(allowed, sub) || ghOnlyHelp(others) {
			return nil
		}
		return fmt.Errorf("gh %s %s is not allowed: only gh %s %s are, since the rest change gh's own configuration", group, sub, group, strings.Join(allowed, "/"))
	}
}

// ghRefuse refuses the named subcommands of group, which run programs on
// this machine (ssh, port forwarding, an editor) or git.
func ghRefuse(group string, refused ...string) func([]string, ghOptions) error {
	return func(rest []string, _ ghOptions) error {
		sub, others, err := ghSubcommand(group, rest)
		if err != nil || sub == "" {
			return err
		}
		if slices.Contains(refused, sub) && !ghOnlyHelp(others) {
			if sub == "clone" {
				return &ghGitError{fmt.Sprintf("gh %s clone", group)}
			}
			return fmt.Errorf("gh %s %s is not allowed: it runs programs on this machine with gh's credentials", group, sub)
		}
		return nil
	}
}

func ghRefuseAll(group, reason string) func([]string, ghOptions) error {
	return func(rest []string, _ ghOptions) error {
		if ghOnlyHelp(rest) {
			return nil
		}
		return fmt.Errorf("gh %s is not allowed: %s", group, reason)
	}
}

// ghFlags returns every flag args name, reading each letter of a short
// cluster as a flag and never skipping a value: a superset of the flags gh
// sees, so a refused flag is never missed (a value that looks like one is
// refused too). Long flags are returned without their =value.
func ghFlags(args []string, valueShort string) []string {
	var out []string
	for _, a := range args {
		switch {
		case a == "--":
			return out
		case strings.HasPrefix(a, "--"):
			name, _, _ := strings.Cut(a, "=")
			out = append(out, name)
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				out = append(out, "-"+string(a[j]))
				if strings.IndexByte(valueShort, a[j]) >= 0 {
					break // the rest of the cluster is the value
				}
			}
		}
	}
	return out
}

func hasAnyFlag(flags []string, names ...string) string {
	for _, f := range flags {
		if slices.Contains(names, f) {
			return f
		}
	}
	return ""
}

// ghParse parses args the way gh's flag parser (pflag) does, given every
// flag the subcommand accepts: valueShort and valueLong take a value, short
// and long do not. It returns the flags seen and the positional arguments,
// or an error for a flag it does not know, so a flag gh reads differently
// cannot shift a value into a positional or hide a flag that must be there.
func ghParse(args []string, short, valueShort string, long, valueLong []string) (flags, positional []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return flags, append(positional, args[i+1:]...), nil
		case strings.HasPrefix(a, "--"):
			name, _, hasValue := strings.Cut(a[2:], "=")
			switch {
			case slices.Contains(valueLong, name):
				if !hasValue {
					i++
				}
			case slices.Contains(long, name) || name == "help":
			default:
				return nil, nil, fmt.Errorf("unknown flag --%s", name)
			}
			flags = append(flags, "--"+name)
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := a[j]
				switch {
				case strings.IndexByte(valueShort, c) >= 0:
					flags = append(flags, "-"+string(c))
					if j == len(a)-1 {
						i++
					}
					j = len(a) // the rest of the cluster is the value
				case strings.IndexByte(short, c) >= 0 || c == 'h':
					flags = append(flags, "-"+string(c))
				default:
					return nil, nil, fmt.Errorf("unknown flag -%c", c)
				}
			}
		default:
			positional = append(positional, a)
		}
	}
	return flags, positional, nil
}

// checkGhAuth allows gh auth status, and gh auth token and status
// --show-token with allow_token; every other auth subcommand prints the token
// (git-credential) or rewrites the credentials or git's config.
func checkGhAuth(rest []string, o ghOptions) error {
	sub, others, err := ghSubcommand("auth", rest)
	if err != nil || sub == "" || ghOnlyHelp(others) {
		return err
	}
	const optionHint = "; the user can allow it with `lite-sandbox config profiles set gh allow_token true`, which lets any command read the token it prints"
	switch sub {
	case "status":
		if f := hasAnyFlag(ghFlags(others, "h"), "-t", "--show-token"); f != "" && !o.allowToken {
			return fmt.Errorf("gh auth status %s is not allowed: it prints the token%s", f, optionHint)
		}
		return nil
	case "token":
		if !o.allowToken {
			return fmt.Errorf("gh auth token is not allowed: it prints the token%s", optionHint)
		}
		return nil
	case "git-credential":
		return fmt.Errorf("gh auth git-credential is not allowed: it prints the token")
	}
	return fmt.Errorf("gh auth %s is not allowed: it changes gh's credentials or git's config; run it yourself outside the sandbox", sub)
}

// checkGhPr refuses the pr invocations that make gh run git: checkout, a
// create that would push the current branch (one without --head), and a
// merge or close that deletes the local branch (-d without -R).
func checkGhPr(rest []string, o ghOptions) error {
	sub, others, err := ghSubcommand("pr", rest)
	if err != nil || sub == "" || ghOnlyHelp(others) {
		return err
	}
	switch sub {
	case "checkout":
		return &ghGitError{"gh pr checkout"}
	case "create":
		if o.allowGit {
			return nil
		}
		flags, _, err := ghParse(others, "dewf", "tbFBHrlapmTR",
			[]string{"draft", "editor", "web", "fill-verbose", "fill", "fill-first", "no-maintainer-edit", "dry-run"},
			[]string{"title", "body", "body-file", "base", "head", "reviewer", "assignee", "label", "project", "milestone", "recover", "template", "repo", "attach"})
		if err != nil {
			return fmt.Errorf("gh pr create: %w", err)
		}
		if hasAnyFlag(flags, "-H", "--head") == "" {
			return &ghGitError{"gh pr create without --head <branch> (push the branch first, then pass --head)"}
		}
		return nil
	case "merge", "close":
		flags := ghFlags(others, "bFtAcR")
		if hasAnyFlag(flags, "-d", "--delete-branch") != "" && hasAnyFlag(flags, "-R", "--repo") == "" {
			return &ghGitError{fmt.Sprintf("gh pr %s --delete-branch without -R owner/repo (which deletes only the remote branch)", sub)}
		}
	}
	return nil
}

// checkGhIssue allows gh issue develop only with --list: creating a linked
// branch fetches it into the local repository.
func checkGhIssue(rest []string, o ghOptions) error {
	sub, others, err := ghSubcommand("issue", rest)
	if err != nil || sub != "develop" || ghOnlyHelp(others) || o.allowGit {
		return err
	}
	flags, _, err := ghParse(others, "cl", "bniR", []string{"checkout", "list"}, []string{"branch-repo", "base", "name", "issue-repo", "repo"})
	if err != nil {
		return fmt.Errorf("gh issue develop: %w", err)
	}
	if hasAnyFlag(flags, "-l", "--list") == "" {
		return &ghGitError{"gh issue develop without --list (creating a branch fetches it)"}
	}
	return nil
}

// checkGhRelease refuses gh release delete --cleanup-tag, which also deletes
// the local tag.
func checkGhRelease(rest []string, _ ghOptions) error {
	sub, others, err := ghSubcommand("release", rest)
	if err != nil || sub != "delete" {
		return err
	}
	if hasAnyFlag(ghFlags(others, "R"), "--cleanup-tag") != "" {
		return &ghGitError{"gh release delete --cleanup-tag"}
	}
	return nil
}

// checkGhRepo refuses the repo invocations that make gh run git: clone, a
// create or fork that clones, pushes, or adds a remote, and a sync of the
// local repository (one without a destination repository argument).
func checkGhRepo(rest []string, o ghOptions) error {
	sub, others, err := ghSubcommand("repo", rest)
	if err != nil || sub == "" || ghOnlyHelp(others) || o.allowGit {
		return err
	}
	switch sub {
	case "clone":
		return &ghGitError{"gh repo clone"}
	case "create":
		// -h is --homepage here and takes a value.
		if f := hasAnyFlag(ghFlags(others, "dhtpglsrR"), "-c", "--clone", "-s", "--source", "--push"); f != "" {
			return &ghGitError{"gh repo create " + f}
		}
	case "fork":
		if f := hasAnyFlag(ghFlags(others, "R"), "--clone", "--remote"); f != "" {
			return &ghGitError{"gh repo fork " + f}
		}
	case "sync":
		_, positional, err := ghParse(others, "", "sb", []string{"force"}, []string{"source", "branch"})
		if err != nil {
			return fmt.Errorf("gh repo sync: %w", err)
		}
		if len(positional) == 0 {
			return &ghGitError{"gh repo sync without a destination repository (gh repo sync owner/fork)"}
		}
	}
	return nil
}

// ghAPIPaths returns, for a gh api invocation (args with the command name at
// index 0), the index of its endpoint argument, which is not a file path
// (gh api /user), and the files its -F/--field key=@file values read. Both
// are -1/nil for any other gh invocation.
func ghAPIPaths(args []string) (endpoint int, files []string) {
	endpoint = -1
	if len(args) < 2 || args[1] != "api" {
		return endpoint, nil
	}
	valueShort := "XFfHptq"
	valueLong := []string{"hostname", "method", "field", "raw-field", "header", "preview", "input", "template", "jq", "cache"}
	fieldFile := func(v string) {
		if _, val, ok := strings.Cut(v, "="); ok && strings.HasPrefix(val, "@") && val != "@-" {
			files = append(files, val[1:])
		}
	}
	for i := 2; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if endpoint < 0 && i+1 < len(args) {
				endpoint = i + 1
			}
			return endpoint, files
		case strings.HasPrefix(a, "--"):
			name, val, hasValue := strings.Cut(a[2:], "=")
			if !slices.Contains(valueLong, name) {
				continue
			}
			if !hasValue && i+1 < len(args) {
				i++
				val = args[i]
			}
			if name == "field" {
				fieldFile(val)
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(valueShort, a[j]) < 0 {
					continue
				}
				val := a[j+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				if a[j] == 'F' {
					fieldFile(val)
				}
				break
			}
		default:
			if endpoint < 0 {
				endpoint = i
			}
		}
	}
	return endpoint, files
}

// ghAttachFiles returns the files gh's --attach values (gh pr create, pr
// comment, issue edit, ...) may read. gh reads '<file>#<alt text>', taking the
// longest prefix ending before a # that exists as the file, so every such
// prefix is returned along with the whole value: the generic pass resolves
// the whole word, which can stay inside the working directory while the
// prefix gh opens does not (../secret#/../x).
func ghAttachFiles(args []string) []string {
	var files []string
	add := func(v string) {
		if v == "" {
			return
		}
		files = append(files, v)
		for i := strings.LastIndex(v, "#"); i > 0; i = strings.LastIndex(v[:i], "#") {
			files = append(files, v[:i])
		}
	}
	for i := 1; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--":
			return files
		case a == "--attach":
			if i+1 < len(args) {
				i++
				add(args[i])
			}
		case strings.HasPrefix(a, "--attach="):
			add(strings.TrimPrefix(a, "--attach="))
		}
	}
	return files
}

// validateGhReads checks the files gh api's -F key=@file values and the
// --attach values read against the read set. The generic pass resolves the
// whole key=@file word as one relative name, which is always inside the
// working directory, and misses the file an --attach value names (see
// ghAttachFiles), so without this gh (which holds the token) could be pointed
// at any file its worker can read, its own hosts.yml included.
func validateGhReads(args []string, workDir string, read []resolvedAllowedPath) error {
	_, files := ghAPIPaths(args)
	for _, f := range append(files, ghAttachFiles(args)...) {
		if err := checkBoundary(f, f, workDir, false, read); err != nil {
			return err
		}
	}
	return nil
}

// ghCommandSpec is gh's entry in profileCommands. gh api's endpoint (gh api
// /user) is a URL path, not a file; the files it and --attach upload are
// read-checked.
var ghCommandSpec = commandSpec{
	validate: func(s *Sandbox, args []*syntax.Word) error {
		cfg := s.getConfig()
		return validateGhArgs(args, ghOptions{
			allowToken: cfg.ProfileOption("gh", "allow_token"),
			allowGit:   cfg.ProfileOption("gh", "allow_git"),
		})
	},
	nonPathArgs: func(args []string) map[int]bool {
		if i, _ := ghAPIPaths(args); i > 0 {
			return map[int]bool{i: true}
		}
		return nil
	},
	checkPaths: func(args []string, workDir string, sets resolvedPathSets) error {
		return validateGhReads(args, workDir, sets.read)
	},
}
