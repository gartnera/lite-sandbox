package bash_sandboxed

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// gitPerm is what a git invocation needs to run: one of the permission levels
// of the config's git section, or gitBlocked/gitAlways.
type gitPerm int

const (
	gitBlocked     gitPerm = iota // never allowed, whatever the config
	gitLocalRead                  // inspects the repository (may write output files)
	gitLocalWrite                 // changes refs, the index, objects, or tracked files
	gitRemoteRead                 // contacts a remote to read from it
	gitRemoteWrite                // writes to a remote
	gitAlways                     // allowed even with every level off (help, version)
)

func (p gitPerm) allowed(cfg *config.GitConfig) bool {
	switch p {
	case gitLocalRead:
		return cfg.GitLocalRead()
	case gitLocalWrite:
		return cfg.GitLocalWrite()
	case gitRemoteRead:
		return cfg.GitRemoteRead()
	case gitRemoteWrite:
		return cfg.GitRemoteWrite()
	case gitAlways:
		return true
	}
	return false
}

// String is the config key of the permission level.
func (p gitPerm) String() string {
	switch p {
	case gitLocalRead:
		return "local_read"
	case gitLocalWrite:
		return "local_write"
	case gitRemoteRead:
		return "remote_read"
	case gitRemoteWrite:
		return "remote_write"
	}
	return ""
}

// gitFlag is a flag that changes what its subcommand needs: a write flag of a
// read subcommand (git branch -d), a remote flag of a local one (git archive
// --remote), or one that is never allowed (perm gitBlocked) because it runs a
// command given on the command line or reads files the path checks can't see.
type gitFlag struct {
	perm   gitPerm
	reason string
}

// gitSubcommand describes what one git subcommand needs.
type gitSubcommand struct {
	perm gitPerm
	// reason explains a gitBlocked perm, whether the subcommand's or an
	// action's.
	reason string
	// actions overrides perm by the subcommand's first operand, for the
	// subcommands whose action decides what they touch (git stash list,
	// git reflog expire). "" is the subcommand with no operand.
	actions map[string]gitPerm
	// flags lists the flags (spelled "-x" or "--name") that need more than
	// perm; see gitFlag.
	flags map[string]gitFlag
	// check, when set, validates the arguments after the subcommand once the
	// subcommand, its action, and its flags are allowed.
	check func(rest []*syntax.Word, cfg *config.GitConfig) error
}

var (
	gitRead      = gitSubcommand{perm: gitLocalRead}
	gitWrite     = gitSubcommand{perm: gitLocalWrite}
	gitFetchLike = gitSubcommand{perm: gitRemoteRead}
)

// gitBlockedSubcommand is a subcommand that is never allowed.
func gitBlockedSubcommand(reason string) gitSubcommand {
	return gitSubcommand{perm: gitBlocked, reason: reason}
}

// gitSubcommands classifies every git subcommand (as of git 2.5x; see
// `git help -a`). A subcommand that is not listed (including a user's alias,
// which would run its expansion unvalidated) is refused.
//
// A local read never changes the repository's refs, index, or tracked files,
// though it may write the output file it is told to (git archive -o, git
// format-patch, git bundle create) — the path checks and the OS sandbox
// confine those like any other write — and git merge-tree writes the
// unreferenced objects of the merge it reports on. Commands that run programs
// git's config names (pagers, hooks, diff drivers, gpg) are classified by what
// they do: the config is the user's, and setting it is itself a local write
// (git config). What is blocked outright is a subcommand or flag that runs a
// program named on the command line, launches something outside the repository
// (a server, a GUI, a scheduler), or handles credentials.
var gitSubcommands = map[string]gitSubcommand{
	// Local reads.
	"status":            gitRead,
	"log":               gitRead,
	"diff":              gitRead,
	"show":              gitRead,
	"blame":             gitRead,
	"annotate":          gitRead,
	"shortlog":          gitRead,
	"describe":          gitRead,
	"rev-parse":         gitRead,
	"rev-list":          gitRead,
	"ls-files":          gitRead,
	"ls-tree":           gitRead,
	"cat-file":          gitRead,
	"name-rev":          gitRead,
	"merge-base":        gitRead,
	"whatchanged":       gitRead,
	"range-diff":        gitRead,
	"show-branch":       gitRead,
	"cherry":            gitRead,
	"diff-files":        gitRead,
	"diff-index":        gitRead,
	"diff-tree":         gitRead,
	"diff-pairs":        gitRead,
	"for-each-ref":      gitRead,
	"show-ref":          gitRead,
	"count-objects":     gitRead,
	"verify-commit":     gitRead,
	"verify-tag":        gitRead,
	"verify-pack":       gitRead,
	"show-index":        gitRead,
	"pack-redundant":    gitRead,
	"get-tar-commit-id": gitRead,
	"merge-tree":        gitRead,
	"last-modified":     gitRead,
	"format-rev":        gitRead,
	"repo":              gitRead,
	"var":               gitRead,
	"check-attr":        gitRead,
	"check-ignore":      gitRead,
	"check-mailmap":     gitRead,
	"check-ref-format":  gitRead,
	"url-parse":         gitRead,
	"column":            gitRead,
	"stripspace":        gitRead,
	"patch-id":          gitRead,
	"mailinfo":          gitRead,
	"mailsplit":         gitRead,
	"fmt-merge-msg":     gitRead,
	// Local reads that write the output files they are told to.
	"format-patch": gitRead,
	"fast-export":  gitRead,
	"pack-objects": gitRead,
	"unpack-file":  gitRead,
	"bugreport":    gitRead,
	"diagnose":     gitRead,
	"archive": {perm: gitLocalRead, flags: map[string]gitFlag{
		"--remote": {gitRemoteRead, "fetches the archive from a remote"},
		// For a local --remote, git runs this program itself.
		"--exec": {gitBlocked, "runs the given command as git-upload-archive"},
	}},
	"grep": {perm: gitLocalRead, check: validateGitGrepArgs},
	// Local reads with flags or forms that write.
	"branch": {perm: gitLocalRead, flags: map[string]gitFlag{
		"-d":                 {gitLocalWrite, "deletes a branch"},
		"-D":                 {gitLocalWrite, "force deletes a branch"},
		"--delete":           {gitLocalWrite, "deletes a branch"},
		"-m":                 {gitLocalWrite, "renames a branch"},
		"-M":                 {gitLocalWrite, "force renames a branch"},
		"--move":             {gitLocalWrite, "renames a branch"},
		"-c":                 {gitLocalWrite, "copies a branch"},
		"-C":                 {gitLocalWrite, "force copies a branch"},
		"--copy":             {gitLocalWrite, "copies a branch"},
		"--edit-description": {gitLocalWrite, "modifies branch description"},
	}},
	"tag": {perm: gitLocalRead, flags: map[string]gitFlag{
		"-a":         {gitLocalWrite, "creates an annotated tag"},
		"--annotate": {gitLocalWrite, "creates an annotated tag"},
		"-d":         {gitLocalWrite, "deletes a tag"},
		"--delete":   {gitLocalWrite, "deletes a tag"},
		"-s":         {gitLocalWrite, "creates a signed tag"},
		"--sign":     {gitLocalWrite, "creates a signed tag"},
		"-f":         {gitLocalWrite, "force creates/replaces a tag"},
		"--force":    {gitLocalWrite, "force creates/replaces a tag"},
	}},
	"config": {perm: gitLocalRead, check: validateGitConfigArgs},
	"reflog": {perm: gitLocalRead, actions: map[string]gitPerm{
		"expire": gitLocalWrite,
		"delete": gitLocalWrite,
		"drop":   gitLocalWrite,
		"write":  gitLocalWrite,
	}},
	"fsck": {perm: gitLocalRead, flags: map[string]gitFlag{
		"--lost-found": {gitLocalWrite, "writes dangling objects into .git/lost-found"},
	}},
	"hash-object": {perm: gitLocalRead, flags: map[string]gitFlag{
		"-w": {gitLocalWrite, "writes the object into the repository"},
		// Listed so that it is not taken for an abbreviation of --stdin-paths.
		"--stdin": {gitLocalRead, "reads the object from stdin"},
		// Paths read from stdin never meet the path boundary check.
		"--stdin-paths": {gitBlocked, "reads the files named on stdin, which the sandbox can't check"},
	}},
	"symbolic-ref": {perm: gitLocalRead, check: validateGitSymbolicRefArgs, flags: map[string]gitFlag{
		"-d":       {gitLocalWrite, "deletes a symbolic ref"},
		"--delete": {gitLocalWrite, "deletes a symbolic ref"},
		"-m":       {gitLocalWrite, "updates a symbolic ref"},
	}},
	"interpret-trailers": {perm: gitLocalRead, flags: map[string]gitFlag{
		"--in-place": {gitLocalWrite, "edits the files in place"},
	}},

	// Local writes.
	"add":                gitWrite,
	"commit":             gitWrite,
	"checkout":           gitWrite,
	"switch":             gitWrite,
	"restore":            gitWrite,
	"reset":              gitWrite,
	"merge":              gitWrite,
	"rebase":             gitWrite,
	"cherry-pick":        gitWrite,
	"rm":                 gitWrite,
	"mv":                 gitWrite,
	"init":               gitWrite,
	"bisect":             gitWrite,
	"clean":              gitWrite,
	"revert":             gitWrite,
	"apply":              gitWrite,
	"am":                 gitWrite,
	"quiltimport":        gitWrite,
	"history":            gitWrite,
	"replay":             gitWrite,
	"replace":            gitWrite,
	"gc":                 gitWrite,
	"prune":              gitWrite,
	"prune-packed":       gitWrite,
	"repack":             gitWrite,
	"pack-refs":          gitWrite,
	"update-server-info": gitWrite,
	"checkout-index":     gitWrite,
	"read-tree":          gitWrite,
	"write-tree":         gitWrite,
	"commit-tree":        gitWrite,
	"mktag":              gitWrite,
	"mktree":             gitWrite,
	"merge-file":         gitWrite,
	"index-pack":         gitWrite,
	"unpack-objects":     gitWrite,
	"update-ref":         gitWrite,
	// update-index only edits the index (and, under --test-untracked-cache,
	// a scratch directory in the worktree). Its --fsmonitor runs only the
	// core.fsmonitor hook, which git config (also local_write) already sets.
	"update-index": gitWrite,
	"fast-import": {perm: gitLocalWrite, flags: map[string]gitFlag{
		// Lets the stream's own import-marks/export-marks name any file.
		"--allow-unsafe-features": {gitBlocked, "lets the import stream read and write files the sandbox can't check"},
	}},
	// Local writes whose listing actions only read.
	"stash":    {perm: gitLocalWrite, actions: map[string]gitPerm{"list": gitLocalRead, "show": gitLocalRead}},
	"worktree": {perm: gitLocalWrite, actions: map[string]gitPerm{"list": gitLocalRead}},
	"notes": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"": gitLocalRead, "list": gitLocalRead, "show": gitLocalRead, "get-ref": gitLocalRead,
	}},
	"rerere": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"status": gitLocalRead, "diff": gitLocalRead, "remaining": gitLocalRead,
	}},
	"sparse-checkout": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"list": gitLocalRead, "check-rules": gitLocalRead,
	}},
	"refs": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"list": gitLocalRead, "exists": gitLocalRead, "verify": gitLocalRead,
	}},
	"commit-graph":     {perm: gitLocalWrite, actions: map[string]gitPerm{"verify": gitLocalRead}},
	"multi-pack-index": {perm: gitLocalWrite, actions: map[string]gitPerm{"verify": gitLocalRead}},
	"bundle": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"create": gitLocalRead, "verify": gitLocalRead, "list-heads": gitLocalRead,
	}},
	"maintenance": {
		perm:    gitBlocked,
		reason:  "schedules background maintenance (cron, systemd, launchd) or edits the global config; use git maintenance run",
		actions: map[string]gitPerm{"run": gitLocalWrite, "is-needed": gitLocalRead},
		check:   validateGitMaintenanceArgs,
	},

	// Remote reads.
	"fetch":        gitFetchLike,
	"pull":         gitFetchLike,
	"clone":        gitFetchLike,
	"ls-remote":    gitFetchLike,
	"backfill":     gitFetchLike,
	"request-pull": gitFetchLike,
	"fetch-pack": {perm: gitRemoteRead, flags: map[string]gitFlag{
		"--upload-pack": {gitBlocked, "runs the given command as git-upload-pack"},
		"--exec":        {gitBlocked, "runs the given command as git-upload-pack"},
	}},
	// "git remote" lists and shows remotes (show queries them); its
	// configuration actions are local writes.
	"remote": {perm: gitRemoteRead, actions: map[string]gitPerm{
		"add":          gitLocalWrite,
		"remove":       gitLocalWrite,
		"rm":           gitLocalWrite,
		"rename":       gitLocalWrite,
		"set-head":     gitLocalWrite,
		"set-branches": gitLocalWrite,
		"set-url":      gitLocalWrite,
		"prune":        gitLocalWrite,
	}},
	"submodule": {perm: gitLocalWrite, actions: map[string]gitPerm{
		"": gitRemoteRead, "status": gitRemoteRead, "summary": gitRemoteRead, "foreach": gitRemoteRead,
	}},

	// Remote writes.
	"push": {perm: gitRemoteWrite},
	"send-pack": {perm: gitRemoteWrite, flags: map[string]gitFlag{
		"--receive-pack": {gitBlocked, "runs the given command as git-receive-pack"},
		"--exec":         {gitBlocked, "runs the given command as git-receive-pack"},
	}},

	// Allowed whatever the config, like git --help and git --version.
	"help":    {perm: gitAlways, check: validateGitHelpArgs},
	"version": {perm: gitAlways},

	// Never allowed.
	"hook":             gitBlockedSubcommand("runs repository hooks directly"),
	"filter-branch":    gitBlockedSubcommand("runs the shell commands given to its filters"),
	"difftool":         gitBlockedSubcommand("launches an external diff tool (--extcmd runs any command)"),
	"mergetool":        gitBlockedSubcommand("launches an external merge tool"),
	"merge-index":      gitBlockedSubcommand("runs the merge program given on its command line"),
	"merge-one-file":   gitBlockedSubcommand("is a helper for git merge-index"),
	"for-each-repo":    gitBlockedSubcommand("runs a git command, unvalidated, in each repository a config key lists"),
	"credential":       gitBlockedSubcommand("reads and stores saved credentials"),
	"credential-cache": gitBlockedSubcommand("reads and stores saved credentials"),
	"credential-store": gitBlockedSubcommand("reads and stores saved credentials"),
	"send-email":       gitBlockedSubcommand("sends mail, and its --smtp-server, --to-cmd, and --cc-cmd run commands"),
	"imap-send":        gitBlockedSubcommand("uploads patches to an IMAP server"),
	"http-push":        gitBlockedSubcommand("writes to a remote outside git push; use git push"),
	"http-fetch":       gitBlockedSubcommand("is a transport helper; use git fetch"),
	"daemon":           gitBlockedSubcommand("serves repositories over the network"),
	"http-backend":     gitBlockedSubcommand("serves repositories over the network"),
	"instaweb":         gitBlockedSubcommand("starts a web server"),
	"gitweb":           gitBlockedSubcommand("is a web server frontend"),
	"upload-pack":      gitBlockedSubcommand("is the server side of fetch"),
	"upload-archive":   gitBlockedSubcommand("is the server side of git archive --remote"),
	"receive-pack":     gitBlockedSubcommand("is the server side of push"),
	"shell":            gitBlockedSubcommand("is a restricted login shell for git servers"),
	"cvsserver":        gitBlockedSubcommand("serves repositories over the network"),
	"web--browse":      gitBlockedSubcommand("launches a web browser"),
	"gui":              gitBlockedSubcommand("is a graphical interface"),
	"citool":           gitBlockedSubcommand("is a graphical interface"),
	"gitk":             gitBlockedSubcommand("is a graphical interface"),
	"scalar":           gitBlockedSubcommand("registers the repository for scheduled background maintenance"),
	"archimport":       gitBlockedSubcommand("drives another version control system's tools"),
	"cvsimport":        gitBlockedSubcommand("drives another version control system's tools"),
	"cvsexportcommit":  gitBlockedSubcommand("drives another version control system's tools"),
	"p4":               gitBlockedSubcommand("drives another version control system's tools"),
	"svn":              gitBlockedSubcommand("drives another version control system's tools"),
}

// gitGlobalValueFlags are git global options that consume the following token
// as their value, so it is not mistaken for the subcommand. (This is a superset
// of gitGlobalPathFlags in paths.go, which covers only the value flags whose
// value is a path exempt from the sandbox boundary check.)
var gitGlobalValueFlags = map[string]bool{
	"-C":             true,
	"-c":             true,
	"--git-dir":      true,
	"--work-tree":    true,
	"--namespace":    true,
	"--super-prefix": true,
	"--config-env":   true,
}

// validateGitArgs validates git commands according to the granular permission model.
func validateGitArgs(args []*syntax.Word, gitCfg *config.GitConfig) error {
	subcommand, idx, err := findSubcommand("git", args, gitGlobalValueFlags)
	if err != nil {
		return err
	}
	if subcommand == "" {
		// Bare "git", or only flags (e.g. "git --version") — prints help.
		return nil
	}
	spec, ok := gitSubcommands[subcommand]
	if !ok {
		return fmt.Errorf("git subcommand %q is not allowed", subcommand)
	}
	rest := args[idx+1:]

	perm, what := spec.perm, fmt.Sprintf("git subcommand %q", subcommand)
	if spec.actions != nil {
		action := gitAction(rest)
		if p, ok := spec.actions[action]; ok {
			perm = p
		}
		if action != "" {
			what = fmt.Sprintf("git %s %s", subcommand, action)
		}
	}
	if perm == gitBlocked {
		return fmt.Errorf("%s is not allowed: %s", what, spec.reason)
	}
	if !perm.allowed(gitCfg) {
		return fmt.Errorf("%s is not allowed (%s is disabled)", what, perm)
	}

	if err := checkGitFlags(subcommand, rest, spec.flags, gitCfg); err != nil {
		return err
	}
	if spec.check != nil {
		return spec.check(rest, gitCfg)
	}
	return nil
}

// gitAction returns the first operand after the subcommand — the action of
// subcommands like stash, remote, and reflog — or "" when there is none. It
// assumes no option before the action takes a separate value; where one does
// (git notes --ref x list), the value is taken for the action, and the
// subcommand's default permission applies, which is the stricter one for
// every subcommand whose options allow that.
func gitAction(rest []*syntax.Word) string {
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" || strings.HasPrefix(lit, "-") {
			continue
		}
		return lit
	}
	return ""
}

// checkGitFlags refuses a flag in rest (the arguments after the subcommand,
// up to "--") that is blocked, or that needs a permission the config
// doesn't grant. A long flag also matches by any prefix git would expand to
// it (--del for --delete, --exec=cmd); a short flag matches only alone.
// Quoted parts count (--exec='sh -c id'); a flag spelled with an expansion
// is matched by its literal part here and in full after expansion.
func checkGitFlags(subcommand string, rest []*syntax.Word, flags map[string]gitFlag, cfg *config.GitConfig) error {
	if len(flags) == 0 {
		return nil
	}
	for _, arg := range rest {
		lit := wordText(arg)
		if lit == "--" {
			return nil
		}
		name, ok := matchGitFlag(lit, flags)
		if !ok {
			continue
		}
		f := flags[name]
		if f.perm == gitBlocked {
			return fmt.Errorf("git %s flag %q is not allowed: %s", subcommand, lit, f.reason)
		}
		if !f.perm.allowed(cfg) {
			return fmt.Errorf("git %s flag %q is not allowed: %s (%s is disabled)", subcommand, lit, f.reason, f.perm)
		}
	}
	return nil
}

// matchGitFlag returns the key of flags that the argument lit sets.
func matchGitFlag(lit string, flags map[string]gitFlag) (string, bool) {
	if _, ok := flags[lit]; ok {
		return lit, true
	}
	if !strings.HasPrefix(lit, "--") {
		return "", false
	}
	name, _, _ := strings.Cut(lit[2:], "=")
	if name == "" {
		return "", false
	}
	for _, key := range slices.Sorted(maps.Keys(flags)) {
		if strings.HasPrefix(key, "--") && strings.HasPrefix(key[2:], name) {
			return key, true
		}
	}
	return "", false
}

// validateGitGrepArgs blocks git grep's -O/--open-files-in-pager, which runs
// an arbitrary command (the optional value, or core.pager) on the matching
// files. git accepts the short form bundled with other short flags (-nO,
// -iOvim) and any unambiguous prefix of the long form (--open), so both are
// matched loosely; a false positive like -eOops can be spelled -e Oops.
func validateGitGrepArgs(rest []*syntax.Word, _ *config.GitConfig) error {
	for i := 0; i < len(rest); i++ {
		lit := rest[i].Lit()
		switch {
		case lit == "--":
			return nil
		case lit == "-e":
			i++ // the next token is a pattern, which may start with "-"
		case strings.HasPrefix(lit, "--"):
			name, _, _ := strings.Cut(lit[2:], "=")
			if name != "" && strings.HasPrefix("open-files-in-pager", name) {
				return fmt.Errorf("git grep flag %q is not allowed: runs a pager command on matching files", lit)
			}
		case strings.HasPrefix(lit, "-") && strings.Contains(lit[1:], "O"):
			return fmt.Errorf("git grep flag %q is not allowed: -O runs a pager command on matching files", lit)
		}
	}
	return nil
}

// gitConfigReadFlags are the git config flags that only read.
var gitConfigReadFlags = map[string]bool{
	"--list":          true,
	"-l":              true,
	"--get":           true,
	"--get-all":       true,
	"--get-regexp":    true,
	"--get-urlmatch":  true,
	"--get-color":     true,
	"--get-colorbool": true,
}

// validateGitConfigArgs allows git config only to read when local_write is
// disabled: with one of gitConfigReadFlags, or the list/get actions of
// newer git (git config get user.name). Older git reads those as a key
// named "list" or "get", which it rejects as having no section.
func validateGitConfigArgs(rest []*syntax.Word, cfg *config.GitConfig) error {
	if cfg.GitLocalWrite() {
		return nil
	}
	if action := gitAction(rest); action == "list" || action == "get" {
		return nil
	}
	for _, arg := range rest {
		if gitConfigReadFlags[arg.Lit()] {
			return nil
		}
	}
	return fmt.Errorf("git config is only allowed with list, get, --list, --get, --get-all, --get-regexp, or --get-urlmatch (local_write is disabled)")
}

// validateGitSymbolicRefArgs refuses git symbolic-ref with two operands —
// which points the first at the second — when local_write is disabled.
// (Its write flags are refused by gitSubcommands' flags.)
func validateGitSymbolicRefArgs(rest []*syntax.Word, cfg *config.GitConfig) error {
	if cfg.GitLocalWrite() {
		return nil
	}
	operands := 0
	for _, arg := range rest {
		if lit := wordText(arg); lit != "--" && !strings.HasPrefix(lit, "-") {
			operands++
		}
	}
	if operands > 1 {
		return fmt.Errorf("git symbolic-ref with a target is not allowed: updates a symbolic ref (local_write is disabled)")
	}
	return nil
}

// validateGitHelpArgs blocks git help -w/--web, which launches a web
// browser. All of git help's short options are boolean, so -w is caught
// bundled with them too (-mw).
func validateGitHelpArgs(rest []*syntax.Word, _ *config.GitConfig) error {
	for _, arg := range rest {
		lit := wordText(arg)
		if lit == "--" {
			return nil
		}
		web := false
		if strings.HasPrefix(lit, "--") {
			name, _, _ := strings.Cut(lit[2:], "=")
			web = name != "" && strings.HasPrefix("web", name)
		} else if strings.HasPrefix(lit, "-") {
			web = strings.Contains(lit[1:], "w")
		}
		if web {
			return fmt.Errorf("git help flag %q is not allowed: launches a web browser", lit)
		}
	}
	return nil
}

// validateGitMaintenanceArgs requires remote_read for the prefetch task of
// git maintenance run, which fetches from every remote.
func validateGitMaintenanceArgs(rest []*syntax.Word, cfg *config.GitConfig) error {
	for i, arg := range rest {
		lit := wordText(arg)
		prefetch := lit == "--task=prefetch" ||
			(lit == "--task" && i+1 < len(rest) && wordText(rest[i+1]) == "prefetch")
		if prefetch && !cfg.GitRemoteRead() {
			return fmt.Errorf("git maintenance task \"prefetch\" is not allowed: fetches from remotes (remote_read is disabled)")
		}
	}
	return nil
}
