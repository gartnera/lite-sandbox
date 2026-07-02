package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// gitLocalReadSubcommands are read-only subcommands that inspect the local repo.
var gitLocalReadSubcommands = map[string]bool{
	"status":    true,
	"log":       true,
	"diff":      true,
	"show":      true,
	"blame":     true,
	"branch":    true,
	"tag":       true,
	"shortlog":  true,
	"describe":  true,
	"rev-parse": true,
	"rev-list":  true,
	"ls-files":  true,
	"ls-tree":   true,
	"cat-file":  true,
	"name-rev":    true,
	"merge-base":  true,
	"config":      true,
	"reflog":      true,
}

// gitLocalWriteSubcommands are subcommands that modify local repo state.
var gitLocalWriteSubcommands = map[string]bool{
	"add":         true,
	"commit":      true,
	"checkout":    true,
	"switch":      true,
	"restore":     true,
	"reset":       true,
	"stash":       true,
	"merge":       true,
	"rebase":      true,
	"cherry-pick": true,
	"rm":          true,
	"mv":          true,
	"init":        true,
	"bisect":      true,
	"clean":       true,
	"revert":      true,
	"worktree":    true,
	"notes":       true,
	"apply":       true,
	"am":          true,
}

// gitRemoteReadSubcommands are subcommands that read from remotes.
var gitRemoteReadSubcommands = map[string]bool{
	"fetch":     true,
	"pull":      true,
	"clone":     true,
	"ls-remote": true,
}

// gitRemoteWriteSubcommands are subcommands that write to remotes.
var gitRemoteWriteSubcommands = map[string]bool{
	"push": true,
}

// gitAlwaysBlockedSubcommands are dangerous subcommands that allow arbitrary execution.
var gitAlwaysBlockedSubcommands = map[string]bool{
	"hook":          true,
	"filter-branch": true,
}

// gitSubcommandsThatSpanCategories are subcommands that appear in localRead
// but need special flag handling when localWrite is enabled/disabled.
// "branch", "tag", and "config" are in localRead but have mutation flags
// that should only be allowed when localWrite is enabled.

// "remote" and "submodule" span read/write boundaries and need special handling.
var gitRemoteSubcommands = map[string]bool{
	"remote":    true,
	"submodule": true,
}

// blockedGitBranchFlags lists git branch flags that mutate state.
var blockedGitBranchFlags = map[string]string{
	"-d":                 "deletes a branch",
	"-D":                 "force deletes a branch",
	"--delete":           "deletes a branch",
	"-m":                 "renames a branch",
	"-M":                 "force renames a branch",
	"--move":             "renames a branch",
	"-c":                 "copies a branch",
	"-C":                 "force copies a branch",
	"--copy":             "copies a branch",
	"--edit-description": "modifies branch description",
}

// blockedGitTagFlags lists git tag flags that mutate state.
var blockedGitTagFlags = map[string]string{
	"-a":         "creates an annotated tag",
	"--annotate": "creates an annotated tag",
	"-d":         "deletes a tag",
	"--delete":   "deletes a tag",
	"-s":         "creates a signed tag",
	"--sign":     "creates a signed tag",
	"-f":         "force creates/replaces a tag",
	"--force":    "force creates/replaces a tag",
}

// blockedRemoteReadFlags are flags for "remote" that are write operations.
var blockedRemoteWriteSubcommands = map[string]bool{
	"add":    true,
	"remove": true,
	"rm":     true,
	"rename": true,
	"set-head":  true,
	"set-branches": true,
	"set-url":  true,
	"prune":    true,
}

// validateGitArgs validates git commands according to the granular permission model.
func validateGitArgs(args []*syntax.Word, gitCfg *config.GitConfig) error {
	if len(args) < 2 {
		// bare "git" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags like -C, --git-dir, etc.
	subcommand := ""
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("git arguments must be literal strings")
		}
		// Skip global git flags that take a value argument
		if lit == "-C" || lit == "-c" || lit == "--git-dir" || lit == "--work-tree" ||
			lit == "--namespace" || lit == "--super-prefix" || lit == "--config-env" {
			skipNext = true
			continue
		}
		// Skip flags (start with -)
		if strings.HasPrefix(lit, "-") {
			continue
		}
		subcommand = lit
		break
	}

	if subcommand == "" {
		// Only flags, no subcommand (e.g., "git --version")
		return nil
	}

	// Always blocked regardless of config
	if gitAlwaysBlockedSubcommands[subcommand] {
		return fmt.Errorf("git subcommand %q is not allowed", subcommand)
	}

	// Check each permission category
	if gitLocalReadSubcommands[subcommand] {
		if !gitCfg.GitLocalRead() {
			return fmt.Errorf("git subcommand %q is not allowed (local_read is disabled)", subcommand)
		}
		// For subcommands shared between read/write, apply flag restrictions
		// only when local_write is disabled.
		switch subcommand {
		case "branch":
			if !gitCfg.GitLocalWrite() {
				return validateGitBranchArgs(args)
			}
		case "tag":
			if !gitCfg.GitLocalWrite() {
				return validateGitTagArgs(args)
			}
		case "config":
			if !gitCfg.GitLocalWrite() {
				return validateGitConfigReadOnlyArgs(args)
			}
		}
		return nil
	}

	if gitLocalWriteSubcommands[subcommand] {
		if !gitCfg.GitLocalWrite() {
			return fmt.Errorf("git subcommand %q is not allowed (local_write is disabled)", subcommand)
		}
		return nil
	}

	if gitRemoteReadSubcommands[subcommand] {
		if !gitCfg.GitRemoteRead() {
			return fmt.Errorf("git subcommand %q is not allowed (remote_read is disabled)", subcommand)
		}
		return nil
	}

	if gitRemoteWriteSubcommands[subcommand] {
		if !gitCfg.GitRemoteWrite() {
			return fmt.Errorf("git subcommand %q is not allowed (remote_write is disabled)", subcommand)
		}
		return nil
	}

	// Handle remote/submodule which span read/write
	if gitRemoteSubcommands[subcommand] {
		return validateGitRemoteSubcommand(args, subcommand, gitCfg)
	}

	// Unknown subcommand - block by default
	return fmt.Errorf("git subcommand %q is not allowed", subcommand)
}

// validateGitRemoteSubcommand handles "remote" and "submodule" which have
// both read and write sub-subcommands.
func validateGitRemoteSubcommand(args []*syntax.Word, subcommand string, gitCfg *config.GitConfig) error {
	switch subcommand {
	case "remote":
		// Find the sub-subcommand of "remote"
		subSub := findSubSubcommand(args, "remote")
		if subSub == "" {
			// "git remote" with no sub-subcommand lists remotes (read)
			if !gitCfg.GitRemoteRead() {
				return fmt.Errorf("git subcommand %q is not allowed (remote_read is disabled)", subcommand)
			}
			return nil
		}
		if blockedRemoteWriteSubcommands[subSub] {
			if !gitCfg.GitLocalWrite() {
				return fmt.Errorf("git remote %s is not allowed (local_write is disabled)", subSub)
			}
			return nil
		}
		// Read operations: show, get-url
		if !gitCfg.GitRemoteRead() {
			return fmt.Errorf("git subcommand %q is not allowed (remote_read is disabled)", subcommand)
		}
		return nil

	case "submodule":
		subSub := findSubSubcommand(args, "submodule")
		// read-like: status, summary, foreach
		// write-like: add, init, update, deinit, sync, absorbgitdirs, set-branch, set-url
		readOps := map[string]bool{"status": true, "summary": true, "foreach": true, "": true}
		if readOps[subSub] {
			if !gitCfg.GitRemoteRead() {
				return fmt.Errorf("git subcommand %q is not allowed (remote_read is disabled)", subcommand)
			}
			return nil
		}
		if !gitCfg.GitLocalWrite() {
			return fmt.Errorf("git submodule %s is not allowed (local_write is disabled)", subSub)
		}
		return nil
	}

	return fmt.Errorf("git subcommand %q is not allowed", subcommand)
}

// findSubSubcommand finds the first non-flag argument after the given subcommand.
func findSubSubcommand(args []*syntax.Word, subcommand string) string {
	foundSub := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if !foundSub {
			if lit == subcommand {
				foundSub = true
			}
			continue
		}
		if strings.HasPrefix(lit, "-") {
			continue
		}
		return lit
	}
	return ""
}

// validateGitBranchArgs checks that git branch is not invoked with mutation flags.
func validateGitBranchArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedGitBranchFlags[lit]; blocked {
			return fmt.Errorf("git branch flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateGitTagArgs checks that git tag is not invoked with mutation flags.
func validateGitTagArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedGitTagFlags[lit]; blocked {
			return fmt.Errorf("git tag flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateGitConfigReadOnlyArgs checks that git config is only used with read flags.
func validateGitConfigReadOnlyArgs(args []*syntax.Word) error {
	hasReadOnlyFlag := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == "--list" || lit == "-l" || lit == "--get" || lit == "--get-all" ||
			lit == "--get-regexp" || lit == "--get-urlmatch" {
			hasReadOnlyFlag = true
		}
	}
	if !hasReadOnlyFlag {
		return fmt.Errorf("git config is only allowed with --list, --get, --get-all, --get-regexp, or --get-urlmatch")
	}
	return nil
}
