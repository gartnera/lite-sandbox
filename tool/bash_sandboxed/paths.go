package bash_sandboxed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// gitGlobalPathFlags lists git global flags whose next argument is a path
// that controls where git runs (not a file being read/written). These
// arguments are exempt from sandbox path validation because they determine
// git's working context; git's own command validator enforces what operations
// are permitted within that context.
var gitGlobalPathFlags = map[string]bool{
	"-C":             true,
	"--git-dir":      true,
	"--work-tree":    true,
	"--super-prefix": true,
}

// gitGlobalPathArgIndices returns a set of argument indices (within args)
// that are path values for git's global flags (e.g., -C /path). These
// should be excluded from file-path security checks.
func gitGlobalPathArgIndices(args []string) map[int]bool {
	skip := make(map[int]bool)
	for i, arg := range args {
		if gitGlobalPathFlags[arg] && i+1 < len(args) {
			skip[i+1] = true
		}
	}
	return skip
}

// wordLits reduces AST words to their literal text, with "" for words that
// are not plain literals (variables, quoted strings, substitutions). The
// static preflight can only reason about literals; empty entries are skipped
// by validateCommandArgPaths and re-checked after expansion by the
// interpreter's CallHandler.
func wordLits(words []*syntax.Word) []string {
	lits := make([]string, len(words))
	for i, w := range words {
		lits[i] = w.Lit()
	}
	return lits
}

// validatePaths checks that all path-like arguments in the AST resolve to
// locations under the allowed directories. This prevents reading files outside
// the sandbox boundary (e.g., cat /etc/passwd, cat ../../../etc/shadow).
// Write commands (cp, mv, rm, etc.) are checked against writeAllowedPaths;
// all other commands are checked against readAllowedPaths.
func validatePaths(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	// Resolve each allowed-path set once and reuse across every node, rather
	// than re-resolving symlinks for every argument of every command.
	resolvedRead := resolveAllowedPaths(readAllowedPaths)
	resolvedWrite := resolveAllowedPaths(writeAllowedPaths)
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		callExpr, ok := node.(*syntax.CallExpr)
		if !ok || len(callExpr.Args) == 0 {
			return true
		}
		cmdName := extractCommandName(callExpr.Args[0])
		allowedPaths := resolvedRead
		if writeCommands[cmdName] {
			allowedPaths = resolvedWrite
		}
		if err := validateCommandArgPaths(cmdName, wordLits(callExpr.Args), workDir, allowedPaths); err != nil {
			validationErr = err
			return false
		}
		return true
	})
	return validationErr
}

// validateCommandArgPaths checks the path-like arguments of a single command
// against the allowed directories. It is the shared core of the static AST
// preflight (validatePaths, which passes each argument's literal text with ""
// for non-literal words) and the interpreter's CallHandler
// (validateExpandedPaths, which passes post-expansion values). args includes
// the command name at index 0; allowed must already be selected for read vs
// write commands (see writeCommands) and pre-resolved.
func validateCommandArgPaths(cmdName string, args []string, workDir string, allowed []resolvedAllowedPath) error {
	isWriteCmd := writeCommands[cmdName]
	skipIndices := nonPathArgIndices(cmdName, args)
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue // dynamic/non-literal argument (static pass only)
		}
		if skipIndices[i] {
			continue // git global flag path values, sed scripts, grep patterns
		}
		var pathToCheck string
		if strings.HasPrefix(arg, "-") {
			// Extract any path embedded in a flag (e.g., -f/etc/passwd, --file=/etc/passwd).
			// Skip for commands whose flag values are never paths (e.g., cut -d/).
			if noFlagPathExtractionCommands[cmdName] {
				continue
			}
			pathToCheck = extractPathFromFlag(arg)
		} else {
			pathToCheck = arg
		}
		// Check for .git access even if it doesn't look like a typical path
		if pathToCheck == ".git" || strings.HasPrefix(pathToCheck, ".git/") || strings.HasPrefix(pathToCheck, ".git\\") {
			return fmt.Errorf("path %q accesses .git directory which is not allowed", arg)
		}
		if pathToCheck == "" || !looksLikePath(pathToCheck) {
			continue
		}
		if err := checkPathBoundary(arg, pathToCheck, workDir, isWriteCmd, allowed); err != nil {
			return err
		}
	}
	return nil
}

// nonPathArgIndices returns the argument indices (within args, which includes
// the command name at index 0) that are known not to be file paths for
// cmdName — git global-flag values (e.g., -C /repo, which controls where git
// runs, not what files are accessed), sed script expressions, and grep
// patterns — so they are excluded from file-path security checks.
func nonPathArgIndices(cmdName string, args []string) map[int]bool {
	switch cmdName {
	case "git":
		return gitGlobalPathArgIndices(args)
	case "sed":
		return sedNonPathArgIndices(args)
	case "grep", "egrep", "fgrep":
		return grepNonPathArgIndices(args)
	}
	return nil
}

// checkPathBoundary validates one candidate path against the allowed set:
// it resolves the path relative to workDir, verifies containment, and blocks
// .git internals. orig is the argument as written, used in error messages.
// For reads, an absolute path that doesn't exist locally is allowed through:
// it is likely a URL path argument (e.g., /v3/api/endpoint?query=value passed
// to curl) rather than a real filesystem path, and can't be read from disk
// anyway. Relative paths are always validated to prevent traversal attempts.
func checkPathBoundary(orig, path, workDir string, isWrite bool, allowed []resolvedAllowedPath) error {
	resolved := ResolvePath(path, workDir)
	if !isWrite && filepath.IsAbs(path) && !pathExistsLocally(resolved) {
		return nil
	}
	if !isUnderResolvedAllowedPaths(resolved, allowed) {
		return fmt.Errorf("path %q resolves to %q which is outside allowed directories", orig, resolved)
	}
	if isGitInternalPath(resolved) {
		return fmt.Errorf("path %q accesses .git directory which is not allowed", orig)
	}
	return nil
}

// validateRedirectPaths checks that file targets in redirections resolve to
// locations under the allowed directories. This covers both input redirects (<)
// and output redirects (>, >>, etc.) which must respect path boundaries.
// Input redirects are checked against readAllowedPaths; output redirects are
// checked against writeAllowedPaths. Output redirects to /dev/null are always allowed.
func validateRedirectPaths(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	resolvedRead := resolveAllowedPaths(readAllowedPaths)
	resolvedWrite := resolveAllowedPaths(writeAllowedPaths)
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		for _, r := range stmt.Redirs {
			// Only check redirects that reference file paths.
			// fd dups (DplIn, DplOut) and heredocs don't have file targets.
			var allowedPaths []resolvedAllowedPath
			switch r.Op {
			case syntax.RdrIn:
				allowedPaths = resolvedRead
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut,
				syntax.RdrAll, syntax.AppAll:
				allowedPaths = resolvedWrite
			case syntax.RdrInOut:
				// Read+write; must satisfy write permissions
				allowedPaths = resolvedWrite
			default:
				continue
			}
			lit := r.Word.Lit()
			if lit == "" {
				continue
			}
			// /dev/null is always allowed for output
			if lit == "/dev/null" {
				continue
			}
			resolved := ResolvePath(lit, workDir)
			if !isUnderResolvedAllowedPaths(resolved, allowedPaths) {
				validationErr = fmt.Errorf("redirect path %q resolves to %q which is outside allowed directories", lit, resolved)
				return false
			}
			if isGitInternalPath(resolved) {
				validationErr = fmt.Errorf("redirect path %q accesses .git directory which is not allowed", lit)
				return false
			}
		}
		return true
	})
	return validationErr
}

// IsGitInternalPath reports whether the resolved path is inside a .git directory.
// It is the exported form of isGitInternalPath for callers outside this package
// (e.g. the PreToolUse hook's write-boundary check).
func IsGitInternalPath(resolved string) bool {
	return isGitInternalPath(resolved)
}

// isGitInternalPath returns true if the resolved path is inside a .git directory.
// Direct access to .git contents is blocked to prevent reading sensitive data
// (hooks, config) and to force usage through the git command with its validator.
func isGitInternalPath(resolved string) bool {
	// Check each path component for ".git"
	parts := strings.Split(resolved, string(filepath.Separator))
	for _, part := range parts {
		if part == ".git" {
			return true
		}
	}
	return false
}

// noFlagPathExtractionCommands is the set of commands whose short-flag values
// are never file paths (e.g., cut -d/ uses / as a delimiter, not a path).
// For these commands, extractPathFromFlag is skipped to avoid false positives.
var noFlagPathExtractionCommands = map[string]bool{
	"cut":  true, // -d<delim>, -f<fields>, -b<bytes>, -c<chars>
	"sort": true, // -t<sep>
	"tr":   true, // operands are char classes, not paths
}

// looksLikePath returns true if the string looks like it references a filesystem
// path rather than a plain argument. We check arguments that are absolute,
// start with ./ or ../, or contain a path separator.
func looksLikePath(s string) bool {
	if filepath.IsAbs(s) {
		return true
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || s == "." || s == ".." {
		return true
	}
	if strings.Contains(s, "/") {
		return true
	}
	return false
}

// extractPathFromFlag extracts an embedded path value from a flag argument.
// Handles two forms:
//   - Long flags with '=': --file=/etc/passwd → /etc/passwd
//   - Short flags with appended value: -f/etc/passwd → /etc/passwd
//
// Returns empty string if no embedded path is found.
func extractPathFromFlag(flag string) string {
	// Long flag with = separator: --file=/etc/passwd
	if strings.HasPrefix(flag, "--") {
		if idx := strings.Index(flag, "="); idx != -1 {
			return flag[idx+1:]
		}
		return ""
	}
	// Short flag with appended value: -f/etc/passwd
	// Must be -X<value> where X is a single letter
	if len(flag) > 2 && flag[0] == '-' && flag[1] != '-' {
		// The value starts after the flag letter(s). For single-char flags
		// like -f, the value is at index 2. Return it and let looksLikePath decide.
		return flag[2:]
	}
	return ""
}

// ResolvePath resolves a potentially relative path to an absolute path,
// handling symlinks for any existing prefix of the path.
func ResolvePath(path, workDir string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(workDir, path)
	}
	path = filepath.Clean(path)

	// Try to resolve symlinks on the full path
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}

	// Path doesn't fully exist; resolve the longest existing prefix
	return resolveExistingPrefix(path)
}

// resolveExistingPrefix recursively resolves symlinks on the longest existing
// ancestor of path, then joins the non-existing suffix back.
func resolveExistingPrefix(path string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if dir == path {
		// Reached root
		return path
	}

	resolved, err := filepath.EvalSymlinks(dir)
	if err == nil {
		return filepath.Join(resolved, base)
	}

	return filepath.Join(resolveExistingPrefix(dir), base)
}

// nestedOnlyMarker is the trailing path segment that, when appended to a
// configured readable/writable path, grants access to everything *nested
// below* that directory while denying access to the directory itself. A bare
// path (no marker) grants the directory and all of its contents.
//
// The motivating case: a worktree container like ~/.superconductor/worktrees
// holds many sibling worktrees. Granting the bare container lets a single
// read/grep/glob sweep every worktree at once. Marking it as "<container>/*"
// instead permits reading an individual worktree under it (e.g. a peer) while
// blocking the container itself as a target, so no single call can span them all.
const nestedOnlyMarker = "*"

// splitNestedOnly separates an allowed-path entry into its base directory and
// whether it carries the descendants-only marker (a trailing "/*"). The base is
// returned with the marker removed. A degenerate entry that trims to empty or
// the filesystem root is treated as a literal (no marker), so it can never be
// (mis)used to widen access to everything below "/".
func splitNestedOnly(allowed string) (base string, nestedOnly bool) {
	marker := string(filepath.Separator) + nestedOnlyMarker
	if !strings.HasSuffix(allowed, marker) {
		return allowed, false
	}
	trimmed := strings.TrimSuffix(allowed, marker)
	if trimmed == "" || trimmed == string(filepath.Separator) {
		return allowed, false
	}
	return trimmed, true
}

// StripNestedOnlyMarker returns the base directory of an allowed-path entry,
// removing any trailing descendants-only "/*" marker. Use this where a real
// directory is required (e.g. granting a runtime its own read scope) rather
// than a path-matching boundary, since the marker is a lite-sandbox construct
// that those consumers don't understand.
func StripNestedOnlyMarker(allowed string) string {
	base, _ := splitNestedOnly(allowed)
	return base
}

// stripNestedOnlyMarkers maps allowed-path entries to their base directories,
// dropping any descendants-only "/*" markers. Used when handing the paths to a
// runtime (e.g. deno --allow-read) that needs real directories; such a runtime
// is granted the base subtree, since its permission model can't express
// "everything below but not the directory itself".
func stripNestedOnlyMarkers(paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = StripNestedOnlyMarker(p)
	}
	return out
}

// IsUnderAllowedPaths checks whether the resolved path is equal to or nested
// under one of the allowed directories. It resolves symlinks in the allowed
// paths to ensure comparisons work correctly on systems where directories
// may be accessed through symlinks (e.g., /var -> /private/var on macOS).
//
// An allowed entry carrying the descendants-only marker (a trailing "/*") only
// matches paths strictly nested below the directory, never the directory
// itself, so a single read/grep/glob cannot target the container and sweep
// every child at once.
func IsUnderAllowedPaths(path string, allowedPaths []string) bool {
	return isUnderResolvedAllowedPaths(path, resolveAllowedPaths(allowedPaths))
}

// resolvedAllowedPath is an allowed-path entry with its symlinks already
// resolved and its descendants-only marker already parsed. Resolving is a
// per-entry filesystem syscall (EvalSymlinks), so callers that check many
// argument paths against the same allowed set should resolve the set once with
// resolveAllowedPaths and reuse the result, rather than re-resolving inside the
// per-argument loop.
type resolvedAllowedPath struct {
	base       string
	nestedOnly bool
}

// resolveAllowedPaths resolves the symlinks of each allowed-path entry once.
func resolveAllowedPaths(allowedPaths []string) []resolvedAllowedPath {
	out := make([]resolvedAllowedPath, len(allowedPaths))
	for i, allowed := range allowedPaths {
		base, nestedOnly := splitNestedOnly(allowed)
		resolved, err := filepath.EvalSymlinks(base)
		if err != nil {
			// If we can't resolve, fall back to the original path.
			resolved = base
		}
		out[i] = resolvedAllowedPath{base: resolved, nestedOnly: nestedOnly}
	}
	return out
}

// isUnderResolvedAllowedPaths reports whether path is equal to or nested under
// one of the pre-resolved allowed paths. See IsUnderAllowedPaths for the
// descendants-only semantics.
func isUnderResolvedAllowedPaths(path string, allowed []resolvedAllowedPath) bool {
	for _, a := range allowed {
		if !a.nestedOnly && path == a.base {
			return true
		}
		if strings.HasPrefix(path, a.base+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// sedNonPathArgIndices returns the set of argument indices (within args) that
// are sed script expressions (not file paths) and should be excluded from
// file-path security checks. For sed:
//   - Arguments following -e/--expression are script expressions (not paths).
//   - The first positional (non-flag) argument is the sed script (not a path).
//   - Subsequent positional arguments are file paths and must be path-checked.
func sedNonPathArgIndices(args []string) map[int]bool {
	skip := make(map[int]bool)
	scriptSeen := false
	i := 1
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			switch arg {
			case "-e", "--expression":
				i++
				if i < len(args) {
					skip[i] = true // expression value, not a path
					scriptSeen = true
				}
			case "-f", "--file":
				i++ // file path value — NOT skipped (already blocked by validateSedArgs)
			}
			i++
			continue
		}
		// First non-flag positional arg is the sed script expression.
		if !scriptSeen {
			scriptSeen = true
			skip[i] = true
		}
		// Subsequent positional args are file paths — path-checked normally.
		i++
	}
	return skip
}

// grepNonPathArgIndices returns the set of argument indices (within args) that
// are grep pattern or non-path flag values and should be excluded from file-path
// security checks. For grep/egrep/fgrep:
//   - Arguments following -e/--regexp are regex patterns (not file paths).
//   - Arguments following -f/--file ARE file paths and must be path-checked.
//   - Arguments following numeric-value flags (-m, -A, -B, -C, etc.) are numbers.
//   - -e/-f (and their --regexp=/--file= and embedded forms) supply the pattern,
//     so when one is present the first positional is a file to search, not the
//     pattern, and must be path-checked.
//   - Otherwise the first positional (non-flag) argument is the regex pattern
//     (not a path).
//   - Subsequent positional arguments are file paths and must be path-checked.
func grepNonPathArgIndices(args []string) map[int]bool {
	skip := make(map[int]bool)
	patternSeen := false
	i := 1
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			// Everything after -- is a file path; stop skipping.
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			switch {
			case arg == "-e" || arg == "--regexp":
				i++
				if i < len(args) {
					skip[i] = true // regex pattern value
				}
				patternSeen = true // -e supplies the pattern; next positional is a file
			case arg == "-f" || arg == "--file":
				i++                // file path value — NOT skipped
				patternSeen = true // -f supplies the pattern; next positional is a file
			case strings.HasPrefix(arg, "--regexp=") || strings.HasPrefix(arg, "-e") ||
				strings.HasPrefix(arg, "--file=") || strings.HasPrefix(arg, "-f"):
				// Embedded forms (-epat, --regexp=pat, -fFILE, --file=FILE) carry
				// the pattern (or pattern file) in this same arg — no separate value
				// follows. The flag still supplies the pattern, so the next
				// positional is a file to search, not the pattern. The arg itself is
				// left out of the skip set so any embedded path is still checked.
				patternSeen = true
			case arg == "-m" || arg == "--max-count" ||
				arg == "-A" || arg == "--after-context" ||
				arg == "-B" || arg == "--before-context" ||
				arg == "-C" || arg == "--context":
				i++ // numeric value — not a path, skip silently
				if i < len(args) {
					skip[i] = true
				}
			}
			i++
			continue
		}
		// First non-flag positional arg is the regex pattern.
		if !patternSeen {
			patternSeen = true
			skip[i] = true
		}
		// Subsequent positional args are file paths — path-checked normally.
		i++
	}
	return skip
}

// validateExpandedPaths checks command arguments after variable expansion.
// This is called by the interpreter's CallHandler, where all variables and
// command substitutions have been resolved to their actual values.
// This catches bypasses like "cat $HOME/secret" that static validation misses.
// Write commands are checked against writeAllowedPaths; others against readAllowedPaths.
func validateExpandedPaths(args []string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	if len(args) == 0 {
		return nil
	}
	cmdName := args[0]
	allowedPaths := readAllowedPaths
	if writeCommands[cmdName] {
		allowedPaths = writeAllowedPaths
	}
	// Resolve the allowed-path set once; a single command (e.g. a glob) can
	// expand to thousands of args, and re-resolving inside the loop would do
	// O(args × allowedPaths) EvalSymlinks syscalls.
	return validateCommandArgPaths(cmdName, args, workDir, resolveAllowedPaths(allowedPaths))
}

// validateOpenPath checks a file path before the interpreter opens it (for
// redirections). This is called by the interpreter's OpenHandler, where
// variables in redirect targets have been expanded to actual paths.
// If the open flags include any write bits, the path is checked against
// writeAllowedPaths; otherwise it is checked against readAllowedPaths.
func validateOpenPath(path string, flag int, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	if path == "/dev/null" {
		return nil
	}
	isWrite := isWriteFlag(flag)
	allowedPaths := readAllowedPaths
	if isWrite {
		allowedPaths = writeAllowedPaths
	}
	return checkPathBoundary(path, path, workDir, isWrite, resolveAllowedPaths(allowedPaths))
}

// isWriteFlag returns true if the open flags include any write-related bits.
func isWriteFlag(flag int) bool {
	const writeBits = os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_APPEND | os.O_TRUNC
	return flag&writeBits != 0
}

// pathExistsLocally returns true if the path exists on the local filesystem.
func pathExistsLocally(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
