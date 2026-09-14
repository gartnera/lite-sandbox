package bash_sandboxed

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// deniedEntry is one parsed denied_commands entry, indexed by command name.
// prefix nil means a bare entry ("curl"), which denies every invocation of the
// command; a non-nil prefix ("lite-sandbox config" -> ["config"]) denies only
// invocations whose leading non-flag arguments start with those tokens. text is
// the entry exactly as configured, so the error can name what matched.
type deniedEntry struct {
	prefix []string
	text   string
}

// parseDeniedCommands parses denied_commands entries into a lookup keyed by
// command base name. The base name is the key so an entry written as
// "lite-sandbox config" also denies "/usr/local/bin/lite-sandbox config" and
// "./lite-sandbox config": a deny list that can be sidestepped by spelling the
// path differently is not a deny list. The cost is that a bare entry for a
// path ("./scripts/deploy.sh") denies any deploy.sh, which is the safe
// direction to err in.
func parseDeniedCommands(entries []string) map[string][]deniedEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string][]deniedEntry, len(entries))
	for _, e := range entries {
		fields := strings.Fields(e)
		if len(fields) == 0 {
			continue
		}
		key := filepath.Base(fields[0])
		entry := deniedEntry{text: strings.Join(fields, " ")}
		if len(fields) > 1 {
			entry.prefix = fields[1:]
		}
		out[key] = append(out[key], entry)
	}
	return out
}

// getDeniedCommands returns a snapshot of the parsed deny list.
func (s *Sandbox) getDeniedCommands() map[string][]deniedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deniedCommands
}

// deniedCommandName reports whether any deny entry is registered for the
// command name, whatever its arguments. It is the cheap pre-check for the
// raw-bash bypass, which has no parsed argv to match against: a command whose
// name appears in the deny list must go through AST parsing so the precise
// per-entry match below can run.
func (s *Sandbox) deniedCommandName(cmdName string) bool {
	if cmdName == "" {
		return false
	}
	return len(s.getDeniedCommands()[filepath.Base(cmdName)]) > 0
}

// deniedCommand reports whether an invocation of cmdName with the given
// expanded arguments (argv[1:]) matches the deny list, returning the entry
// that matched for the error message.
func (s *Sandbox) deniedCommand(cmdName string, args []string) (string, bool) {
	if cmdName == "" {
		return "", false
	}
	entries := s.getDeniedCommands()[filepath.Base(cmdName)]
	if len(entries) == 0 {
		return "", false
	}
	nonFlag, maxStart := positionalCandidates(args)
	for _, e := range entries {
		if len(e.prefix) == 0 {
			return e.text, true // bare entry: the command itself is denied
		}
		for start := 0; start <= maxStart && start < len(nonFlag); start++ {
			if hasTokenPrefix(nonFlag[start:], e.prefix) {
				return e.text, true
			}
		}
	}
	return "", false
}

// positionalCandidates returns a command's non-flag arguments together with
// the last index at which its first positional argument could sit.
//
// Which flags consume the next argument as their value is per-command
// knowledge the deny list does not have, and guessing wrong is exploitable:
// `lite-sandbox --log-level debug config mode set open` puts "debug" where the
// subcommand would be, so matching the prefix at index 0 alone would let a
// documented global flag walk straight through the deny list. So every
// position that could be the first positional is tried — index 0, plus each
// following one whose predecessors all sit directly after a flag and could
// therefore be that flag's value.
//
// Positions past that are not candidates, which is what keeps the match from
// firing on a denied token that appears later as data: with "git push" denied,
// `git log --grep push` is untouched, because "log" is a positional in its own
// right and nothing before "push" could have consumed it.
func positionalCandidates(args []string) (nonFlag []string, maxStart int) {
	prevFlag := false
	for _, a := range args {
		if a == "" {
			continue // a word that is not a plain literal: nothing to match
		}
		if strings.HasPrefix(a, "-") {
			prevFlag = true
			continue
		}
		nonFlag = append(nonFlag, a)
		if i := len(nonFlag) - 1; i == maxStart && prevFlag {
			maxStart = i + 1
		}
		prevFlag = false
	}
	return nonFlag, maxStart
}

// deniedCommandWords is deniedCommand for an unexpanded AST invocation, where
// args are the command's argument words. A word that is not a plain literal
// yields "" and is skipped exactly as an empty expanded argument is, so
// `lite-sandbox $SUB` matches nothing here and is left to the runtime handlers,
// which see the expanded argv.
func (s *Sandbox) deniedCommandWords(cmdName string, args []*syntax.Word) (string, bool) {
	return s.deniedCommand(cmdName, wordLits(args))
}

// hasTokenPrefix reports whether args starts with every token in prefix. An
// invocation with too few non-flag arguments never matches, so a
// subcommand-restricted entry leaves the bare command (`lite-sandbox`, which
// prints help) alone.
func hasTokenPrefix(args, prefix []string) bool {
	if len(prefix) > len(args) {
		return false
	}
	for i, tok := range prefix {
		if args[i] != tok {
			return false
		}
	}
	return true
}

// nonFlagArgs drops flags and empty (non-literal) arguments, leaving the
// positional tokens that a subcommand prefix is matched against.
func nonFlagArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		out = append(out, a)
	}
	return out
}
