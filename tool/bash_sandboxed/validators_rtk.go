package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// rtkWrappedCommands is the set of sandbox-whitelisted commands that rtk
// (https://github.com/rtk-ai/rtk) knows how to optimize. When the rtk
// integration is enabled, invocations of these commands are transparently
// rerouted through rtk (e.g. "git status" -> "rtk git status") so their output
// is filtered/compressed before it reaches the model.
//
// Only read-only / inspection commands are included. None are write commands,
// which keeps path validation correct: validatePaths keys on the original
// command name (e.g. "git"), so the rtk prefix added at exec time never changes
// whether read or write paths are enforced.
var rtkWrappedCommands = map[string]bool{
	"git":   true,
	"ls":    true,
	"grep":  true,
	"find":  true,
	"diff":  true,
	"cargo": true,
	"go":    true,
	"aws":   true,
	"pnpm":  true,
}

// rtkMetaSubcommands are rtk's own read-only subcommands (not proxied tools).
// "init" is intentionally excluded: it writes shell/agent hook configuration.
var rtkMetaSubcommands = map[string]bool{
	"gain":      true, // token-savings statistics
	"discover":  true, // missed-optimization analysis
	"session":   true, // session info
	"telemetry": true, // telemetry info
}

// rtkGlobalValueFlags are rtk global flags that consume the following argument
// as their value. rtk currently has none, but this keeps flag skipping robust.
var rtkGlobalValueFlags = map[string]bool{}

// validateRtkCommand gates the rtk command behind config and validates the
// command it proxies. Direct invocations like "rtk git status" are validated
// here; transparent rerouting (see rerouteThroughRtk) reuses the same wrap set.
func validateRtkCommand(s *Sandbox, args []*syntax.Word) error {
	if !s.getConfig().Rtk.RtkEnabled() {
		return fmt.Errorf("command \"rtk\" is not allowed (rtk.enabled is disabled)")
	}
	return validateRtkArgs(s, args)
}

// validateRtkArgs validates the arguments to rtk: it skips rtk's global flags,
// then either allows a read-only rtk meta-subcommand or recursively validates
// the proxied command against the whitelist (restricted to rtkWrappedCommands).
func validateRtkArgs(s *Sandbox, args []*syntax.Word) error {
	i := 1 // skip "rtk"
	for i < len(args) {
		lit := args[i].Lit()
		if lit == "" {
			return fmt.Errorf("rtk arguments must be literal strings")
		}
		// rtk global flags: -u/--ultra-compact, -v/--verbose (repeatable: -vv),
		// --version, and any future value-taking flag.
		if rtkGlobalValueFlags[lit] {
			i += 2
			continue
		}
		if strings.HasPrefix(lit, "-") {
			i++
			continue
		}
		// First non-flag token is the proxied command or rtk meta-subcommand.
		if rtkMetaSubcommands[lit] {
			return nil
		}
		if lit == "init" {
			return fmt.Errorf("rtk subcommand \"init\" is not allowed: it writes hook/agent configuration")
		}
		if !rtkWrappedCommands[lit] {
			return fmt.Errorf("rtk does not proxy command %q in the sandbox", lit)
		}
		return validateSubCommand(s, args[i:])
	}
	// Bare "rtk" (only flags / no subcommand) just prints help — allowed.
	return nil
}

// rtkEnabled reports whether the rtk integration is enabled in the current config.
func (s *Sandbox) rtkEnabled() bool {
	return s.getConfig().Rtk.RtkEnabled()
}

// rerouteThroughRtk rewrites args to run through rtk when the integration is
// enabled and cmdName is a command rtk knows how to optimize. It is applied at
// execution time, after validation, so the original command name drives all
// security checks while rtk only changes how the output is rendered.
func rerouteThroughRtk(cmdName string, args []string, rtkEnabled bool) []string {
	if !rtkEnabled || !rtkWrappedCommands[cmdName] {
		return args
	}
	rerouted := make([]string, 0, len(args)+1)
	rerouted = append(rerouted, "rtk")
	return append(rerouted, args...)
}
