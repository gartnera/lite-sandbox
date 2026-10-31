package bash_sandboxed

import (
	"fmt"
)

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
