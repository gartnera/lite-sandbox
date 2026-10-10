package bash_sandboxed

import (
	"context"
	"fmt"
	"slices"

	"mvdan.cc/sh/v3/syntax"
)

// A commands entry with ask: true makes every matching invocation wait for
// the user's approval. The sandbox cannot ask the user itself: the approval is
// given for a whole bash tool call, before it runs (the PreToolUse hook asks,
// and the MCP server marks the call's context with WithApproval once it holds
// the hook's ticket). What the sandbox does is refuse a prompted invocation
// whose call was not approved, at every command gate the deny list checks —
// static, runtime, and the raw-bash path — so a command the hook could not see
// coming (a dynamic name, a script) is refused rather than run unasked.
//
// An approved invocation of a ask-only entry is treated as whitelisted
// (its argument validators and path checks still apply); an asking allow
// takes effect as the allow it is.

type approvalKey struct{}

// WithApproval marks the command run under ctx as approved by the user, which
// lets its prompted invocations (commands entries with ask: true) run. The
// approval covers the command line the user was shown, not a script file it
// runs: entering one drops it (see withoutApproval).
func WithApproval(ctx context.Context) context.Context {
	return context.WithValue(ctx, approvalKey{}, true)
}

// withoutApproval drops the approval for the contents of a script file the
// approved command runs: the user approved the command line they saw, not
// the commands of a file they did not.
func withoutApproval(ctx context.Context) context.Context {
	if !approved(ctx) {
		return ctx
	}
	return context.WithValue(ctx, approvalKey{}, false)
}

// approved reports whether ctx carries the user's approval.
func approved(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(approvalKey{}).(bool)
	return v
}

// getAskCommands returns a snapshot of the parsed ask entries.
func (s *Sandbox) getAskCommands() map[string][]deniedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.askCommands
}

// HasAskCommands reports whether any commands entry has ask: true,
// so a caller can skip looking for an approval when none can be needed.
func (s *Sandbox) HasAskCommands() bool {
	return len(s.getAskCommands()) > 0
}

// askCommand reports whether an invocation of cmdName with the expanded
// arguments args (argv[1:]) matches a ask entry, matched exactly as the
// deny list matches (by base name, with the leading positional arguments
// against an entry's subcommand), and returns the entry.
func (s *Sandbox) askCommand(cmdName string, args []string) (string, bool) {
	return matchCommandEntries(s.getAskCommands(), cmdName, args)
}

// checkAsk is the ask gate for one invocation. It returns
// whitelisted=true when the invocation matches a ask entry and the call
// was approved (the caller then treats the command as whitelisted), and the
// error to report when it matches one and was not.
func (s *Sandbox) checkAsk(ctx context.Context, cmdName string, args []string) (whitelisted bool, err error) {
	entry, ok := s.askCommand(cmdName, args)
	if !ok {
		return false, nil
	}
	if approved(ctx) {
		return true, nil
	}
	return false, askRequiredError(cmdName, entry)
}

// askCalls walks f for the invocations the static walk can name — every
// call with a literal command name — and returns the ask entries they
// match, deduplicated, in order. A dynamically-named command matches nothing
// here and is left to the runtime gates.
func (s *Sandbox) askCalls(f *syntax.File) (names, entries []string) {
	prompts := s.getAskCommands()
	if len(prompts) == 0 {
		return nil, nil
	}
	syntax.Walk(f, func(node syntax.Node) bool {
		ce, ok := node.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		name := ce.Args[0].Lit()
		if entry, ok := matchCommandEntries(prompts, name, wordLits(ce.Args[1:])); ok && !slices.Contains(entries, entry) {
			names = append(names, name)
			entries = append(entries, entry)
		}
		return true
	})
	return names, entries
}

// AskCommands returns the ask entries (commands entries with
// ask: true) that command runs, as far as a static reading of it can tell,
// or nil when it runs none or the mode enforces nothing. The PreToolUse hook
// asks the user to approve the call when it returns any. A command that does
// not parse returns nil; the sandbox refuses it anyway.
func (s *Sandbox) AskCommands(command string) []string {
	if len(s.getAskCommands()) == 0 || !ruleCommandAsk.blockedIn(s.getConfig().EffectiveMode()) {
		return nil
	}
	f, err := ParseBash(command)
	if err != nil {
		return nil
	}
	_, entries := s.askCalls(f)
	return entries
}

// checkRawAsk is the ask gate for a command string taking the raw-bash
// path (a bare allow leading it), which no other gate sees: the whole string
// is handed to the real bash. Any prompted invocation in it, wherever it sits,
// needs the call approved. A string that does not parse cannot be checked, so
// it is refused when there are ask entries to check it against.
func (s *Sandbox) checkRawAsk(ctx context.Context, command string) error {
	if len(s.getAskCommands()) == 0 || approved(ctx) {
		return nil
	}
	f, err := ParseBash(command)
	if err != nil {
		return s.report(ctx, layerStatic, ruleCommandAsk, tagRule(ruleCommandAsk, "", fmt.Errorf(
			"the command could not be parsed to check it for commands that need the user's approval: %w", err)))
	}
	names, entries := s.askCalls(f)
	if len(entries) == 0 {
		return nil
	}
	return s.report(ctx, layerStatic, ruleCommandAsk, askRequiredError(names[0], entries[0]))
}

// askRequiredError builds the tagged error for a prompted invocation of
// name (matching entry) in a call the user did not approve.
func askRequiredError(name, entry string) error {
	return tagRule(ruleCommandAsk, name, fmt.Errorf(
		"command %q needs the user's approval (the commands entry %q has ask: true), and this call was not approved. "+
			"The user is asked only when the agent's PreToolUse hook sees the command in the tool call itself: run it "+
			"with its name written out literally, in the command line rather than inside a script, `bash -c` string or variable, "+
			"and only with an agent installed to ask (Claude Code, by `lite-sandbox install`)",
		name, entry))
}

// askWrappedError builds the error for a prompted command run by a wrapper
// (find -exec, xargs, env, timeout, xcrun), which spawns it itself: the
// approval is not visible to the validators there, so the invocation is
// refused whether or not the call was approved.
func askWrappedError(name, entry string) error {
	return tagRule(ruleCommandAsk, name, fmt.Errorf(
		"command %q needs the user's approval (the commands entry %q has ask: true), which applies only to a command run "+
			"on its own, not under find -exec, xargs, env, timeout or xcrun; run it directly",
		name, entry))
}
