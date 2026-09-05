package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
)

// rule identifies a validation check. Every error a validation layer produces
// is classified under one rule, which decides two things: whether the current
// mode enforces it (see rule.blockedIn) and how it is labeled in the audit log.
type rule string

const (
	// ruleCommandWhitelist: the command is not on the allowlist. Allowlist only.
	ruleCommandWhitelist rule = "command_whitelist"
	// ruleRuntimeDisabled: a code-execution runtime (go, pnpm, cargo, deno,
	// flutter, uv) is not enabled in config. Allowlist only.
	ruleRuntimeDisabled rule = "runtime_disabled"
	// ruleLocalBinary: direct execution of a path (./script, /path/bin) without
	// local_binary_execution enabled. Allowlist only.
	ruleLocalBinary rule = "local_binary"
	// rulePathBoundary: a path argument, redirection target, or file open
	// resolves outside the readable/writable boundary, or inside .git.
	rulePathBoundary rule = "path_boundary"
	// ruleArgValidator: a per-command argument validator rejected the
	// invocation (find -delete, tar -x, git push, publish flags, ...).
	ruleArgValidator rule = "argument_validator"
	// ruleStructural: a construct the sandbox does not run at all — blocked
	// redirection forms, coprocesses, protected environment assignments, shell
	// interpreters in wrapped position, dynamic command names inside wrappers.
	ruleStructural rule = "structural"
	// ruleRedundantCd: a leading `cd` into the working directory the sandbox
	// already runs in (reject_redundant_cd).
	ruleRedundantCd rule = "redundant_cd"
)

// allowlistOnly reports whether the rule is enforced solely in allowlist mode.
// These are the checks that gate *what may run*; every other rule gates *what
// a command may touch* and is enforced in denylist mode too.
func (r rule) allowlistOnly() bool {
	switch r {
	case ruleCommandWhitelist, ruleRuntimeDisabled, ruleLocalBinary:
		return true
	}
	return false
}

// blockedIn reports whether a finding under r is enforced in mode m.
func (r rule) blockedIn(m config.Mode) bool {
	switch m {
	case config.ModeOpen:
		return false
	case config.ModeDenylist:
		return !r.allowlistOnly()
	default:
		return true
	}
}

// modes lists the modes in which r is enforced, for the audit record.
func (r rule) modes() []string {
	if r.allowlistOnly() {
		return []string{string(config.ModeAllowlist)}
	}
	return []string{string(config.ModeDenylist), string(config.ModeAllowlist)}
}

// ruleError tags a validation error with the rule that produced it and, when
// it can be isolated, the subject the rule fired on (a command name, a resolved
// path). Sites that report an untagged error supply a fallback rule.
type ruleError struct {
	rule    rule
	subject string
	err     error
}

func (e *ruleError) Error() string { return e.err.Error() }
func (e *ruleError) Unwrap() error { return e.err }

// tagRule wraps err with r and subject; a nil err stays nil.
func tagRule(r rule, subject string, err error) error {
	if err == nil {
		return nil
	}
	return &ruleError{rule: r, subject: subject, err: err}
}

// ruleOf returns the rule and subject err was tagged with, or fallback and ""
// when it carries no tag. Wrapped tags (fmt.Errorf("...: %w", tagged)) are found.
func ruleOf(err error, fallback rule) (rule, string) {
	var re *ruleError
	if errors.As(err, &re) {
		return re.rule, re.subject
	}
	return fallback, ""
}

// Validation layers, as recorded in the audit log.
const (
	layerStatic  = "static"
	layerRuntime = "runtime"
)

// auditScope carries the top-level command being validated so runtime
// handlers deep inside the interpreter can attribute their findings. It rides
// on the context, which the interpreter propagates to every handler and to
// nested `bash -c` / script interpreters.
type auditScope struct {
	command string
	cwd     string
	source  string
}

type auditScopeKey struct{}

// withAuditScope returns ctx carrying the command under validation. source is
// audit.Record.Source: "bash" for the MCP bash tool, "hook" for the PreToolUse
// hook's --validate-bash path.
func withAuditScope(ctx context.Context, command, cwd, source string) context.Context {
	return context.WithValue(ctx, auditScopeKey{}, &auditScope{command: command, cwd: cwd, source: source})
}

func auditScopeFrom(ctx context.Context) *auditScope {
	if ctx == nil {
		return nil
	}
	if sc, ok := ctx.Value(auditScopeKey{}).(*auditScope); ok {
		return sc
	}
	return nil
}

// report is the single decision point for every validation finding. Given an
// error from a check (nil means the check passed), it classifies the error
// under a rule, writes an audit record when auditing is on, and returns the
// error only if the current mode enforces that rule — otherwise nil, so the
// caller carries on as if the check had passed.
//
// layer is the validation layer the finding surfaced in; fallback is the rule
// to use when err carries no ruleError tag.
func (s *Sandbox) report(ctx context.Context, layer string, fallback rule, err error) error {
	if err == nil {
		return nil
	}
	mode := s.getConfig().EffectiveMode()
	r, subject := ruleOf(err, fallback)
	blocked := r.blockedIn(mode)

	if logger := s.auditLogger(); logger != nil {
		rec := audit.Record{
			Mode:         string(mode),
			Source:       "bash",
			Layer:        layer,
			Rule:         string(r),
			Message:      err.Error(),
			Subject:      subject,
			Blocked:      blocked,
			WouldBlockIn: r.modes(),
		}
		if sc := auditScopeFrom(ctx); sc != nil {
			rec.Command = sc.command
			rec.CWD = sc.cwd
			if sc.source != "" {
				rec.Source = sc.source
			}
		}
		if werr := logger.Write(rec); werr != nil {
			slog.Warn("failed to write audit record", "error", werr)
		}
	}

	if blocked {
		return err
	}
	return nil
}

// auditLogger returns the current audit logger, or nil when auditing is off.
func (s *Sandbox) auditLogger() *audit.Logger {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.audit
}

// enforcesAllowlist reports whether the command whitelist and runtime gates are
// enforced (mode allowlist). Used by sites that must decide before validating
// further whether an unlisted command may proceed.
func (s *Sandbox) enforcesAllowlist() bool {
	return s.getConfig().EffectiveMode() == config.ModeAllowlist
}

// commandNotAllowed builds the tagged whitelist error for name, with a hint
// naming the config change that would permit it. The hint is what the agent
// relays to the user, so it should be exact.
func commandNotAllowed(name string) error {
	hint := fmt.Sprintf("allow it with `lite-sandbox config extra-commands add %s`, or run in denylist mode (`lite-sandbox config mode set denylist`)", name)
	return tagRule(ruleCommandWhitelist, name, fmt.Errorf("command %q is not allowed; %s", name, hint))
}

// directExecutionNotAllowed builds the tagged error for running a path
// (./script, /path/bin) while local_binary_execution is off.
func directExecutionNotAllowed(name string) error {
	return tagRule(ruleLocalBinary, name, fmt.Errorf("direct execution of %q is not allowed; enable it with `lite-sandbox config local-binary-execution enable`, or run in denylist mode (`lite-sandbox config mode set denylist`)", name))
}
