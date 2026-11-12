package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

// A wrapper (timeout, env, ...) would start a shell script as a native
// program, so a native shell would run its body with none of it validated.
// For the wrappers whose effect the sandbox can apply itself, it peels the
// wrapper off instead and runs the script through its own interpreter, as
// it runs ./b.sh typed directly: timeout becomes a deadline on the script's
// context, env an environment for it, and nice, nohup, setsid, and stdbuf
// run it unchanged. xargs, find -exec, and xcrun still start what they wrap
// natively.

// inProcessWrappers are the wrappers runWrappedScript applies in-process.
var inProcessWrappers = map[string]bool{
	"timeout": true, "env": true, "nice": true, "nohup": true, "setsid": true, "stdbuf": true,
}

// wrapsShellScript reports whether args, under one or more inProcessWrappers,
// runs a shell script that the interpreter would run if it were typed
// directly (executeScript): a path to a file that is not a compiled binary,
// with no shebang or a shell's. A script allowed with no_sandbox runs
// natively on the host either way, and is left to the wrapper.
func (s *Sandbox) wrapsShellScript(dir string, args []string) bool {
	if len(args) == 0 || !inProcessWrappers[args[0]] {
		return false
	}
	for len(args) > 0 && inProcessWrappers[args[0]] {
		args = unwrapWrapper(args)
	}
	if len(args) == 0 || !isScriptPath(args[0]) {
		return false
	}
	path := absPath(args[0], dir)
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return false
	}
	if s.bareAllowsScript(args[0], dir) && s.scriptUnsandboxed(path) {
		return false
	}
	if isBinaryExecutable(path) {
		return false
	}
	shebang := scriptShebangArgv(path)
	return len(shebang) == 0 || isShellInterpreter(shebang[0])
}

// runWrappedScript applies the wrapper args[0] (one of inProcessWrappers) and
// runs the command it wraps through execArgv, so every gate a direct run
// passes applies to it too (see wrapsShellScript).
func (s *Sandbox) runWrappedScript(ctx context.Context, args []string, useOSSandbox bool, readAllowedPaths, writeAllowedPaths []string, sets resolvedPathSets, depth int) error {
	spec := wrapperSpecs[args[0]]
	p, idx, operands, err := spec.parse(args, args)
	if err != nil {
		return err
	}
	if idx < 0 {
		return fmt.Errorf("%s: no command to run", args[0])
	}
	inner := args[idx:]
	run := func(ctx context.Context) error {
		return s.execArgv(ctx, inner, useOSSandbox, readAllowedPaths, writeAllowedPaths, sets, depth)
	}
	switch args[0] {
	case "env":
		env, err := s.wrappedEnv(ctx, p, args[operands:idx])
		if err != nil {
			return err
		}
		return run(withEnvOverride(ctx, env))
	case "timeout":
		return runWithTimeout(ctx, p, args[operands], run)
	}
	return run(ctx)
}

// runWithTimeout runs run under timeout's DURATION (a decimal number of
// seconds, or of minutes, hours, or days with an m, h, or d suffix; 0 for
// none), with timeout's exit status when it expires: 124, or with
// --preserve-status that of a command killed by SIGTERM (143). The -s and
// -k options have no in-process counterpart: the script is stopped at its
// next command, and the native program it is running is killed.
func runWithTimeout(ctx context.Context, p parsedArgs, duration string, run func(context.Context) error) error {
	d, err := parseTimeoutDuration(duration)
	if err != nil {
		return fmt.Errorf("timeout: invalid time interval %q", duration)
	}
	if d == 0 {
		return run(ctx)
	}
	preserve := false
	for _, o := range p.opts {
		if o.name == "preserve-status" {
			preserve = true
		}
	}
	tctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	err = run(tctx)
	if ctx.Err() == nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
		if preserve {
			return interp.ExitStatus(128 + 15)
		}
		return interp.ExitStatus(124)
	}
	return err
}

// parseTimeoutDuration parses timeout(1)'s DURATION.
func parseTimeoutDuration(v string) (time.Duration, error) {
	unit := time.Second
	if n := len(v); n > 0 {
		switch v[n-1] {
		case 's':
			v = v[:n-1]
		case 'm':
			unit, v = time.Minute, v[:n-1]
		case 'h':
			unit, v = time.Hour, v[:n-1]
		case 'd':
			unit, v = 24*time.Hour, v[:n-1]
		}
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || strings.ContainsAny(v, "xXpP") {
		return 0, fmt.Errorf("invalid duration")
	}
	d := f * float64(unit)
	if d > float64(1<<62) {
		d = float64(1 << 62)
	}
	if f > 0 && d < 1 {
		d = 1
	}
	return time.Duration(d), nil
}

// wrappedEnv is the environment env(1) gives its command: the exported
// variables the script would inherit, emptied by -i (or a lone "-"), less
// those -u names, plus assigns (NAME=VALUE). env's other options don't
// change it.
func (s *Sandbox) wrappedEnv(ctx context.Context, p parsedArgs, assigns []string) (expand.Environ, error) {
	vars := map[string]string{}
	var order []string
	set := func(name, value string) {
		if _, ok := vars[name]; !ok {
			order = append(order, name)
		}
		vars[name] = value
	}
	scriptBaseEnv(ctx).Each(func(name string, vr expand.Variable) bool {
		if isExportedEnvVar(vr) {
			set(name, vr.String())
		}
		return true
	})
	for _, o := range p.opts {
		switch o.name {
		case "i", "ignore-environment":
			vars, order = map[string]string{}, nil
		case "u", "unset":
			delete(vars, o.value)
		}
	}
	for _, a := range assigns {
		name, value, _ := strings.Cut(a, "=")
		set(name, value)
	}
	var list []string
	for _, name := range order {
		if v, ok := vars[name]; ok {
			list = append(list, name+"="+v)
		}
	}
	env := expand.ListEnviron(list...)
	if err := s.checkBlockedEnv(env); err != nil {
		return nil, err
	}
	return env, nil
}

type envOverrideKey struct{}

// withEnvOverride makes env the environment of the script the next
// runNestedInterp runs, in place of the caller's exported variables.
func withEnvOverride(ctx context.Context, env expand.Environ) context.Context {
	return context.WithValue(ctx, envOverrideKey{}, env)
}

// scriptBaseEnv is the environment a script run under ctx inherits: an
// outer env's (withEnvOverride), or the caller's.
func scriptBaseEnv(ctx context.Context) expand.Environ {
	if env, ok := ctx.Value(envOverrideKey{}).(expand.Environ); ok && env != nil {
		return env
	}
	return interp.HandlerCtx(ctx).Env
}
