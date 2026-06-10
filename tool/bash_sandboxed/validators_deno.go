package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// blockedDenoSubcommands are dangerous subcommands that affect shared state
// outside the sandbox (the registry or the deno installation itself).
var blockedDenoSubcommands = map[string]string{
	"upgrade": "upgrades the deno binary in place (modifies the deno installation)",
}

// validateDenoArgs validates deno commands according to the runtime config.
//
// Deno is itself a permissioned runtime: `deno run` only gains filesystem,
// network, or env access when granted explicit --allow-* flags, and the OS
// sandbox confines whatever access is granted. We therefore allow the usual
// development subcommands (run, test, check, fmt, lint, bench, task, compile,
// add, install, etc.) and only gate the operations that reach shared state:
// `deno publish` (JSR registry) behind runtimes.deno.publish, and `deno
// upgrade` (self-modifying binary) unconditionally.
func validateDenoArgs(args []*syntax.Word, denoCfg *config.DenoConfig) error {
	if len(args) < 2 {
		// bare "deno" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags.
	subcommand := ""
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("deno arguments must be literal strings")
		}
		// Skip flags (start with -). Deno's global flags (-q, --quiet,
		// --unstable, --version, etc.) do not take separate value arguments.
		if strings.HasPrefix(lit, "-") {
			continue
		}
		subcommand = lit
		break
	}

	if subcommand == "" {
		// Only flags, no subcommand (e.g., "deno --version")
		return nil
	}

	// Gate publish behind the publish permission (affects the JSR registry).
	if subcommand == "publish" {
		if !denoCfg.DenoPublish() {
			return fmt.Errorf("deno publish is not allowed (runtimes.deno.publish is disabled)")
		}
		return nil
	}

	// Check for other blocked subcommands.
	if reason, blocked := blockedDenoSubcommands[subcommand]; blocked {
		return fmt.Errorf("deno subcommand %q is not allowed: %s", subcommand, reason)
	}

	// All other subcommands are allowed (run, eval, test, bench, check, fmt,
	// lint, doc, info, task, compile, add, remove, install, uninstall, etc.).
	return nil
}

// denoPermissionSubcommands are deno subcommands that accept --allow-* runtime
// permission flags. Auto-sandbox injection only targets these so we never pass
// permission flags to a subcommand that would reject them.
var denoPermissionSubcommands = map[string]bool{
	"run":     true,
	"eval":    true,
	"test":    true,
	"bench":   true,
	"repl":    true,
	"serve":   true,
	"compile": true,
	"install": true,
}

// applyDenoAutoSandbox rewrites a deno command (post-expansion argv) so Deno's
// own permission model mirrors the lite-sandbox policy:
//
//   - --allow-read / --allow-write are scoped to the sandbox's allowed paths.
//   - Network is denied unless allowNetwork is true; when denied, --deny-net is
//     forced, which takes precedence over any --allow-net or --allow-all the
//     invoker supplied (so it cannot be bypassed).
//
// It is a no-op unless the subcommand accepts permission flags. Existing
// --allow-read / --allow-write flags (or a blanket --allow-all / -A) are left
// in place for the filesystem scope, but never override the network denial.
func applyDenoAutoSandbox(args []string, readPaths, writePaths []string, allowNetwork bool) []string {
	if len(args) < 2 {
		return args
	}

	// Locate the subcommand (first non-flag token after "deno").
	subIdx := -1
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		subIdx = i
		break
	}
	if subIdx == -1 || !denoPermissionSubcommands[args[subIdx]] {
		return args
	}

	// Inspect existing permission flags to avoid clobbering explicit intent.
	hasAllowAll := false
	hasAllowRead := false
	hasAllowWrite := false
	hasDenyNet := false
	for _, a := range args[subIdx+1:] {
		switch {
		case a == "-A" || a == "--allow-all":
			hasAllowAll = true
		case a == "--allow-read" || strings.HasPrefix(a, "--allow-read="):
			hasAllowRead = true
		case a == "--allow-write" || strings.HasPrefix(a, "--allow-write="):
			hasAllowWrite = true
		case a == "--deny-net" || strings.HasPrefix(a, "--deny-net="):
			hasDenyNet = true
		}
	}

	var inject []string
	// Filesystem scope: only inject when the invoker hasn't already granted it
	// (an explicit --allow-read/-write or a blanket -A means they chose a scope).
	if !hasAllowAll && !hasAllowRead && len(readPaths) > 0 {
		inject = append(inject, "--allow-read="+strings.Join(readPaths, ","))
	}
	if !hasAllowAll && !hasAllowWrite && len(writePaths) > 0 {
		inject = append(inject, "--allow-write="+strings.Join(writePaths, ","))
	}
	// Network: force a deny that overrides any allow the invoker supplied.
	if !allowNetwork && !hasDenyNet {
		inject = append(inject, "--deny-net")
	}
	if len(inject) == 0 {
		return args
	}

	// Insert the flags immediately after the subcommand so deno parses them as
	// runtime permissions (anything after the script target is a script arg).
	out := make([]string, 0, len(args)+len(inject))
	out = append(out, args[:subIdx+1]...)
	out = append(out, inject...)
	out = append(out, args[subIdx+1:]...)
	return out
}
