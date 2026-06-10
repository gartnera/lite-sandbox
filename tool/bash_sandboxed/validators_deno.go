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

// denoPerms records which permission grants/denials are already present on a
// deno subcommand's argument list.
type denoPerms struct {
	allowAll   bool
	allowRead  bool
	allowWrite bool
	denyNet    bool
	denyImport bool
}

// scanDenoPerms inspects the args following a deno subcommand for existing
// permission flags. It understands both long forms (--allow-read[=...]) and
// the short forms documented by `deno run --help`: -A (allow-all), -R
// (allow-read), -W (allow-write), including bundled short flags like -RW.
// Network/import allows are intentionally not tracked: a forced --deny-* always
// takes precedence over any --allow-* or -A, so detecting them is unnecessary.
func scanDenoPerms(args []string) denoPerms {
	var p denoPerms
	for _, a := range args {
		switch {
		case a == "-A" || a == "--allow-all":
			p.allowAll = true
		case a == "--allow-read" || strings.HasPrefix(a, "--allow-read=") ||
			a == "-R" || strings.HasPrefix(a, "-R="):
			p.allowRead = true
		case a == "--allow-write" || strings.HasPrefix(a, "--allow-write=") ||
			a == "-W" || strings.HasPrefix(a, "-W="):
			p.allowWrite = true
		case a == "--deny-net" || strings.HasPrefix(a, "--deny-net="):
			p.denyNet = true
		case a == "--deny-import" || strings.HasPrefix(a, "--deny-import="):
			p.denyImport = true
		default:
			// Bundled short permission flags, e.g. -RW or -AR. Only single-dash
			// tokens; strip any attached =value before inspecting the letters.
			if len(a) > 1 && a[0] == '-' && a[1] != '-' {
				letters := a[1:]
				if i := strings.IndexByte(letters, '='); i >= 0 {
					letters = letters[:i]
				}
				if strings.ContainsRune(letters, 'A') {
					p.allowAll = true
				}
				if strings.ContainsRune(letters, 'R') {
					p.allowRead = true
				}
				if strings.ContainsRune(letters, 'W') {
					p.allowWrite = true
				}
			}
		}
	}
	return p
}

// applyDenoAutoSandbox rewrites a deno command (post-expansion argv) so Deno's
// own permission model mirrors the lite-sandbox policy:
//
//   - --allow-read / --allow-write are scoped to the sandbox's allowed paths.
//   - Network is denied unless allowNetwork is true. Deno's network surface is
//     two distinct permissions: --allow-net (sockets) and --allow-import
//     (fetching remote modules, which defaults to an allowlist of hosts like
//     deno.land/jsr.io even with no flags). Both are force-denied via
//     --deny-net and --deny-import, which take precedence over any --allow-*
//     or --allow-all the invoker supplied, so network access cannot be
//     bypassed.
//
// It is a no-op unless the subcommand accepts permission flags. Existing
// read/write grants (or a blanket --allow-all / -A) are left in place for the
// filesystem scope, but never override the network denial.
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

	perms := scanDenoPerms(args[subIdx+1:])

	var inject []string
	// Filesystem scope: only inject when the invoker hasn't already granted it
	// (an explicit --allow-read/-write or a blanket -A means they chose a scope).
	if !perms.allowAll && !perms.allowRead && len(readPaths) > 0 {
		inject = append(inject, "--allow-read="+strings.Join(readPaths, ","))
	}
	if !perms.allowAll && !perms.allowWrite && len(writePaths) > 0 {
		inject = append(inject, "--allow-write="+strings.Join(writePaths, ","))
	}
	// Network: force denials that override any allow the invoker supplied.
	// --deny-import is required because remote module imports are allowed by
	// default and are not covered by --deny-net.
	if !allowNetwork {
		if !perms.denyNet {
			inject = append(inject, "--deny-net")
		}
		if !perms.denyImport {
			inject = append(inject, "--deny-import")
		}
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
