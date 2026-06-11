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

// denoFetchSubcommands perform remote module/package fetches as a CLI
// operation (not as a runtime import in executed code), so an injected
// --deny-import does not stop them. They are gated at validation time behind
// runtimes.deno.allow_import instead.
var denoFetchSubcommands = map[string]bool{
	"cache":   true,
	"add":     true,
	"install": true,
}

// validateDenoArgs validates deno commands according to the runtime config.
//
// Deno is itself a permissioned runtime: `deno run` only gains filesystem,
// network, or env access when granted explicit --allow-* flags, and the OS
// sandbox confines whatever access is granted. We therefore allow the usual
// development subcommands (run, test, check, fmt, lint, bench, task, compile,
// add, install, etc.) and gate the operations that reach shared state or the
// network: `deno publish` (JSR registry) behind runtimes.deno.publish, `deno
// upgrade` (self-modifying binary) unconditionally, and the remote-fetch
// subcommands behind runtimes.deno.allow_import.
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

	// Gate remote-fetch subcommands behind allow_import. These fetch at the CLI
	// level, so the runtime --deny-import injected for code-executing
	// subcommands cannot stop them; blocking the subcommand is the only lever.
	if denoFetchSubcommands[subcommand] && !denoCfg.DenoAllowImport() {
		return fmt.Errorf("deno %s is not allowed (runtimes.deno.allow_import is disabled)", subcommand)
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

// scanDenoPerms inspects the permission-flag region of a deno subcommand (the
// tokens between the subcommand and the script target) for existing permission
// flags. It understands both long forms (--allow-read[=...]) and the short
// forms documented by `deno run --help`: -A (allow-all), -R (allow-read), -W
// (allow-write), including bundled short flags like -RW.
//
// Scanning STOPS at the first non-flag token, which is the script target (or a
// task name); everything after it is an argument to the script, not a Deno
// permission, and must not be interpreted here. Deno's permission flags only
// take attached values (--allow-read=PATH), never a separate argument, so a
// bare token is always the script boundary.
//
// Network/import allows are intentionally not tracked: a forced --deny-* always
// takes precedence over any --allow-* or -A, so detecting them is unnecessary.
func scanDenoPerms(args []string) denoPerms {
	var p denoPerms
	for _, a := range args {
		// First bare (non-flag) token is the script target; stop before its args.
		if !strings.HasPrefix(a, "-") {
			break
		}
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

// applyDenoSandbox rewrites a deno command (post-expansion argv) so Deno's own
// permission model mirrors the lite-sandbox policy:
//
//   - Filesystem (only when autoSandbox is true): --allow-read / --allow-write
//     are scoped to the sandbox's allowed paths, unless the invoker already
//     chose a scope (explicit --allow-read/-write or a blanket --allow-all/-A).
//   - Sockets: --deny-net is forced unless allowNetwork is true.
//   - Remote imports: --deny-import is forced unless allowImport is true. Deno
//     allows imports from a default host allowlist (deno.land/jsr.io/...) out
//     of the box and they are not covered by --deny-net, so import is a
//     separate lever.
//
// The network/import denials are applied independent of autoSandbox so the
// policy holds even when filesystem auto-scoping is turned off. Deno's --deny-*
// flags take precedence over any --allow-* or --allow-all the invoker supplied,
// so the denial cannot be bypassed.
//
// It is a no-op unless the subcommand accepts permission flags.
func applyDenoSandbox(args []string, readPaths, writePaths []string, autoSandbox, allowNetwork, allowImport bool) []string {
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
	// Filesystem scope: only when auto-sandbox is on, and only when the invoker
	// hasn't already granted read/write (an explicit --allow-read/-write or a
	// blanket -A means they chose a scope).
	if autoSandbox {
		if !perms.allowAll && !perms.allowRead && len(readPaths) > 0 {
			inject = append(inject, "--allow-read="+strings.Join(readPaths, ","))
		}
		if !perms.allowAll && !perms.allowWrite && len(writePaths) > 0 {
			inject = append(inject, "--allow-write="+strings.Join(writePaths, ","))
		}
	}
	// Network/import: force denials that override any allow the invoker supplied.
	if !allowNetwork && !perms.denyNet {
		inject = append(inject, "--deny-net")
	}
	if !allowImport && !perms.denyImport {
		inject = append(inject, "--deny-import")
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
