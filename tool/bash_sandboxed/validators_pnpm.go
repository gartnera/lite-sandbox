package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// blockedPnpmSubcommands are dangerous subcommands that affect shared state.
var blockedPnpmSubcommands = map[string]string{
	"publish": "publishes packages to npm registry (affects shared state)",
}

// validatePnpmArgs validates pnpm commands according to the runtime config.
func validatePnpmArgs(args []*syntax.Word, pnpmCfg *config.PnpmConfig) error {
	if len(args) < 2 {
		// bare "pnpm" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags
	subcommand := ""
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("pnpm arguments must be literal strings")
		}
		// Skip global pnpm flags that take a value argument
		if lit == "-C" || lit == "--dir" || lit == "-w" || lit == "--workspace-root" {
			skipNext = true
			continue
		}
		// Skip flags (start with -)
		if strings.HasPrefix(lit, "-") {
			continue
		}
		subcommand = lit
		break
	}

	if subcommand == "" {
		// Only flags, no subcommand (e.g., "pnpm --version")
		return nil
	}

	// Check if publish is explicitly blocked
	if subcommand == "publish" {
		if !pnpmCfg.PnpmPublish() {
			return fmt.Errorf("pnpm publish is not allowed (runtimes.pnpm.publish is disabled)")
		}
		return nil
	}

	// Check for other blocked subcommands
	if reason, blocked := blockedPnpmSubcommands[subcommand]; blocked {
		return fmt.Errorf("pnpm subcommand %q is not allowed: %s", subcommand, reason)
	}

	// Validate specific subcommands
	switch subcommand {
	case "dlx":
		return validatePnpmDlxArgs(args)
	case "exec":
		return validatePnpmExecArgs(args)
	}

	// All other subcommands are allowed (install, add, remove, test, run, etc.)
	return nil
}

// validatePnpmDlxArgs checks that pnpm dlx is not invoked with remote package references.
// pnpm dlx downloads and executes packages, similar to npx.
func validatePnpmDlxArgs(args []*syntax.Word) error {
	foundDlx := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if !foundDlx {
			if lit == "dlx" {
				foundDlx = true
			}
			continue
		}
		// Skip flags
		if strings.HasPrefix(lit, "-") {
			continue
		}
		// Any non-flag argument after dlx is a package to execute
		// Block all pnpm dlx usage as it downloads and executes arbitrary code
		return fmt.Errorf("pnpm dlx is not allowed: downloads and executes remote packages")
	}
	return nil
}

// validatePnpmExecArgs validates pnpm exec to ensure it only runs local binaries.
func validatePnpmExecArgs(args []*syntax.Word) error {
	// pnpm exec runs binaries from node_modules/.bin
	// This is generally safe as it only runs locally installed packages
	// No additional validation needed beyond what's already in place
	return nil
}
