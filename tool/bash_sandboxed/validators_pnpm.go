package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// pnpmGlobalValueFlags are pnpm global options treated as consuming the
// following token as their value, so it is not mistaken for the subcommand.
var pnpmGlobalValueFlags = map[string]bool{
	"-C":               true,
	"--dir":            true,
	"-w":               true,
	"--workspace-root": true,
}

// validatePnpmArgs validates pnpm commands according to the runtime config.
func validatePnpmArgs(args []*syntax.Word, pnpmCfg *config.PnpmConfig) error {
	subcommand, _, err := findSubcommand("pnpm", args, pnpmGlobalValueFlags)
	if err != nil {
		return err
	}
	if subcommand == "" {
		// Bare "pnpm", or only flags (e.g. "pnpm --version") — prints help.
		return nil
	}

	// pnpm publish pushes packages to the npm registry (shared state), so it is
	// gated behind its own permission.
	if subcommand == "publish" {
		return publishGate("pnpm", "runtimes.pnpm.publish", pnpmCfg.PnpmPublish())
	}

	// Validate specific subcommands. `pnpm exec` needs no validation of its own:
	// it runs binaries from node_modules/.bin, i.e. only locally installed
	// packages, which the OS sandbox confines like any other pnpm script.
	switch subcommand {
	case "dlx":
		return validatePnpmDlxArgs(argsAfterToken(args, "dlx"))
	}

	// All other subcommands are allowed (install, add, remove, test, run, etc.)
	return nil
}

// validatePnpmDlxArgs checks that pnpm dlx is not invoked with remote package
// references. pnpm dlx downloads and executes packages, similar to npx. rest is
// the argument list following "dlx".
func validatePnpmDlxArgs(rest []*syntax.Word) error {
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" {
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
