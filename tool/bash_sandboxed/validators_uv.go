package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// uvGlobalValueFlags are uv global options that consume the following token as
// their value. They are skipped when locating the subcommand so a value that
// looks like a subcommand (e.g. `uv --directory publish ...`) is not mistaken
// for one. Only flags we are confident take a value are listed: skipping too
// few merely risks a spurious block on the value, while skipping too many could
// hide a real blocked subcommand, so we bias toward the safe (fail-closed)
// direction — matching the conservative approach in the Go/cargo validators.
var uvGlobalValueFlags = map[string]bool{
	"--cache-dir":           true,
	"--config-file":         true,
	"--directory":           true,
	"--project":             true,
	"--color":               true,
	"--python":              true,
	"-p":                    true,
	"--index":               true,
	"--default-index":       true,
	"--allow-insecure-host": true,
}

// validateUvArgs validates uv commands according to the runtime config. uv is a
// code-execution runtime like Go/Deno: running Python code and fetching
// packages is core to normal use and is contained by the OS sandbox, so those
// are permitted. Only shared-state and self-modifying operations are gated:
//   - `uv publish` uploads distributions to an index (behind runtimes.uv.publish)
//   - `uv self update` rewrites the uv executable in place (always blocked,
//     mirroring `deno upgrade`)
func validateUvArgs(args []*syntax.Word, uvCfg *config.UvConfig) error {
	subcommand, subcommandIdx, err := findSubcommand("uv", args, uvGlobalValueFlags)
	if err != nil {
		return err
	}
	if subcommand == "" {
		// Bare "uv", or only flags (e.g. "uv --version") — prints help.
		return nil
	}

	switch subcommand {
	case "publish":
		return publishGate("uv", "runtimes.uv.publish", uvCfg.UvPublish())
	case "self":
		return validateUvSelfArgs(args[subcommandIdx+1:])
	}

	// All other subcommands are allowed (run, add, remove, sync, lock, pip,
	// venv, build, tool, python, cache, etc.)
	return nil
}

// validateUvSelfArgs blocks `uv self update`, which downloads and overwrites the
// uv executable in place — an unsandboxable modification of the tool itself.
// Other `uv self` subcommands (e.g. `uv self version`) are read-only and allowed.
func validateUvSelfArgs(rest []*syntax.Word) error {
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" || strings.HasPrefix(lit, "-") {
			continue
		}
		if lit == "update" {
			return fmt.Errorf("uv self update is not allowed: modifies the uv executable in place")
		}
		// First positional after "self" that isn't "update" — allowed.
		return nil
	}
	return nil
}
