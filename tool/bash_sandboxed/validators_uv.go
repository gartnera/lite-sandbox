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
	if len(args) < 2 {
		// bare "uv" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags (and their values).
	subcommand := ""
	subcommandIdx := 0
	skipNext := false
	for i, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("uv arguments must be literal strings")
		}
		// Skip global flags that take a separate value argument (space form).
		// The --flag=value form carries its own value and never consumes the
		// next token.
		if uvGlobalValueFlags[lit] {
			skipNext = true
			continue
		}
		if strings.HasPrefix(lit, "-") {
			continue
		}
		subcommand = lit
		subcommandIdx = i + 1
		break
	}

	if subcommand == "" {
		// Only flags, no subcommand (e.g., "uv --version")
		return nil
	}

	switch subcommand {
	case "publish":
		if !uvCfg.UvPublish() {
			return fmt.Errorf("uv publish is not allowed (runtimes.uv.publish is disabled)")
		}
		return nil
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
