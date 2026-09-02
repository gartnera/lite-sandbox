package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// blockedCargoSubcommands are dangerous subcommands that affect shared state.
var blockedCargoSubcommands = map[string]string{
	"publish": "publishes crates to crates.io registry (affects shared state)",
	"login":   "stores registry credentials",
	"logout":  "removes registry credentials",
	"owner":   "manages crate ownership on the registry",
	"yank":    "removes a version from the registry index",
}

// cargoGlobalValueFlags are cargo global options that consume the following
// token as their value, so it is not mistaken for the subcommand.
var cargoGlobalValueFlags = map[string]bool{
	"-C":              true,
	"--manifest-path": true,
	"--config":        true,
	"-Z":              true,
}

// cargoInstallValueFlags are `cargo install` options that consume the following
// token as their value, so it is not mistaken for a crate name.
var cargoInstallValueFlags = map[string]bool{
	"--version":    true,
	"--vers":       true,
	"--git":        true,
	"--branch":     true,
	"--tag":        true,
	"--rev":        true,
	"--path":       true,
	"--root":       true,
	"--registry":   true,
	"--index":      true,
	"--target":     true,
	"--target-dir": true,
	"--jobs":       true,
	"-j":           true,
}

// validateCargoArgs validates cargo commands according to the runtime config.
func validateCargoArgs(args []*syntax.Word, rustCfg *config.RustConfig) error {
	subcommand, _, err := findSubcommand("cargo", args, cargoGlobalValueFlags)
	if err != nil {
		return err
	}
	if subcommand == "" {
		// Bare "cargo", or only flags (e.g. "cargo --version") — prints help.
		return nil
	}

	// Check if publish is explicitly blocked
	if subcommand == "publish" {
		return publishGate("cargo", "runtimes.rust.publish", rustCfg.RustPublish())
	}

	// Check for other blocked subcommands
	if reason, blocked := blockedCargoSubcommands[subcommand]; blocked {
		return fmt.Errorf("cargo subcommand %q is not allowed: %s", subcommand, reason)
	}

	// Validate specific subcommands
	switch subcommand {
	case "install":
		return validateCargoInstallArgs(argsAfterToken(args, "install"))
	}

	// All other subcommands are allowed (build, check, test, run, fmt, clippy, add, remove, new, init, etc.)
	return nil
}

// validateCargoInstallArgs checks that cargo install is not invoked with remote
// crate references. Local path installs (--path) are allowed, but remote crate
// installs fetch and execute build scripts. rest is the argument list following
// "install".
func validateCargoInstallArgs(rest []*syntax.Word) error {
	hasPath := false
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == "--path" || strings.HasPrefix(lit, "--path=") {
			hasPath = true
		}
	}
	// If --path is specified, it's a local install which is safe
	if hasPath {
		return nil
	}
	// Check if there are positional arguments (crate names) after "install"
	skipNext := false
	for _, arg := range rest {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		// Skip flags that take values
		if cargoInstallValueFlags[lit] {
			skipNext = true
			continue
		}
		if strings.HasPrefix(lit, "-") {
			continue
		}
		// Found a positional argument (crate name) - block remote installs
		return fmt.Errorf("cargo install with remote crate references is not allowed: fetches and executes remote build scripts")
	}
	return nil
}
