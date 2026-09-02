package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// goGlobalValueFlags are go global options that consume the following token as
// their value, so it is not mistaken for the subcommand.
var goGlobalValueFlags = map[string]bool{
	"-C": true,
}

// validateGoArgs validates go commands according to the runtime config.
func validateGoArgs(args []*syntax.Word, goCfg *config.GoConfig) error {
	subcommand, _, err := findSubcommand("go", args, goGlobalValueFlags)
	if err != nil {
		return err
	}
	if subcommand == "" {
		// Bare "go", or only flags (e.g. "go --help") — prints help.
		return nil
	}

	// go generate runs arbitrary shell commands from //go:generate directives,
	// so it is gated behind its own permission.
	if subcommand == "generate" {
		if !goCfg.GoGenerate() {
			return fmt.Errorf("go generate is not allowed (runtimes.go.generate is disabled)")
		}
		return nil
	}

	// Validate specific subcommands
	switch subcommand {
	case "run":
		return validateGoRunArgs(argsAfterToken(args, "run"))
	case "install":
		return validateGoInstallArgs(argsAfterToken(args, "install"))
	}

	// All other subcommands are allowed (build, test, mod, list, etc.)
	return nil
}

// validateGoRunArgs checks that go run is not invoked with remote package
// references or the -exec flag. rest is the argument list following "run".
func validateGoRunArgs(rest []*syntax.Word) error {
	skipNext := false
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		// Check for -exec flag
		if lit == "-exec" {
			return fmt.Errorf("go run -exec is not allowed: arbitrary command execution via external program")
		}
		// Flags that take values
		if strings.HasPrefix(lit, "-") && !strings.Contains(lit, "=") {
			// Could be a flag that takes a value, skip next
			skipNext = true
			continue
		}
		// Check if argument contains @ (remote package reference)
		if strings.Contains(lit, "@") {
			return fmt.Errorf("go run with remote package references (@) is not allowed: fetches and executes remote code")
		}
	}
	return nil
}

// validateGoInstallArgs checks that go install is not invoked with remote
// package references. rest is the argument list following "install".
func validateGoInstallArgs(rest []*syntax.Word) error {
	for _, arg := range rest {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		// Skip flags
		if strings.HasPrefix(lit, "-") {
			continue
		}
		// Check if argument contains @ (remote package reference)
		if strings.Contains(lit, "@") {
			return fmt.Errorf("go install with remote package references (@) is not allowed: fetches and installs remote code")
		}
	}
	return nil
}
