package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

// installMode is the --mode flag: an enforcement mode to write into the
// sandbox config. Empty leaves the mode alone, which for a new config means the
// strict allowlist default.
var installMode string

// installConfigResult describes what configureSandboxConfig did, for output
// and tests.
type installConfigResult struct {
	Path    string
	Created bool
	Mode    config.Mode
	ModeSet bool // --mode was applied
	Audit   bool
	// OSSandbox is the resulting os_sandbox setting; OSSandboxEnabled reports
	// whether this call turned it on (denylist opt-in with a passing preflight).
	OSSandbox        bool
	OSSandboxEnabled bool
	// OSSandboxErr is the preflight failure when denylist mode was requested
	// but the OS sandbox could not be turned on; nil otherwise.
	OSSandboxErr error
}

// configureSandboxConfig manages lite-sandbox's own config during install.
// Defaults stay strict: a new config is created with only audit: true, so the
// mode remains the allowlist default and findings are logged for `audit
// report`. An existing config is never changed unless --mode is given.
//
// --mode opts into a posture explicitly. Denylist additionally turns on the OS
// sandbox when the platform backend passes preflight and os_sandbox was never
// set, because the deny lists only hold against child processes at the OS
// layer; a failing preflight is reported, not fatal.
func configureSandboxConfig(ctx context.Context, preflight func(context.Context) error) (*installConfigResult, error) {
	path, err := config.Path()
	if err != nil {
		return nil, err
	}
	res := &installConfigResult{Path: path}

	var requested config.Mode
	if installMode != "" {
		requested, err = config.ParseMode(installMode)
		if err != nil {
			return nil, err
		}
	}

	_, statErr := os.Stat(path)
	res.Created = statErr != nil

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("loading sandbox config: %w", err)
	}

	changed := false
	if res.Created {
		// Audit is observation, not enforcement, so it is the one setting a
		// first install turns on: it is what makes the adoption workflow
		// (loosen, watch the report, tighten) possible.
		on := true
		cfg.Audit = &on
		changed = true
	}
	if requested != "" && (cfg.Mode == "" || cfg.EffectiveMode() != requested) {
		cfg.Mode = string(requested)
		res.ModeSet = true
		changed = true
	}
	if requested == config.ModeDenylist && cfg.OSSandbox == nil && preflight != nil {
		enabled, perr := enableOSSandboxIfAvailable(ctx, cfg, preflight)
		res.OSSandboxErr = perr
		if enabled {
			res.OSSandboxEnabled = true
			changed = true
		}
	}
	if changed {
		if err := config.Save(cfg); err != nil {
			return nil, err
		}
	}
	res.Mode = cfg.EffectiveMode()
	res.Audit = cfg.AuditEnabled()
	res.OSSandbox = cfg.OSSandboxEnabled()
	return res, nil
}

// enableOSSandboxIfAvailable sets os_sandbox: true on cfg (not saved) when the
// preflight passes. It returns whether it did, and the preflight error when it
// did not.
func enableOSSandboxIfAvailable(ctx context.Context, cfg *config.Config, preflight func(context.Context) error) (bool, error) {
	if err := preflight(ctx); err != nil {
		return false, err
	}
	on := true
	cfg.OSSandbox = &on
	return true, nil
}

// printInstallConfig reports the sandbox config outcome after the agents are
// configured.
func printInstallConfig(res *installConfigResult) {
	fmt.Println()
	fmt.Println("── Sandbox config ──")
	if res.Created {
		fmt.Printf("✓ Created %s\n", res.Path)
	} else if res.ModeSet {
		fmt.Printf("✓ Updated %s\n", res.Path)
	} else {
		fmt.Printf("✓ Kept existing %s\n", res.Path)
	}
	fmt.Printf("  mode: %s — %s\n", res.Mode, modeSummary(res.Mode))
	if res.Audit {
		fmt.Println("  audit: true — findings are logged; `lite-sandbox audit report` shows what is blocked and what a stricter mode would block")
	} else {
		fmt.Println("  audit: false — `lite-sandbox config audit enable` records what each mode would block, so you can tighten with evidence")
	}
	switch {
	case res.OSSandboxEnabled:
		fmt.Println("  os_sandbox: true — enabled for denylist mode; credential and config paths are masked from every command, including scripts")
	case res.OSSandboxErr != nil:
		fmt.Println("  os_sandbox: false — " + strings.SplitN(res.OSSandboxErr.Error(), "\n", 2)[0])
		fmt.Println("  Without it the deny lists are enforced only on the agent's own bash commands, not on programs they start.")
		fmt.Println("  Once the backend is installed: `lite-sandbox config os-sandbox enable`")
	default:
		fmt.Printf("  os_sandbox: %v\n", res.OSSandbox)
	}
	if res.Mode == config.ModeAllowlist && !res.ModeSet {
		fmt.Println("  This is the strict default; see docs/adoption.md for other options.")
	}
}

func modeSummary(m config.Mode) string {
	switch m {
	case config.ModeOpen:
		return "nothing is enforced; every command runs (pair with audit to evaluate)"
	case config.ModeDenylist:
		return "any program may run; paths stay inside the project, git push/publish stay blocked"
	default:
		return "only whitelisted commands run; runtimes are opt-in"
	}
}

// osSandboxPreflight is the preflight used by install; tests substitute it.
var osSandboxPreflight = os_sandbox.Preflight
