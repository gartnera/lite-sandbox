package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
)

var configModeCmd = &cobra.Command{
	Use:   "mode",
	Short: "Manage the enforcement mode (open, denylist, allowlist)",
	Long: `The mode selects how much the sandbox enforces:

  open       Nothing is enforced; every command runs. With audit enabled each
             finding is still recorded with the modes that would block it.
  denylist   Any program may run, but path arguments and redirections must stay
             inside the working directory (plus readable/writable paths), the
             per-command validators still apply (find -delete, git push, publish
             flags, ...), and under the OS sandbox the home directory is writable
             with credential and config paths masked. Assumes a cooperative
             agent; the opt-out for incremental adoption (docs/adoption.md).
  allowlist  Only whitelisted commands run and code-execution runtimes are
             opt-in. The posture for untrusted input, and the default.

Turn on auditing alongside any mode (lite-sandbox config audit enable) to see
what the next stricter mode would block before switching to it.`,
}

var configModeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the effective mode, audit setting, and deny lists",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if configDir != "" {
			fmt.Printf("Directory: %s\n", resolveDirArg(configDir))
		}
		fmt.Printf("Mode: %s", cfg.EffectiveMode())
		if cfg.Mode == "" {
			fmt.Print(" (default; not set in config)")
		}
		fmt.Println()
		fmt.Printf("Audit: %v\n", cfg.AuditEnabled())
		fmt.Printf("OS sandbox: %v\n", cfg.OSSandboxEnabled())
		// The deny list is enforced in denylist and allowlist mode alike (in
		// open mode it is audit-only, like every other rule), so it prints
		// outside the denylist-only section below.
		fmt.Println("\nDenied commands (refused in denylist and allowlist mode, whatever else allows them):")
		fmt.Print(deniedCommandsSummary(cfg))
		if cfg.EffectiveMode() == config.ModeOpen {
			fmt.Println("\nNote: mode is open, so denied commands are recorded but not blocked.")
		}
		// The credential masks hold under the OS sandbox in every mode; the
		// rest of the deny lists only in denylist mode. A built-in a paths
		// grant lifted is listed with the grant, so the gap is visible.
		liftedRead, liftedWrite := cfg.LiftedDeniedEntries()
		printDenyList("Always hidden under the OS sandbox (every mode):",
			cfg.AlwaysDeniedReadEntries(), allModesOnly(liftedRead, true))
		if cfg.EffectiveMode() == config.ModeDenylist {
			printDenyList("Read-denied paths (hidden from sandboxed commands under the OS sandbox):",
				allModesOnly(cfg.EffectiveDeniedReadEntries(), false), allModesOnly(liftedRead, false))
			printDenyList("Write-denied paths (readable, not modifiable, under the OS sandbox):",
				cfg.EffectiveDeniedWriteEntries(), liftedWrite)
		}
		if !cfg.OSSandboxEnabled() {
			fmt.Println("\nNote: os_sandbox is off, so the deny lists are not enforced against child processes.")
		}
		return nil
	},
}

var configModeSetCmd = &cobra.Command{
	Use:       "set <open|denylist|allowlist>",
	Short:     "Set the enforcement mode (globally, or for one directory with --dir)",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"open", "denylist", "allowlist"},
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, err := config.ParseMode(args[0])
		if err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		baseMode := configBase(cfg).EffectiveMode()
		cfg.Mode = string(mode)

		if configDir != "" {
			// Per-directory: only the override's mode changes. The OS sandbox
			// toggle is a base-config decision and is left alone.
			if err := saveConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("mode set to %s%s (base mode stays %s)\n", mode, configScope(), baseMode)
			if mode == config.ModeDenylist && !cfg.OSSandboxEnabled() {
				fmt.Println("note: os_sandbox is off for this directory, so the deny lists are not enforced against programs commands start")
			}
			return nil
		}

		// Denylist relies on the OS sandbox to hold its deny lists against child
		// processes; turn it on when it was never configured and the backend works.
		var osErr error
		enabledOS := false
		if mode == config.ModeDenylist && cfg.OSSandbox == nil {
			enabledOS, osErr = enableOSSandboxIfAvailable(cmd.Context(), cfg, osSandboxPreflight)
		}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("mode set to %s\n", mode)
		switch {
		case enabledOS:
			fmt.Println("os_sandbox enabled: credential and config paths are masked from every command, including scripts")
		case osErr != nil:
			fmt.Println("os_sandbox left off: " + strings.SplitN(osErr.Error(), "\n", 2)[0])
			fmt.Println("without it the deny lists are enforced only on the agent's own bash commands, not on programs they start")
		case mode == config.ModeDenylist && !cfg.OSSandboxEnabled():
			fmt.Println("note: os_sandbox is off, so the deny lists are not enforced against programs commands start")
		}
		if mode == config.ModeOpen && !cfg.AuditEnabled() {
			fmt.Println("warning: mode open with audit off enforces nothing and records nothing; consider `lite-sandbox config audit enable`")
		}
		return nil
	},
}

var configAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Manage audit logging of validation findings",
	Long: `With audit enabled, every validation finding — whether or not the current mode
blocked it — is appended to a JSONL log together with the modes that would
block it. Read it with ` + "`lite-sandbox audit report`" + `. The log is written by the
MCP server and the hook, never by sandboxed commands, and is created 0600
since commands can carry inline secrets.`,
}

var configAuditShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show whether audit logging is enabled and where the log lives",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		p, err := audit.DefaultPath()
		if err != nil {
			return err
		}
		fmt.Printf("Audit: %v\nLog: %s\n", cfg.AuditEnabled(), p)
		return nil
	},
}

var configAuditEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Record validation findings to the audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		t := true
		cfg.Audit = &t
		if err := saveConfig(cfg); err != nil {
			return err
		}
		p, _ := audit.DefaultPath()
		fmt.Printf("audit enabled (log: %s)\n", p)
		return nil
	},
}

var configAuditDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Stop recording validation findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		f := false
		cfg.Audit = &f
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("audit disabled")
		return nil
	},
}

// printDenyList prints deny-list entries, marking file entries that do not
// exist: on Linux those cannot be masked until they are created (see
// os_sandbox.DenyPath), so the gap is made visible rather than implied closed.
// The lifted entries — built-ins a paths grant overrides — follow, each with
// the grant that lifts it, since a deny list that is silently shorter than
// the documented one would be a gap too.
func printDenyList(title string, entries, lifted []config.DeniedPath) {
	fmt.Println()
	fmt.Println(title)
	if len(entries)+len(lifted) == 0 {
		fmt.Println("  none")
		return
	}
	for _, e := range entries {
		note := ""
		if e.Note != "" {
			note = "   (" + e.Note + ")"
		}
		if !e.Dir {
			if _, err := os.Stat(e.Path); err != nil {
				note += "   (does not exist; on Linux not masked until created)"
			}
		}
		fmt.Printf("  %s%s\n", e.Path, note)
	}
	for _, e := range lifted {
		note := ""
		if e.Note != "" {
			note = "; " + e.Note
		}
		fmt.Printf("  %s   (NOT enforced: lifted by the paths grant on %s%s)\n", e.Path, e.LiftedBy, note)
	}
}

// allModesOnly filters deny-list entries by whether they hold in every mode,
// so `mode show` lists each entry once: under the every-mode heading or the
// denylist one.
func allModesOnly(entries []config.DeniedPath, allModes bool) []config.DeniedPath {
	var out []config.DeniedPath
	for _, e := range entries {
		if e.AllModes == allModes {
			out = append(out, e)
		}
	}
	return out
}

func init() {
	configCmd.AddCommand(configModeCmd)
	configModeCmd.AddCommand(configModeShowCmd)
	configModeCmd.AddCommand(configModeSetCmd)

	configCmd.AddCommand(configAuditCmd)
	configAuditCmd.AddCommand(configAuditShowCmd)
	configAuditCmd.AddCommand(configAuditEnableCmd)
	configAuditCmd.AddCommand(configAuditDisableCmd)
}
