package cmd

import (
	"fmt"
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
		fmt.Printf("Mode: %s", cfg.EffectiveMode())
		if cfg.Mode == "" {
			fmt.Print(" (default; not set in config)")
		}
		fmt.Println()
		fmt.Printf("Audit: %v\n", cfg.AuditEnabled())
		fmt.Printf("OS sandbox: %v\n", cfg.OSSandboxEnabled())
		if cfg.EffectiveMode() == config.ModeDenylist {
			fmt.Println("\nRead-denied paths (hidden from sandboxed commands under the OS sandbox):")
			for _, p := range cfg.EffectiveDeniedReadPaths() {
				fmt.Printf("  %s\n", p)
			}
			fmt.Println("\nWrite-denied paths (readable, not modifiable, under the OS sandbox):")
			for _, p := range cfg.EffectiveDeniedWritePaths() {
				fmt.Printf("  %s\n", p)
			}
			if !cfg.OSSandboxEnabled() {
				fmt.Println("\nNote: os_sandbox is off, so the deny lists are not enforced against child processes.")
			}
		}
		return nil
	},
}

var configModeSetCmd = &cobra.Command{
	Use:       "set <open|denylist|allowlist>",
	Short:     "Set the enforcement mode",
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
		cfg.Mode = string(mode)
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

func init() {
	configCmd.AddCommand(configModeCmd)
	configModeCmd.AddCommand(configModeShowCmd)
	configModeCmd.AddCommand(configModeSetCmd)

	configCmd.AddCommand(configAuditCmd)
	configAuditCmd.AddCommand(configAuditShowCmd)
	configAuditCmd.AddCommand(configAuditEnableCmd)
	configAuditCmd.AddCommand(configAuditDisableCmd)

	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "denied-read-paths",
		short: "Manage paths hidden from sandboxed commands in denylist mode (on top of the built-in defaults)",
		long: "Paths listed here are masked inside the OS sandbox in denylist mode, in addition to the built-in\n" +
			"defaults (credential stores and the agents' own auth files). `lite-sandbox config mode show`\n" +
			"prints the effective list. Entries support ~ expansion.",
		noun:      "path",
		items:     "user-added read-denied paths",
		listLabel: "denied_read_paths",
		get:       func(c *config.Config) []string { return c.DeniedReadPaths },
		set:       func(c *config.Config, v []string) { c.DeniedReadPaths = v },
	}))
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "denied-write-paths",
		short: "Manage paths sandboxed commands may read but not modify in denylist mode (on top of the built-in defaults)",
		long: "Paths listed here are mounted read-only inside the OS sandbox in denylist mode, in addition to the\n" +
			"built-in defaults (shell startup files, the sandbox's own config, the agents' settings).\n" +
			"`lite-sandbox config mode show` prints the effective list. Entries support ~ expansion.",
		noun:      "path",
		items:     "user-added write-denied paths",
		listLabel: "denied_write_paths",
		get:       func(c *config.Config) []string { return c.DeniedWritePaths },
		set:       func(c *config.Config, v []string) { c.DeniedWritePaths = v },
	}))
}
