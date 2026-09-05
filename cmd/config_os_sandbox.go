package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/os_sandbox"
)

var configOSSandboxCmd = &cobra.Command{
	Use:   "os-sandbox",
	Short: "Manage OS-level sandboxing (bubblewrap on Linux, sandbox-exec on macOS)",
}

var configOSSandboxShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current OS sandbox configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("OS Sandbox: %v\n", cfg.OSSandboxEnabled())
		return nil
	},
}

var osSandboxEnableForce bool

var configOSSandboxEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable OS-level sandboxing (bubblewrap on Linux, sandbox-exec on macOS)",
	Long: `Enables the OS sandbox after checking that it can actually start on this host.
With it on, every command runs inside a bubblewrap (Linux) or sandbox-exec
(macOS) worker; if the backend is missing, every command would fail, so the
check refuses rather than leaving you with a broken sandbox. Pass --force to
write the setting anyway (e.g. when configuring a different machine).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !osSandboxEnableForce {
			if err := os_sandbox.Preflight(cmd.Context()); err != nil {
				return fmt.Errorf("OS sandbox unavailable: %w\n(pass --force to enable it anyway)", err)
			}
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		t := true
		cfg.OSSandbox = &t
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("OS sandbox enabled")
		return nil
	},
}

var configOSSandboxDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable OS-level sandboxing",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		f := false
		cfg.OSSandbox = &f
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("OS sandbox disabled")
		return nil
	},
}

var configOSSandboxCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check whether the OS sandbox can run on this host",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := os_sandbox.Preflight(cmd.Context()); err != nil {
			return fmt.Errorf("OS sandbox unavailable: %w", err)
		}
		fmt.Println("OS sandbox available")
		return nil
	},
}

func init() {
	configOSSandboxEnableCmd.Flags().BoolVar(&osSandboxEnableForce, "force", false, "enable without checking that the sandbox backend works here")
	configOSSandboxCmd.AddCommand(configOSSandboxCheckCmd)
	configCmd.AddCommand(configOSSandboxCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxShowCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxEnableCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxDisableCmd)
}
