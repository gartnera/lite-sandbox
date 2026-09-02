package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var configOSSandboxCmd = &cobra.Command{
	Use:   "os-sandbox",
	Short: "Manage OS-level sandboxing with bubblewrap",
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

var configOSSandboxEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable OS-level sandboxing with bubblewrap",
	RunE: func(cmd *cobra.Command, args []string) error {
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

func init() {
	configCmd.AddCommand(configOSSandboxCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxShowCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxEnableCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxDisableCmd)
}
