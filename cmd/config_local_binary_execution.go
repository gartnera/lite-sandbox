package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var configLocalBinaryExecutionCmd = &cobra.Command{
	Use:   "local-binary-execution",
	Short: "Manage local binary execution permissions (./binary, /path/to/binary)",
}

var configLocalBinaryExecutionShowCmd = &cobra.Command{
	Annotations: readOnly,
	Use:         "show",
	Short:       "Show current local binary execution configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("Local Binary Execution: %v\n", cfg.LocalBinaryExecution.IsEnabled())
		return nil
	},
}

var configLocalBinaryExecutionEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable direct execution of local binaries and scripts via path",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		t := true
		cfg.LocalBinaryExecution = &config.LocalBinaryExecutionConfig{Enabled: &t}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Local binary execution enabled")
		return nil
	},
}

var configLocalBinaryExecutionDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable direct execution of local binaries and scripts via path",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		f := false
		cfg.LocalBinaryExecution = &config.LocalBinaryExecutionConfig{Enabled: &f}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Local binary execution disabled")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configLocalBinaryExecutionCmd)
	configLocalBinaryExecutionCmd.AddCommand(configLocalBinaryExecutionShowCmd)
	configLocalBinaryExecutionCmd.AddCommand(configLocalBinaryExecutionEnableCmd)
	configLocalBinaryExecutionCmd.AddCommand(configLocalBinaryExecutionDisableCmd)
}
