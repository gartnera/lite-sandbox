package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var configRedundantCdCmd = &cobra.Command{
	Use:   "redundant-cd",
	Short: "Manage rejection of a redundant leading `cd` into the working directory",
}

var configRedundantCdShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show whether a redundant leading cd is rejected",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("Reject redundant cd: %v\n", cfg.RejectsRedundantCd())
		return nil
	},
}

var configRedundantCdEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Reject `cd /abs/path/to/repo && ...` when the sandbox already runs there",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		t := true
		cfg.RejectRedundantCd = &t
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Redundant cd rejection enabled")
		return nil
	},
}

var configRedundantCdDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Allow a redundant leading cd into the working directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		f := false
		cfg.RejectRedundantCd = &f
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Redundant cd rejection disabled")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configRedundantCdCmd)
	configRedundantCdCmd.AddCommand(configRedundantCdShowCmd)
	configRedundantCdCmd.AddCommand(configRedundantCdEnableCmd)
	configRedundantCdCmd.AddCommand(configRedundantCdDisableCmd)
}
