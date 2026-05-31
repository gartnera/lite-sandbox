package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var configRtkCmd = &cobra.Command{
	Use:   "rtk",
	Short: "Manage the rtk (token-reducing command proxy) integration",
	Long: `When enabled, supported read-only/dev commands (git, ls, grep, find, diff,
cargo, go, aws, pnpm) are transparently rerouted through rtk
(https://github.com/rtk-ai/rtk) so their output is filtered and compressed
before reaching the model. rtk's data directory (~/.local/share/rtk) is also
made readable so the full, unfiltered output it saves for failed commands can
be read back.`,
}

var configRtkShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current rtk integration settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		fmt.Printf("enabled: %v\n", cfg.Rtk.RtkEnabled())
		return nil
	},
}

var configRtkEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable the rtk integration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.Rtk == nil {
			cfg.Rtk = &config.RtkConfig{}
		}
		t := true
		cfg.Rtk.Enabled = &t
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Println("rtk.enabled set to true")
		return nil
	},
}

var configRtkDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable the rtk integration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.Rtk == nil {
			cfg.Rtk = &config.RtkConfig{}
		}
		f := false
		cfg.Rtk.Enabled = &f
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Println("rtk.enabled set to false")
		return nil
	},
}

func init() {
	configRtkCmd.AddCommand(configRtkShowCmd)
	configRtkCmd.AddCommand(configRtkEnableCmd)
	configRtkCmd.AddCommand(configRtkDisableCmd)
	configCmd.AddCommand(configRtkCmd)
}
