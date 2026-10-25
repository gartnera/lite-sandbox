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
		fmt.Printf("Hide home: %v\n", cfg.OSSandboxHidesHome())
		if cfg.OSSandboxHidesHome() {
			for _, d := range cfg.HiddenDirs() {
				fmt.Printf("  hidden: %s\n", d)
			}
			for _, p := range cfg.HomeVisiblePaths() {
				fmt.Printf("  visible (built-in): %s\n", p)
			}
			fmt.Println("  visible: the working directory and every paths grant")
		}
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
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		if err := os_sandbox.Preflight(cmd.Context()); err != nil {
			return fmt.Errorf("OS sandbox unavailable: %w", err)
		}
		fmt.Println("OS sandbox available")
		return nil
	},
}

var configOSSandboxHideHomeCmd = &cobra.Command{
	Use:   "hide-home",
	Short: "Manage whether the OS sandbox hides $HOME, the runtime dir, and the keychain",
	Long: `With hide-home on (the default), the OS sandbox worker hides the user's
private state from the programs commands run, so a malicious dependency's
install script or test cannot read credentials the static checks never see it
open: $HOME is empty except the working directory, the paths grants (profile
toolchain dirs included), git's config, and the toolchains under $HOME that
PATH names (allowlist mode; denylist mode keeps $HOME and its deny lists); the
user's runtime directory (session D-Bus, keyrings, gpg and ssh agents) is
hidden in denylist mode too; and on macOS the keychain is out of reach. A paths grant
re-exposes a path, e.g. lite-sandbox config paths allow ~/.npmrc --internal.`,
}

var configOSSandboxHideHomeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Hide $HOME, the runtime dir, and the keychain from sandboxed commands (the default)",
	RunE:  func(cmd *cobra.Command, args []string) error { return setHideHome(true) },
}

var configOSSandboxHideHomeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Let sandboxed commands read $HOME, the runtime dir, and the keychain",
	RunE:  func(cmd *cobra.Command, args []string) error { return setHideHome(false) },
}

func setHideHome(on bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.OSSandboxHideHome = &on
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if on {
		fmt.Println("OS sandbox hides home")
	} else {
		fmt.Println("OS sandbox shows home")
	}
	return nil
}

func init() {
	configOSSandboxHideHomeCmd.AddCommand(configOSSandboxHideHomeEnableCmd)
	configOSSandboxHideHomeCmd.AddCommand(configOSSandboxHideHomeDisableCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxHideHomeCmd)
	configOSSandboxEnableCmd.Flags().BoolVar(&osSandboxEnableForce, "force", false, "enable without checking that the sandbox backend works here")
	configOSSandboxCmd.AddCommand(configOSSandboxCheckCmd)
	configCmd.AddCommand(configOSSandboxCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxShowCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxEnableCmd)
	configOSSandboxCmd.AddCommand(configOSSandboxDisableCmd)
}
