package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var runtimesCmd = &cobra.Command{
	Use:   "runtimes",
	Short: "Manage runtime permission settings",
}

var runtimesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			fmt.Println("No runtime settings configured (all defaults)")
			return nil
		}
		fmt.Println("Runtimes:")
		if cfg.Runtimes.Go != nil {
			fmt.Println("  go:")
			fmt.Printf("    enabled:  %v\n", cfg.Runtimes.Go.GoEnabled())
			fmt.Printf("    generate: %v\n", cfg.Runtimes.Go.GoGenerate())
		} else {
			fmt.Println("  go: (defaults)")
			fmt.Printf("    enabled:  %v\n", false)
			fmt.Printf("    generate: %v\n", false)
		}
		if cfg.Runtimes.Pnpm != nil {
			fmt.Println("  pnpm:")
			fmt.Printf("    enabled: %v\n", cfg.Runtimes.Pnpm.PnpmEnabled())
			fmt.Printf("    publish: %v\n", cfg.Runtimes.Pnpm.PnpmPublish())
		} else {
			fmt.Println("  pnpm: (defaults)")
			fmt.Printf("    enabled: %v\n", false)
			fmt.Printf("    publish: %v\n", false)
		}
		if cfg.Runtimes.Rust != nil {
			fmt.Println("  rust:")
			fmt.Printf("    enabled: %v\n", cfg.Runtimes.Rust.RustEnabled())
			fmt.Printf("    publish: %v\n", cfg.Runtimes.Rust.RustPublish())
		} else {
			fmt.Println("  rust: (defaults)")
			fmt.Printf("    enabled: %v\n", false)
			fmt.Printf("    publish: %v\n", false)
		}
		if cfg.Runtimes.Deno != nil {
			fmt.Println("  deno:")
			fmt.Printf("    enabled:       %v\n", cfg.Runtimes.Deno.DenoEnabled())
			fmt.Printf("    publish:       %v\n", cfg.Runtimes.Deno.DenoPublish())
			fmt.Printf("    auto_sandbox:  %v\n", cfg.Runtimes.Deno.DenoAutoSandbox())
			fmt.Printf("    allow_network: %v\n", cfg.Runtimes.Deno.DenoAllowNetwork())
		} else {
			fmt.Println("  deno: (defaults)")
			fmt.Printf("    enabled:       %v\n", false)
			fmt.Printf("    publish:       %v\n", false)
			fmt.Printf("    auto_sandbox:  %v\n", true)
			fmt.Printf("    allow_network: %v\n", false)
		}
		return nil
	},
}

// Go runtime commands
var goRuntimeCmd = &cobra.Command{
	Use:   "go",
	Short: "Manage Go runtime permission settings",
}

var goRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current Go runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		g := &config.GoConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.Go != nil {
			g = cfg.Runtimes.Go
		}
		fmt.Printf("enabled:  %v\n", g.GoEnabled())
		fmt.Printf("generate: %v\n", g.GoGenerate())
		return nil
	},
}

var goRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Go runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withGenerate, _ := cmd.Flags().GetBool("with-generate")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Go == nil {
			cfg.Runtimes.Go = &config.GoConfig{}
		}

		trueVal := true
		cfg.Runtimes.Go.Enabled = &trueVal

		if withGenerate {
			cfg.Runtimes.Go.Generate = &trueVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.go.enabled set to true")
		if withGenerate {
			fmt.Println("runtimes.go.generate set to true")
		}
		return nil
	},
}

var goRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Go runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withGenerate, _ := cmd.Flags().GetBool("with-generate")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Go == nil {
			cfg.Runtimes.Go = &config.GoConfig{}
		}

		falseVal := false
		cfg.Runtimes.Go.Enabled = &falseVal

		if withGenerate {
			cfg.Runtimes.Go.Generate = &falseVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.go.enabled set to false")
		if withGenerate {
			fmt.Println("runtimes.go.generate set to false")
		}
		return nil
	},
}

// Pnpm runtime commands
var pnpmRuntimeCmd = &cobra.Command{
	Use:   "pnpm",
	Short: "Manage pnpm runtime permission settings",
}

var pnpmRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current pnpm runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		p := &config.PnpmConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.Pnpm != nil {
			p = cfg.Runtimes.Pnpm
		}
		fmt.Printf("enabled: %v\n", p.PnpmEnabled())
		fmt.Printf("publish: %v\n", p.PnpmPublish())
		return nil
	},
}

var pnpmRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable pnpm runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Pnpm == nil {
			cfg.Runtimes.Pnpm = &config.PnpmConfig{}
		}

		trueVal := true
		cfg.Runtimes.Pnpm.Enabled = &trueVal

		if withPublish {
			cfg.Runtimes.Pnpm.Publish = &trueVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.pnpm.enabled set to true")
		if withPublish {
			fmt.Println("runtimes.pnpm.publish set to true")
		}
		return nil
	},
}

var pnpmRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable pnpm runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Pnpm == nil {
			cfg.Runtimes.Pnpm = &config.PnpmConfig{}
		}

		falseVal := false
		cfg.Runtimes.Pnpm.Enabled = &falseVal

		if withPublish {
			cfg.Runtimes.Pnpm.Publish = &falseVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.pnpm.enabled set to false")
		if withPublish {
			fmt.Println("runtimes.pnpm.publish set to false")
		}
		return nil
	},
}

// Rust runtime commands
var rustRuntimeCmd = &cobra.Command{
	Use:   "rust",
	Short: "Manage Rust runtime permission settings",
}

var rustRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current Rust runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		r := &config.RustConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.Rust != nil {
			r = cfg.Runtimes.Rust
		}
		fmt.Printf("enabled: %v\n", r.RustEnabled())
		fmt.Printf("publish: %v\n", r.RustPublish())
		return nil
	},
}

var rustRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Rust runtime commands (cargo, rustc)",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Rust == nil {
			cfg.Runtimes.Rust = &config.RustConfig{}
		}

		trueVal := true
		cfg.Runtimes.Rust.Enabled = &trueVal

		if withPublish {
			cfg.Runtimes.Rust.Publish = &trueVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.rust.enabled set to true")
		if withPublish {
			fmt.Println("runtimes.rust.publish set to true")
		}
		return nil
	},
}

var rustRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Rust runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Rust == nil {
			cfg.Runtimes.Rust = &config.RustConfig{}
		}

		falseVal := false
		cfg.Runtimes.Rust.Enabled = &falseVal

		if withPublish {
			cfg.Runtimes.Rust.Publish = &falseVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.rust.enabled set to false")
		if withPublish {
			fmt.Println("runtimes.rust.publish set to false")
		}
		return nil
	},
}

// Deno runtime commands
var denoRuntimeCmd = &cobra.Command{
	Use:   "deno",
	Short: "Manage Deno runtime permission settings",
}

var denoRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current Deno runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		d := &config.DenoConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.Deno != nil {
			d = cfg.Runtimes.Deno
		}
		fmt.Printf("enabled:       %v\n", d.DenoEnabled())
		fmt.Printf("publish:       %v\n", d.DenoPublish())
		fmt.Printf("auto_sandbox:  %v\n", d.DenoAutoSandbox())
		fmt.Printf("allow_network: %v\n", d.DenoAllowNetwork())
		return nil
	},
}

var denoRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Deno runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")
		withAutoSandbox, _ := cmd.Flags().GetBool("with-auto-sandbox")
		withNetwork, _ := cmd.Flags().GetBool("with-network")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Deno == nil {
			cfg.Runtimes.Deno = &config.DenoConfig{}
		}

		trueVal := true
		cfg.Runtimes.Deno.Enabled = &trueVal

		if withPublish {
			cfg.Runtimes.Deno.Publish = &trueVal
		}
		if withAutoSandbox {
			cfg.Runtimes.Deno.AutoSandbox = &trueVal
		}
		if withNetwork {
			cfg.Runtimes.Deno.AllowNetwork = &trueVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.deno.enabled set to true")
		if withPublish {
			fmt.Println("runtimes.deno.publish set to true")
		}
		if withAutoSandbox {
			fmt.Println("runtimes.deno.auto_sandbox set to true")
		}
		if withNetwork {
			fmt.Println("runtimes.deno.allow_network set to true")
		}
		return nil
	},
}

var denoRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Deno runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withPublish, _ := cmd.Flags().GetBool("with-publish")
		withAutoSandbox, _ := cmd.Flags().GetBool("with-auto-sandbox")
		withNetwork, _ := cmd.Flags().GetBool("with-network")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Deno == nil {
			cfg.Runtimes.Deno = &config.DenoConfig{}
		}

		falseVal := false

		// With a sub-setting flag, only that sub-setting is turned off and the
		// runtime stays enabled (e.g. disable auto_sandbox while keeping deno).
		// With no flags, the whole runtime is disabled.
		anySub := withPublish || withAutoSandbox || withNetwork
		if !anySub {
			cfg.Runtimes.Deno.Enabled = &falseVal
		}
		if withPublish {
			cfg.Runtimes.Deno.Publish = &falseVal
		}
		if withAutoSandbox {
			cfg.Runtimes.Deno.AutoSandbox = &falseVal
		}
		if withNetwork {
			cfg.Runtimes.Deno.AllowNetwork = &falseVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		if !anySub {
			fmt.Println("runtimes.deno.enabled set to false")
		}
		if withPublish {
			fmt.Println("runtimes.deno.publish set to false")
		}
		if withAutoSandbox {
			fmt.Println("runtimes.deno.auto_sandbox set to false")
		}
		if withNetwork {
			fmt.Println("runtimes.deno.allow_network set to false")
		}
		return nil
	},
}

func init() {
	// Add --with-generate flag to enable/disable commands
	goRuntimeEnableCmd.Flags().Bool("with-generate", false, "Also enable go generate")
	goRuntimeDisableCmd.Flags().Bool("with-generate", false, "Also disable go generate")

	// Add go subcommands
	goRuntimeCmd.AddCommand(goRuntimeShowCmd)
	goRuntimeCmd.AddCommand(goRuntimeEnableCmd)
	goRuntimeCmd.AddCommand(goRuntimeDisableCmd)

	// Add --with-publish flag to enable/disable commands
	pnpmRuntimeEnableCmd.Flags().Bool("with-publish", false, "Also enable pnpm publish")
	pnpmRuntimeDisableCmd.Flags().Bool("with-publish", false, "Also disable pnpm publish")

	// Add pnpm subcommands
	pnpmRuntimeCmd.AddCommand(pnpmRuntimeShowCmd)
	pnpmRuntimeCmd.AddCommand(pnpmRuntimeEnableCmd)
	pnpmRuntimeCmd.AddCommand(pnpmRuntimeDisableCmd)

	// Add --with-publish flag to rust enable/disable commands
	rustRuntimeEnableCmd.Flags().Bool("with-publish", false, "Also enable cargo publish")
	rustRuntimeDisableCmd.Flags().Bool("with-publish", false, "Also disable cargo publish")

	// Add rust subcommands
	rustRuntimeCmd.AddCommand(rustRuntimeShowCmd)
	rustRuntimeCmd.AddCommand(rustRuntimeEnableCmd)
	rustRuntimeCmd.AddCommand(rustRuntimeDisableCmd)

	// Add deno enable/disable flags
	denoRuntimeEnableCmd.Flags().Bool("with-publish", false, "Also enable deno publish")
	denoRuntimeEnableCmd.Flags().Bool("with-auto-sandbox", false, "Also auto-configure --allow-read/--allow-write from sandbox paths")
	denoRuntimeEnableCmd.Flags().Bool("with-network", false, "Also allow network access under auto-sandbox (default: denied)")
	denoRuntimeDisableCmd.Flags().Bool("with-publish", false, "Also disable deno publish")
	denoRuntimeDisableCmd.Flags().Bool("with-auto-sandbox", false, "Also disable deno auto-sandbox")
	denoRuntimeDisableCmd.Flags().Bool("with-network", false, "Also disable deno network access under auto-sandbox")

	// Add deno subcommands
	denoRuntimeCmd.AddCommand(denoRuntimeShowCmd)
	denoRuntimeCmd.AddCommand(denoRuntimeEnableCmd)
	denoRuntimeCmd.AddCommand(denoRuntimeDisableCmd)

	// Add runtimes subcommands
	runtimesCmd.AddCommand(runtimesShowCmd)
	runtimesCmd.AddCommand(goRuntimeCmd)
	runtimesCmd.AddCommand(pnpmRuntimeCmd)
	runtimesCmd.AddCommand(rustRuntimeCmd)
	runtimesCmd.AddCommand(denoRuntimeCmd)

	// Add runtimes to config
	configCmd.AddCommand(runtimesCmd)
}
