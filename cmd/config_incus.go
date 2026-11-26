package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var incusCmd = &cobra.Command{
	Use:   "incus",
	Short: "Manage Incus / LXD permission settings",
}

var incusShowCmd = &cobra.Command{
	Annotations: readOnly,
	Use:         "show",
	Short:       "Show current Incus / LXD configuration (with --dir, the one in effect there)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		c := cfg.Incus
		if !c.IncusEnabled() {
			fmt.Println("Incus: disabled")
			fmt.Println("  incus and lxc commands are not allowed")
			return nil
		}
		onOff := func(b bool, on, off string) string {
			if b {
				return on
			}
			return off
		}
		fmt.Println("Incus / LXD Configuration:")
		fmt.Println("  Mode: enabled (filtering proxy)")
		fmt.Printf("  Upstream socket: %s\n", c.UpstreamSocket())
		fmt.Printf("  Project: %s (requests for other projects are refused)\n", c.ProjectName())
		fmt.Println("  Instances: " + onOff(c.RequiresTag(),
			"tagged only (instances the sandbox created, tagged "+config.IncusTagKey+"=true)",
			"ALL instances in the project"))
		fmt.Println("  Disk devices: host paths restricted to readable/writable sandbox paths")
		fmt.Println("  Privileged: " + onOff(c.AllowsPrivileged(),
			"ALLOWED (security.privileged, raw.*, passthrough devices permitted)",
			"blocked (security.privileged, raw.*, volatile.*, passthrough devices rejected)"))
		fmt.Println("  Nesting: " + onOff(c.AllowsNesting(), "ALLOWED (security.nesting)", "blocked (security.nesting)"))
		fmt.Println("  OS sandbox: " + onOff(c.AllowsUnsandboxed(),
			"NOT required (allow_unsandboxed; proxy is bypassable)",
			"required (incus/lxc are blocked unless os_sandbox is enabled)"))
		return nil
	},
}

// updateIncus loads the config, applies set to its incus section (created and
// enabled first), saves it, and prints msg.
func updateIncus(set func(*config.IncusConfig), msg ...string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Incus == nil {
		cfg.Incus = &config.IncusConfig{}
	}
	t := true
	cfg.Incus.Enabled = &t
	set(cfg.Incus)
	if err := saveConfig(cfg); err != nil {
		return err
	}
	for _, m := range msg {
		fmt.Println(m)
	}
	return nil
}

func incusFlag(use, short, long string, set func(*config.IncusConfig, *bool), msg ...string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateIncus(func(c *config.IncusConfig) {
				v := true
				set(c, &v)
			}, msg...)
		},
	}
}

var incusEnableSocket, incusEnableProject string

var incusEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable incus and lxc via a filtering proxy in front of the daemon socket",
	Long: `Enable the incus and lxc commands through a filtering proxy.

In this mode:
- The CLIs talk to a local proxy via INCUS_SOCKET / LXD_SOCKET (the real socket is masked)
- Every request is pinned to one project (--project, default "default")
- Only instances the sandbox created (tagged user.lite-sandbox=true) can be used
- Privileged containers, raw.* and other low-level options, and passthrough
  devices are rejected, as in an Incus restricted project
- Host-path disk devices must fall within the sandbox's readable/writable paths

Use --socket to point at a non-default daemon socket (for example incus-user's
unix.socket.user).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateIncus(func(c *config.IncusConfig) {
			if incusEnableSocket != "" {
				c.SocketPath = incusEnableSocket
			}
			if incusEnableProject != "" {
				c.Project = incusEnableProject
			}
		}, "Incus / LXD enabled via filtering proxy",
			"  Privileged instances are blocked (use 'config incus allow-privileged' to permit)",
			"  Requires the OS sandbox unless 'config incus allow-unsandboxed'")
	},
}

var incusTaggedOnlyCmd = incusFlag("tagged-only", "Restrict the sandbox to the instances it created (the default)", "",
	func(c *config.IncusConfig, _ *bool) { c.TaggedOnly = nil },
	"Incus: only instances tagged "+config.IncusTagKey+"=true can be used")

var incusAllInstancesCmd = incusFlag("all-instances", "Let the sandbox use every instance in its project, not only its own", `Turn off tagged-only mode: every instance in the configured project can be
used, and profiles can be changed (subject to the same policy).`,
	func(c *config.IncusConfig, _ *bool) { f := false; c.TaggedOnly = &f },
	"Incus: ALL instances in the project can be used")

var incusAllowPrivilegedCmd = incusFlag("allow-privileged", "Allow privileged instances and low-level options (less secure)", `Permit security.privileged, raw.*, volatile.* and the other low-level options,
syscall interception, and passthrough devices (unix-char, gpu, proxy, ...).
Host-path disk devices remain restricted to the sandbox's paths.`,
	func(c *config.IncusConfig, v *bool) { c.AllowPrivileged = v },
	"Incus privileged instances ALLOWED", "  Warning: this weakens the sandbox boundary")

var incusAllowNestingCmd = incusFlag("allow-nesting", "Allow security.nesting (containers inside unprivileged containers)", "",
	func(c *config.IncusConfig, v *bool) { c.AllowNesting = v },
	"Incus nesting ALLOWED")

var incusAllowUnsandboxedCmd = incusFlag("allow-unsandboxed", "Allow incus/lxc without the OS sandbox (less secure; proxy becomes bypassable)", `Permit the incus and lxc commands when the OS sandbox is disabled. Without the
OS sandbox the real daemon socket is not masked, so a command can unset
INCUS_SOCKET and talk to it directly. Prefer enabling os_sandbox instead.`,
	func(c *config.IncusConfig, v *bool) { c.AllowUnsandboxed = v },
	"Incus allowed without the OS sandbox", "  Warning: the filtering proxy is bypassable without os_sandbox")

var incusDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable incus and lxc entirely",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		// Under --dir an unset section inherits the base; record an explicitly
		// disabled one instead.
		if configDir != "" {
			f := false
			cfg.Incus = &config.IncusConfig{Enabled: &f}
		} else {
			cfg.Incus = nil
		}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Incus disabled")
		fmt.Println("  incus and lxc commands will not be allowed")
		return nil
	},
}

func init() {
	incusEnableCmd.Flags().StringVar(&incusEnableSocket, "socket", "", "upstream daemon socket (default: autodetected, e.g. /var/lib/incus/unix.socket)")
	incusEnableCmd.Flags().StringVar(&incusEnableProject, "project", "", `project to confine the sandbox to (default "default")`)
	incusCmd.AddCommand(incusShowCmd, incusEnableCmd, incusTaggedOnlyCmd, incusAllInstancesCmd,
		incusAllowPrivilegedCmd, incusAllowNestingCmd, incusAllowUnsandboxedCmd, incusDisableCmd)
	configCmd.AddCommand(incusCmd)
}
