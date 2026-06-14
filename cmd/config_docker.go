package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var dockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Manage Docker permission settings",
}

var dockerShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current Docker configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.Docker == nil || !cfg.Docker.DockerEnabled() {
			fmt.Println("Docker: disabled")
			fmt.Println("  docker commands are not allowed")
			return nil
		}

		fmt.Println("Docker Configuration:")
		fmt.Println("  Mode: enabled (filtering proxy)")
		fmt.Printf("  Upstream socket: %s\n", cfg.Docker.UpstreamSocket())
		fmt.Println("  Description: docker CLI talks to a local proxy that filters the Docker API")
		fmt.Println("  Bind mounts: restricted to readable/writable sandbox paths")
		if cfg.Docker.AllowsPrivileged() {
			fmt.Println("  Privileged: ALLOWED (--privileged, --cap-add, host namespaces permitted)")
		} else {
			fmt.Println("  Privileged: blocked (--privileged, --cap-add, host namespaces rejected)")
		}
		return nil
	},
}

var dockerEnableSocket string

var dockerEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable docker via a filtering proxy in front of the Docker socket",
	Long: `Enable docker commands through a filtering proxy.

In this mode:
- The docker CLI talks to a local proxy via DOCKER_HOST (the real socket is never exposed)
- Privileged containers and equivalent escalation vectors are rejected by default
- Host bind-mount sources must fall within the sandbox's readable/writable paths
- Named and anonymous volumes are allowed

Use --socket to point at a non-default upstream Docker socket.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.Docker == nil {
			cfg.Docker = &config.DockerConfig{}
		}
		t := true
		cfg.Docker.Enabled = &t
		if dockerEnableSocket != "" {
			cfg.Docker.SocketPath = dockerEnableSocket
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("Docker enabled via filtering proxy")
		fmt.Printf("  Upstream socket: %s\n", cfg.Docker.UpstreamSocket())
		fmt.Println("  Privileged containers are blocked (use 'config docker allow-privileged' to permit)")
		return nil
	},
}

var dockerAllowPrivilegedCmd = &cobra.Command{
	Use:   "allow-privileged",
	Short: "Allow privileged containers and equivalent escalation vectors (less secure)",
	Long: `Permit --privileged, --cap-add, --device, host namespaces, and
unconfined security options through the docker proxy.

This significantly weakens the sandbox boundary; a privileged container can
escape to the host. Use only when you understand the risk.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.Docker == nil {
			cfg.Docker = &config.DockerConfig{}
		}
		t := true
		cfg.Docker.Enabled = &t
		cfg.Docker.AllowPrivileged = &t

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("Docker privileged containers ALLOWED")
		fmt.Println("  Warning: this weakens the sandbox boundary")
		return nil
	},
}

var dockerDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable docker entirely",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		cfg.Docker = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("Docker disabled")
		fmt.Println("  docker commands will not be allowed")
		return nil
	},
}

func init() {
	dockerEnableCmd.Flags().StringVar(&dockerEnableSocket, "socket", "", "upstream Docker daemon socket (default /var/run/docker.sock)")

	dockerCmd.AddCommand(dockerShowCmd)
	dockerCmd.AddCommand(dockerEnableCmd)
	dockerCmd.AddCommand(dockerAllowPrivilegedCmd)
	dockerCmd.AddCommand(dockerDisableCmd)
	configCmd.AddCommand(dockerCmd)
}
