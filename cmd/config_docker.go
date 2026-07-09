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
		if cfg.Docker.AllowsHostNamespaces() {
			fmt.Println("  Host namespaces: ALLOWED (--pid=host, --net=host, --ipc=host permitted)")
		} else {
			fmt.Println("  Host namespaces: blocked (--pid=host, --net=host, --ipc=host rejected)")
		}
		if cfg.Docker.AllowsUnsandboxed() {
			fmt.Println("  OS sandbox: NOT required (allow_unsandboxed; proxy is bypassable)")
		} else {
			fmt.Println("  OS sandbox: required (docker is blocked unless os_sandbox is enabled)")
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
		if !cfg.Docker.AllowsUnsandboxed() {
			fmt.Println("  Requires the OS sandbox (enable os_sandbox, or 'config docker allow-unsandboxed')")
		}
		return nil
	},
}

var dockerAllowUnsandboxedCmd = &cobra.Command{
	Use:   "allow-unsandboxed",
	Short: "Allow docker without the OS sandbox (less secure; proxy becomes bypassable)",
	Long: `Permit the docker command when the OS sandbox is disabled.

By default docker requires os_sandbox, because only the OS sandbox can mask the
real Docker socket and make the filtering proxy unbypassable. Without it, a
sandboxed command can simply 'unset DOCKER_HOST' (or pass -H) and talk to the
real /var/run/docker.sock directly, defeating the proxy's privileged and
bind-mount policy.

Setting this accepts that weaker, bypassable boundary. Prefer enabling
os_sandbox instead.`,
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
		cfg.Docker.AllowUnsandboxed = &t

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("Docker allowed without the OS sandbox")
		fmt.Println("  Warning: the filtering proxy is bypassable without os_sandbox")
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

var dockerAllowHostNamespacesCmd = &cobra.Command{
	Use:   "allow-host-namespaces",
	Short: "Allow the host PID, network, and IPC namespaces (--pid=host, --net=host, --ipc=host)",
	Long: `Permit --pid=host, --net=host, and --ipc=host (and docker build
--network=host) through the docker proxy without allowing full privileged mode.

This is narrower than 'allow-privileged': --privileged, --cap-add, --device, the
host user namespace, and container-joined namespaces remain blocked. It is still
a meaningful weakening of isolation — a container sharing the host PID, network,
or IPC namespace can observe and interfere with host processes, networking, and
shared memory. Use only when you understand the risk.`,
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
		cfg.Docker.AllowHostNamespaces = &t

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("Docker host PID/network/IPC namespaces ALLOWED")
		fmt.Println("  --pid=host, --net=host, and --ipc=host are now permitted")
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
	dockerCmd.AddCommand(dockerAllowHostNamespacesCmd)
	dockerCmd.AddCommand(dockerAllowUnsandboxedCmd)
	dockerCmd.AddCommand(dockerDisableCmd)
	configCmd.AddCommand(dockerCmd)
}
