package cmd

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage ssh hosts and the ssh agent",
	Long: `Manage the ssh section: the hosts ssh and sshpass may connect to, and
the ssh agent ssh, sshpass, and git's remote commands (fetch, pull, push,
clone, ...) get.

  lite-sandbox config ssh hosts add build-box 10.0.0.12
  lite-sandbox config ssh agent unrestrict   # hand over the real agent socket
  lite-sandbox config ssh show`,
}

var sshShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the ssh configuration (with --dir, the one in effect there)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		s := cfg.SSH
		if s == nil {
			fmt.Println("SSH: not configured")
			fmt.Println("  ssh and sshpass are not allowed (allowlist mode); the agent is left as it was")
			return nil
		}
		fmt.Println("SSH Configuration:")
		if s.HostsConfigured() {
			fmt.Printf("  Hosts: %s\n", strings.Join(s.Hosts, ", "))
			fmt.Println("  ssh and sshpass may connect to these hosts only (forwarding and local commands refused)")
		} else {
			fmt.Println("  Hosts: none (ssh and sshpass are not allowed)")
		}
		agentUsers := "git's remote commands"
		if s.HostsConfigured() {
			agentUsers = "ssh, sshpass, and git's remote commands"
		}
		switch {
		case !s.AgentEnabled():
			fmt.Println("  Agent: off (masked from every command)")
		case s.AgentUnrestricted():
			fmt.Printf("  Agent: unrestricted (the real agent socket, for %s alone)\n", agentUsers)
		default:
			fmt.Printf("  Agent: restricted (lists and signs only, no forwarding; for %s alone)\n", agentUsers)
		}
		if config.SSHAuthSock() == "" {
			fmt.Println("  Note: SSH_AUTH_SOCK names no agent socket here")
		}
		return nil
	},
}

var sshHostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "Manage the hosts ssh and sshpass may connect to",
}

var sshHostsAddCmd = &cobra.Command{
	Use:   "add <host>...",
	Short: "Allow ssh and sshpass to connect to hosts (as typed: an alias of ~/.ssh/config or a host name)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, h := range args {
			added, err := cfg.AddSSHHost(h)
			if err != nil {
				return err
			}
			if added {
				fmt.Printf("Added ssh host %s\n", h)
			} else {
				fmt.Printf("ssh host %s is already allowed\n", h)
			}
		}
		return saveConfig(cfg)
	},
}

var sshHostsRemoveCmd = &cobra.Command{
	Use:     "remove <host>...",
	Aliases: []string{"rm"},
	Short:   "Stop allowing ssh and sshpass to connect to hosts",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, h := range args {
			if cfg.RemoveSSHHost(h) {
				fmt.Printf("Removed ssh host %s\n", h)
			} else {
				fmt.Printf("ssh host %s was not listed\n", h)
			}
		}
		return saveConfig(cfg)
	},
}

var sshAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage the ssh agent ssh, sshpass, and git's remote commands get",
}

// sshAgentSetter returns a subcommand that sets the ssh section's agent
// fields with set, creating the section.
func sshAgentSetter(use, short, done string, set func(s *config.SSHConfig)) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.SSH == nil {
				cfg.SSH = &config.SSHConfig{}
			}
			set(cfg.SSH)
			if err := saveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(done)
			return nil
		},
	}
}

func boolRef(b bool) *bool { return &b }

var (
	sshAgentEnableCmd = sshAgentSetter("enable", "Give ssh, sshpass, and git's remote commands the ssh agent (the default once the ssh section exists)",
		"ssh agent enabled for ssh, sshpass, and git's remote commands",
		func(s *config.SSHConfig) { s.Agent = boolRef(true) })
	sshAgentDisableCmd = sshAgentSetter("disable", "Keep the ssh agent from every command",
		"ssh agent disabled: masked from every command",
		func(s *config.SSHConfig) { s.Agent = boolRef(false) })
	sshAgentRestrictCmd = sshAgentSetter("restrict", "Give them the agent through a filter that only lists keys and signs (the default)",
		"ssh agent restricted: keys can be listed and used, not added, removed, locked, or forwarded",
		func(s *config.SSHConfig) { s.UnrestrictedAgent = nil })
	sshAgentUnrestrictCmd = sshAgentSetter("unrestrict", "Give them the real agent socket (less secure: they can add, remove, and lock keys, and forward the agent)",
		"ssh agent unrestricted: ssh, sshpass, and git's remote commands get the real agent socket",
		func(s *config.SSHConfig) { s.UnrestrictedAgent = boolRef(true) })
)

var sshDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Remove the ssh section (ssh and sshpass refused, the agent left as before)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		cfg.SSH = nil
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Println("ssh section removed")
		return nil
	},
}

func init() {
	sshHostsCmd.AddCommand(sshHostsAddCmd, sshHostsRemoveCmd)
	sshAgentCmd.AddCommand(sshAgentEnableCmd, sshAgentDisableCmd, sshAgentRestrictCmd, sshAgentUnrestrictCmd)
	sshCmd.AddCommand(sshShowCmd, sshHostsCmd, sshAgentCmd, sshDisableCmd)
	configCmd.AddCommand(sshCmd)
}
