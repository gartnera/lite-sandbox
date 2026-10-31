package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage ssh hosts and the ssh agent",
	Long: `Manage the ssh section: the hosts ssh and sshpass may connect to (and
scp and rsync, for the hosts that allow writes), and the ssh agent they and
git's remote commands (fetch, pull, push, clone, ...) get.

  lite-sandbox config ssh hosts add build-box 10.0.0.12
  lite-sandbox config ssh hosts add deploy-box --command 'systemctl restart'
  lite-sandbox config ssh agent unrestrict   # hand over the real agent socket
  lite-sandbox config ssh git-signing enable # sign commits and tags with the agent
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
			fmt.Println("  ssh, sshpass, scp, and rsync are not allowed (allowlist mode); the agent is left as it was")
			return nil
		}
		fmt.Println("SSH Configuration:")
		if s.HostsConfigured() {
			fmt.Println("  Hosts (ssh and sshpass may connect to these only; forwarding and local commands refused):")
			for _, h := range s.Hosts {
				fmt.Printf("    %s: %s\n", h.Host, h.Describe())
			}
		} else {
			fmt.Println("  Hosts: none (ssh and sshpass are not allowed)")
		}
		if s.HostsConfigured() && !s.WriteHostsConfigured() {
			fmt.Println("  scp and rsync: not allowed (no host allows writes; add one with --write)")
		}
		agentUsers := "git's remote commands"
		switch {
		case s.WriteHostsConfigured():
			agentUsers = "ssh, sshpass, scp, rsync, and git's remote commands"
		case s.HostsConfigured():
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
		if s.GitSigningEnabled() {
			fmt.Println("  Git signing: on (commit, tag, merge, rebase, ... sign with the agent; their hooks do not run)")
		} else {
			fmt.Println("  Git signing: off")
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

var (
	sshHostsAddWrite    bool
	sshHostsAddCommands []string
)

var sshHostsAddCmd = &cobra.Command{
	Use:   "add <host>...",
	Short: "Allow ssh and sshpass to connect to hosts (as typed: an alias of ~/.ssh/config or a host name)",
	Long: `Allow ssh and sshpass to connect to hosts, as typed: an alias of
~/.ssh/config or a host name. The command ssh runs there is held to read-only
commands; --command allows a command beyond those (with any arguments, or
limited to the leading arguments given), and --write lifts the check, lets
scp and rsync copy files to and from the host, and lets ssh forward ports
(-L, -R, -D) and share connections (-M, -S, -O) with it.

  lite-sandbox config ssh hosts add build-box
  lite-sandbox config ssh hosts add deploy-box --command 'systemctl restart' --command 'docker compose up'
  lite-sandbox config ssh hosts add scratch-vm --write

On a host already listed, the flags add to its entry.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, h := range args {
			listed := cfg.SSH.AllowsHost(h)
			changed, err := cfg.AddSSHHost(h, sshHostsAddWrite, sshHostsAddCommands...)
			if err != nil {
				return err
			}
			entry := cfg.SSH.Host(h)
			switch {
			case !listed:
				fmt.Printf("Added ssh host %s: %s\n", h, entry.Describe())
			case changed:
				fmt.Printf("Updated ssh host %s: %s\n", h, entry.Describe())
			default:
				fmt.Printf("ssh host %s is already allowed: %s\n", h, entry.Describe())
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

var sshGitSigningCmd = &cobra.Command{
	Use:   "git-signing",
	Short: "Sign git commits and tags with the ssh agent (gpg.format ssh)",
}

var (
	sshGitSigningEnableCmd = sshAgentSetter("enable", "Let the git commands that sign (commit, tag, merge, rebase, ...) use the agent; they then run without the project's hooks",
		"git signing enabled: commit, tag, merge, rebase, cherry-pick, revert, am, and commit-tree sign with the ssh agent, without running the project's hooks",
		func(s *config.SSHConfig) { s.GitSigning = boolRef(true) })
	sshGitSigningDisableCmd = sshAgentSetter("disable", "Stop signing git commits and tags with the ssh agent",
		"git signing disabled",
		func(s *config.SSHConfig) { s.GitSigning = nil })
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
	sshHostsAddCmd.Flags().BoolVar(&sshHostsAddWrite, "write", false, "let the remote command run unchecked (not only read-only commands), scp and rsync copy to and from the host, and ssh forward ports and share connections")
	sshHostsAddCmd.Flags().StringArrayVar(&sshHostsAddCommands, "command", nil, "allow a remote command beyond the read-only ones: a name, or a name and its leading arguments ('systemctl restart'); repeatable")
	sshHostsCmd.AddCommand(sshHostsAddCmd, sshHostsRemoveCmd)
	sshAgentCmd.AddCommand(sshAgentEnableCmd, sshAgentDisableCmd, sshAgentRestrictCmd, sshAgentUnrestrictCmd)
	sshGitSigningCmd.AddCommand(sshGitSigningEnableCmd, sshGitSigningDisableCmd)
	sshCmd.AddCommand(sshShowCmd, sshHostsCmd, sshAgentCmd, sshGitSigningCmd, sshDisableCmd)
	configCmd.AddCommand(sshCmd)
}
