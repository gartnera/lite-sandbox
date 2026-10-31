package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/internal/approval"
	"github.com/gartnera/lite-sandbox/internal/configrequest"
)

// approveOptions are the approve command's flags.
type approveOptions struct {
	cwd    string
	dryRun bool
	global bool
}

var approveFlags approveOptions

// approveResult is what `lite-sandbox approve` prints, as JSON.
type approveResult struct {
	// Kind is "config" for a config request, "command" for a command that
	// runs a commands entry with ask: true, and "none" for a command that
	// needs no approval (any other command, or a config request for --help).
	Kind string `json:"kind"`
	// Command is what runs once approved: for a config request, the scoped
	// `lite-sandbox config --dir <project> ...` (as written, with --global).
	Command string `json:"command,omitempty"`
	// Args are a config request's arguments as the agent wrote them.
	Args []string `json:"args,omitempty"`
	// Prompted are the commands entries with ask: true a command runs.
	Prompted []string `json:"prompted,omitempty"`
	// Global says the config request is approved for the global config.
	Global bool `json:"global,omitempty"`
	// Approved says a ticket was recorded (false on --dry-run).
	Approved bool `json:"approved"`
}

var approveCmd = &cobra.Command{
	Use:   "approve <command>",
	Short: "Record the user's approval of a sandbox bash command (for an approval plugin)",
	Long: "Records the user's approval of one call to the sandbox's bash tool, for an " +
		"approval plugin that asks the user itself instead of the agent's permission " +
		"prompt (the hook registered with --external-approval). <command> is the bash " +
		"tool's command, exactly as the call will send it. A config request " +
		"(`lite-sandbox config ...` on its own) is scoped to the project as the server " +
		"scopes it, or with --global approved to run against the global config as " +
		"written; a command that runs a commands entry with ask: true is validated as " +
		"the server will run it. The ticket approves that one call, once, for 15 minutes.\n\n" +
		"With --dry-run nothing is recorded: the JSON printed says what kind of " +
		"approval the command needs and what would run, for the plugin to show the user.\n\n" +
		"Sandboxed commands cannot run it (it is on the built-in command deny list): " +
		"only the user's own approval should mint a ticket.",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd := approveFlags.cwd
		if cwd == "" {
			var err error
			if cwd, err = os.Getwd(); err != nil {
				return err
			}
		}
		res, err := approve(cwd, args[0], approveFlags)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		return enc.Encode(res)
	},
}

func init() {
	approveCmd.Flags().StringVar(&approveFlags.cwd, "cwd", "", "the directory the call runs from (default: the current directory)")
	approveCmd.Flags().BoolVar(&approveFlags.dryRun, "dry-run", false, "print what the command needs approved without recording a ticket")
	approveCmd.Flags().BoolVar(&approveFlags.global, "global", false, "approve a config request for the global config instead of the project")
	rootCmd.AddCommand(approveCmd)
}

// approve works out what command, run with the sandbox's bash tool from cwd,
// needs approved and, unless opts.dryRun, records the ticket the server
// consumes when it runs the call.
func approve(cwd, command string, opts approveOptions) (approveResult, error) {
	if req, ok := configrequest.Parse(command); ok {
		return approveConfigRequest(cwd, req, opts)
	}
	if opts.global {
		return approveResult{}, errors.New("--global applies only to a `lite-sandbox config` request")
	}
	prompted, err := askCommandPrompts(cwd, command)
	if err != nil {
		return approveResult{}, fmt.Errorf("this command did not pass sandbox validation: %w", err)
	}
	if len(prompted) == 0 {
		return approveResult{Kind: "none"}, nil
	}
	res := approveResult{Kind: "command", Command: command, Prompted: prompted}
	if opts.dryRun {
		return res, nil
	}
	if err := approval.Issue(cwd, approval.CommandSubject(command), command); err != nil {
		return approveResult{}, fmt.Errorf("recording the approval: %w", err)
	}
	res.Approved = true
	return res, nil
}

func approveConfigRequest(cwd string, req configrequest.Request, opts approveOptions) (approveResult, error) {
	if req.IsHelp() {
		return approveResult{Kind: "none"}, nil
	}
	if err := req.Validate(); err != nil {
		return approveResult{}, err
	}
	res := approveResult{Kind: "config", Args: req.Args, Global: opts.global}
	if opts.global {
		if err := req.ValidateGlobal(); err != nil {
			return approveResult{}, err
		}
		res.Command = req.Command()
	} else {
		scoped, err := req.Scope(cwd)
		if err != nil {
			return approveResult{}, err
		}
		res.Command = scoped.Command()
	}
	if opts.dryRun {
		return res, nil
	}
	issue := configrequest.Issue
	if opts.global {
		issue = configrequest.IssueGlobal
	}
	if err := issue(cwd, req); err != nil {
		return approveResult{}, fmt.Errorf("recording the approval: %w", err)
	}
	res.Approved = true
	return res, nil
}
