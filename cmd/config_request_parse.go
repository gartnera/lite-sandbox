package cmd

import (
	"errors"
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/gartnera/lite-sandbox/internal/configrequest"
)

// configRequestParseMu serializes parseConfigRequest, which parses into the
// commands' shared flag variables; the MCP server can handle tool calls
// concurrently.
var configRequestParseMu sync.Mutex

// parseConfigRequest is the one reading of a config request's arguments that
// the hook and the server act on. It parses them the way the config
// subprocess will, with cobra itself — rootCmd.Find and ParseFlags, the steps
// Command.Execute takes before it runs anything — so what the user approves
// is exactly what the command acts on, however the arguments are spelled (a
// flag taking the next word as its value, a `--` consumed as one, a root flag
// before the subcommand, ...).
//
// A request that changes nothing comes back as Scope.ReadOnly and is not
// checked further: one whose help flag cobra parses as set, which only prints
// usage (Execute returns ErrHelp before any hook or RunE), or one naming a
// subcommand marked readOnlyAnnotation. Any other request must have displayable
// arguments (Request.Validate) and may not use --dir (a request lands in the
// project or, with --global, the base config) or a command that edits the
// config file as a whole rather than a setting for a directory.
//
// The flag values are read and then reset, so parsing leaves no state behind
// in the long-lived server or in tests.
func parseConfigRequest(req configrequest.Request) (configrequest.Scope, error) {
	configRequestParseMu.Lock()
	defer configRequestParseMu.Unlock()

	cmd, rest, err := rootCmd.Find(append([]string{"config"}, req.Args...))
	if err != nil {
		return configrequest.Scope{}, err
	}
	// As Execute does: the help flag exists, and the inherited persistent
	// flags are merged into cmd.Flags() so they are parsed and reset with it.
	cmd.InitDefaultHelpFlag()
	cmd.InheritedFlags()
	resetFlags(cmd)
	defer resetFlags(cmd)
	if err := cmd.ParseFlags(rest); err != nil {
		return configrequest.Scope{}, err
	}
	if help, _ := cmd.Flags().GetBool("help"); help || cmd.Annotations[readOnlyAnnotation] != "" {
		return configrequest.Scope{ReadOnly: true}, nil
	}
	if err := req.Validate(); err != nil {
		return configrequest.Scope{}, err
	}
	if cmd == configCmd || !hasAncestor(cmd, configCmd) || cmd.RunE == nil && cmd.Run == nil {
		return configrequest.Scope{}, fmt.Errorf("`%s` is not a config setting; request a subcommand, e.g. `lite-sandbox config commands allow make`", cmd.CommandPath())
	}
	if cmd.Deprecated != "" {
		return configrequest.Scope{}, fmt.Errorf("`%s` is deprecated and cannot be requested: %s", cmd.CommandPath(), cmd.Deprecated)
	}
	if cmd.Annotations[interactiveAnnotation] != "" {
		// Checked before wholeFileAnnotation, which an interactive command
		// may also carry, for the more useful message.
		return configrequest.Scope{}, fmt.Errorf("`%s` is interactive and cannot be run here; request the individual change instead (e.g. `lite-sandbox config paths allow <path>`)", cmd.CommandPath())
	}
	if cmd.Annotations[wholeFileAnnotation] != "" {
		return configrequest.Scope{}, fmt.Errorf("`%s` works on the config file as a whole and cannot be requested; ask the user to run it", cmd.CommandPath())
	}
	flags := cmd.Flags()
	if flags.Changed("dir") {
		return configrequest.Scope{}, errors.New("`--dir` is not allowed: a config change the agent requests applies to this project, or to every directory with --global; leave out --dir")
	}
	scope := configrequest.Scope{Global: configGlobal}
	if cmd == configPathsAllowCmd {
		scope.PathsAllow = true
		scope.Write = pathsAllowWrite
		scope.Internal = pathsAllowInternal || len(pathsAllowCommands) > 0
	}
	return scope, nil
}

func hasAncestor(cmd, ancestor *cobra.Command) bool {
	for c := cmd.Parent(); c != nil; c = c.Parent() {
		if c == ancestor {
			return true
		}
	}
	return false
}

// resetFlags restores every flag cmd parsed (its own and the inherited
// persistent ones) to its default.
func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed {
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
}
