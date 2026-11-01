package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"

	"github.com/gartnera/lite-sandbox/internal/configrequest"
)

// TestParseConfigRequest checks a config request is read the way cobra will
// run it, including spellings a word scan would misread, and that parsing
// leaves the shared flag variables as they were.
func TestParseConfigRequest(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		want    configrequest.Scope
		wantErr string
	}{
		{args: []string{"commands", "allow", "make"}},
		{args: []string{"commands", "allow", "make", "--global"}, want: configrequest.Scope{Global: true}},
		{args: []string{"commands", "allow", "make", "--global=1"}, want: configrequest.Scope{Global: true}},
		{args: []string{"commands", "allow", "make", "--global=false"}},
		// A `--` taken as --log-level's value does not end the flags.
		{args: []string{"commands", "allow", "foo", "--log-level", "--", "--global"}, want: configrequest.Scope{Global: true}},
		// After a real `--`, --global is an operand.
		{args: []string{"commands", "allow", "--", "--global"}},
		{args: []string{"paths", "allow", "/tmp/x"}, want: configrequest.Scope{PathsAllow: true}},
		{args: []string{"paths", "allow", "/tmp/x", "--write=1", "--internal=false"}, want: configrequest.Scope{PathsAllow: true, Write: true}},
		{args: []string{"paths", "allow", "/tmp/x", "--commands", "gh"}, want: configrequest.Scope{PathsAllow: true, Internal: true}},
		// A root flag with a value before the subcommand.
		{args: []string{"--log-level", "debug", "paths", "allow", "/tmp/x", "--write"}, want: configrequest.Scope{PathsAllow: true, Write: true}},
		{args: []string{"commands", "allow", "make", "--dir", "."}, wantErr: "--dir"},
		{args: []string{"--dir=/", "mode", "set", "open"}, wantErr: "--dir"},
		// Whole-file and deprecated commands are not requestable.
		{args: []string{"--log-level", "x", "edit", "--global"}, wantErr: "interactive"},
		{args: []string{"overrides", "remove", "/other", "--global"}, wantErr: "as a whole"},
		{args: []string{"paths", "migrate"}, wantErr: "as a whole"},
		{args: []string{"writable-paths", "add", "/tmp/x"}, wantErr: "deprecated"},
		{args: []string{"paths"}, wantErr: "not a config setting"},
		{args: []string{"commands", "allow", "make", "--no-such-flag"}, wantErr: "unknown flag"},
		// `edit` is refused as the subcommand, but not as a value.
		{args: []string{"edit"}, wantErr: "interactive"},
		{args: []string{"--log-level", "edit", "commands", "allow", "make"}},
		{args: []string{"commands", "allow", "edit"}},
		{args: nil, wantErr: "not a config setting"},
		// Arguments the approval prompt cannot show faithfully.
		{args: []string{"commands", "allow", "x\n✓ this project  ✗ global"}, wantErr: "control"},
		// Help is whatever cobra parses as its help flag: it then prints usage
		// before any hook or the command runs, so nothing else is checked.
		{args: []string{"--help"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"-h"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"paths", "--help"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"paths", "allow", "-h"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"--help", "mode", "set", "open"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"paths", "allow", "/x", "--write", "-h"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"mode", "set", "open", "--dir=.", "--help"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"edit", "--help"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"mode", "set", "", "--help"}, want: configrequest.Scope{ReadOnly: true}},
		// A command marked read-only changes nothing, in any scope.
		{args: []string{"show"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"show", "--global"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"paths", "list", "--dir", "/elsewhere"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"--log-level", "debug", "mode", "show"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"path"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"overrides", "list"}, want: configrequest.Scope{ReadOnly: true}},
		{args: []string{"overrides", "remove", "/x"}, wantErr: "as a whole"},
		// `show` as a value, not the subcommand.
		{args: []string{"commands", "allow", "show"}},
		// --help taken as a value, turned off, or after `--` is not help.
		{args: []string{"mode", "set", "open", "--dir", "--help"}, wantErr: "--dir"},
		{args: []string{"commands", "allow", "make", "--log-level", "--help"}},
		{args: []string{"mode", "set", "open", "--help=false"}},
		{args: []string{"mode", "set", "open", "--", "--help"}},
		{args: []string{"mode", "set", "open", "-hx"}, wantErr: "unknown shorthand"},
	} {
		got, err := parseConfigRequest(configrequest.Request{Args: tc.args})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parseConfigRequest(%q) = %+v, %v; want error containing %q", tc.args, got, err, tc.wantErr)
			}
		} else if err != nil || got != tc.want {
			t.Errorf("parseConfigRequest(%q) = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
		if configGlobal || configDir != "" || pathsAllowWrite || pathsAllowInternal || len(pathsAllowCommands) != 0 || logLevel != "" || helpSet(t, tc.args) {
			t.Fatalf("parseConfigRequest(%q) left flag state behind", tc.args)
		}
	}
}

// helpSet reports whether the help flag of the command args name was left set.
func helpSet(t *testing.T, args []string) bool {
	t.Helper()
	cmd, _, err := rootCmd.Find(append([]string{"config"}, args...))
	if err != nil {
		return false
	}
	f := cmd.Flags().Lookup("help")
	return f != nil && f.Changed
}

// TestReadOnlyConfigCommandsLeaveConfig runs every config subcommand marked
// readOnlyAnnotation, which a config request runs without the user's
// approval, and checks the config file is left byte for byte as it was.
func TestReadOnlyConfigCommandsLeaveConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"config", "commands", "allow", "make", "--global"},
		{"config", "paths", "allow", "/tmp/x", "--dir", wd},
	} {
		if err := runRootCmd(t, args...); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		cmd, _, _ := rootCmd.Find(args)
		resetFlags(cmd)
		configDir, configDirExplicit = "", false
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	var readOnlyCmds []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Annotations[readOnlyAnnotation] != "" {
			readOnlyCmds = append(readOnlyCmds, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(configCmd)
	if len(readOnlyCmds) < 10 {
		t.Fatalf("found %d read-only commands, want the show/list/path commands", len(readOnlyCmds))
	}
	for _, c := range readOnlyCmds {
		args := strings.Fields(c.CommandPath())[1:]
		if c == configProfilesShowCmd {
			args = append(args, config.Profiles()[0].Name)
		}
		for _, scope := range [][]string{nil, {"--global"}} {
			if c.Annotations[wholeFileAnnotation] != "" && scope != nil {
				continue
			}
			err := runRootCmd(t, append(args, scope...)...)
			// The pre-run defaults configDir itself, not through the flag.
			resetFlags(c)
			configDir, configDirExplicit = "", false
			if err != nil {
				t.Errorf("%q: %v", args, err)
			}
			after, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("%q %q changed the config:\n%s\n--- became ---\n%s", args, scope, before, after)
			}
		}
	}
}
