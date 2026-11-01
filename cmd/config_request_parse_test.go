package cmd

import (
	"strings"
	"testing"

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
		{args: []string{"--log-level", "x", "edit", "--global"}, wantErr: "as a whole"},
		{args: []string{"overrides", "remove", "/other", "--global"}, wantErr: "as a whole"},
		{args: []string{"paths", "migrate"}, wantErr: "as a whole"},
		{args: []string{"writable-paths", "add", "/tmp/x"}, wantErr: "deprecated"},
		{args: []string{"paths"}, wantErr: "not a config setting"},
		{args: []string{"commands", "allow", "make", "--no-such-flag"}, wantErr: "unknown flag"},
	} {
		got, err := parseConfigRequest(configrequest.Request{Args: tc.args})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parseConfigRequest(%q) = %+v, %v; want error containing %q", tc.args, got, err, tc.wantErr)
			}
		} else if err != nil || got != tc.want {
			t.Errorf("parseConfigRequest(%q) = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
		if configGlobal || configDir != "" || pathsAllowWrite || pathsAllowInternal || len(pathsAllowCommands) != 0 || logLevel != "" {
			t.Fatalf("parseConfigRequest(%q) left flag state behind", tc.args)
		}
	}
}
