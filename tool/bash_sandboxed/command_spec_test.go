package bash_sandboxed

import (
	"slices"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestCommandSpecsReachable catches a registration under a name nothing can
// whitelist (a typo registers a spec no invocation ever looks up, and the
// command it meant runs as a plain reader).
func TestCommandSpecsReachable(t *testing.T) {
	for name := range commandSpecs {
		switch {
		case allowedCommands[name],
			len(config.ProfilesForCommand(name)) > 0,
			slices.Contains(config.SSHCommands, name),
			slices.Contains(config.SSHCopyCommands, name),
			name == "time": // a shell keyword; registered only to refuse it under a wrapper
		default:
			t.Errorf("command %q is registered but no whitelist, profile, or ssh host can allow it", name)
		}
	}
}

// TestCommandSpecLookup: an unregistered command is a plain reader.
func TestCommandSpecLookup(t *testing.T) {
	sp := lookupCommand("no-such-command")
	if sp.writes || sp.validate != nil || sp.writeTargets != nil || sp.unwrap != nil {
		t.Errorf("unregistered command has a non-empty spec: %+v", sp)
	}
	if !lookupCommand("cp").writes || lookupCommand("cat").writes {
		t.Error("cp should be a writer, cat a reader")
	}
}
