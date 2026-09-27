package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestValidateFlutterRuntimeGate(t *testing.T) {
	enabled := []config.ProfileEntry{{Name: "flutter"}}
	disabled := []config.ProfileEntry{{Name: "flutter", Enabled: boolPtr(false)}}

	tests := []struct {
		name      string
		command   string
		profiles  []config.ProfileEntry
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "flutter allowed when enabled",
			command:  "flutter test",
			profiles: enabled,
			wantErr:  false,
		},
		{
			name:     "dart allowed when enabled",
			command:  "dart pub get",
			profiles: enabled,
			wantErr:  false,
		},
		{
			name:     "fvm allowed when enabled",
			command:  "fvm flutter build apk",
			profiles: enabled,
			wantErr:  false,
		},
		{
			name:      "flutter blocked when disabled",
			command:   "flutter test",
			profiles:  disabled,
			wantErr:   true,
			errSubstr: `command "flutter" is not allowed (the flutter profile is not enabled)`,
		},
		{
			name:      "dart blocked by default",
			command:   "dart run",
			profiles:  nil,
			wantErr:   true,
			errSubstr: `command "dart" is not allowed (the flutter profile is not enabled)`,
		},
		{
			name:      "fvm blocked by default",
			command:   "fvm use stable",
			profiles:  nil,
			wantErr:   true,
			errSubstr: `command "fvm" is not allowed (the flutter profile is not enabled)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSandboxWithConfig(&config.Config{Profiles: tt.profiles})
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("failed to parse command: %v", err)
			}
			err = s.validate(f)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
