package bash_sandboxed

import (
	"context"
	"slices"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestValidateXcodeProfile(t *testing.T) {
	enabled := []config.ProfileEntry{{Name: "xcode"}}
	devices := []config.ProfileEntry{{Name: "xcode", Options: map[string]bool{"allow_devices": true}}}

	tests := []struct {
		name      string
		command   string
		profiles  []config.ProfileEntry
		extra     []string // commands allows
		errSubstr string   // "" means allowed
	}{
		{name: "xcodebuild blocked by default", command: "xcodebuild build", errSubstr: `command "xcodebuild" is not allowed (the xcode profile is not enabled)`},
		{name: "swift blocked by default", command: "swift build", errSubstr: `command "swift" is not allowed (the xcode profile is not enabled)`},
		{name: "xcrun blocked by default", command: "xcrun --show-sdk-path", errSubstr: `command "xcrun" is not allowed (the xcode profile is not enabled)`},

		// xcodebuild
		{name: "build", command: "xcodebuild -scheme App -destination 'generic/platform=iOS Simulator' build", profiles: enabled},
		{name: "archive", command: "xcodebuild -scheme App -archivePath build/App.xcarchive archive", profiles: enabled},
		{name: "list and showsdks", command: "xcodebuild -list && xcodebuild -showsdks && xcodebuild -version", profiles: enabled},
		{name: "expanded option value", command: `xcodebuild -scheme "$SCHEME" -derivedDataPath "$PWD/dd" build`, profiles: enabled},
		{name: "test on the Mac", command: "xcodebuild -scheme App -destination 'platform=macOS' test", profiles: enabled},
		{name: "test on Mac Catalyst", command: "xcodebuild -scheme App -destination 'platform=macOS,variant=Mac Catalyst' test", profiles: enabled},
		{name: "scheme named test is not the test action", command: "xcodebuild -scheme test build", profiles: enabled},
		{name: "test on a simulator", command: "xcodebuild -scheme App -destination 'platform=iOS Simulator,name=iPhone 17' test", profiles: enabled, errSubstr: "run outside the OS sandbox"},
		{name: "test on a device by id", command: "xcodebuild -scheme App -destination 'id=00008110-001' test-without-building", profiles: enabled, errSubstr: "is not allowed"},
		{name: "test on the Mac and a simulator", command: "xcodebuild -scheme App -destination platform=macOS -destination 'platform=iOS Simulator,name=iPhone 17' test", profiles: enabled, errSubstr: "run outside the OS sandbox"},
		{name: "test without a destination", command: "xcodebuild -scheme App test", profiles: enabled, errSubstr: "needs an explicit -destination"},
		{name: "test with an expanded destination", command: `xcodebuild -scheme App -destination "$DEST" test`, profiles: enabled, errSubstr: "needs a literal -destination"},
		{name: "test on a simulator with allow_devices", command: "xcodebuild -scheme App -destination 'platform=iOS Simulator,name=iPhone 17' test", profiles: devices},
		{name: "exportArchive refused", command: "xcodebuild -exportArchive -archivePath a.xcarchive -exportPath out -exportOptionsPlist o.plist", profiles: devices, errSubstr: "xcodebuild -exportArchive is not allowed"},
		{name: "double-dash spelling refused", command: "xcodebuild --exportArchive -archivePath a.xcarchive", profiles: enabled, errSubstr: "xcodebuild -exportArchive is not allowed"},
		{name: "provisioning updates refused", command: "xcodebuild -scheme App -allowProvisioningUpdates build", profiles: enabled, errSubstr: "Apple Developer website"},
		{name: "license refused", command: "xcodebuild -license accept", profiles: enabled, errSubstr: "xcodebuild -license is not allowed"},
		{name: "dynamic action refused", command: `xcodebuild -scheme App "$ACTION"`, profiles: enabled, errSubstr: "must be literal"},

		// xcode-select
		{name: "xcode-select -p", command: "xcode-select -p", profiles: enabled},
		{name: "xcode-select --switch refused", command: "xcode-select --switch /Applications/Xcode.app", profiles: enabled, errSubstr: "xcode-select --switch is not allowed"},
		{name: "xcode-select --install refused", command: "xcode-select --install", profiles: enabled, errSubstr: "is not allowed"},

		// xcrun
		{name: "xcrun queries", command: "xcrun --show-sdk-path && xcrun --sdk iphoneos --show-sdk-version && xcrun --find notarytool", profiles: enabled},
		{name: "xcrun toolchain tool", command: "xcrun --sdk macosx clang -c main.c", profiles: enabled},
		{name: "xcrun swift is validated as swift", command: "xcrun swift build", profiles: enabled},
		{name: "xcrun xcodebuild is validated as xcodebuild", command: "xcrun xcodebuild -exportArchive -archivePath a", profiles: enabled, errSubstr: "xcodebuild -exportArchive is not allowed"},
		{name: "xcrun git is validated as git", command: "xcrun git push", profiles: enabled, errSubstr: "push"},
		{name: "xcrun falls back to PATH", command: "xcrun curl https://example.com", profiles: enabled, errSubstr: `command "curl" is not allowed`},
		{name: "xcrun bash refused", command: "xcrun bash -c ls", profiles: enabled, errSubstr: "wrapped subcommand"},
		{name: "xcrun python3 refused", command: "xcrun python3 -c 1", profiles: enabled, errSubstr: "wrapped subcommand"},
		{name: "xcrun tool by path refused", command: "xcrun ./tool", profiles: enabled, errSubstr: "runs developer tools by name"},
		{name: "xcrun dynamic tool refused", command: `xcrun "$TOOL"`, profiles: enabled, errSubstr: "must be literal"},
		{name: "xcrun notarytool refused", command: "xcrun notarytool submit App.zip", profiles: devices, errSubstr: "notary service"},
		{name: "xcrun altool refused", command: "xcrun altool --upload-app -f App.ipa", profiles: devices, errSubstr: "App Store Connect"},
		{name: "simctl list", command: "xcrun simctl list devices", profiles: enabled},
		{name: "simctl --set list", command: "xcrun simctl --set sims list", profiles: enabled},
		{name: "simctl spawn refused", command: "xcrun simctl spawn booted /bin/sh -c id", profiles: enabled, errSubstr: "xcrun simctl spawn is not allowed"},
		{name: "simctl --set spawn refused", command: "xcrun simctl --set sims spawn booted ls", profiles: enabled, errSubstr: "xcrun simctl spawn is not allowed"},
		{name: "simctl dynamic subcommand refused", command: `xcrun simctl "$SUB" booted`, profiles: enabled, errSubstr: "must be literal"},
		{name: "simctl spawn with allow_devices", command: "xcrun simctl spawn booted ls", profiles: devices},
		{name: "devicectl refused", command: "xcrun devicectl list devices", profiles: enabled, errSubstr: "connected devices"},
		{name: "devicectl with allow_devices", command: "xcrun devicectl list devices", profiles: devices},

		// swift
		{name: "swift build/test/run", command: `swift build -c release && swift test --filter T && swift run hello "$ARG"`, profiles: enabled},
		{name: "swift package resolve", command: "swift package resolve", profiles: enabled},
		{name: "swiftc", command: "swiftc -o hello main.swift", profiles: enabled},
		{name: "xcodegen", command: "xcodegen generate --use-cache && xcodegen dump --type yaml", profiles: enabled},
		{name: "xcodegen blocked by default", command: "xcodegen generate", errSubstr: `command "xcodegen" is not allowed (the xcode profile is not enabled)`},
		{name: "registry publish refused", command: "swift package-registry publish acme.hello 1.0.0", profiles: enabled, errSubstr: "swift package-registry publish is not allowed"},
		{name: "registry login refused", command: "swift package-registry login https://r.example.com", profiles: enabled, errSubstr: "swift package-registry login is not allowed"},
		{name: "registry publish allowed by a commands entry", command: "swift package-registry publish acme.hello 1.0.0", profiles: enabled, extra: []string{"swift package-registry publish"}},
		{name: "registry set allowed", command: "swift package-registry set https://r.example.com", profiles: enabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Profiles: tt.profiles}
			yes := true
			for _, c := range tt.extra {
				cfg.Commands = append(cfg.Commands, config.CommandEntry{Command: c, Allow: &yes})
			}
			s := newTestSandboxWithConfig(cfg)
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("failed to parse command: %v", err)
			}
			err = s.validate(f)
			switch {
			case tt.errSubstr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.errSubstr != "" && err == nil:
				t.Errorf("expected error containing %q, got nil", tt.errSubstr)
			case tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr):
				t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

func TestIsMacDestination(t *testing.T) {
	for spec, want := range map[string]bool{
		"platform=macOS":                      true,
		"platform=macOS,arch=arm64":           true,
		"arch=x86_64,platform=OS X":           true,
		"platform=macOS,variant=Mac Catalyst": true,
		"platform=iOS Simulator,name=iPhone":  false,
		"platform=iOS,id=abc":                 false,
		"id=abc":                              false,
		"name=My Mac":                         false,
		"":                                    false,
	} {
		if got := isMacDestination(spec); got != want {
			t.Errorf("isMacDestination(%q) = %v, want %v", spec, got, want)
		}
	}
}

func TestXcodeDisableNestedSandbox(t *testing.T) {
	const manifest = "-IDEPackageSupportDisableManifestSandbox=YES"
	for _, tt := range []struct {
		in, want []string
	}{
		{[]string{"swift", "build"}, []string{"swift", "build", "--disable-sandbox"}},
		{[]string{"swift", "run", "hello", "--", "-x"}, []string{"swift", "run", "--disable-sandbox", "hello", "--", "-x"}},
		{[]string{"swift", "package", "resolve"}, []string{"swift", "package", "--disable-sandbox", "resolve"}},
		{[]string{"swift", "test", "--disable-sandbox"}, []string{"swift", "test", "--disable-sandbox"}},
		{[]string{"swift", "--version"}, []string{"swift", "--version"}},
		{[]string{"swift", "main.swift"}, []string{"swift", "main.swift"}},
		{[]string{"xcodebuild", "-scheme", "App", "build"}, []string{"xcodebuild", manifest, "-scheme", "App", "build"}},
		{[]string{"xcodebuild", "-IDEPackageSupportDisableManifestSandbox=NO"}, []string{"xcodebuild", "-IDEPackageSupportDisableManifestSandbox=NO"}},
		{[]string{"xcrun", "--sdk", "macosx", "swift", "build"}, []string{"xcrun", "--sdk", "macosx", "swift", "build", "--disable-sandbox"}},
		{[]string{"xcrun", "xcodebuild", "build"}, []string{"xcrun", "xcodebuild", manifest, "build"}},
		{[]string{"xcrun", "--find", "swift"}, []string{"xcrun", "--find", "swift"}},
		{[]string{"xcrun", "clang", "a.c"}, []string{"xcrun", "clang", "a.c"}},
	} {
		if got := xcodeDisableNestedSandbox(slices.Clone(tt.in)); !slices.Equal(got, tt.want) {
			t.Errorf("xcodeDisableNestedSandbox(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestUnwrapXcrunArgs(t *testing.T) {
	for _, tt := range []struct {
		in, want []string
	}{
		{[]string{"xcrun", "clang", "a.c"}, []string{"clang", "a.c"}},
		{[]string{"xcrun", "-sdk", "iphoneos", "-l", "ld", "-v"}, []string{"ld", "-v"}},
		{[]string{"xcrun", "-f", "clang"}, nil},
		{[]string{"xcrun", "-f", "-r", "clang"}, []string{"clang"}},
		{[]string{"xcrun", "--show-sdk-path"}, nil},
		{[]string{"timeout", "60", "xcrun", "swift", "build"}, []string{"swift", "build"}},
	} {
		if got := unwrapWrapperArgs(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("unwrapWrapperArgs(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestXcodeNoSandboxOption checks the xcode profile's no_sandbox option routes
// its commands to the host while keeping them whitelisted and validated.
func TestXcodeNoSandboxOption(t *testing.T) {
	yes := true
	for _, noSandbox := range []bool{false, true} {
		s := newTestSandboxWithConfig(&config.Config{
			OSSandbox: &yes,
			Profiles:  []config.ProfileEntry{{Name: "xcode", Options: map[string]bool{"no_sandbox": noSandbox}}},
		})
		for _, argv := range [][]string{{"swift", "build"}, {"xcodebuild", "build"}, {"xcrun", "swift", "build"}} {
			if got := s.execIsUnsandboxed(context.Background(), argv); got != noSandbox {
				t.Errorf("no_sandbox=%v: execIsUnsandboxed(%q) = %v", noSandbox, argv, got)
			}
		}
		// Routing looks through xcrun to the tool it runs, so the option
		// moves only the profile's own commands to the host: xcrun cannot
		// carry curl or git out of the sandbox with it.
		for _, argv := range [][]string{{"xcrun", "clang"}, {"xcrun", "curl"}, {"xcrun", "git", "status"}} {
			if s.execIsUnsandboxed(context.Background(), argv) {
				t.Errorf("no_sandbox=%v: %q must stay in the OS sandbox", noSandbox, argv)
			}
		}
		f, err := ParseBash("xcodebuild -exportArchive -archivePath a")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.validate(f); err == nil || !contains(err.Error(), "-exportArchive is not allowed") {
			t.Errorf("no_sandbox=%v: -exportArchive must stay refused, got %v", noSandbox, err)
		}
	}
}
