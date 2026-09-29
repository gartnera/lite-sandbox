package bash_sandboxed

import (
	"fmt"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The xcode profile's parser hooks. xcodebuild and swift are build tools like
// go and cargo: the code they compile and the build phases and tests they run
// are confined by the OS sandbox, so building and testing are allowed. What is
// gated is what the OS sandbox cannot confine:
//
//   - talking to Apple on the user's behalf: distributing an archive (which can
//     upload it to App Store Connect), notarizing, and creating certificates,
//     profiles, and device registrations on the developer account;
//   - host-wide installs: the license, first-launch components, platforms, and
//     switching the active developer directory;
//   - running code on a simulator or device. CoreSimulator (and a device's own
//     OS) starts those processes, not the command the sandbox confines, so a
//     test run on the iOS Simulator can write anywhere the user can. That is
//     the xcode profile's allow_devices option.
//
// xcrun runs any tool by name — from the toolchain, and failing that from PATH
// (`xcrun curl` runs /usr/bin/curl) — so it is validated as a wrapper: the tool
// it runs goes through the same gates as if it had been typed.

// staticWordText returns w's text when it is fully determined by the source —
// literals and quoted literals, no expansions — and false otherwise. Unlike
// Lit it accepts quoting, which xcodebuild destinations always need
// (-destination 'platform=iOS Simulator,name=iPhone 17').
func staticWordText(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false
			}
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				sb.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// xcodebuildRefusedOptions are the options xcodebuild is refused outright, with
// why. They act outside anything the sandbox can confine — Apple's servers,
// the user's developer account, the whole host — so they are the user's to
// run.
var xcodebuildRefusedOptions = map[string]string{
	"-exportArchive":                       "distributes an archive, which can upload it to App Store Connect",
	"-exportNotarizedApp":                  "exports an app Apple has notarized",
	"-allowProvisioningUpdates":            "creates and updates certificates, app IDs, and provisioning profiles on the Apple Developer website",
	"-allowProvisioningDeviceRegistration": "registers devices on the Apple Developer website",
	"-authenticationKeyPath":               "authenticates with App Store Connect",
	"-authenticationKeyID":                 "authenticates with App Store Connect",
	"-authenticationKeyIssuerID":           "authenticates with App Store Connect",
	"-license":                             "accepts the Xcode license for the whole host",
	"-runFirstLaunch":                      "installs system components for the whole host",
	"-downloadAllPlatforms":                "installs platforms for the whole host",
	"-downloadPlatform":                    "installs a platform for the whole host",
	"-importPlatform":                      "installs a platform for the whole host",
	"-downloadComponent":                   "installs a component for the whole host",
	"-importComponent":                     "installs a component for the whole host",
}

// xcodebuildValueOptions are the xcodebuild options that take the next
// argument as their value, from xcodebuild(1) and `xcodebuild -help`. Their
// values are skipped when looking for actions, so `-scheme test` is not the
// test action, and are not required to be literal (-derivedDataPath
// "$PWD/dd"). Only options known to take a value are listed: an unlisted one
// leaves its value to be read as an action, which can only refuse more.
var xcodebuildValueOptions = map[string]bool{
	"-project": true, "-target": true, "-workspace": true, "-scheme": true,
	"-destination": true, "-destination-timeout": true, "-configuration": true,
	"-arch": true, "-sdk": true, "-toolchain": true, "-xcconfig": true,
	"-derivedDataPath": true, "-resultBundlePath": true, "-resultBundleVersion": true,
	"-archivePath": true, "-exportPath": true, "-exportOptionsPlist": true,
	"-localizationPath": true, "-exportLanguage": true,
	"-testProductsPath": true, "-xctestrun": true, "-testPlan": true,
	"-only-testing": true, "-skip-testing": true,
	"-only-test-configuration": true, "-skip-test-configuration": true,
	"-testLanguage": true, "-testRegion": true,
	"-enableAddressSanitizer": true, "-enableThreadSanitizer": true,
	"-enableUndefinedBehaviorSanitizer": true, "-enableCodeCoverage": true,
	"-maximum-concurrent-test-device-destinations":    true,
	"-maximum-concurrent-test-simulator-destinations": true,
	"-parallel-testing-enabled":                       true, "-parallel-testing-worker-count": true,
	"-maximum-parallel-testing-workers": true, "-test-timeouts-enabled": true,
	"-default-test-execution-time-allowance": true,
	"-maximum-test-execution-time-allowance": true,
	"-test-iterations":                       true, "-test-repetition-relaunch-enabled": true,
	"-collect-test-diagnostics": true, "-test-enumeration-style": true,
	"-test-enumeration-format": true, "-test-enumeration-output-path": true,
	"-clonedSourcePackagesDirPath": true, "-packageCachePath": true,
	"-packageAuthorizationProvider": true, "-defaultPackageRegistryURL": true,
	"-packageDependencySCMToRegistryTransformation": true,
	"-packageFingerprintPolicy":                     true, "-packageSigningEntityPolicy": true,
}

// xcodebuildRunActions are the actions that run the tests they build.
var xcodebuildRunActions = map[string]bool{
	"test":                  true,
	"test-without-building": true,
}

func validateXcodebuildArgs(s *Sandbox, args []*syntax.Word) error {
	allowDevices := s.getConfig().ProfileOption("xcode", "allow_devices")
	runsTests := false
	var destinations []string
	dynamicDestination := false
	for i := 1; i < len(args); i++ {
		text, ok := staticWordText(args[i])
		if !ok {
			return fmt.Errorf("xcodebuild options and actions must be literal strings (only an option's value may be expanded)")
		}
		if !strings.HasPrefix(text, "-") {
			// An action or a buildsetting=value.
			if xcodebuildRunActions[text] {
				runsTests = true
			}
			continue
		}
		// xcodebuild spells its options with one dash; accept two, and an
		// attached =value, so neither spelling slips past the gates.
		name := "-" + strings.TrimLeft(text, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if why, refused := xcodebuildRefusedOptions[name]; refused {
			return fmt.Errorf("xcodebuild %s is not allowed: it %s; the user can run it outside the sandbox", name, why)
		}
		if xcodebuildValueOptions[name] && !strings.Contains(text, "=") && i+1 < len(args) {
			i++
			if name == "-destination" {
				if dest, ok := staticWordText(args[i]); ok {
					destinations = append(destinations, dest)
				} else {
					dynamicDestination = true
				}
			}
		}
	}
	if !runsTests || allowDevices {
		return nil
	}
	if dynamicDestination {
		return fmt.Errorf("xcodebuild test needs a literal -destination to check it is the Mac: %s", allowDevicesHint)
	}
	if len(destinations) == 0 {
		return fmt.Errorf("xcodebuild test needs an explicit -destination 'platform=macOS': without one it may pick a simulator, and %s", allowDevicesHint)
	}
	for _, d := range destinations {
		if !isMacDestination(d) {
			return fmt.Errorf("xcodebuild test on -destination %q is not allowed: %s", d, allowDevicesHint)
		}
	}
	return nil
}

// allowDevicesHint explains the allow_devices gate and how to open it.
const allowDevicesHint = "tests on a simulator or device run outside the OS sandbox (CoreSimulator starts them), so only -destination 'platform=macOS' is allowed; the user can allow simulators and devices with `lite-sandbox config profiles set xcode allow_devices true`"

// isMacDestination reports whether an xcodebuild destination specifier names
// the local Mac: its platform key is macOS (or the older "OS X"). A Mac
// Catalyst variant is still the Mac. Anything without a platform — an id= or
// name= alone — may be a simulator, so it is not.
func isMacDestination(spec string) bool {
	for _, kv := range strings.Split(spec, ",") {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(key) != "platform" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "macos", "os x":
			return true
		}
		return false
	}
	return false
}

// xcodeSelectAllowedOptions are the xcode-select invocations that only print.
// --switch, --reset, and --install change the developer directory or install
// the Command Line Tools for the whole host.
var xcodeSelectAllowedOptions = map[string]bool{
	"-p": true, "--print-path": true,
	"-v": true, "--version": true,
	"-h": true, "--help": true,
}

func validateXcodeSelectArgs(_ *Sandbox, args []*syntax.Word) error {
	for _, w := range args[1:] {
		lit := w.Lit()
		if !xcodeSelectAllowedOptions[lit] {
			if lit == "" {
				lit = "a non-literal argument"
			}
			return fmt.Errorf("xcode-select %s is not allowed: only -p/--print-path and --version are (switching or installing the developer tools changes the whole host)", lit)
		}
	}
	return nil
}

// xcrunValueOptions are xcrun's options that take the next argument as their
// value. xcrun accepts them with one dash too.
var xcrunValueOptions = map[string]bool{
	"--sdk": true, "-sdk": true,
	"--toolchain": true, "-toolchain": true,
}

// xcrunCommandIndex returns the index of the tool an `xcrun ...` invocation
// runs (lits[0] is "xcrun"), or wrapperNoCommand when it runs none: no tool
// named, or --find/-f, which prints the tool's path, and the --show-* queries.
// Everything before the tool is xcrun's own option: xcrun(1) has no "--".
func xcrunCommandIndex(lits []string) int {
	find := false
	for i := 1; i < len(lits); i++ {
		lit := lits[i]
		if !strings.HasPrefix(lit, "-") {
			if find {
				return wrapperNoCommand
			}
			return i
		}
		switch {
		case xcrunValueOptions[lit]:
			i++
		case lit == "-f" || lit == "--find":
			find = true
		case lit == "-r" || lit == "--run":
			find = false
		}
	}
	return wrapperNoCommand
}

// xcrunToolchainTools are the developer tools xcrun may run that are not
// commands of their own on the sandbox's whitelist: compilers, linkers, and
// the binary and asset tools a build uses, all confined by the OS sandbox like
// the build itself. A tool that is on the whitelist (git, ar, swift, ...) is
// validated as that command instead, and one on neither list is refused like
// any command that is not allowed.
var xcrunToolchainTools = map[string]bool{
	"clang": true, "clang++": true, "cc": true, "c++": true, "ld": true,
	"swift-frontend": true, "swift-demangle": true, "swift-format": true,
	"sourcekit-lsp": true, "clangd": true, "clang-format": true,
	"lipo": true, "libtool": true, "strip": true, "nm": true, "otool": true,
	"size": true, "objdump": true, "dsymutil": true, "dwarfdump": true,
	"llvm-cov": true, "llvm-profdata": true, "llvm-objdump": true,
	"llvm-nm": true, "llvm-size": true, "llvm-dwarfdump": true,
	"install_name_tool": true, "vtool": true, "codesign_allocate": true,
	"actool": true, "ibtool": true, "momc": true, "mapc": true,
	"xcstringstool": true, "metal": true, "metallib": true, "docc": true,
	"xctest": true, "xcresulttool": true, "xctrace": true,
	"simctl": true, "devicectl": true,
}

// xcrunRefusedTools are the developer tools that act on Apple's servers with
// the user's credentials: notarizing and uploading builds.
var xcrunRefusedTools = map[string]string{
	"notarytool":      "submits software to Apple's notary service",
	"altool":          "uploads builds to App Store Connect",
	"iTMSTransporter": "uploads builds to App Store Connect",
	"stapler":         "fetches and attaches notarization tickets from Apple",
}

// simctlReadOnly are the simctl subcommands that only report on simulators.
// The rest boot, create, erase, install into, and run code on them, which
// CoreSimulator does outside the OS sandbox (allow_devices).
var simctlReadOnly = []string{"list", "help", "getenv", "listapps", "appinfo", "get_app_container", "bootstatus"}

// simctlValueOptions are simctl's global options that take a value: --set
// picks the device set directory.
var simctlValueOptions = map[string]bool{"--set": true}

func validateXcrunArgs(s *Sandbox, args []*syntax.Word) error {
	lits := make([]string, len(args))
	for i, w := range args {
		text, ok := staticWordText(w)
		if !ok {
			// The tool xcrun runs and the options that locate it must be
			// known; its own arguments are checked by the tool's validator.
			if idx := xcrunCommandIndex(lits[:i]); idx < 0 {
				return fmt.Errorf("xcrun options and the tool it runs must be literal strings")
			}
			break
		}
		lits[i] = text
	}
	idx := xcrunCommandIndex(lits)
	if idx < 0 {
		return nil
	}
	tool := lits[idx]
	if strings.Contains(tool, "/") {
		return fmt.Errorf("xcrun %s is not allowed: xcrun runs developer tools by name", tool)
	}
	if why, refused := xcrunRefusedTools[tool]; refused {
		return fmt.Errorf("xcrun %s is not allowed: it %s; the user can run it outside the sandbox", tool, why)
	}
	allowDevices := s.getConfig().ProfileOption("xcode", "allow_devices")
	switch tool {
	case "simctl":
		if allowDevices {
			return nil
		}
		sub, _, err := findSubcommand("simctl", args[idx:], simctlValueOptions)
		if err != nil {
			return err
		}
		if sub != "" && !slices.Contains(simctlReadOnly, sub) {
			return fmt.Errorf("xcrun simctl %s is not allowed: simulators run outside the OS sandbox, so only %s are; the user can allow the rest with `lite-sandbox config profiles set xcode allow_devices true`", sub, strings.Join(simctlReadOnly, ", "))
		}
		return nil
	case "devicectl":
		if !allowDevices {
			return fmt.Errorf("xcrun devicectl is not allowed: it installs and runs code on connected devices; the user can allow it with `lite-sandbox config profiles set xcode allow_devices true`")
		}
		return nil
	}
	if xcrunToolchainTools[tool] && !s.commandWhitelisted(tool) {
		return nil
	}
	return validateSubCommand(s, args[idx:])
}

// unwrapXcrunArgs returns the tool command an `xcrun ...` invocation runs,
// using the same walker as validateXcrunArgs, so no_sandbox routing sees
// `xcrun clang` as clang.
func unwrapXcrunArgs(args []string) []string {
	return sliceWrappedCommand(args, xcrunCommandIndex(args))
}

// swiftRegistryGated are the `swift package-registry` subcommands that act on
// a registry with the user's credentials. Each is opened by a commands allow
// of its text ("swift package-registry publish").
var swiftRegistryGated = map[string]bool{"publish": true, "login": true}

func validateSwiftArgs(s *Sandbox, args []*syntax.Word) error {
	sub, idx, err := findSubcommand("swift", args, nil)
	if err != nil || sub != "package-registry" {
		return err
	}
	action, _, err := findSubcommand("swift package-registry", args[idx:], nil)
	if err != nil || !swiftRegistryGated[action] {
		return err
	}
	if s.extraAllowsTokens("swift", sub, action) {
		return nil
	}
	text := "swift package-registry " + action
	return fmt.Errorf("%s is not allowed: it acts on a package registry with the user's credentials; the user can allow it with `lite-sandbox config commands allow %q`", text, text)
}

// swiftPMSubcommands are the swift subcommands that run SwiftPM, which
// sandboxes the package manifest and plugins with sandbox-exec of its own.
var swiftPMSubcommands = map[string]bool{"build": true, "test": true, "run": true, "package": true}

// xcodeDisableNestedSandbox rewrites a swift or xcodebuild invocation (bare or
// under xcrun) that is about to run inside the OS sandbox worker so that it
// does not try to sandbox package manifests and plugins itself. macOS refuses
// to apply a sandbox inside a restrictive one ("sandbox-exec: sandbox_apply:
// Operation not permitted"), which fails every package resolution; the worker's
// sandbox already confines the manifest and plugins more than SwiftPM's would.
// Any other invocation is returned unchanged.
func xcodeDisableNestedSandbox(args []string) []string {
	if len(args) == 0 {
		return args
	}
	if args[0] == "xcrun" {
		idx := xcrunCommandIndex(args)
		if idx < 0 {
			return args
		}
		return append(slices.Clone(args[:idx]), xcodeDisableNestedSandbox(args[idx:])...)
	}
	switch args[0] {
	case "swift":
		// After the subcommand: `swift build --disable-sandbox`,
		// `swift package --disable-sandbox resolve`.
		if len(args) < 2 || !swiftPMSubcommands[args[1]] || slices.Contains(args, "--disable-sandbox") {
			return args
		}
		return slices.Concat(args[:2], []string{"--disable-sandbox"}, args[2:])
	case "xcodebuild":
		const opt = "-IDEPackageSupportDisableManifestSandbox=YES"
		if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-IDEPackageSupportDisableManifestSandbox=") }) {
			return args
		}
		return slices.Concat(args[:1], []string{opt}, args[1:])
	}
	return args
}
