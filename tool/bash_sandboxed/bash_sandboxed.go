package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	montygo "github.com/fugue-labs/monty-go"
	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
	"github.com/gartnera/lite-sandbox/os_sandbox"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// CommandFailedError is returned when a command passes validation and starts
// executing but exits with a non-zero status or fails during execution.
// Use errors.As to distinguish this from validation errors.
type CommandFailedError struct {
	Err    error
	Output string
}

func (e *CommandFailedError) Error() string {
	return fmt.Sprintf("command failed: %v\noutput: %s", e.Err, e.Output)
}

func (e *CommandFailedError) Unwrap() error {
	return e.Err
}

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu            sync.RWMutex
	cfg           *config.Config
	extraCommands map[string]bool
	// extraSubCommands holds per-command argument-prefix restrictions parsed
	// from extra_commands entries that contain a space (e.g. "pnpx prettier"
	// or "uv run pyright"). Each inner slice is one allowed prefix of
	// non-flag arguments; an invocation matches when its leading non-flag
	// args start with any of those sequences.
	extraSubCommands map[string][][]string
	// bareExtraCommands tracks commands that have a bare entry in extra_commands
	// (i.e., the entry has no subcommand restriction). These commands bypass
	// bash AST parsing and are executed directly with the real bash.
	bareExtraCommands map[string]bool
	// bareExtraScriptPaths is the set of absolute paths corresponding to
	// path-like bare entries in extra_commands (e.g., "./scripts/foo.sh"
	// resolved against workDir at config-update time). The ExecHandler uses
	// this so that invoking the same script from a different cwd (after a
	// `cd`) still hits the bare-extra bypass — interp tracks cwd in
	// HandlerContext, so the lookup is done with the post-`cd` directory.
	bareExtraScriptPaths map[string]bool
	// unsandboxed_commands entries are treated exactly like extra_commands for
	// validation (merged into the maps above so they are allowed and bare entries
	// skip AST parsing); the only difference is that matching invocations execute
	// directly on the host, bypassing the OS sandbox worker even when it is
	// enabled. The maps below mirror bareExtraCommands / bareExtraScriptPaths /
	// extraSubCommands but only for the unsandboxed subset, so routing is decided
	// per invocation (a subcommand-restricted entry like "git push" unsandboxes
	// only matching calls, not every use of the binary).
	unsandboxedBare            map[string]bool
	unsandboxedBareScriptPaths map[string]bool
	unsandboxedSub             map[string][][]string
	// deniedCommands is the parsed command deny list (denied_commands plus the
	// built-in self-protection entries), keyed by command base name. It is
	// checked before every other command gate — static, runtime, and wrapped —
	// and outranks extra_commands / unsandboxed_commands: a denied invocation
	// is denied however it was allowed. See denied_commands.go.
	deniedCommands map[string][]deniedEntry
	// askCommands is the parsed list of commands entries with
	// ask: true, keyed like deniedCommands: an invocation matching one
	// runs only in a call the user approved. See ask_commands.go.
	askCommands  map[string][]deniedEntry
	imdsEndpoint string
	// imdsRegion is the AWS region resolved for the brokered profile (from the
	// host-side ~/.aws config, which is masked inside the sandbox). It is injected
	// as AWS_REGION so regional AWS commands work without an explicit --region,
	// matching how the profile behaves outside the sandbox. Empty when no region
	// is configured for the profile or no IMDS server is running.
	imdsRegion string
	// imdsProfiles maps each brokered AWS profile (the default force_profile plus
	// any allowed_profiles) to its IMDS endpoint and region. It drives per-command
	// AWS_PROFILE routing in the exec handlers: a command that sets AWS_PROFILE to
	// a key here is repointed at that profile's server; one that selects a profile
	// absent from the map is denied. Empty (nil) when multi-profile routing is not
	// configured, in which case the exec handlers leave AWS_PROFILE untouched.
	imdsProfiles map[string]IMDSTarget
	// dockerHost is the DOCKER_HOST value (unix://… proxy socket) injected into
	// sandboxed commands when the docker proxy is running. dockerSocketDir is the
	// directory holding that socket, bind-mounted into the OS sandbox worker so
	// the worker can connect to it.
	dockerHost      string
	dockerSocketDir string
	// dockerMaskPaths are real daemon socket paths to mask inside the OS sandbox
	// worker (e.g. /var/run/docker.sock) so the proxy is the only reachable
	// daemon and cannot be bypassed.
	dockerMaskPaths []string
	// whitelistedCommands are the commands the config's commands list adds to
	// the whitelist (each enabled profile's, see config.Config.Effective). They
	// are validated like the built-in allowedCommands, unlike an allow.
	whitelistedCommands map[string]bool
	worker              *os_sandbox.Worker
	workerWorkDir       string
	// argValidators holds a reference to commandArgValidators so that
	// validateSubCommand can look up per-command validators at runtime
	// without creating a package-level initialization cycle.
	argValidators map[string]func(s *Sandbox, args []*syntax.Word) error
	// bg tracks background ("run_in_background") processes started via
	// ExecuteBackground, mirroring the Claude Code Bash/KillShell tools.
	bg *backgroundManager
	// audit receives every validation finding (see Sandbox.report) while the
	// config's audit flag is on; nil otherwise. Managed by UpdateConfig.
	audit *audit.Logger
	// monty is the compiled Python (monty) wasm runtime backing `python`/
	// `python3`, built on first use and shared across invocations — compiling
	// it costs ~2s, so a sandbox that never runs Python never pays for it.
	// It has its own mutex so that one-off compile does not hold the config
	// lock every other handler reads through. See python.go.
	montyMu sync.Mutex
	monty   *montygo.Runner
}

// NewSandbox creates a Sandbox with the default configuration: no extra
// commands, and only the default-on profiles.
func NewSandbox() *Sandbox {
	s := &Sandbox{
		cfg:           &config.Config{},
		argValidators: commandArgValidators,
		bg:            newBackgroundManager(),
	}
	// The built-in deny entries and default profiles hold before any config is
	// loaded, so a sandbox that never sees another UpdateConfig (or one whose
	// config failed to load) still refuses the self-protection commands.
	s.UpdateConfig((&config.Config{}).Effective(), "")
	return s
}

// UpdateConfig replaces the sandbox configuration with the provided config.
//
// cfg must be the effective config for workDir (config.LoadForDirectory, or
// Config.ForDirectory followed by Config.Effective): per-directory overrides,
// profiles, and the deprecated keys are all merged by the caller into the one
// Paths and one Commands list, and the sandbox — like every other subsystem —
// applies those lists verbatim, never having to know where an entry came
// from. workDir is still needed to anchor bare script paths and the
// OS-sandbox worker's working directory.
func (s *Sandbox) UpdateConfig(cfg *config.Config, workDir string) {
	m := make(map[string]bool, len(cfg.Commands))
	whitelisted := make(map[string]bool)
	sub := make(map[string][][]string)
	bare := make(map[string]bool)
	bareScripts := make(map[string]bool)
	unsandboxedBare := make(map[string]bool)
	unsandboxedBareScripts := make(map[string]bool)
	unsandboxedSub := make(map[string][][]string)
	// processEntry parses one whitespace-separated entry into the command maps.
	// A single token (e.g. "fvm") is a bare entry that allows the command with
	// any arguments; multiple tokens (e.g. "pnpx prettier", "uv run pyright")
	// restrict the command so that its leading non-flag arguments must match the
	// remaining tokens as a prefix. When fromUnsandboxed is set the same parse is
	// also recorded in the unsandboxed maps so matching invocations bypass the OS
	// sandbox worker.
	processEntry := func(c string, fromUnsandboxed bool) {
		fields := strings.Fields(c)
		if len(fields) == 0 {
			return
		}
		cmd := fields[0]
		m[cmd] = true
		if len(fields) == 1 {
			bare[cmd] = true
			if isScriptPath(cmd) && workDir != "" {
				bareScripts[absPath(cmd, workDir)] = true
			}
			if fromUnsandboxed {
				unsandboxedBare[cmd] = true
				if isScriptPath(cmd) && workDir != "" {
					unsandboxedBareScripts[absPath(cmd, workDir)] = true
				}
			}
		} else {
			sub[cmd] = append(sub[cmd], fields[1:])
			if fromUnsandboxed {
				unsandboxedSub[cmd] = append(unsandboxedSub[cmd], fields[1:])
			}
		}
	}
	// One pass over the commands list: a profile's allow of a bare name
	// whitelists the command (routed to the host when it is no_sandbox), any
	// other allow is an escape hatch (no_sandbox recorded with it), and
	// denials are collected by EffectiveDeniedCommands below.
	for _, e := range cfg.Commands {
		switch {
		case !e.Allows():
		case e.Whitelists():
			whitelisted[e.Text()] = true
			if e.NoSandbox {
				unsandboxedBare[e.Text()] = true
			}
		default:
			processEntry(e.Command, e.NoSandbox)
		}
	}
	s.mu.Lock()
	// The OS sandbox toggle and the AWS credential mask are read straight off
	// s.cfg wherever they are needed, so only the previous value of the toggle
	// has to be captured here (for the enable-transition log below).
	prevOSSandbox := s.cfg.OSSandboxEnabled()
	s.cfg = cfg
	// Auditing follows the config: open the logger when it turns on, drop it
	// when it turns off. The path is resolved once; LITE_SANDBOX_AUDIT_LOG
	// overrides it (see audit.DefaultPath).
	if cfg.AuditEnabled() {
		if s.audit == nil {
			if p, err := audit.DefaultPath(); err == nil {
				s.audit = audit.New(p, 0)
			} else {
				slog.Warn("audit enabled but log path unavailable", "error", err)
			}
		}
	} else {
		s.audit = nil
	}
	s.extraCommands = m
	s.whitelistedCommands = whitelisted
	s.extraSubCommands = sub
	s.bareExtraCommands = bare
	s.bareExtraScriptPaths = bareScripts
	s.unsandboxedBare = unsandboxedBare
	s.unsandboxedBareScriptPaths = unsandboxedBareScripts
	s.unsandboxedSub = unsandboxedSub
	s.deniedCommands = parseDeniedCommands(cfg.EffectiveDeniedCommands())
	s.askCommands = parseDeniedCommands(cfg.AskCommandList())

	// Store worker config for lazy start / restart.
	s.workerWorkDir = workDir

	// Close any live worker on every config update: the AWS credential mask,
	// writable paths, worktree-parent grant, profile paths, and more are all
	// baked into the worker's mount setup / SBPL profile at start time, so a
	// stale worker would keep enforcing the old policy. Rather than tracking
	// which of those inputs changed, recycle unconditionally — UpdateConfig only
	// fires when the config actually changed, and the next command lazily starts
	// a replacement with the new settings.
	if s.worker != nil {
		slog.Info("closing existing worker after config update")
		s.worker.Close()
		s.worker = nil
	}
	if cfg.OSSandboxEnabled() && !prevOSSandbox {
		slog.Info("enabling OS sandbox", "block_aws_credentials", cfg.AWS.UsesIMDS())
	}
	s.mu.Unlock()
}

// getConfig returns a snapshot of the current config.
func (s *Sandbox) getConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// osSandboxEnabled reports whether the OS sandbox (bwrap/sandbox-exec worker)
// is currently active. Used to gate process-control commands that are only
// safe when execution is contained.
func (s *Sandbox) osSandboxEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.OSSandboxEnabled()
}

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// getExtraSubCommands returns the per-command argument-prefix restriction map.
// A nil entry for a command means no restriction (any args allowed).
// A non-nil entry means the invocation's leading non-flag args must match
// one of the recorded token sequences as a prefix.
func (s *Sandbox) getExtraSubCommands() map[string][][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraSubCommands
}

// SetIMDSEndpoint sets the IMDS endpoint URL for AWS credential fetching.
func (s *Sandbox) SetIMDSEndpoint(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imdsEndpoint = endpoint
}

// SetIMDSRegion sets (or clears, with "") the AWS region injected as AWS_REGION
// for the brokered profile. See the imdsRegion field.
func (s *Sandbox) SetIMDSRegion(region string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imdsRegion = region
}

// IMDSTarget is the brokered IMDS endpoint and resolved region for one AWS
// profile. Region may be "" when the profile configures none.
type IMDSTarget struct {
	Endpoint string
	Region   string
}

// SetIMDSProfiles installs (or clears, with nil) the per-profile IMDS routing
// table used for AWS_PROFILE selection. See the imdsProfiles field.
func (s *Sandbox) SetIMDSProfiles(profiles map[string]IMDSTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imdsProfiles = profiles
}

// routeAWSProfile applies per-command AWS_PROFILE selection to a command's
// environment map. When the command explicitly selects a profile (via
// AWS_PROFILE or AWS_DEFAULT_PROFILE — ambient host values are stripped from the
// base env in IMDS mode, so a value present here was set by the command), the
// profile must be one of the brokered profiles: the selector vars are removed
// (so the SDK uses the IMDS endpoint instead of reading the masked ~/.aws) and
// the endpoint/region are repointed at that profile's server. Selecting a
// profile outside the brokered set is denied. It is a no-op when the command
// selects no profile or when multi-profile routing is not configured.
func (s *Sandbox) routeAWSProfile(env map[string]string) error {
	profile := env["AWS_PROFILE"]
	if profile == "" {
		profile = env["AWS_DEFAULT_PROFILE"]
	}
	if profile == "" {
		return nil
	}

	s.mu.RLock()
	target, ok := s.imdsProfiles[profile]
	active := len(s.imdsProfiles) > 0
	defaultRegion := s.imdsRegion
	var allowed []string
	if active && !ok {
		allowed = make([]string, 0, len(s.imdsProfiles))
		for p := range s.imdsProfiles {
			allowed = append(allowed, p)
		}
	}
	s.mu.RUnlock()

	if !active {
		// Multi-profile routing not configured (e.g. raw-credentials mode); leave
		// the command's AWS_PROFILE untouched.
		return nil
	}
	if !ok {
		sort.Strings(allowed)
		return fmt.Errorf("AWS profile %q is not in allowed_profiles (%s)", profile, strings.Join(allowed, ", "))
	}

	delete(env, "AWS_PROFILE")
	delete(env, "AWS_DEFAULT_PROFILE")
	if target.Endpoint != "" {
		env["AWS_EC2_METADATA_SERVICE_ENDPOINT"] = target.Endpoint
	}
	// Preserve an AWS_REGION the command set explicitly (one that differs from the
	// default profile's base-injected region), mirroring the base-env rule that an
	// explicit AWS_REGION wins. Otherwise apply the selected profile's region, or
	// drop the inherited default region when the profile configures none so the
	// command doesn't silently run in the wrong one (pass --region to be explicit).
	if cur, has := env["AWS_REGION"]; has && cur != defaultRegion {
		// Explicit per-command region: leave AWS_REGION/AWS_DEFAULT_REGION as-is.
	} else if target.Region != "" {
		env["AWS_REGION"] = target.Region
		env["AWS_DEFAULT_REGION"] = target.Region
	} else {
		delete(env, "AWS_REGION")
		delete(env, "AWS_DEFAULT_REGION")
	}
	return nil
}

// maybeListProfiles intercepts `aws configure list-profiles` when brokered IMDS
// mode is active. The real command reads ~/.aws, which is masked in the sandbox,
// so it would return nothing; instead we print the brokered profile names (the
// default force_profile plus any allowed_profiles), one per line like the CLI,
// so an agent can discover which profiles it may select via AWS_PROFILE. Returns
// handled=false (letting the command run normally) when it is not this
// invocation or when routing is not configured. When routing is active the aws
// command is allowed, so intercepting before the whitelist check is safe.
func (s *Sandbox) maybeListProfiles(ctx context.Context, args []string) (handled bool, err error) {
	if len(args) != 3 || args[0] != "aws" || args[1] != "configure" || args[2] != "list-profiles" {
		return false, nil
	}
	s.mu.RLock()
	profiles := make([]string, 0, len(s.imdsProfiles))
	for p := range s.imdsProfiles {
		profiles = append(profiles, p)
	}
	s.mu.RUnlock()
	if len(profiles) == 0 {
		return false, nil // IMDS not active; let the real command run.
	}
	sort.Strings(profiles)
	hc := interp.HandlerCtx(ctx)
	for _, p := range profiles {
		fmt.Fprintln(hc.Stdout, p)
	}
	return true, nil
}

// awsRegionToInject returns the region to inject (as both AWS_REGION and
// AWS_DEFAULT_REGION) for brokered IMDS mode, or "" when injection should be
// skipped: no region is configured for the profile, or the caller's environment
// already sets AWS_REGION/AWS_DEFAULT_REGION (an explicit choice we must not
// override). Both vars are set because tooling is split on which it honors (the
// AWS CLI v2 and Go SDK prefer AWS_REGION; older boto-based tools read only
// AWS_DEFAULT_REGION). A command-level assignment (AWS_REGION=… aws …) or an
// explicit --region flag still wins, since those are applied over this base
// environment.
func awsRegionToInject(region string) string {
	if region == "" {
		return ""
	}
	if _, ok := os.LookupEnv("AWS_REGION"); ok {
		return ""
	}
	if _, ok := os.LookupEnv("AWS_DEFAULT_REGION"); ok {
		return ""
	}
	return region
}

// awsBaseEnv applies the default brokered-IMDS AWS environment to a base env
// slice: it strips any inherited AWS_PROFILE/AWS_DEFAULT_PROFILE (which can't
// work — ~/.aws is masked — and would otherwise trigger per-command routing for
// commands that never meant to select a profile), then injects the default
// profile's IMDS endpoint and region. Per-command AWS_PROFILE selection (routed
// in the exec handlers) still works because it is set on the command itself, not
// inherited here. A no-op when IMDS is not active (endpoint == "").
func awsBaseEnv(base []string, imdsEndpoint, imdsRegion string) []string {
	if imdsEndpoint == "" {
		return base
	}
	env := make([]string, 0, len(base)+3)
	for _, kv := range base {
		if strings.HasPrefix(kv, "AWS_PROFILE=") || strings.HasPrefix(kv, "AWS_DEFAULT_PROFILE=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "AWS_EC2_METADATA_SERVICE_ENDPOINT="+imdsEndpoint)
	if r := awsRegionToInject(imdsRegion); r != "" {
		env = append(env, "AWS_REGION="+r, "AWS_DEFAULT_REGION="+r)
	}
	return env
}

// envSliceToMap converts a "KEY=VALUE" environment slice into a map, dropping
// entries with no "=" and letting later entries win — the same precedence
// os/exec applies when it de-duplicates a command's environment.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// DockerHostConfigured reports whether a docker proxy endpoint has been wired
// in via SetDockerHost. Command gating uses this so the "docker" command is
// only allowed when the filtering proxy is actually running and DOCKER_HOST
// will be injected — otherwise a command would fall back to the real daemon
// socket, bypassing the proxy.
func (s *Sandbox) DockerHostConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dockerHost != ""
}

// SetDockerHost sets the DOCKER_HOST value (the docker proxy socket) and the
// directory holding that socket. The directory is bind-mounted into the OS
// sandbox worker so sandboxed commands can reach the proxy, and maskSockets are
// the real daemon socket paths masked inside the worker so the proxy cannot be
// bypassed (e.g. via `unset DOCKER_HOST`). Passing an empty host disables
// docker access for subsequent commands.
func (s *Sandbox) SetDockerHost(host, socketDir string, maskSockets ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dockerHost = host
	s.dockerSocketDir = socketDir
	s.dockerMaskPaths = dedupeMaskPaths(maskSockets)
}

// dedupeMaskPaths returns the non-empty, de-duplicated socket paths to mask,
// always including the conventional /var/run/docker.sock so a sandboxed command
// cannot reach the default socket even when a custom upstream is configured.
func dedupeMaskPaths(sockets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range sockets {
		add(p)
	}
	add(config.DefaultDockerSocket)
	return out
}

// ConfigReadPaths returns the configured readable paths (with ~ expanded):
// the read grants of the paths list, a profile's included.
func (s *Sandbox) ConfigReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedReadablePaths()
}

// ConfigWritePaths returns the configured writable paths (with ~ expanded).
func (s *Sandbox) ConfigWritePaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedWritablePaths()
}

// ConfigInternalReadPaths returns the configured internal readable paths
// (with ~ expanded). These apply only to the OS sandbox worker: they are never
// folded into the AST/interpreter read paths, so the agent cannot read them
// directly and Deno's injected --allow-read never includes them.
func (s *Sandbox) ConfigInternalReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedInternalReadablePaths()
}

// ConfigInternalWritePaths returns the configured internal writable paths
// (with ~ expanded). These apply only to the OS sandbox worker: they are never
// folded into the AST/interpreter write paths, so the agent cannot write them
// directly and Deno's injected --allow-write never includes them.
func (s *Sandbox) ConfigInternalWritePaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedInternalWritablePaths()
}

// Close shuts down the sandbox, killing any background processes and closing
// the worker if running.
func (s *Sandbox) Close() error {
	if s.bg != nil {
		s.bg.killAll()
		s.bg.removeOutputDir()
	}

	// The monty runtime has its own lock (see python.go), so release it
	// independently of the config lock taken below.
	s.montyMu.Lock()
	if s.monty != nil {
		s.monty.Close()
		s.monty = nil
	}
	s.montyMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.worker != nil {
		return s.worker.Close()
	}
	return nil
}

// ParseBash parses a command string as bash and returns the AST.
func ParseBash(command string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse bash: %w", err)
	}
	return f, nil
}

// stripShebang removes a leading "#!" interpreter line from a script's source,
// which the bash parser would otherwise treat as a comment. A file whose only
// line is the shebang (no trailing newline) becomes empty: an interpreter line
// carries no shell statements, so dropping it never discards executable code.
func stripShebang(script string) string {
	if !strings.HasPrefix(script, "#!") {
		return script
	}
	if idx := strings.IndexByte(script, '\n'); idx >= 0 {
		return script[idx+1:]
	}
	return ""
}

// blockedEnvVars lists environment variables that cannot be assigned in sandboxed commands.
// PATH is inherited but cannot be mutated (prevents command whitelist bypass).
// Others prevent shared library injection, auto-sourced scripts, and unexpected behavior.
var blockedEnvVars = map[string]string{
	"PATH":            "mutating PATH could bypass the command whitelist",
	"LD_PRELOAD":      "shared library injection",
	"LD_LIBRARY_PATH": "shared library injection",
	"BASH_ENV":        "auto-sourced script injection",
	"ENV":             "auto-sourced script injection",
	"CDPATH":          "unexpected directory resolution",
	"PROMPT_COMMAND":  "arbitrary command execution",
	// Option injection into the archive tools, past their argument validators.
	"TAR_OPTIONS": "injects tar options",
	"TAPE":        "selects tar's default archive, which may be remote",
	"UNZIP":       "injects unzip options",
	"UNZIPOPT":    "injects unzip options",
	"ZIPOPT":      "injects zip options",
	"ZIP":         "injects zip options",
}

// validateAssigns checks that none of the assignments target a blocked environment variable.
func validateAssigns(assigns []*syntax.Assign) error {
	for _, a := range assigns {
		if a.Name == nil {
			continue
		}
		if err := blockedEnvVarError(a.Name.Value); err != nil {
			return err
		}
	}
	return nil
}

// blockedEnvVarError returns the error for assigning a blocked environment
// variable, or nil when name may be set.
func blockedEnvVarError(name string) error {
	if reason, blocked := blockedEnvVars[name]; blocked {
		return fmt.Errorf("setting %s is not allowed: %s", name, reason)
	}
	return nil
}

// collectDeclaredFunctions walks the AST and collects function names from:
// 1. FuncDecl nodes (inline function declarations)
// 2. source/. commands with literal file paths (read and extract FuncDecl names)
// This allows validate() to permit calls to user-defined functions.
func collectDeclaredFunctions(f *syntax.File, workDir string) map[string]bool {
	funcs := make(map[string]bool)
	syntax.Walk(f, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.FuncDecl:
			funcs[n.Name.Value] = true
		case *syntax.CallExpr:
			if len(n.Args) >= 2 {
				cmdName := n.Args[0].Lit()
				if cmdName == "source" || cmdName == "." {
					filePath := n.Args[1].Lit()
					if filePath != "" && workDir != "" {
						extractFunctionsFromFile(filePath, workDir, funcs)
					}
				}
			}
		}
		return true
	})
	return funcs
}

// extractFunctionsFromFile reads a shell script file and adds any function
// declarations to the funcs set. Errors are silently ignored (fail-open).
func extractFunctionsFromFile(filePath, workDir string, funcs map[string]bool) {
	path := absPath(filePath, workDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	sf, err := ParseBash(stripShebang(string(data)))
	if err != nil {
		return
	}
	syntax.Walk(sf, func(node syntax.Node) bool {
		if fd, ok := node.(*syntax.FuncDecl); ok {
			funcs[fd.Name.Value] = true
		}
		return true
	})
}

// validate walks the parsed AST and enforces:
// 1. All commands must be in the allowedCommands whitelist, extra commands, or declared functions
// 2. Redirections must pass validateRedirect (safe subset only)
// 3. No process substitutions are permitted
// 4. Per-command argument validators (e.g., blocking find -exec)
// 5. Blocked environment variable assignments (PATH, LD_PRELOAD, etc.)
func (s *Sandbox) validate(f *syntax.File) error {
	return s.validateWithFunctionsCtx(context.Background(), f, nil)
}

// validateWithWorkDir validates the AST, also collecting function declarations
// from inline FuncDecl nodes and sourced files to allow calls to user-defined functions.
func (s *Sandbox) validateWithWorkDir(f *syntax.File, workDir string) error {
	return s.validateWithWorkDirCtx(context.Background(), f, workDir)
}

// validateWithWorkDirCtx is validateWithWorkDir with the audit scope on ctx.
func (s *Sandbox) validateWithWorkDirCtx(ctx context.Context, f *syntax.File, workDir string) error {
	funcs := collectDeclaredFunctions(f, workDir)
	return s.validateWithFunctionsCtx(ctx, f, funcs)
}

// validateFile runs the full static preflight over a parsed AST: the command /
// redirection / assignment validation (workDir-aware, so declared and sourced
// functions count as allowed commands), then the argument and redirection path
// boundary checks. It is the single entry point used by every site that
// statically validates a parsed script — Execute, ExecuteBackground,
// ValidateCommand, validateScriptFile, executeBash and executeScript — so the
// three passes always run in the same order with the same inputs. Callers wrap
// the returned error with their own context prefix.
//
// The allowed-path sets are symlink-resolved once here and shared by both path
// passes rather than being resolved separately by each.
func (s *Sandbox) validateFile(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	return s.validateFileCtx(context.Background(), f, workDir, readAllowedPaths, writeAllowedPaths)
}

// validateFileCtx is validateFile with the audit scope on ctx. Every check's
// result goes through Sandbox.report, which audits it and decides — by rule
// and mode — whether it is enforced.
func (s *Sandbox) validateFileCtx(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	if err := s.validateWithWorkDirCtx(ctx, f, workDir); err != nil {
		return err
	}
	if s.getConfig().RejectsRedundantCd() {
		if err := s.report(ctx, layerStatic, ruleRedundantCd, validateNoRedundantCd(f, workDir)); err != nil {
			return err
		}
	}
	sets := resolvePathSets(readAllowedPaths, writeAllowedPaths)
	if err := s.report(ctx, layerStatic, rulePathBoundary, validatePathsResolved(f, workDir, sets)); err != nil {
		return err
	}
	return s.report(ctx, layerStatic, rulePathBoundary, validateRedirectPathsResolved(f, workDir, sets))
}

// validateNoRedundantCd rejects a `cd <absolute-path>` whose target resolves to
// the working directory itself. Agents habitually prefix commands with
// `cd /abs/path/to/repo && ...` even though the sandbox already runs there, so
// the cd is pure noise; surfacing it as an error prompts the agent to drop it.
//
// The match is deliberately narrow — only a `cd` with a single literal argument
// that is an absolute path resolving exactly to workDir. `cd .`, a relative
// path, a dynamic target (`cd "$PWD"`), a cd carrying flags, or a cd into a
// subdirectory are all left alone: those are either legitimate or not the
// redundant form agents emit.
func validateNoRedundantCd(f *syntax.File, workDir string) error {
	if workDir == "" {
		return nil
	}
	resolvedWorkDir := ResolvePath(workDir, workDir)
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		ce, ok := node.(*syntax.CallExpr)
		// Only `cd <arg>` with exactly one argument; a cd with flags (e.g.
		// `cd -P /path`) or no argument is not the redundant prefix we target.
		if !ok || len(ce.Args) != 2 || ce.Args[0].Lit() != "cd" {
			return true
		}
		arg := ce.Args[1].Lit()
		if arg == "" || !filepath.IsAbs(arg) {
			return true
		}
		if ResolvePath(arg, workDir) == resolvedWorkDir {
			validationErr = fmt.Errorf("unneeded cd: cwd is already %s (drop the leading %q)", resolvedWorkDir, "cd "+arg)
			return false
		}
		return true
	})
	return validationErr
}

// validateWithFunctions is the core validation logic, optionally accepting
// a set of declared function names to allow in addition to the command whitelist.
func (s *Sandbox) validateWithFunctions(f *syntax.File, declaredFuncs map[string]bool) error {
	return s.validateWithFunctionsCtx(context.Background(), f, declaredFuncs)
}

// validateWithFunctionsCtx is validateWithFunctions with the audit scope on
// ctx. Each finding is routed through Sandbox.report: an enforced finding
// stops the walk and is returned; an advisory one (a rule the current mode
// does not enforce) is audited and the walk continues, so in denylist mode an
// unlisted command still has its arguments and paths checked.
func (s *Sandbox) validateWithFunctionsCtx(ctx context.Context, f *syntax.File, declaredFuncs map[string]bool) error {
	extra := s.getExtraCommands()
	extraSub := s.getExtraSubCommands()
	bare := s.getBareExtraCommands()
	var validationErr error
	// fail records an enforced finding and stops the walk.
	fail := func(layer string, fallback rule, err error) bool {
		if err := s.report(ctx, layer, fallback, err); err != nil {
			validationErr = err
			return true
		}
		return false
	}
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if fail(layerStatic, ruleStructural, validateRedirect(r)) {
					return false
				}
			}
		case *syntax.CallExpr:
			if fail(layerStatic, ruleStructural, validateAssigns(n.Assigns)) {
				return false
			}
			if len(n.Args) > 0 {
				// Word.Lit() is "" when the command name is not a plain
				// literal (a variable, quoted string, or substitution), i.e.
				// when it cannot be statically determined.
				cmdName := n.Args[0].Lit()
				// A dynamically-named command (e.g. "$CMD ...", "$(...)") has no
				// literal name to resolve against the whitelist or a per-command
				// validator here, so static analysis cannot check it. Rather than
				// rejecting it outright, defer to the runtime handlers, which see
				// the fully expanded argv: the CallHandler enforces the whitelist
				// for builtins and the ExecHandler enforces it (and re-runs the
				// per-command argument validators) for external commands. Keep
				// walking so nested commands in the arguments (command/process
				// substitutions) are still validated statically.
				if cmdName != "" {
					// The deny list comes first and is checked even for commands
					// extra_commands allows: it is the one gate those entries do
					// not lift. A dynamically-named command reaches the runtime
					// handlers, which re-check it against the expanded argv.
					if entry, denied := s.deniedCommandWords(cmdName, n.Args[1:]); denied {
						if fail(layerStatic, ruleCommandDenylist, commandDeniedError(cmdName, entry)) {
							return false
						}
					}
					// A prompted invocation runs only in an approved call, and
					// once approved counts as whitelisted.
					askApproved, askErr := s.checkAsk(ctx, cmdName, wordLits(n.Args[1:]))
					if fail(layerStatic, ruleCommandAsk, askErr) {
						return false
					}
					// Check whether this command is allowed via extra_commands.
					// Bare entries (no subcommand restriction) always match.
					// Restricted entries (e.g. "pnpx prettier") only match when the
					// first non-flag argument matches the restriction.
					inExtra := extra[cmdName] && (bare[cmdName] || extraSubCommandMatches(extraSub, cmdName, n.Args))
					// Process-control commands (kill, pkill) are allowed only when the
					// OS sandbox is active, where they are contained to sandbox-spawned
					// processes.
					osOnly := osSandboxOnlyCommands[cmdName] && s.osSandboxEnabled()
					if !s.commandWhitelisted(cmdName) && !inExtra && !declaredFuncs[cmdName] && !osOnly && !askApproved {
						// Whitelist and local-binary gates: allowlist-only rules, so
						// in denylist/open mode this records the finding and moves on.
						var gateErr error
						if isScriptPath(cmdName) {
							if !s.getConfig().LocalBinaryExecution.IsEnabled() {
								gateErr = directExecutionNotAllowed(cmdName)
							}
						} else {
							gateErr = commandNotAllowed(cmdName)
						}
						if fail(layerStatic, ruleCommandWhitelist, gateErr) {
							return false
						}
					}
					// Skip per-command validators for commands allowed via extra_commands —
					// the user has explicitly opted in to those commands.
					if !inExtra {
						// The command's own argument validator applies in every
						// enforcing mode.
						if validator, ok := commandArgValidators[cmdName]; ok {
							if fail(layerStatic, ruleArgValidator, validator(s, n.Args)) {
								return false
							}
						}
					}
				}
			}
		case *syntax.DeclClause:
			if fail(layerStatic, ruleStructural, validateAssigns(n.Args)) {
				return false
			}
		case *syntax.ProcSubst:
			// Allowed: the walker recurses into the substitution's statements,
			// so all commands inside are validated against the whitelist.
		case *syntax.CoprocClause:
			if fail(layerStatic, ruleStructural, fmt.Errorf("coprocesses are not allowed")) {
				return false
			}
		}
		return true
	})
	return validationErr
}

// extraSubCommandMatches reports whether a command invocation satisfies any
// subcommand restriction registered for cmdName in extraSub.
//
//   - If extraSub has no entry for cmdName, the bare command is in extra_commands
//     with no restriction, so it always matches (returns true).
//   - If extraSub has an entry, the invocation's leading non-flag arguments
//     must match one of the recorded token sequences as a prefix.
//   - If the invocation has no non-flag arguments at all, it is allowed
//     (typically prints help).
//
// The prefix match itself is argsMatchSubCommand, shared with the expanded-argv
// path: wordLits yields "" for non-literal words, which that matcher skips
// exactly as it skips empty expanded arguments.
func extraSubCommandMatches(extraSub map[string][][]string, cmdName string, args []*syntax.Word) bool {
	allowed, hasRestriction := extraSub[cmdName]
	if !hasRestriction {
		return true // bare "cmd" entry, no subcommand restriction
	}
	return argsMatchSubCommand(allowed, wordLits(args[1:]))
}

// ValidateCommand parses and validates a bash command without executing it.
// It mirrors the validation in Execute() but skips execution.
// workDir is the working directory for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
func (s *Sandbox) ValidateCommand(command string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	return s.ValidateCommandContext(context.Background(), command, workDir, readAllowedPaths, writeAllowedPaths)
}

// ValidateCommandContext is ValidateCommand under ctx, which may carry the
// user's approval (WithApproval) for the command's prompted invocations.
func (s *Sandbox) ValidateCommandContext(ctx context.Context, command string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	// ValidateCommand backs the PreToolUse hook, so its findings are
	// attributed to the hook in the audit log.
	ctx = withAuditScope(ctx, command, workDir, "hook")
	// Bare extra_commands entries bypass AST parsing; treat as valid, once
	// any command needing approval in them has it.
	if s.isExtraCommandInvocation(command) {
		return s.checkRawAsk(ctx, command)
	}
	f, err := ParseBash(command)
	if err != nil {
		return err
	}
	if err := s.validateFileCtx(ctx, f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return err
	}
	if err := s.validateScriptContents(f, workDir, readAllowedPaths, writeAllowedPaths, 0); err != nil {
		return err
	}
	return nil
}

// validateScriptContents walks the AST looking for script invocations
// (direct script paths like ./script.sh or bash/sh with a script file),
// reads the script contents, and validates them recursively. This catches
// cases where a script file contains blocked commands that would otherwise
// only fail once reached at runtime, rejecting the command up front instead.
// Errors reading files are silently ignored (fail-open) since the file may
// not exist yet at validation time.
func (s *Sandbox) validateScriptContents(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	if depth >= maxBashDepth {
		return fmt.Errorf("script nesting depth exceeded (max %d)", maxBashDepth)
	}

	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		ce, ok := node.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}

		cmdName := ce.Args[0].Lit()
		if cmdName == "" {
			return true
		}

		switch {
		case isScriptPath(cmdName):
			validationErr = s.validateScriptFile(cmdName, workDir, readAllowedPaths, writeAllowedPaths, depth)
		case cmdName == "bash" || cmdName == "sh":
			validationErr = s.validateBashScriptArg(ce.Args, workDir, readAllowedPaths, writeAllowedPaths, depth)
		case cmdName == "source" || cmdName == ".":
			validationErr = s.validateSourceFileArg(ce.Args, workDir, readAllowedPaths, writeAllowedPaths, depth)
		}

		return validationErr == nil
	})
	return validationErr
}

// validateScriptFile reads a script file path, parses and validates its contents.
func (s *Sandbox) validateScriptFile(scriptPath, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	path := absPath(scriptPath, workDir)
	// Bare extra_commands script entries are an explicit trust opt-in; skip
	// body validation regardless of how the script is reached (directly,
	// `bash <script>`, or `source <script>`). This mirrors the runtime
	// ExecHandler bypass so static preflight does not reject a script the user
	// deliberately opted out of validation for.
	if s.getBareExtraCommands()[scriptPath] || s.getBareExtraScriptPaths()[path] {
		return nil
	}
	if isBinaryExecutable(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // fail-open: file may not exist at validation time
	}
	// A script for another interpreter (#!/usr/bin/env python3) is not bash;
	// parsing it as bash would flag its keywords as unknown commands. The
	// runtime ExecHandler gates the interpreter itself instead.
	if interp := scriptInterpreter(string(data)); interp != "" && !isShellInterpreter(interp) {
		return nil
	}
	sf, err := ParseBash(stripShebang(string(data)))
	if err != nil {
		return nil // fail-open: unparseable scripts handled at runtime
	}
	if err := s.validateFile(sf, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return fmt.Errorf("script %s: %w", scriptPath, err)
	}
	return s.validateScriptContents(sf, workDir, readAllowedPaths, writeAllowedPaths, depth+1)
}

// validateBashScriptArg extracts the script file argument from bash/sh args
// (when not using -c) and validates the script contents.
func (s *Sandbox) validateBashScriptArg(args []*syntax.Word, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	i := 1
	foundC := false
	for i < len(args) {
		text := wordText(args[i])
		if text == "" {
			i++
			continue
		}
		if text == "-c" {
			foundC = true
			break
		}
		if text == "-o" {
			i += 2
			continue
		}
		// Combined short flags
		if len(text) > 1 && text[0] == '-' && text[1] != '-' {
			for _, ch := range text[1:] {
				if string(ch) == "c" {
					foundC = true
				}
			}
			if foundC {
				break
			}
			i++
			continue
		}
		// Known flags
		if strings.HasPrefix(text, "-") || strings.HasPrefix(text, "+") {
			i++
			continue
		}
		// First non-flag argument is the script file
		if !foundC {
			return s.validateScriptFile(text, workDir, readAllowedPaths, writeAllowedPaths, depth)
		}
		i++
	}
	return nil
}

// validateSourceFileArg extracts the file argument from source/. args
// and validates the file contents recursively.
func (s *Sandbox) validateSourceFileArg(args []*syntax.Word, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	if len(args) < 2 {
		return nil
	}
	filePath := wordText(args[1])
	if filePath == "" {
		return nil // dynamic path, can't validate statically
	}
	return s.validateScriptFile(filePath, workDir, readAllowedPaths, writeAllowedPaths, depth)
}

// firstCommandWord extracts the first word from a command string, stopping at
// the first whitespace or shell metacharacter. Returns empty string if the
// command starts with a metacharacter or is empty.
func firstCommandWord(s string) string {
	s = strings.TrimLeft(s, " \t\n")
	for i, ch := range s {
		switch ch {
		case ' ', '\t', '\n', '|', '&', ';', '(', ')', '<', '>', '`', '$', '#', '!':
			return s[:i]
		}
	}
	return s
}

// getBareExtraCommands returns a snapshot of the bare (unrestricted) extra commands.
func (s *Sandbox) getBareExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bareExtraCommands
}

// getBareExtraScriptPaths returns a snapshot of the absolute paths of
// path-like bare extra commands (entries like "./scripts/foo.sh" resolved
// against the sandbox's workDir at config-update time). The ExecHandler uses
// this to recognize the same script invoked from a different cwd, since
// interp's HandlerContext tracks the post-`cd` directory.
func (s *Sandbox) getBareExtraScriptPaths() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bareExtraScriptPaths
}

// isExtraCommandInvocation reports whether the command string should bypass
// bash AST parsing because its leading command is a bare extra_commands entry
// (i.e., added without a subcommand restriction).
//
// A command whose name appears anywhere in the deny list never takes the
// bypass, even with a bare extra_commands entry: the raw path has no parsed
// argv to match entries against, so the invocation is routed through normal
// parsing instead, where deniedCommandWords decides it precisely. An
// invocation that turns out not to match an entry still runs — just parsed and
// validated rather than handed to the real bash.
func (s *Sandbox) isExtraCommandInvocation(command string) bool {
	word := firstCommandWord(command)
	if word == "" {
		return false
	}
	return s.getBareExtraCommands()[word] && !s.deniedCommandName(word)
}

// isUnsandboxedInvocation reports whether the command string's leading command
// is a bare unsandboxed_commands entry, meaning it must run directly on the host
// (bypassing the OS sandbox worker). Used by the top-level raw-execution path,
// which only ever handles bare entries.
func (s *Sandbox) isUnsandboxedInvocation(command string) bool {
	word := firstCommandWord(command)
	if word == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unsandboxedBare[word]
}

// execIsUnsandboxed reports whether an exec invocation (from the interpreter's
// ExecHandler) should run on the host instead of the OS sandbox worker because
// it matches an unsandboxed_commands entry. Bare script-path entries are matched
// by absolute path (resolved against the post-`cd` directory tracked in the
// interp HandlerContext) so a script survives a working-directory change.
// Subcommand-restricted entries match only when the invocation's leading
// arguments match the restriction, so e.g. "git push" unsandboxes only pushes
// and not every git command.
func (s *Sandbox) execIsUnsandboxed(ctx context.Context, args []string) bool {
	if len(args) == 0 {
		return false
	}
	// Peer through wrapper commands (timeout, env, xargs) so the wrapped
	// command's unsandboxed status governs routing, mirroring how the arg
	// validators recurse into these wrappers. This lets e.g. `timeout 60 mycmd`
	// run on the host when mycmd is an unsandboxed_commands entry.
	args = unwrapWrapperArgs(args)
	if len(args) == 0 {
		return false
	}
	cmdName := args[0]
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.unsandboxedBare[cmdName] {
		return true
	}
	if len(s.unsandboxedBareScriptPaths) > 0 && isScriptPath(cmdName) {
		hc := interp.HandlerCtx(ctx)
		if s.unsandboxedBareScriptPaths[absPath(cmdName, hc.Dir)] {
			return true
		}
	}
	if restrictions, ok := s.unsandboxedSub[cmdName]; ok {
		return argsMatchSubCommand(restrictions, args[1:])
	}
	return false
}

// argsMatchSubCommand reports whether the arguments (already stripped of the
// command name) satisfy any recorded subcommand-prefix restriction. It backs
// both the expanded-argv path (execIsUnsandboxed, plain strings from the
// ExecHandler) and the AST path (extraSubCommandMatches, via wordLits). An
// invocation with no non-flag arguments matches (typically prints help).
func argsMatchSubCommand(restrictions [][]string, args []string) bool {
	nonFlag := nonFlagArgs(args)
	if len(nonFlag) == 0 {
		return true
	}
	for _, seq := range restrictions {
		if hasTokenPrefix(nonFlag, seq) {
			return true
		}
	}
	return false
}

// dispatchExec runs an exec invocation inside the OS sandbox worker or directly
// on the host. Commands go to the worker when the OS sandbox is enabled and the
// command is not an unsandboxed_commands entry. Host execution injects the
// docker filtering proxy's DOCKER_HOST only for non-unsandboxed commands, so
// unsandboxed ones reach the real docker daemon (or the host's own DOCKER_HOST).
func (s *Sandbox) dispatchExec(ctx context.Context, args []string, useOSSandbox bool) error {
	unsandboxed := s.execIsUnsandboxed(ctx, args)
	if useOSSandbox && !unsandboxed {
		return s.execInWorker(ctx, args)
	}
	return s.execOnHost(ctx, args, !unsandboxed)
}

// commandEnv builds the environment for one dispatched command, shared by both
// exec paths (execOnHost and execInWorker) so a command sees the same variables
// wherever it runs. It starts from the interpreter's current variables (which
// already carry the base brokered-IMDS environment from awsBaseEnv), applies
// per-command AWS_PROFILE routing, and — when injectDockerProxy is set and the
// docker filtering proxy is running — points DOCKER_HOST at the proxy socket.
// execInWorker always injects (worker commands are never unsandboxed_commands);
// execOnHost passes false for unsandboxed_commands so they inherit whatever
// DOCKER_HOST the interpreter environment already carries (the host's, or none).
func (s *Sandbox) commandEnv(hc interp.HandlerContext, injectDockerProxy bool) (map[string]string, error) {
	envMap := make(map[string]string)
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if isExportedEnvVar(vr) {
			envMap[name] = vr.String()
		}
		return true
	})
	// Route a per-command AWS_PROFILE to its brokered IMDS server (or deny an
	// out-of-set profile) before the command runs.
	if err := s.routeAWSProfile(envMap); err != nil {
		return nil, err
	}
	if injectDockerProxy {
		s.mu.RLock()
		proxyHost := s.dockerHost
		s.mu.RUnlock()
		if proxyHost != "" {
			envMap["DOCKER_HOST"] = proxyHost
		}
	}
	return envMap, nil
}

// isExportedEnvVar reports whether a shell variable belongs in a child
// process's environment: like bash (and interp's own execEnv), only exported,
// set, plain string variables are passed on, so `FOO=bar; printenv FOO` prints
// nothing while `export FOO=bar` and `FOO=bar printenv FOO` print bar.
func isExportedEnvVar(vr expand.Variable) bool {
	return vr.IsSet() && vr.Exported && vr.Kind == expand.String
}

// execOnHost runs a command directly on the host, mirroring
// interp.DefaultExecHandler. injectDockerProxy is passed through to commandEnv.
func (s *Sandbox) execOnHost(ctx context.Context, args []string, injectDockerProxy bool) error {
	hc := interp.HandlerCtx(ctx)

	envMap, err := s.commandEnv(hc, injectDockerProxy)
	if err != nil {
		return err
	}
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}

	path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if err != nil {
		fmt.Fprintln(hc.Stderr, err)
		return interp.ExitStatus(127)
	}

	cmd := &exec.Cmd{
		Path:   path,
		Args:   args,
		Env:    env,
		Dir:    hc.Dir,
		Stdin:  hc.Stdin,
		Stdout: hc.Stdout,
		Stderr: hc.Stderr,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(hc.Stderr, "%v\n", err)
		return interp.ExitStatus(127)
	}
	// Cancellation mirrors interp.DefaultExecHandler(gracefulKillTimeout):
	// SIGINT, then SIGKILL after the grace period.
	stopf := context.AfterFunc(ctx, func() {
		if runtime.GOOS == "windows" {
			_ = cmd.Process.Signal(os.Kill)
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)
		time.Sleep(gracefulKillTimeout)
		_ = cmd.Process.Signal(os.Kill)
	})
	defer stopf()

	err = cmd.Wait()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return interp.ExitStatus(exitErr.ExitCode())
	}
	return err
}

// executeRaw executes a command string directly using the system bash without
// going through AST parsing or validation. Used for bare extra_commands entries.
// When forceHost is true (bare unsandboxed_commands entries) the command runs on
// the host even if the OS sandbox is enabled.
func (s *Sandbox) executeRaw(ctx context.Context, command string, workDir string, forceHost bool) (string, error) {
	var out bytes.Buffer
	if err := s.runRawToWriter(ctx, command, workDir, &out, false, forceHost); err != nil {
		output := out.String()
		return output, &CommandFailedError{Err: err, Output: output}
	}
	return out.String(), nil
}

// runRawToWriter executes a command string directly with the system bash,
// streaming combined stdout/stderr to out. It performs no AST parsing or
// validation and is used both by executeRaw (bare extra_commands) and by
// background execution of those commands.
//
// When newProcessGroup is true the bash process leads its own process group and
// cancellation SIGKILLs the whole group, so children the command forked (a dev
// server, a daemon, `something &`) are reaped too — not just bash itself. This
// is used for background runs; foreground runs keep the default behavior where
// CommandContext kills only the direct process.
//
// When forceHost is true the command always runs on the host even if the OS
// sandbox is enabled — used for bare unsandboxed_commands entries.
func (s *Sandbox) runRawToWriter(ctx context.Context, command string, workDir string, out io.Writer, newProcessGroup, forceHost bool) error {
	s.mu.RLock()
	useOSSandbox := s.cfg.OSSandboxEnabled() && !forceHost
	imdsEndpoint := s.imdsEndpoint
	imdsRegion := s.imdsRegion
	dockerHost := s.dockerHost
	s.mu.RUnlock()

	// The AST bypass skips validation, not confinement: when the OS sandbox is
	// enabled the raw bash still runs inside the worker, so filesystem
	// restrictions apply to extra_commands like any other command. The worker
	// runs each command in its own process group and kills the whole subtree on
	// cancellation, so newProcessGroup is only needed for the host path below.
	if useOSSandbox {
		return s.runRawInWorker(ctx, command, workDir, imdsEndpoint, imdsRegion, dockerHost, out)
	}

	env := awsBaseEnv(os.Environ(), imdsEndpoint, imdsRegion)
	// Skip the docker filtering proxy for unsandboxed commands (forceHost) so
	// they reach the real docker daemon rather than the proxy socket.
	if dockerHost != "" && !forceHost {
		env = append(env, fmt.Sprintf("DOCKER_HOST=%s", dockerHost))
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Env = env

	var finished atomic.Bool
	if newProcessGroup {
		setProcessGroup(cmd)
		// Override CommandContext's default Cancel (which kills only bash) so
		// cancellation tears down the whole group. Escalate gracefully: SIGTERM
		// first, then SIGKILL the group after a grace period if it has not
		// exited. The finished guard avoids signaling a recycled pid/group once
		// the command has returned.
		cmd.Cancel = func() error {
			terminateProcessGroup(cmd)
			time.AfterFunc(gracefulKillTimeout, func() {
				if !finished.Load() {
					killProcessGroup(cmd)
				}
			})
			return nil
		}
	}

	// Bound how long Wait blocks on I/O after the context is cancelled. Without
	// this, a backgrounded grandchild (e.g. `npm run dev &`) inherits the stdout
	// pipe's write end and keeps it open after bash exits, so cmd.Run would block
	// until that child exits — pinning the calling MCP worker indefinitely and
	// ignoring the timeout entirely. WaitDelay makes the runtime close the pipes
	// and return once the delay elapses after cancellation. CommandContext has
	// already installed a Cancel func that kills bash on ctx.Done(). It must
	// exceed gracefulKillTimeout so the graceful SIGKILL lands before WaitDelay's
	// force-kill of the direct process.
	cmd.WaitDelay = runnerKillGracePeriod

	err := cmd.Run()
	finished.Store(true)
	return err
}

// runRawInWorker executes a bare extra_commands string with `bash -c` inside
// the OS sandbox worker, streaming combined stdout/stderr to out. No AST
// parsing or validation is performed — trust comes from the user's explicit
// opt-in plus the worker's bwrap/sandbox-exec confinement.
func (s *Sandbox) runRawInWorker(ctx context.Context, command, workDir, imdsEndpoint, imdsRegion, dockerHost string, out io.Writer) error {
	w, err := s.getOrCreateWorker()
	if err != nil {
		return fmt.Errorf("failed to get worker: %w", err)
	}

	// Same base environment the host raw path uses (ambient profile selectors
	// stripped, default brokered endpoint/region injected), as a map for the
	// worker protocol. Converting after awsBaseEnv is equivalent to deleting and
	// re-setting the keys by hand: awsBaseEnv appends its injections last and
	// later entries win in a map, matching os/exec's own duplicate handling.
	env := envSliceToMap(awsBaseEnv(os.Environ(), imdsEndpoint, imdsRegion))
	// awsBaseEnv only injects the region alongside an IMDS endpoint; this path has
	// always injected it whenever a region is configured, so re-apply it here to
	// keep the worker environment unchanged. (The two agree in practice: the IMDS
	// lifecycle only ever publishes a region together with an endpoint.)
	if r := awsRegionToInject(imdsRegion); r != "" {
		env["AWS_REGION"] = r
		env["AWS_DEFAULT_REGION"] = r
	}
	if dockerHost != "" {
		env["DOCKER_HOST"] = dockerHost
	}

	exitCode, err := w.Exec(ctx, []string{"bash", "-c", command}, workDir, env, nil, out, out)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}
	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}
	return nil
}

// Execute parses, validates, and executes a bash command.
// workDir is the working directory for the command and for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
// It returns the combined stdout and stderr output.
func (s *Sandbox) Execute(ctx context.Context, command string, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	// Bare extra_commands entries bypass bash AST parsing entirely and are
	// executed directly with the real bash for maximum compatibility. When the
	// OS sandbox is enabled the raw bash runs inside the worker, so filesystem
	// confinement still applies — unless the entry came from unsandboxed_commands,
	// which runs on the host regardless.
	if s.isExtraCommandInvocation(command) {
		if err := s.checkRawAsk(withAuditScope(ctx, command, workDir, "bash"), command); err != nil {
			return "", fmt.Errorf("validation failed: %w", err)
		}
		return s.executeRaw(ctx, command, workDir, s.isUnsandboxedInvocation(command))
	}

	// Parse and validate
	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	// The audit scope rides on ctx into the static pass and, through the
	// interpreter, into every runtime handler and nested interpreter.
	ctx = withAuditScope(ctx, command, workDir, "bash")
	if err := s.validateFileCtx(ctx, f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Always execute using interp
	// If OS sandbox is enabled, ExecHandler will send commands to worker
	return s.executeWithInterp(ctx, f, workDir, readAllowedPaths, writeAllowedPaths)
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing interpreter output.
// It is needed because executeWithInterp may return before runner.Run completes
// (when the context is cancelled and the runner is stuck on blocked io.Pipe ops).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runnerKillGracePeriod is the extra time allowed for runner.Run to return
// after the context is already cancelled. mvdan.cc/sh pipelines can have
// internal goroutines blocked on io.Pipe that SIGKILL cannot unblock; this
// grace period bounds how long we wait before giving up and returning a timeout
// error to the caller.
const runnerKillGracePeriod = 5 * time.Second

// runInterpToWriter builds a sandboxed interpreter and runs the parsed command,
// streaming combined stdout/stderr to out. It applies the same security
// handlers as the foreground path and is shared by executeWithInterp and
// background execution. It blocks until the runner returns (which honors ctx
// cancellation for OS-level subprocesses).
func (s *Sandbox) runInterpToWriter(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string, out io.Writer) error {
	s.mu.RLock()
	useOSSandbox := s.cfg.OSSandboxEnabled()
	imdsEndpoint := s.imdsEndpoint
	imdsRegion := s.imdsRegion
	s.mu.RUnlock()

	// Build environment with IMDS endpoint if AWS is enabled. The interpreter
	// hands this env to every spawned subprocess (e.g. aws cli), so there is
	// no need — and no safe way — to mutate the host process's environment.
	// The docker filtering proxy's DOCKER_HOST is intentionally NOT set here:
	// it is injected per command at dispatch time (execInWorker / execOnHost)
	// so unsandboxed_commands can reach the real daemon while everything else is
	// routed through the proxy. The host's own DOCKER_HOST (if any) flows through
	// untouched via os.Environ().
	env := awsBaseEnv(os.Environ(), imdsEndpoint, imdsRegion)

	// Store sandbox paths in context so nested bash/sh can access them
	ctx = context.WithValue(ctx, sandboxPathsKey, &sandboxPaths{
		readAllowedPaths:  readAllowedPaths,
		writeAllowedPaths: writeAllowedPaths,
	})

	// Build interpreter options
	opts := []interp.RunnerOption{
		interp.Dir(workDir),
		interp.StdIO(nil, out, out),
		interp.Env(expand.ListEnviron(env...)),
	}

	// Add security handlers (CallHandler, OpenHandler, ExecHandler)
	opts = append(opts, s.buildSecurityHandlers(readAllowedPaths, writeAllowedPaths, useOSSandbox)...)

	runner, err := interp.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create interpreter: %w", err)
	}

	return runner.Run(ctx, f)
}

// executeWithInterp executes the parsed command using interp.
// If OS sandbox is enabled, ExecHandler delegates to the worker.
func (s *Sandbox) executeWithInterp(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	var out syncBuffer

	// Run the interpreter in a goroutine so we can enforce a hard deadline.
	// runner.Run(ctx, f) may not return promptly after context cancellation when
	// a pipeline stage fails inside the CallHandler (before becoming an OS process):
	// the adjacent stages' io.Pipe copy goroutines block indefinitely because
	// io.Pipe operations are not context-aware and SIGKILL only kills OS processes.
	type runResult struct{ err error }
	done := make(chan runResult, 1)
	go func() {
		done <- runResult{s.runInterpToWriter(ctx, f, workDir, readAllowedPaths, writeAllowedPaths, &out)}
	}()

	select {
	case r := <-done:
		output := out.String()
		if r.err != nil {
			return output, &CommandFailedError{Err: r.err, Output: output}
		}
		return output, nil
	case <-ctx.Done():
		// Context cancelled (timeout). Give the runner a short grace period to
		// clean up before we abandon it.
		timer := time.NewTimer(runnerKillGracePeriod)
		defer timer.Stop()
		select {
		case r := <-done:
			output := out.String()
			if r.err != nil {
				return output, &CommandFailedError{Err: r.err, Output: output}
			}
			return output, nil
		case <-timer.C:
			// runner.Run is stuck (blocked io.Pipe goroutines). Return the
			// timeout error; the goroutine may leak but is otherwise harmless.
			return out.String(), fmt.Errorf("command timed out: %w", ctx.Err())
		}
	}
}

// execInWorker sends a command to the worker for execution in the OS sandbox.
func (s *Sandbox) execInWorker(ctx context.Context, args []string) error {
	w, err := s.getOrCreateWorker()
	if err != nil {
		return fmt.Errorf("failed to get worker: %w", err)
	}

	hc := interp.HandlerCtx(ctx)

	// Same environment the host path builds, always with the docker filtering
	// proxy injected: DOCKER_HOST is set here rather than in the interpreter's
	// base env so that unsandboxed_commands (which never reach the worker) can
	// talk to the real daemon instead.
	envMap, err := s.commandEnv(hc, true)
	if err != nil {
		return err
	}

	exitCode, err := w.Exec(ctx, args, hc.Dir, envMap, hc.Stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}

	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}

	return nil
}

// getOrCreateWorker returns the current worker, starting a new one if the worker
// is nil or dead. Must be called without holding s.mu.
func (s *Sandbox) getOrCreateWorker() (*os_sandbox.Worker, error) {
	s.mu.Lock()
	if s.worker != nil && !s.worker.IsDead() {
		w := s.worker
		s.mu.Unlock()
		return w, nil
	}
	s.mu.Unlock()

	// The worker is writable in the working directory by default; every other
	// directory a command may legitimately write to must be added here or the
	// OS sandbox denies the write (EPERM) even though the Go validator
	// permitted it.
	//
	// Write grants are enforced by the Go validator via Execute(...,
	// writeAllowedPaths), but that only gates the interpreter — the OS sandbox
	// worker has its own profile. Without adding them here, a write the
	// validator allows is still denied by bwrap/seatbelt with EPERM.
	extraBinds := s.ConfigWritePaths()

	// Internal write grants are the inverse: the OS sandbox worker allows the
	// writes (so spawned programs can reach their own data — a profile's build
	// cache, a tool's ~/.cache), but the paths are deliberately NOT part of the
	// interpreter's write set, so the agent's direct writes there are still
	// rejected at the AST/runtime layer.
	extraBinds = append(extraBinds, s.ConfigInternalWritePaths()...)

	// Internal read grants likewise only reach the worker (as read-only
	// binds); reads inside the OS sandbox are broadly allowed already, so this
	// mainly re-exposes host paths hidden by the worker's /tmp overlay.
	roBinds := s.ConfigInternalReadPaths()

	// Background commands' output files live under BackgroundOutputRoot,
	// which on Linux sits under the /tmp the worker overlays with its own
	// tmpfs. Like the other internal write grants, the worker gets it
	// writable while the interpreter's write set leaves it out (the agent
	// only gets a read grant, via sandboxPaths), so a sandboxed `cat` or
	// `tail` of an output file sees the host's file. Created now if need be:
	// the bind needs it to exist when the worker starts, and output
	// directories created inside it later show through the bind.
	if root := BackgroundOutputRoot(); ensureOutputRoot(root) == nil {
		extraBinds = append(extraBinds, root)
	} else {
		slog.Warn("background output directory unavailable to the sandbox worker", "path", root)
	}

	// Same for the main worktree when the session runs in a linked git worktree
	// with git.allow_worktree_parent: git writes index/lock files under the main
	// repo's .git/worktrees/<name>/, which is outside the worker's workDir.
	s.mu.RLock()
	workerWorkDir := s.workerWorkDir
	s.mu.RUnlock()
	if parent := s.WorktreeParentPath(workerWorkDir); parent != "" {
		extraBinds = append(extraBinds, parent)
	}

	// Bind the docker proxy socket dir into the worker so sandboxed commands
	// can reach the proxy via DOCKER_HOST, and mask the real daemon socket(s)
	// so the proxy cannot be bypassed.
	s.mu.RLock()
	dockerSocketDir := s.dockerSocketDir
	var dockerMaskPaths []string
	if dockerSocketDir != "" {
		dockerMaskPaths = append([]string(nil), s.dockerMaskPaths...)
	}
	s.mu.RUnlock()
	if dockerSocketDir != "" {
		extraBinds = append(extraBinds, dockerSocketDir)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.worker != nil && !s.worker.IsDead() {
		return s.worker, nil
	}

	// s.cfg is read directly rather than via getConfig(): s.mu is already held
	// exclusively here and sync.RWMutex is not reentrant.
	opts := os_sandbox.WorkerOptions{
		WorkDir:    s.workerWorkDir,
		ExtraBinds: extraBinds,
		ROBinds:    roBinds,
		MaskPaths:  dockerMaskPaths,
		// The credential masks hold in every mode: the ~/.ssh private keys,
		// and ~/.aws in brokered IMDS mode where credentials come from the
		// IMDS server instead of the files (raw-credentials mode and an
		// unconfigured aws section leave it readable) — less whatever a paths
		// grant on the path lifted.
		DeniedReadPaths: denyPaths(s.cfg.AlwaysDeniedReadEntries()),
	}
	// Denylist mode flips the worker's write posture: the home directory is
	// writable and only the deny lists are carved out. Allowlist mode keeps the
	// original cwd-confined layout.
	if s.cfg.EffectiveMode() == config.ModeDenylist {
		opts.HomeWritable = true
		opts.DeniedReadPaths = denyPaths(s.cfg.EffectiveDeniedReadEntries())
		opts.DeniedWritePaths = denyPaths(s.cfg.EffectiveDeniedWriteEntries())
	}
	slog.Info("starting new sandbox worker", "workDir", s.workerWorkDir, "mode", s.cfg.EffectiveMode(), "deniedRead", len(opts.DeniedReadPaths))
	w, err := os_sandbox.StartWorker(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	s.worker = w
	return w, nil
}

// denyPaths converts config deny-list entries to the worker's type.
func denyPaths(entries []config.DeniedPath) []os_sandbox.DenyPath {
	out := make([]os_sandbox.DenyPath, 0, len(entries))
	for _, e := range entries {
		out = append(out, os_sandbox.DenyPath{Path: e.Path, Dir: e.Dir})
	}
	return out
}
