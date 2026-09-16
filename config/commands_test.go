package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestCommands_OneListFeedsEveryAccessor is the point of the section: a single
// `commands` list with per-entry flags resolves to the same three lists the
// sandbox has always read, plus the built-in deny list with lifts applied.
func TestCommands_OneListFeedsEveryAccessor(t *testing.T) {
	writeConfig(t, `
commands:
  - command: curl
    allow: true
  - command: "uv   run pyright"
    allow: true
  - command: docker
    allow: true
    no_sandbox: true
  - command: sudo
    allow: false
  - command: gh auth
    allow: false
  - command: lite-sandbox update
    allow: true
  - command: lite-sandbox
    allow: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"curl", "uv   run pyright", "lite-sandbox update", "lite-sandbox"}) {
		t.Errorf("ExtraCommandList = %v", got)
	}
	if got := cfg.UnsandboxedCommandList(); !slices.Equal(got, []string{"docker"}) {
		t.Errorf("UnsandboxedCommandList = %v", got)
	}
	if got := cfg.DeniedCommandList(); !slices.Equal(got, []string{"sudo", "gh auth"}) {
		t.Errorf("DeniedCommandList = %v", got)
	}
	if got := cfg.LiftedDeniedCommands(); !slices.Equal(got, []string{"lite-sandbox update"}) {
		t.Errorf("LiftedDeniedCommands = %v (a bare allow must not lift the subcommand entries)", got)
	}
	eff := cfg.EffectiveDeniedCommands()
	for _, want := range []string{"lite-sandbox config", "lite-sandbox install", "lite-sandbox hook", "sudo", "gh auth"} {
		if !slices.Contains(eff, want) {
			t.Errorf("effective deny list lacks %q: %v", want, eff)
		}
	}
	if slices.Contains(eff, "lite-sandbox update") {
		t.Errorf("lifted built-in still in effect: %v", eff)
	}
}

// TestCommands_LegacyKeysStillLoadAsUnion: the three deprecated lists keep
// loading, resolve as the union with commands, and a "-" entry still lifts.
func TestCommands_LegacyKeysStillLoadAsUnion(t *testing.T) {
	writeConfig(t, `
extra_commands: [make]
unsandboxed_commands: [./deploy.sh]
denied_commands: [sudo, "-lite-sandbox update"]
commands:
  - command: npm
    allow: true
  - command: gh auth
    allow: false
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UsesDeprecatedCommandKeys() {
		t.Error("UsesDeprecatedCommandKeys should be true")
	}
	if got := cfg.ExtraCommandList(); !slices.Equal(got, []string{"make", "npm"}) {
		t.Errorf("ExtraCommandList = %v", got)
	}
	if got := cfg.UnsandboxedCommandList(); !slices.Equal(got, []string{"./deploy.sh"}) {
		t.Errorf("UnsandboxedCommandList = %v", got)
	}
	eff := cfg.EffectiveDeniedCommands()
	if !slices.Contains(eff, "sudo") || !slices.Contains(eff, "gh auth") || slices.Contains(eff, "lite-sandbox update") {
		t.Errorf("effective deny list = %v", eff)
	}
	yes, no := true, false
	want := []CommandEntry{
		{Command: "make", Allow: &yes},
		{Command: "./deploy.sh", Allow: &yes, NoSandbox: true},
		{Command: "sudo", Allow: &no},
		{Command: "lite-sandbox update", Allow: &yes},
	}
	got := cfg.LegacyCommandEntries()
	if len(got) != len(want) {
		t.Fatalf("LegacyCommandEntries = %+v", got)
	}
	for i := range want {
		if got[i].Command != want[i].Command || got[i].NoSandbox != want[i].NoSandbox || !boolPtrEqual(got[i].Allow, want[i].Allow) {
			t.Errorf("LegacyCommandEntries[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if n := len(cfg.AllCommandEntries()); n != 6 {
		t.Errorf("AllCommandEntries has %d entries, want 6", n)
	}
}

func TestCommands_Validation(t *testing.T) {
	for _, tc := range []struct{ name, body, wantErr string }{
		{"no command", "commands:\n  - allow: true\n", "without a command"},
		{"neither", "commands:\n  - command: curl\n", "neither allow: true nor allow: false"},
		{"no_sandbox on deny", "commands:\n  - command: curl\n    allow: false\n    no_sandbox: true\n", "no_sandbox applies to an allow only"},
		{"leading dash", "commands:\n  - command: -lite-sandbox hook\n    allow: false\n", "deprecated denied_commands way"},
		{"in override", "overrides:\n  - path: /x\n    commands:\n      - command: curl\n", `override "/x"`},
	} {
		writeConfig(t, tc.body)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
	// A command's internal whitespace is not significant.
	if !(CommandEntry{Command: "uv  run"}).SameCommand("uv run") {
		t.Error("SameCommand should normalize whitespace")
	}
}

func TestCommandEntry_Describe(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		e    CommandEntry
		want string
	}{
		{CommandEntry{Command: "curl", Allow: &yes}, "allow"},
		{CommandEntry{Command: "docker", Allow: &yes, NoSandbox: true}, "allow, no sandbox (runs on the host, outside the OS sandbox)"},
		{CommandEntry{Command: "sudo", Allow: &no}, "deny"},
	} {
		if got := tc.e.Describe(); got != tc.want {
			t.Errorf("%+v.Describe() = %q, want %q", tc.e, got, tc.want)
		}
	}
}

func TestCommands_SetAndRemove(t *testing.T) {
	writeConfig(t, `
extra_commands: [curl, make]
denied_commands: [sudo, "-lite-sandbox update"]
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	// Setting a command drops it from every deprecated list, lift included.
	if err := cfg.SetCommand(CommandEntry{Command: "curl", Allow: &no}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetCommand(CommandEntry{Command: "lite-sandbox  update", Allow: &yes}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.ExtraCommands, []string{"make"}) || !slices.Equal(cfg.DeniedCommands, []string{"sudo"}) {
		t.Errorf("deprecated lists after SetCommand: extra %v denied %v", cfg.ExtraCommands, cfg.DeniedCommands)
	}
	if got := cfg.DeniedCommandList(); !slices.Equal(got, []string{"sudo", "curl"}) {
		t.Errorf("DeniedCommandList = %v", got)
	}
	if cfg.Commands[1].Command != "lite-sandbox update" {
		t.Errorf("SetCommand should store the normalized text, got %q", cfg.Commands[1].Command)
	}
	if slices.Contains(cfg.EffectiveDeniedCommands(), "lite-sandbox update") {
		t.Error("lift via allow entry not applied")
	}
	// Setting it again replaces rather than duplicating.
	if err := cfg.SetCommand(CommandEntry{Command: "curl", Allow: &yes, NoSandbox: true}); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Commands) != 2 || !slices.Equal(cfg.UnsandboxedCommandList(), []string{"curl"}) {
		t.Errorf("commands after re-set = %+v", cfg.Commands)
	}
	// An invalid entry changes nothing.
	if err := cfg.SetCommand(CommandEntry{Command: "x"}); err == nil {
		t.Error("SetCommand should reject an entry that says nothing")
	}
	if len(cfg.Commands) != 2 {
		t.Errorf("a rejected entry must not be stored: %+v", cfg.Commands)
	}
	// Remove drops every statement, in either spelling.
	if !cfg.RemoveCommand("sudo") || !cfg.RemoveCommand("curl") || cfg.RemoveCommand("nothing") {
		t.Error("RemoveCommand reported the wrong result")
	}
	if len(cfg.DeniedCommands) != 0 || len(cfg.DeniedCommandList()) != 0 || len(cfg.UnsandboxedCommandList()) != 0 {
		t.Errorf("after remove: %+v", cfg)
	}
	if !cfg.RemoveCommand("lite-sandbox update") || cfg.Commands != nil {
		t.Errorf("removing the last entry should leave Commands nil, got %+v", cfg.Commands)
	}
}

func TestCommands_Migrate(t *testing.T) {
	writeConfig(t, `
extra_commands: [make, sudo]
unsandboxed_commands: [./deploy.sh]
denied_commands: [sudo, "-lite-sandbox update"]
commands:
  - command: npm
    allow: true
overrides:
  - path: /work/a
    extra_commands: [gradle]           # replaces extra, inherits the rest
  - path: /work/b
    os_sandbox: true                   # touches no command list: keeps inheriting
  - path: /work/c
    commands:                          # already new-style: was unioned with the base's old keys
      - command: cargo
        allow: true
`)
	before, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	after, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	n := after.MigrateCommands()
	if n == 0 {
		t.Fatal("MigrateCommands reported nothing to do")
	}
	if after.UsesDeprecatedCommandKeys() {
		t.Errorf("deprecated keys remain after migrate: %+v", after)
	}
	if after.MigrateCommands() != 0 {
		t.Error("a second migrate should be a no-op")
	}
	if err := Save(after); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/elsewhere", "/work/a/sub", "/work/b", "/work/c"} {
		b, a := before.ForDirectory(dir), reloaded.ForDirectory(dir)
		type view struct{ x, u, d []string }
		mk := func(c *Config) view {
			// Two entries are not one-to-one: sudo was both allowed and denied
			// before, and the denial wins at every gate, so the migrated form
			// keeps only the denial; the "-lite-sandbox update" lift becomes
			// an allow, which lifts the same built-in and is also listed as
			// allowed. Compare what is in effect with both dropped.
			x := slices.DeleteFunc(slices.Clone(c.ExtraCommandList()), func(s string) bool {
				return slices.Contains(c.EffectiveDeniedCommands(), s) || IsDefaultDeniedCommand(s)
			})
			return view{x, c.UnsandboxedCommandList(), c.EffectiveDeniedCommands()}
		}
		vb, va := mk(b), mk(a)
		for _, l := range []*[]string{&vb.x, &vb.u, &vb.d, &va.x, &va.u, &va.d} {
			slices.Sort(*l)
		}
		if !slices.Equal(vb.x, va.x) || !slices.Equal(vb.u, va.u) || !slices.Equal(vb.d, va.d) {
			t.Errorf("%s resolves differently after migrate:\n before %+v\n after  %+v", dir, vb, va)
		}
	}
	for _, o := range reloaded.Overrides {
		if o.Path == "/work/b" && o.Commands != nil {
			t.Errorf("/work/b should keep inheriting, got commands %+v", o.Commands)
		}
	}
	data, _ := os.ReadFile(os.Getenv("LITE_SANDBOX_CONFIG"))
	if strings.Contains(string(data), "_commands:") {
		t.Errorf("migrated file still has an old key:\n%s", data)
	}
}

// TestCommands_OverrideReplacesSection: like every section, an override's
// commands list replaces the base's for its directory.
func TestCommands_OverrideReplacesSection(t *testing.T) {
	writeConfig(t, `
commands:
  - command: make
    allow: true
overrides:
  - path: /work
    commands:
      - command: npm
        allow: true
`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory("/elsewhere").ExtraCommandList(); !slices.Equal(got, []string{"make"}) {
		t.Errorf("base allowed = %v", got)
	}
	if got := cfg.ForDirectory("/work/x").ExtraCommandList(); !slices.Equal(got, []string{"npm"}) {
		t.Errorf("override allowed = %v", got)
	}
	if !(&DirectoryOverride{Path: "/x", Config: Config{Commands: []CommandEntry{{Command: "y"}}}}).SetsAnySection() {
		t.Error("an override with commands should report a set section")
	}
}
