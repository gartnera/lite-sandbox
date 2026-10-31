package cmd

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestOpencodeV2LaunchSpec checks v2's inline config (mcp.servers, the
// permission rules, the directive file) and that it runs --standalone.
func TestOpencodeV2LaunchSpec(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")
	stubOpencodeVersion(t, "2.2.5\n", nil)

	spec, err := opencodeLaunchSpec(testBin, []string{"run", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.args, []string{"--standalone", "run", "hi"}) {
		t.Errorf("args = %v, want --standalone before the agent's own", spec.args)
	}
	cfg := opencodeConfig(t, spec)
	server := asMap(asMap(asMap(cfg["mcp"])["servers"])["lite-sandbox"])
	if cmd := asSlice(server["command"]); len(cmd) != 2 || cmd[0] != testBin || cmd[1] != "serve-mcp" || server["type"] != "local" {
		t.Errorf("mcp server = %v", server)
	}
	if asMap(cfg["mcp"])["lite-sandbox"] != nil || cfg["permission"] != nil {
		t.Errorf("v1 keys in a v2 inline config: %v", cfg)
	}
	var rules []opencodeV2Rule
	b, _ := json.Marshal(cfg["permissions"])
	if err := json.Unmarshal(b, &rules); err != nil || !slices.Equal(rules, opencodeV2Rules) {
		t.Errorf("permissions = %s (%v)", b, err)
	}
	if len(asSlice(cfg["instructions"])) != 1 {
		t.Errorf("instructions = %v", cfg["instructions"])
	}
}

// TestOpencodeV2LaunchConfigMergesExisting checks the sandbox rules come after
// a user's own inline rules, so they are the last ones opencode reads.
func TestOpencodeV2LaunchConfigMergesExisting(t *testing.T) {
	existing := `{"permissions":[{"action":"shell","resource":"*","effect":"allow"}],"mcp":{"servers":{"other":{"type":"local","command":["o"]}}}}`
	content, err := opencodeV2LaunchConfig(testBin, "/cache/lite-sandbox.md", existing)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Permissions []opencodeV2Rule `json:"permissions"`
		MCP         struct {
			Servers map[string]any `json:"servers"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		t.Fatal(err)
	}
	want := append([]opencodeV2Rule{{Action: "shell", Resource: "*", Effect: "allow"}}, opencodeV2Rules...)
	if !slices.Equal(cfg.Permissions, want) {
		t.Errorf("permissions = %+v, want %+v", cfg.Permissions, want)
	}
	if cfg.MCP.Servers["other"] == nil || cfg.MCP.Servers["lite-sandbox"] == nil {
		t.Errorf("servers = %v", cfg.MCP.Servers)
	}
}

func TestOpencodeV2LaunchArgs(t *testing.T) {
	for _, tt := range []struct {
		in, want []string
		err      bool
	}{
		{in: nil, want: []string{"--standalone"}},
		{in: []string{"run", "hi"}, want: []string{"--standalone", "run", "hi"}},
		{in: []string{"run", "--standalone", "hi"}, want: []string{"run", "--standalone", "hi"}},
		{in: []string{"run", "--", "--server"}, want: []string{"--standalone", "run", "--", "--server"}},
		{in: []string{"run", "--server", "http://x"}, err: true},
		{in: []string{"--server=http://x"}, err: true},
		{in: []string{"--standalone=false"}, err: true},
	} {
		got, err := opencodeV2LaunchArgs(tt.in)
		if (err != nil) != tt.err || (!tt.err && !slices.Equal(got, tt.want)) {
			t.Errorf("opencodeV2LaunchArgs(%q) = %q, %v", tt.in, got, err)
		}
	}
}
