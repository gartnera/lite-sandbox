package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseStrict(t *testing.T) {
	valid := []string{
		"",
		"# only a comment\n",
		"mode: denylist\nos_sandbox: true\n",
		"profiles:\n  - go\n  - name: deno\n    options:\n      allow_network: true\n",
		"paths:\n  - path: ~/scratch\n    write: true\ncommands:\n  - command: curl\n    allow: true\n",
		"scopes:\n  - path: ~/work\n    merge: true\n    mode: open\n    profiles:\n      - name: rust\n        enabled: false\n",
		// Deprecated keys still load; Load migrates them.
		"overrides:\n  - path: ~/work\n    mode: open\n",
		"extra_commands: [curl]\nruntimes:\n  go:\n    enabled: true\n",
	}
	for _, in := range valid {
		if _, err := ParseStrict([]byte(in)); err != nil {
			t.Errorf("ParseStrict(%q) = %v, want ok", in, err)
		}
	}

	invalid := map[string]string{
		"mode: [":                                     "",
		"mode: strict\n":                              "strict",
		"os_sandbx: true\n":                           "os_sandbx",
		"git:\n  remote_wirte: true\n":                "remote_wirte",
		"os_sandbox: yes please\n":                    "",
		"profiles:\n  - gopher\n":                     "gopher",
		"profiles:\n  - name: go\n    enable: true\n": "enable",
		"profiles:\n  - name: deno\n    options:\n      network: true\n": "network",
		"paths:\n  - path: ~/x\n":                                                              "",
		"commands:\n  - command: curl\n    alow: true\n":                                       "alow",
		"scopes:\n  - mode: open\n":                                                            "no path",
		"scopes:\n  - path: ~/w\n    mode: opne\n":                                             "opne",
		"scopes:\n  - path: ~/w\n    profiles:\n      - name: go\n        enable: true\n":      "enable",
		"scopes:\n  - path: ~/w\n    mode: open\n  - path: ~/w/\n    audit: true\n":            "already names",
		"scopes:\n  - path: ~/w\n    scopes:\n      - path: ~/w/x\n        mode: open\n":       "nested",
		"overrides:\n  - path: ~/w\n    mode: opne\n":                                          "opne",
		"overrides:\n  - path: ~/w\n    overrides:\n      - path: ~/w/x\n        mode: open\n": "nested",
		"overrides:\n  - path: ~/w\n    mode: open\nscopes:\n  - path: ~/w\n    audit: true\n": "already names",
		"overrides:\n  - path: ~/w\n    profiles:\n      - name: go\n        enable: true\n":   "enable",
		"mode: open\n---\nmode: denylist\n":                                                    "single YAML document",
		"- mode: open\n":                                                                       "",
	}
	for in, want := range invalid {
		_, err := ParseStrict([]byte(in))
		if err == nil {
			t.Errorf("ParseStrict(%q) accepted an invalid config", in)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ParseStrict(%q) = %v, want it to mention %q", in, err, want)
		}
	}
}

// TestParseIgnoresUnknownKeys pins the difference from ParseStrict: Load keeps
// loading a config written by a newer version.
func TestParseIgnoresUnknownKeys(t *testing.T) {
	cfg, err := Parse([]byte("mode: denylist\nsome_future_section: {a: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "denylist" {
		t.Errorf("mode = %q", cfg.Mode)
	}
}

// TestParseFoldsDeprecatedScopes checks that the old `scopes` key loads
// into Scopes (ahead of `scopes` entries) and is written back as `scopes`.
func TestParseFoldsDeprecatedScopes(t *testing.T) {
	in := "overrides:\n  - path: /old\n    mode: open\nscopes:\n  - path: /new\n    mode: denylist\n"
	for name, parse := range map[string]func([]byte) (*Config, error){"Parse": Parse, "ParseStrict": ParseStrict} {
		cfg, err := parse([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.DeprecatedOverrides != nil {
			t.Errorf("%s: DeprecatedOverrides = %+v, want nil", name, cfg.DeprecatedOverrides)
		}
		if len(cfg.Scopes) != 2 || cfg.Scopes[0].Path != "/old" || cfg.Scopes[1].Path != "/new" {
			t.Fatalf("%s: Scopes = %+v, want /old then /new", name, cfg.Scopes)
		}
		if got := cfg.ForDirectory("/old/x").EffectiveMode(); got != ModeOpen {
			t.Errorf("%s: mode under /old = %v, want open", name, got)
		}
		out, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "overrides") || !strings.Contains(string(out), "scopes:") {
			t.Errorf("%s: marshaled config = %q, want only a scopes key", name, out)
		}
	}
}
