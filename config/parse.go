package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse decodes config file contents and runs the checks Load applies: a mode,
// paths entry, commands entry, or profiles entry that could not mean what it
// says is an error. Keys the config does not define are ignored, so a file
// written by a newer version still loads.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.foldDeprecatedOverrides()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ParseStrict is Parse for text a person just wrote (`config edit`), where a
// mistake Load tolerates is almost always a typo that would otherwise sit in
// the file silently doing nothing. On top of Parse's checks it rejects keys
// the config does not define (a misspelled section or field), a second YAML
// document, a scope with no path or with a nested scopes list (which is
// ignored), and two scopes for the same path (only one of which could ever
// apply).
func ParseStrict(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("line %d: the config must be a single YAML document", extra.Line)
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	// ProfileEntry decodes its mapping form itself, and a nested decode does
	// not inherit KnownFields, so its keys are checked on the node tree.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := checkProfileKeys(&root); err != nil {
		return nil, err
	}
	if err := checkSSHHostKeys(&root); err != nil {
		return nil, err
	}
	cfg.foldDeprecatedOverrides()
	if err := cfg.validateScopes(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate runs every check Load applies to a decoded config.
func (c *Config) validate() error {
	for _, check := range []func() error{c.validateModes, c.validatePaths, c.validateCommands, c.validateProfiles, c.validateSSH} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// foldDeprecatedOverrides moves the entries of the deprecated `overrides` key
// into Scopes, ahead of any `scopes` entries, so the rest of the program only
// ever reads Scopes. A scope nesting the old key is moved the same way, so
// validateScopes sees (and rejects) it as a nested scopes list.
func (c *Config) foldDeprecatedOverrides() {
	if len(c.DeprecatedOverrides) > 0 {
		c.Scopes = append(c.DeprecatedOverrides, c.Scopes...)
		c.DeprecatedOverrides = nil
	}
	for i := range c.Scopes {
		s := &c.Scopes[i]
		if len(s.DeprecatedOverrides) > 0 {
			s.Scopes = append(s.DeprecatedOverrides, s.Scopes...)
			s.DeprecatedOverrides = nil
		}
	}
}

// validateScopes rejects scopes that could never take effect as written: one
// without a path, one nesting scopes of its own, or a second scope for a path
// an earlier one already names (under `scopes` or the deprecated `overrides`).
func (c *Config) validateScopes() error {
	seen := map[string]bool{}
	for i, o := range c.Scopes {
		if strings.TrimSpace(o.Path) == "" {
			return fmt.Errorf("scope #%d has no path", i+1)
		}
		if len(o.Scopes) > 0 {
			return fmt.Errorf("scope %q: scopes cannot be nested", o.Path)
		}
		key := expandPath(o.Path)
		if seen[key] {
			return fmt.Errorf("scope %q: another scope already names this path; combine them into one", o.Path)
		}
		seen[key] = true
	}
	return nil
}

// scopeNodes returns the entries of the top-level `scopes` list and of the
// deprecated `overrides` list, for the checks that walk the node tree.
func scopeNodes(root *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	for _, key := range []string{"scopes", "overrides"} {
		if list := mappingValue(root, key); list != nil && list.Kind == yaml.SequenceNode {
			out = append(out, list.Content...)
		}
	}
	return out
}

// checkProfileKeys rejects a key the mapping form of a profiles entry does not
// define, in the global config and in every scope.
func checkProfileKeys(doc *yaml.Node) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	known := yamlFieldNames(reflect.TypeOf(profileEntryFields{}))
	check := func(m *yaml.Node) error {
		profiles := mappingValue(m, "profiles")
		if profiles == nil || profiles.Kind != yaml.SequenceNode {
			return nil
		}
		for _, e := range profiles.Content {
			if e.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(e.Content); i += 2 {
				k := e.Content[i]
				if !known[k.Value] {
					return fmt.Errorf("line %d: field %s not found in profiles entry (fields: %s)", k.Line, k.Value, strings.Join(sortedKeys(known), ", "))
				}
			}
		}
		return nil
	}
	if err := check(root); err != nil {
		return err
	}
	for _, o := range scopeNodes(root) {
		if err := check(o); err != nil {
			return err
		}
	}
	return nil
}

// checkSSHHostKeys rejects a key the mapping form of an ssh hosts entry does
// not define, in the global config and in every scope.
func checkSSHHostKeys(doc *yaml.Node) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	known := yamlFieldNames(reflect.TypeOf(sshHostFields{}))
	check := func(m *yaml.Node) error {
		hosts := mappingValue(mappingValue(m, "ssh"), "hosts")
		if hosts == nil || hosts.Kind != yaml.SequenceNode {
			return nil
		}
		for _, e := range hosts.Content {
			if e.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(e.Content); i += 2 {
				if k := e.Content[i]; !known[k.Value] {
					return fmt.Errorf("line %d: field %s not found in ssh hosts entry (fields: %s)", k.Line, k.Value, strings.Join(sortedKeys(known), ", "))
				}
			}
		}
		return nil
	}
	root := doc.Content[0]
	if err := check(root); err != nil {
		return err
	}
	for _, o := range scopeNodes(root) {
		if err := check(o); err != nil {
			return err
		}
	}
	return nil
}

// mappingValue returns the value under key in mapping node m, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// yamlFieldNames returns the YAML keys struct type t decodes.
func yamlFieldNames(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if name == "" {
			name = strings.ToLower(t.Field(i).Name)
		}
		out[name] = true
	}
	return out
}
