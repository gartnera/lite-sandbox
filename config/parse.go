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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ParseStrict is Parse for text a person just wrote (`config edit`), where a
// mistake Load tolerates is almost always a typo that would otherwise sit in
// the file silently doing nothing. On top of Parse's checks it rejects keys
// the config does not define (a misspelled section or field), a second YAML
// document, an override with no path or with a nested overrides list (which
// is ignored), and two overrides for the same path (only one of which could
// ever apply).
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
	if err := cfg.validateOverrides(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate runs every check Load applies to a decoded config.
func (c *Config) validate() error {
	for _, check := range []func() error{c.validateModes, c.validatePaths, c.validateCommands, c.validateProfiles} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// validateOverrides rejects overrides that could never take effect as
// written: one without a path, one nesting overrides of its own, or a second
// override for a path an earlier one already names.
func (c *Config) validateOverrides() error {
	seen := map[string]bool{}
	for i, o := range c.Overrides {
		if strings.TrimSpace(o.Path) == "" {
			return fmt.Errorf("override #%d has no path", i+1)
		}
		if len(o.Overrides) > 0 {
			return fmt.Errorf("override %q: overrides cannot be nested", o.Path)
		}
		key := expandPath(o.Path)
		if seen[key] {
			return fmt.Errorf("override %q: another override already names this path; combine them into one", o.Path)
		}
		seen[key] = true
	}
	return nil
}

// checkProfileKeys rejects a key the mapping form of a profiles entry does not
// define, in the base config and in every override.
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
	if overrides := mappingValue(root, "overrides"); overrides != nil && overrides.Kind == yaml.SequenceNode {
		for _, o := range overrides.Content {
			if err := check(o); err != nil {
				return err
			}
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
