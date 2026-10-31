package config

// SectionCommand is a command that a config section, rather than the commands
// list or a profile, puts on the whitelist once the section is set up: ssh and
// sshpass once the ssh section lists a host, scp and rsync once one of its
// hosts allows writes. The section's validators then hold the command to what
// the section allows, so the remedy for a refused one is setting the section
// up, never an allow that would skip them.
type SectionCommand struct {
	Name string
	// Missing says why the command is not allowed while the section is not
	// set up ("no ssh hosts are configured").
	Missing string
	// Remedy and Fix are what the user can do about it and the config
	// command that does it.
	Remedy, Fix string
	// enabled reports whether c's section whitelists the command.
	enabled func(c *Config) bool
}

// sectionCommands lists every SectionCommand. A section that whitelists
// commands adds them here, and the sandbox's whitelist and its refusals
// follow.
var sectionCommands = func() []SectionCommand {
	var out []SectionCommand
	for _, name := range SSHCommands {
		out = append(out, SectionCommand{
			Name:    name,
			Missing: "no ssh hosts are configured",
			Remedy:  "allow ssh to a host",
			Fix:     "lite-sandbox config ssh hosts add <host>",
			enabled: func(c *Config) bool { return c.SSH.HostsConfigured() },
		})
	}
	for _, name := range SSHCopyCommands {
		out = append(out, SectionCommand{
			Name:    name,
			Missing: "no ssh host allows writes",
			Remedy:  "allow copying to and from a host",
			Fix:     "lite-sandbox config ssh hosts add <host> --write",
			enabled: func(c *Config) bool { return c.SSH.WriteHostsConfigured() },
		})
	}
	return out
}()

// SectionCommands returns the commands c's sections whitelist.
func (c *Config) SectionCommands() []string {
	var out []string
	for _, sc := range sectionCommands {
		if c != nil && sc.enabled(c) {
			out = append(out, sc.Name)
		}
	}
	return out
}

// SectionCommandFor returns the SectionCommand named name, if a section
// whitelists a command of that name.
func SectionCommandFor(name string) (SectionCommand, bool) {
	for _, sc := range sectionCommands {
		if sc.Name == name {
			return sc, true
		}
	}
	return SectionCommand{}, false
}
