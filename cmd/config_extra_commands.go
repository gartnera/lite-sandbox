package cmd

import (
	"github.com/gartnera/lite-sandbox/config"
)

func init() {
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:       "extra-commands",
		short:     "Manage extra allowed commands",
		noun:      "command",
		items:     "extra allowed commands",
		listLabel: "extra allowed",
		get:       func(c *config.Config) []string { return c.ExtraCommands },
		set:       func(c *config.Config, v []string) { c.ExtraCommands = v },
	}))
}
