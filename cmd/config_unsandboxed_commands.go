package cmd

import (
	"github.com/gartnera/lite-sandbox/config"
)

func init() {
	configCmd.AddCommand(newStringListCommand(stringListSpec{
		use:   "unsandboxed-commands",
		short: "Manage commands that run on the host, bypassing the OS sandbox",
		long: `Manage unsandboxed commands.

Entries behave like extra-commands (they bypass validation and, when bare, bash
AST parsing) except that they always execute directly on the host — bypassing
the OS sandbox worker (bwrap/sandbox-exec) even when it is enabled. This is a
trust-based escape hatch for commands that cannot run confined.`,
		noun:      "command",
		items:     "unsandboxed commands",
		listLabel: "unsandboxed",
		get:       func(c *config.Config) []string { return c.UnsandboxedCommands },
		set:       func(c *config.Config, v []string) { c.UnsandboxedCommands = v },
	}))
}
