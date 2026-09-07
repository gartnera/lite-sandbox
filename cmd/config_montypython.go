package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

// The Python runtime is the one runtime that ships enabled. `python` and
// `python3` are served by monty, a Python interpreter compiled to WebAssembly
// and embedded in the lite-sandbox binary — there is no toolchain to detect and
// nothing to install, and every file it touches goes through the same path
// boundary as bash. So unlike `runtimes go enable`, this command exists mainly
// for turning it off.

var montyPythonRuntimeCmd = &cobra.Command{
	Use:   "montypython",
	Short: "Manage the embedded Python (monty) runtime",
	Long: "Manage the embedded Python runtime.\n\n" +
		"python and python3 run on monty, a sandboxed Python interpreter compiled into\n" +
		"lite-sandbox. It is enabled by default. Python file I/O is checked against the\n" +
		"same readable/writable paths as bash, and monty itself has no network access,\n" +
		"no environment, and no filesystem access of its own.\n\n" +
		"monty implements a subset of Python: third-party packages cannot be imported.\n" +
		"For real CPython, enable the uv runtime and use `uv run`.\n\n" +
		"inline_only narrows it to code the agent writes inline (-c, or a heredoc:\n" +
		"`python3 - <<PY ... PY`) and refuses a script file, which was written for\n" +
		"CPython and may import packages monty lacks or diverge from its subset.",
}

var montyPythonRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the embedded Python runtime setting",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		p := &config.MontyPythonConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.MontyPython != nil {
			p = cfg.Runtimes.MontyPython
		}
		fmt.Printf("enabled:     %v\n", p.MontyPythonEnabled())
		fmt.Printf("inline_only: %v\n", p.MontyPythonInlineOnly())
		if p.MontyPythonInlineOnly() {
			fmt.Println("  only -c and stdin (heredoc/pipe) run; a script file is refused")
		}
		return nil
	},
}

var montyPythonRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable python/python3 (the default)",
	RunE: func(cmd *cobra.Command, args []string) error {
		inlineOnly, _ := cmd.Flags().GetBool("inline-only")
		return setMontyPython(true, inlineOnly)
	},
}

var montyPythonRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable python/python3",
	RunE: func(cmd *cobra.Command, args []string) error {
		inlineOnly, _ := cmd.Flags().GetBool("inline-only")
		return setMontyPython(false, inlineOnly)
	},
}

// setMontyPython applies enable/disable. Following the other runtimes, a
// sub-setting flag scopes the change to that sub-setting and leaves the
// runtime itself alone — `disable --inline-only` turns inline_only off while
// python keeps working.
func setMontyPython(enabled, inlineOnly bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Runtimes == nil {
		cfg.Runtimes = &config.RuntimesConfig{}
	}
	if cfg.Runtimes.MontyPython == nil {
		cfg.Runtimes.MontyPython = &config.MontyPythonConfig{}
	}
	if inlineOnly {
		cfg.Runtimes.MontyPython.InlineOnly = &enabled
	} else {
		cfg.Runtimes.MontyPython.Enabled = &enabled
	}

	if err := saveConfig(cfg); err != nil {
		return err
	}
	if inlineOnly {
		fmt.Printf("runtimes.montypython.inline_only set to %v\n", enabled)
		if enabled {
			fmt.Println("  python runs code from -c and stdin (heredoc/pipe); a script file is refused")
		}
		return nil
	}
	fmt.Printf("runtimes.montypython.enabled set to %v\n", enabled)
	if !enabled {
		fmt.Println("  python and python3 will be rejected like any other command that is not allowed")
	}
	return nil
}
