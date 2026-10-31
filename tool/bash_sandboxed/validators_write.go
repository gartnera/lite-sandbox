package bash_sandboxed

import (
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// blockedRmFlags lists rm flags that bypass safety checks.
var blockedRmFlags = map[string]string{
	"--no-preserve-root": "bypasses root protection",
}

// validateRmArgs checks that rm is not called with dangerous flags.
func validateRmArgs(_ *Sandbox, args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedRmFlags[lit]; blocked {
			return fmt.Errorf("rm flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateSedArgs checks that sed's scripts don't contain dangerous commands
// (sedScriptCheck) and blocks -f/--file since script files contain
// unvalidated commands.
//
// Dangerous sed commands blocked:
//   - e: executes pattern space as a shell command (GNU extension, complete sandbox bypass)
//   - r/R: reads from arbitrary files (filenames embedded in expression, bypass path validation)
//   - w/W: writes to arbitrary files (filenames embedded in expression, bypass path validation)
//
// Note: GNU sed supports --sandbox which disables e/r/w commands natively,
// but BSD sed does not support this flag, so we parse expressions instead
// to stay portable across both implementations.
func validateSedArgs(_ *Sandbox, args []*syntax.Word) error {
	texts := wordTexts(args)
	if opt := refusedOption(texts, sedSpec, sedLongOpts, "-f", "--file"); opt != "" {
		return fmt.Errorf("sed flag %q is not allowed: script files bypass command validation", opt)
	}
	scripts, maybe := sedScripts(texts)
	for _, s := range maybe {
		if err := sedScriptCheck(s, "erRwW"); err == nil || errors.Is(err, errSedRefused) {
			scripts = append(scripts, s)
		}
	}
	for _, s := range scripts {
		switch err := sedScriptCheck(s, "erRwW"); {
		case errors.Is(err, errSedRefused):
			return fmt.Errorf("sed commands 'e', 'r', 'R', 'w', 'W' are not allowed: they can execute commands or access files outside path validation")
		case err != nil:
			return fmt.Errorf("sed script %q is not allowed: %v; only scripts that can be checked run", s, err)
		}
	}
	return nil
}

// unescapeLit removes the backslash before each character of an unquoted
// literal, which is how the shell reads it.
func unescapeLit(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		sb.WriteByte(v[i])
	}
	return sb.String()
}

// wordText extracts the literal text content from a Word node,
// including content inside single and double quotes.
func wordText(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// An unquoted literal keeps its backslashes (--comp\ress is
			// --compress to the program); drop them as the shell does.
			sb.WriteString(unescapeLit(p.Value))
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		}
	}
	return sb.String()
}
