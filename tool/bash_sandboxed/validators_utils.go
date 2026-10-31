package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// wordTexts is wordText over every word: the literal text of each argument,
// quotes included, with "" for a word that is not literal (re-checked after
// expansion, where every word is literal).
func wordTexts(words []*syntax.Word) []string {
	texts := make([]string, len(words))
	for i, w := range words {
		texts[i] = wordText(w)
	}
	return texts
}

// diff3LongOpts and sdiffLongOpts are the GNU diffutils long options of diff3
// and sdiff.
var (
	diff3LongOpts = []string{
		"text", "ascii", "easy-only", "ed", "initial-tab", "label", "merge",
		"overlap-only", "show-all", "show-overlap", "strip-trailing-cr",
		"diff-program", "help", "version",
	}
	sdiffLongOpts = []string{
		"output", "ignore-case", "ignore-tab-expansion", "ignore-trailing-space",
		"ignore-space-change", "ignore-all-space", "ignore-blank-lines",
		"ignore-matching-lines", "strip-trailing-cr", "text", "width",
		"left-column", "suppress-common-lines", "expand-tabs", "tabsize",
		"minimal", "speed-large-files", "diff-program", "help", "version",
	}
)

// validateDiff3Args refuses --diff-program, which runs the named program in
// place of diff.
func validateDiff3Args(_ *Sandbox, args []*syntax.Word) error {
	spec := optSpec{short: "L", long: []string{"label", "diff-program"}}
	if opt := refusedOption(wordTexts(args), spec, diff3LongOpts, "--diff-program"); opt != "" {
		return fmt.Errorf("diff3 option %q is not allowed: it runs another program", opt)
	}
	return nil
}

// validateSdiffArgs refuses --diff-program, which runs the named program in
// place of diff, and -o/--output: the interactive merge it starts reads
// commands from stdin, and its e command opens $EDITOR.
func validateSdiffArgs(_ *Sandbox, args []*syntax.Word) error {
	spec := optSpec{short: "oIw", long: []string{"output", "ignore-matching-lines", "width", "tabsize", "diff-program"}}
	if opt := refusedOption(wordTexts(args), spec, sdiffLongOpts, "--diff-program", "-o", "--output"); opt != "" {
		return fmt.Errorf("sdiff option %q is not allowed: it runs another program", opt)
	}
	return nil
}

// splitSpec lists split's value-taking options (GNU, plus BSD's -p PATTERN).
var splitSpec = optSpec{
	short: "abClntp",
	long:  []string{"suffix-length", "bytes", "line-bytes", "lines", "number", "separator", "additional-suffix", "filter"},
}

// validateSplitArgs refuses --filter, which pipes each chunk to a shell
// command.
func validateSplitArgs(_ *Sandbox, args []*syntax.Word) error {
	all := append(append([]string(nil), splitSpec.long...), "numeric-suffixes", "hex-suffixes", "elide-empty-files", "unbuffered", "verbose", "help", "version")
	if opt := refusedOption(wordTexts(args), splitSpec, all, "--filter"); opt != "" {
		return fmt.Errorf("split option %q is not allowed: it runs a shell command", opt)
	}
	return nil
}

// installSpec lists install's value-taking options.
var installSpec = optSpec{
	short: "gmoSt",
	long:  []string{"group", "mode", "owner", "suffix", "target-directory", "strip-program"},
	flags: []string{
		"backup", "compare", "context", "debug", "directory", "help", "no-target-directory",
		"preserve-context", "preserve-timestamps", "strip", "verbose", "version",
	},
	alias: map[string]string{"target-directory": "t", "directory": "d"},
}

// validateInstallArgs refuses -s/--strip and --strip-program: install runs
// strip (or the program named, or macOS's $STRIPBIN) on what it installs.
func validateInstallArgs(_ *Sandbox, args []*syntax.Word) error {
	all := append(append([]string(nil), installSpec.long...),
		"backup", "compare", "directory", "preserve-timestamps", "strip",
		"no-target-directory", "verbose", "preserve-context", "context", "debug", "help", "version")
	if opt := refusedOption(wordTexts(args), installSpec, all, "-s", "--strip", "--strip-program"); opt != "" {
		return fmt.Errorf("install option %q is not allowed: it runs a strip program", opt)
	}
	return nil
}

// gzipSpec lists gzip's value-taking options; gzipLongOpts all of its long
// options.
var (
	gzipSpec     = optSpec{short: "S", long: []string{"suffix"}}
	gzipLongOpts = []string{
		"best", "decompress", "fast", "force", "help", "keep", "license", "list",
		"name", "no-name", "quiet", "recursive", "rsyncable", "stdout", "suffix",
		"synchronous", "test", "verbose", "version", "uncompress", "to-stdout", "silent", "ascii",
	}
)

// validateGzipArgs refuses -N/--name: decompressing, it names the output
// after the name stored in the archive rather than the operand, so what is
// written is not what the path check saw.
func validateGzipArgs(_ *Sandbox, args []*syntax.Word) error {
	if opt := refusedOption(wordTexts(args), gzipSpec, gzipLongOpts, "-N", "--name"); opt != "" {
		return fmt.Errorf("gzip option %q is not allowed: it names the output after the archive's stored name", opt)
	}
	return nil
}

// xzSpec lists xz's value-taking options.
var xzSpec = optSpec{
	short: "CFMST",
	long: []string{
		"check", "format", "memlimit", "memory", "memlimit-compress", "memlimit-decompress",
		"memlimit-mt-decompress", "suffix", "threads", "block-size", "block-list", "flush-timeout",
	},
}

// xzLongOpts are all of xz's long options (5.4).
var xzLongOpts = append(append([]string(nil), xzSpec.long...),
	"arm", "arm64", "armthumb", "compress", "decompress", "uncompress", "delta", "extreme",
	"files", "files0", "force", "help", "ia64", "ignore-check", "info-memory", "keep",
	"list", "long-help", "lzma1", "lzma2", "no-adjust", "no-sparse", "no-warn", "powerpc",
	"quiet", "robot", "single-stream", "sparc", "stdout", "to-stdout", "test", "verbose",
	"version", "x86", "best", "fast", "riscv",
)

// validateXzArgs refuses --files and --files0, which read the file names to
// process from a file, past the path check of the operands. Any long option
// that abbreviates them is refused too.
func validateXzArgs(_ *Sandbox, args []*syntax.Word) error {
	for _, opt := range scanOptions(wordTexts(args), xzSpec, xzLongOpts) {
		if name, ok := strings.CutPrefix(opt, "--"); ok && len(name) >= 2 && (strings.HasPrefix("files0", name) || strings.HasPrefix(name, "files")) {
			return fmt.Errorf("xz option %q is not allowed: it reads file names from a file", opt)
		}
	}
	return nil
}

// ddOperands returns the values of dd's KEY=VALUE operands named key (if or
// of), in order. A non-literal operand ("" in the static pass) is skipped:
// it is re-checked after expansion.
func ddOperands(args []string, key string) []string {
	var out []string
	for _, a := range args[1:] {
		if v, ok := strings.CutPrefix(a, key+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// ddPseudoDevices are the devices dd is commonly pointed at to generate
// data; reading them exposes nothing.
var ddPseudoDevices = map[string]bool{
	"/dev/zero":    true,
	"/dev/urandom": true,
	"/dev/random":  true,
	"/dev/stdin":   true,
}

// validateDdReads checks the files dd reads (if=) against the read set. Its
// operands are KEY=VALUE words, which the generic pass would resolve as
// relative names (nonPathArgIndices skips them); of= is a write target.
func validateDdReads(args []string, workDir string, read []resolvedAllowedPath) error {
	for _, in := range ddOperands(args, "if") {
		if in == "" || ddPseudoDevices[in] {
			continue
		}
		if err := checkBoundary(in, in, workDir, false, read); err != nil {
			return err
		}
	}
	return nil
}

// lessShortValueOpts are less's short options that take a value (the rest of
// the argument, or the next one); lessRefusedShort the ones refused: -k reads
// a lesskey file, which can set LESSOPEN, and -o/-O copy the input to a log
// file, a write the path check does not see.
const (
	lessShortValueOpts = "bhjkoOpPtTxyzD#"
	lessRefusedShort   = "koO"
)

// lessRefusedLong are the long forms of the refused options. less matches a
// long name case-insensitively and accepts an unambiguous abbreviation.
var lessRefusedLong = []string{"lesskey-file", "lesskey-src", "lesskey-content", "log-file"}

// validateLessArgs refuses the less options that load a lesskey file or
// write a log file (see lessRefusedShort). zless, bzless, and xzless pass
// their arguments to less.
func validateLessArgs(_ *Sandbox, args []*syntax.Word) error {
	texts := wordTexts(args)
	for i := 1; i < len(texts); i++ {
		a := texts[i]
		if a == "--" {
			return nil
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			name, _, _ = strings.Cut(strings.ToLower(name), "=")
			for _, r := range lessRefusedLong {
				if len(name) >= 2 && (strings.HasPrefix(r, name) || strings.HasPrefix(name, r)) {
					return fmt.Errorf("less option %q is not allowed: it loads a lesskey file or writes a log file", a)
				}
			}
			continue
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			if c == '+' {
				continue // -+X resets option X
			}
			if strings.IndexByte(lessRefusedShort, c) >= 0 {
				return fmt.Errorf("less option %q is not allowed: it loads a lesskey file or writes a log file", "-"+string(c))
			}
			if strings.IndexByte(lessShortValueOpts, c) >= 0 {
				if j == len(a)-1 {
					i++
				}
				break
			}
		}
	}
	return nil
}

// validateArchArgs allows only a bare arch. GNU arch takes no operands, but
// macOS's arch runs a command (arch -x86_64 cmd), which would never pass back
// through the interpreter.
func validateArchArgs(_ *Sandbox, args []*syntax.Word) error {
	if len(args) > 1 {
		return fmt.Errorf("arch arguments are not allowed: macOS arch runs a command; use uname -m")
	}
	return nil
}
