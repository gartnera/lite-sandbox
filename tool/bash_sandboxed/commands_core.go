package bash_sandboxed

import "path/filepath"

// The option tables and argument layouts of the coreutils-style commands
// (see argLayout), as their GNU tools declare them (--help); a BSD tool's
// table is given where it disagrees on which options take a value. Only
// value-taking options must be complete; flags are listed so abbreviations
// expand as the tool expands them.

// writesOperands is the layout of a command that writes every operand.
func writesOperands(opts optSpec) *argLayout {
	return &argLayout{opts: opts, operands: roleWrite}
}

var (
	grepOpts = optSpec{
		short: "ABCDXdefm",
		long: []string{
			"after-context", "before-context", "context", "devices", "directories", "regexp", "file",
			"max-count", "label", "exclude", "include", "exclude-dir", "exclude-from", "binary-files",
			"group-separator",
		},
		flags: []string{
			"basic-regexp", "binary", "byte-offset", "color", "colour", "count", "dereference-recursive",
			"extended-regexp", "files-with-matches", "files-without-match", "fixed-strings", "help",
			"ignore-case", "initial-tab", "invert-match", "line-buffered", "line-number", "line-regexp",
			"no-filename", "no-group-separator", "no-ignore-case", "no-messages", "null", "null-data",
			"only-matching", "perl-regexp", "quiet", "recursive", "silent", "text", "version",
			"with-filename", "word-regexp",
		},
		alias: map[string]string{
			"regexp": "e", "file": "f", "max-count": "m", "after-context": "A",
			"before-context": "B", "context": "C", "devices": "D", "directories": "d",
		},
	}
	// BSD grep (macOS): --context's value is optional.
	bsdGrepOpts = optSpec{
		short: "ABCDdefm",
		long: []string{
			"binary-files", "label", "exclude", "include", "exclude-dir", "include-dir",
			"after-context", "before-context", "devices", "directories", "regexp", "file", "max-count",
		},
		flags: append([]string{"context", "mmap", "unix-byte-offsets", "bz2decompress", "lzma", "xz", "decompress"}, grepOpts.flags...),
		alias: grepOpts.alias,
	}
	// grepLayout: grep's patterns (-e, or the first operand when neither
	// -e nor -f gives them) and its counts are not paths; everything else
	// it reads is.
	grepLayout = &argLayout{
		opts:       grepOpts,
		bsd:        &bsdGrepOpts,
		values:     map[string]argRole{"e": roleNonPath, "m": roleNonPath, "A": roleNonPath, "B": roleNonPath, "C": roleNonPath},
		lead:       1,
		leadRole:   roleNonPath,
		leadUnless: []string{"e", "f"},
	}

	// BSD sed: -i and -I take a suffix, and getopt stops at the first operand.
	bsdSedOpts = optSpec{short: "efiI", stopAtOperand: true}
	// sedLayout: the script (-e, or the first operand when neither -e nor
	// -f gives it) is not a path; with -i every file is written.
	sedLayout = &argLayout{
		opts: sedSpec,
		bsd:  &bsdSedOpts,
		// BSD's -i and -I take the backup suffix, which is not a path; GNU's
		// script (sed -i '/^#/d' f) is that suffix in the BSD reading.
		values:     map[string]argRole{"e": roleNonPath, "i": roleNonPath, "I": roleNonPath},
		lead:       1,
		leadRole:   roleNonPath,
		leadUnless: []string{"e", "f"},
		adjust: func(p parsedArgs, r *argRoles) {
			if !p.has("i", "I") {
				return
			}
			for _, i := range p.operands {
				if r.index[i] != roleNonPath {
					r.set(i, roleWrite)
				}
			}
		},
	}

	// cpOpts is cp's, mv's, and ln's table (each has a subset of the flags).
	cpOpts = optSpec{
		short: "tS",
		long:  []string{"target-directory", "suffix", "sparse", "no-preserve"},
		flags: []string{
			"archive", "attributes-only", "backup", "context", "copy-contents", "debug", "dereference",
			"directory", "force", "help", "interactive", "link", "logical", "no-clobber", "no-copy",
			"no-dereference", "no-target-directory", "one-file-system", "parents", "physical",
			"preserve", "recursive", "reflink", "relative", "remove-destination", "strip-trailing-slashes",
			"symbolic", "symbolic-link", "update", "verbose", "version",
		},
		alias: map[string]string{"target-directory": "t", "suffix": "S"},
	}
	// mvLayout: mv rewrites its sources (removes them) and the destination.
	mvLayout = &argLayout{opts: cpOpts, values: map[string]argRole{"t": roleWrite}, operands: roleWrite}
	// cpLayout: cp writes its -t directory, or else its last operand.
	cpLayout = &argLayout{opts: cpOpts, values: map[string]argRole{"t": roleWrite}, adjust: writeLastOperand}
	// lnLayout is cpLayout, but ln TARGET creates the link in the current
	// directory.
	lnLayout = &argLayout{
		opts:   cpOpts,
		values: map[string]argRole{"t": roleWrite},
		adjust: func(p parsedArgs, r *argRoles) {
			if !p.has("t") && len(p.operands) == 1 {
				r.write(".")
			}
			writeLastOperand(p, r)
		},
	}

	// installLayout: install -d creates every operand; otherwise it writes
	// its -t directory or its last operand.
	installLayout = &argLayout{
		opts:   installSpec,
		values: map[string]argRole{"t": roleWrite},
		adjust: func(p parsedArgs, r *argRoles) {
			if p.has("d") {
				for _, i := range p.operands {
					r.set(i, roleWrite)
				}
				return
			}
			writeLastOperand(p, r)
		},
	}

	// chmodLayout: GNU chmod parses a mode like -w or -rwx as options with
	// an optional value ("r::w::x::..."), and then every operand is a file;
	// otherwise (or with --reference) the first operand is the mode. BSD
	// chmod stops at a mode instead, which is the same split.
	chmodLayout = &argLayout{
		opts: optSpec{
			long:     []string{"reference"},
			optional: "rwxXstugoa,+=01234567",
			flags:    []string{"changes", "no-preserve-root", "preserve-root", "quiet", "silent", "verbose", "recursive", "help", "version"},
		},
		lead:       1,
		operands:   roleWrite,
		leadUnless: []string{"r", "w", "x", "X", "s", "t", "u", "g", "o", "a", ",", "+", "=", "0", "1", "2", "3", "4", "5", "6", "7", "reference"},
	}
	// chownLayout: the first operand is the owner (or group), unless
	// --reference supplies it.
	chownLayout = &argLayout{
		opts: optSpec{
			long:  []string{"from", "reference"},
			flags: []string{"changes", "dereference", "no-dereference", "no-preserve-root", "preserve-root", "quiet", "silent", "verbose", "recursive", "help", "version"},
		},
		lead:       1,
		operands:   roleWrite,
		leadUnless: []string{"reference"},
	}

	// compressLayouts: gzip, bzip2, xz, and their decompressors replace
	// each operand with its (de)compressed file beside it, unless the
	// output goes to stdout or nothing is written.
	gzipLayout  = compressLayout(gzipSpec)
	xzLayout    = compressLayout(xzSpec)
	bzip2Layout = compressLayout(optSpec{})

	// splitLayout: split [FILE [PREFIX]] writes PREFIXaa, PREFIXab, ...
	// (default x).
	splitLayout = &argLayout{
		opts: splitSpec,
		adjust: func(p parsedArgs, r *argRoles) {
			if len(p.operands) < 2 {
				r.write("x")
				return
			}
			for _, i := range p.operands[1:] {
				r.set(i, roleWrite)
			}
		},
	}
	// csplitLayout: csplit writes PREFIX followed by the suffix format
	// (default xx%02d); the format may hold a "/", so the two are checked
	// joined.
	csplitLayout = &argLayout{
		opts: optSpec{short: "bfn", long: []string{"suffix-format", "prefix", "digits"}},
		adjust: func(p parsedArgs, r *argRoles) {
			prefix, suffix := "xx", ""
			if v := p.values("f", "prefix"); len(v) > 0 {
				prefix = v[len(v)-1]
			}
			if v := p.values("b", "suffix-format"); len(v) > 0 {
				suffix = v[len(v)-1]
			}
			r.write(prefix + suffix)
		},
	}
	// mktempLayout: mktemp writes its template, under each -p directory.
	mktempLayout = &argLayout{
		opts:     optSpec{short: "p", flags: []string{"directory", "dry-run", "quiet", "suffix", "tmpdir", "help", "version"}},
		values:   map[string]argRole{"p": roleWrite, "tmpdir": roleWrite},
		operands: roleWrite,
		adjust: func(p parsedArgs, r *argRoles) {
			for _, d := range p.values("p", "tmpdir") {
				for _, t := range p.operandWords() {
					if d != "" && t != "" {
						r.write(filepath.Join(d, t))
					}
				}
			}
		},
	}
	// yqLayout: yq -i rewrites its files.
	yqLayout = &argLayout{
		opts: optSpec{short: "Iops", long: []string{"indent", "output-format", "input-format", "split-exp", "expression"}},
		adjust: func(p parsedArgs, r *argRoles) {
			if p.has("i", "inplace") {
				for _, i := range p.operands {
					r.set(i, roleWrite)
				}
			}
		},
	}
)

// outputOptionLayout is the layout of a command that writes only the file
// its -o/--output option names (sort, shuf, iconv).
func outputOptionLayout(opts optSpec) *argLayout {
	return &argLayout{opts: opts, values: map[string]argRole{"o": roleWrite, "output": roleWrite}}
}

// secondOperandLayout is the layout of a command whose second operand is
// its output file (uniq INPUT OUTPUT, xxd infile outfile).
func secondOperandLayout(opts optSpec) *argLayout {
	return &argLayout{opts: opts, lead: 1, operands: roleWrite}
}

// compressLayout is the layout of a compressor (see gzipLayout).
func compressLayout(opts optSpec) *argLayout {
	return &argLayout{
		opts:     opts,
		operands: roleWrite,
		adjust: func(p parsedArgs, r *argRoles) {
			if p.has("c", "stdout", "to-stdout", "t", "test", "l", "list") {
				for _, i := range p.operands {
					r.set(i, roleDefault)
				}
			}
		},
	}
}

// writeLastOperand writes the last operand of cp, ln, and install when no
// -t directory names the destination and there are a source and a
// destination.
func writeLastOperand(p parsedArgs, r *argRoles) {
	if p.has("t") || len(p.operands) < 2 {
		return
	}
	if i, ok := lastOperand(p); ok {
		r.set(i, roleWrite)
	}
}
