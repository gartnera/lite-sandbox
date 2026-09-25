package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// tar and unzip may list or extract. Extraction writes, so besides the flag
// checks here the extraction root is validated against the write set by
// validateArchiveWrites (called from the path layer, which knows the
// working directory). The entries inside an archive cannot be seen statically;
// they are kept under the extraction root by the tools' own defaults (leading
// "/" and "../" are stripped, and writes through symlinks the archive creates
// are refused), which is why the options that turn those defaults off are
// blocked here. The OS sandbox, when enabled, is what confines writes outright.
//
// The parsing is written to be correct for both GNU tar (Linux) and bsdtar
// (macOS). Where they disagree about an option it is blocked rather than
// guessed at, so the destination this code sees is the one either tar uses.

// tarBlockedShort lists tar short options that are never allowed, in either
// the dash form (-x...) or the old-style bundle (xf...).
var tarBlockedShort = map[byte]string{
	'c': "creates archives",
	'r': "appends to archives",
	'u': "updates archives",
	'A': "appends archives to an archive",
	'P': "keeps absolute paths and \"..\" in entry names",
	'I': "runs a compression program (GNU) or reads a file list (bsdtar)",
	'T': "reads a file list, which may change directory",
	'F': "runs a script at the end of each volume",
	'M': "multi-volume prompts can spawn a shell",
	'g': "incremental mode",
	'G': "incremental mode",
	's': "rewrites entry names (bsdtar); means something else in GNU tar",
	'L': "takes an argument in GNU tar but not in bsdtar",
	'H': "takes an argument in GNU tar but not in bsdtar",
}

// tarShortWithArg lists the allowed tar short options that take an argument:
// the rest of the cluster when non-empty, otherwise the next argument. Both
// GNU tar and bsdtar agree on these (or reject the option outright).
var tarShortWithArg = map[byte]bool{
	'b': true, // blocking factor
	'C': true, // change directory
	'f': true, // archive
	'K': true, // starting member (GNU)
	'N': true, // newer-than date (GNU)
	'V': true, // volume label (GNU)
	'X': true, // exclude-from file
}

// tarBlockedLong lists tar long options that are never allowed. A user's long
// option is rejected when it is a prefix of any of these, since both tars
// accept unambiguous abbreviations (e.g. --to-com for --to-command).
var tarBlockedLong = map[string]string{
	"create":                 "creates archives",
	"append":                 "appends to archives",
	"update":                 "updates archives",
	"delete":                 "deletes from archives",
	"catenate":               "appends archives to an archive",
	"concatenate":            "appends archives to an archive",
	"absolute-names":         "keeps absolute paths and \"..\" in entry names",
	"absolute-paths":         "keeps absolute paths and \"..\" in entry names",
	"insecure":               "disables extraction safety checks",
	"overwrite":              "writes through existing symlinks",
	"keep-directory-symlink": "writes through existing symlinks",
	"transform":              "rewrites entry names",
	"xform":                  "rewrites entry names",
	"one-top-level":          "extracts into another directory",
	"files-from":             "reads a file list, which may change directory",
	"use-compress-program":   "runs an arbitrary program",
	"to-command":             "runs an arbitrary program",
	"checkpoint-action":      "can run an arbitrary program",
	"info-script":            "runs an arbitrary script",
	"new-volume-script":      "runs an arbitrary script",
	"rsh-command":            "runs an arbitrary program",
	"rmt-command":            "runs an arbitrary program",
	"multi-volume":           "multi-volume prompts can spawn a shell",
	"index-file":             "writes to an arbitrary file",
	"volno-file":             "writes to an arbitrary file",
	"incremental":            "incremental mode",
	"listed-incremental":     "incremental mode",
}

// tarExactLong lists allowed long options that are also prefixes of a blocked
// one. An exact name wins over abbreviation matching (--file is --file, not an
// abbreviation of --files-from).
var tarExactLong = map[string]bool{
	"file":       true,
	"list":       true,
	"checkpoint": true,
}

// tarInvocation is what parseTarArgs learns from a tar command line.
type tarInvocation struct {
	list, extract bool
	// dirs holds the -C/--directory values in order ("" for a value that is
	// not a literal, which the static pass cannot check).
	dirs []string
}

// parseTarArgs parses a tar argv (args[0] is the command name). Arguments that
// are "" (non-literal words in the static pass) are skipped; the runtime layer
// re-runs this on the expanded argv.
func parseTarArgs(args []string) (tarInvocation, error) {
	var inv tarInvocation
	// value records the argument of an option that takes one.
	value := func(opt string, v string) error {
		switch opt {
		case "C":
			inv.dirs = append(inv.dirs, v)
		case "f":
			// GNU tar treats host:path (a colon before any slash) as a remote
			// archive reached through rsh.
			if colon := strings.IndexByte(v, ':'); colon >= 0 {
				if slash := strings.IndexByte(v, '/'); slash < 0 || slash > colon {
					return fmt.Errorf("tar archive %q is not allowed: GNU tar treats host:path as a remote archive (use ./%s)", v, v)
				}
			}
		}
		return nil
	}
	// nextValue consumes args[*i+1] as the value of opt. A value that looks
	// like an option is rejected: which argument it binds to is exactly where
	// implementations (and option permutation) could disagree.
	nextValue := func(i *int, opt string) error {
		if *i+1 >= len(args) {
			return nil
		}
		*i++
		v := args[*i]
		if strings.HasPrefix(v, "-") && v != "-" {
			return fmt.Errorf("tar option -%s value %q looks like an option; write it as -%s%s", opt, v, opt, v)
		}
		return value(opt, v)
	}

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "" || arg == "-" || arg == "--":
			// Non-literal, stdin/stdout operand, or end-of-options marker. Arguments
			// after "--" are still scanned: a stray option there can only make the
			// check stricter.
		case strings.HasPrefix(arg, "--"):
			name, v, hasValue := strings.Cut(arg[2:], "=")
			if !tarExactLong[name] {
				for blocked, reason := range tarBlockedLong {
					if strings.HasPrefix(blocked, name) {
						return inv, fmt.Errorf("tar flag %q is not allowed: %s", arg, reason)
					}
				}
			}
			switch {
			case name == "list":
				inv.list = true
			case strings.HasPrefix("extract", name) || strings.HasPrefix("get", name):
				inv.extract = true
			case name == "file" || name == "cd" || (len(name) >= 2 && strings.HasPrefix("directory", name)):
				opt := "f"
				if name != "file" {
					opt = "C"
				}
				var err error
				if hasValue {
					err = value(opt, v)
				} else {
					err = nextValue(&i, opt)
				}
				if err != nil {
					return inv, err
				}
			}
		case strings.HasPrefix(arg, "-"):
			flags := arg[1:]
			for j := 0; j < len(flags); j++ {
				c := flags[j]
				if reason, blocked := tarBlockedShort[c]; blocked {
					return inv, fmt.Errorf("tar flag '-%c' is not allowed: %s", c, reason)
				}
				switch c {
				case 't':
					inv.list = true
				case 'x':
					inv.extract = true
				}
				if tarShortWithArg[c] {
					var err error
					if rest := flags[j+1:]; rest != "" {
						err = value(string(c), rest)
					} else {
						err = nextValue(&i, string(c))
					}
					if err != nil {
						return inv, err
					}
					break
				}
			}
		case i == 1:
			// Old-style bundle ("tar xzf a.tgz"): letters that take an argument
			// consume the following arguments in order.
			for j := 0; j < len(arg); j++ {
				c := arg[j]
				if reason, blocked := tarBlockedShort[c]; blocked {
					return inv, fmt.Errorf("tar flag '%c' is not allowed: %s", c, reason)
				}
				switch c {
				case 't':
					inv.list = true
				case 'x':
					inv.extract = true
				}
				if tarShortWithArg[c] {
					if err := nextValue(&i, string(c)); err != nil {
						return inv, err
					}
				}
			}
		}
	}
	if !inv.list && !inv.extract {
		return inv, fmt.Errorf("tar is only allowed in list (-t/--list) or extract (-x/--extract) mode")
	}
	return inv, nil
}

// validateTarArgs allows tar in list or extract mode and blocks the options
// that create or modify archives, run programs, or let entries escape the
// extraction directory.
func validateTarArgs(_ *Sandbox, args []*syntax.Word) error {
	inv, err := parseTarArgs(wordLits(args))
	if err != nil {
		return err
	}
	// Relative -C values accumulate (each is relative to the previous one).
	// Keep extraction to a single -C so the destination is unambiguous.
	if inv.extract && len(inv.dirs) > 1 {
		return fmt.Errorf("tar extraction allows at most one -C/--directory")
	}
	return nil
}

// unzipReadOnlyFlags are unzip options that select a mode which writes nothing
// to disk: list, test, verbose list, extract to stdout, and archive comment.
var unzipReadOnlyFlags = map[byte]bool{
	'l': true,
	't': true,
	'v': true,
	'c': true,
	'p': true,
	'z': true,
}

// unzipInvocation is what parseUnzipArgs learns from an unzip command line.
type unzipInvocation struct {
	extract bool
	// dirs holds the -d values ("" for a non-literal value).
	dirs []string
}

// parseUnzipArgs parses an unzip argv (args[0] is the command name). Every
// argument is scanned for options, even after the zipfile, since unzip accepts
// -d there too; an option-looking member name only makes the check stricter.
func parseUnzipArgs(args []string) (unzipInvocation, error) {
	var inv unzipInvocation
	// zipinfo mode: when -Z is the first option the rest are zipinfo options,
	// all of which only print.
	if len(args) > 1 && strings.HasPrefix(args[1], "-Z") {
		return inv, nil
	}
	readOnly := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		flags := arg[1:]
	cluster:
		for j := 0; j < len(flags); j++ {
			switch c := flags[j]; c {
			case ':':
				return inv, fmt.Errorf("unzip flag '-:' is not allowed: keeps \"../\" in entry names, letting them escape the extraction directory")
			case 'T':
				return inv, fmt.Errorf("unzip flag '-T' is not allowed: modifies the archive's timestamp")
			case 'd', 'P':
				// The value is the rest of the cluster, or the next argument.
				v := flags[j+1:]
				if v == "" && i+1 < len(args) {
					i++
					v = args[i]
				}
				if c == 'd' {
					inv.dirs = append(inv.dirs, v)
				}
				break cluster
			default:
				if unzipReadOnlyFlags[c] {
					readOnly = true
				}
			}
		}
	}
	inv.extract = !readOnly
	return inv, nil
}

// validateUnzipArgs allows unzip to list, test, print, or extract, blocking
// the options that let entries escape the extraction directory.
func validateUnzipArgs(_ *Sandbox, args []*syntax.Word) error {
	_, err := parseUnzipArgs(wordLits(args))
	return err
}

// zipFlags are the zip short options allowed, all taking no value: quiet,
// recurse (paths, patterns), junk paths, store symlinks, no extra attributes,
// no directory entries, update, freshen, delete entries, verbose, test (runs
// the system `unzip -tqq`), grow, latest time, and the compression levels.
// '-' negates the option before it.
var zipFlags = map[byte]bool{
	'q': true, 'r': true, 'R': true, 'j': true, 'y': true, 'X': true,
	'D': true, 'u': true, 'f': true, 'd': true, 'v': true, 'T': true,
	'g': true, 'o': true, '-': true,
	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,
}

// zipValueFlags are the allowed zip short options that take a single value:
// password and compression method.
var zipValueFlags = map[byte]bool{'P': true, 'Z': true}

// zipListFlags are the zip options that take a list of patterns, running up
// to the next option: exclude and include.
var zipListFlags = map[byte]bool{'x': true, 'i': true}

// zipTwoCharOptions are zip's two-character short options. zip reads these in
// preference to two single-letter ones, so "-TT" is --unzip-command (which runs
// its value), not -T twice. None are allowed; a cluster containing one is
// rejected even when both letters are allowed alone.
var zipTwoCharOptions = map[string]bool{
	"AC": true, "AS": true, "C2": true, "C5": true, "db": true, "dc": true,
	"dd": true, "df": true, "DF": true, "dg": true, "ds": true, "du": true,
	"dv": true, "FF": true, "FI": true, "FS": true, "h2": true, "ic": true,
	"jj": true, "la": true, "lf": true, "li": true, "ll": true, "MM": true,
	"nw": true, "RE": true, "sb": true, "sc": true, "sf": true, "so": true,
	"sp": true, "su": true, "sU": true, "sv": true, "TT": true, "tt": true,
	"UN": true, "VV": true, "ws": true, "ww": true,
}

// zipLongFlags maps the allowed zip long options to their short equivalents.
var zipLongFlags = map[string]byte{
	"quiet":              'q',
	"recurse-paths":      'r',
	"recurse-patterns":   'R',
	"junk-paths":         'j',
	"symlinks":           'y',
	"no-extra":           'X',
	"no-dir-entries":     'D',
	"update":             'u',
	"freshen":            'f',
	"delete":             'd',
	"verbose":            'v',
	"test":               'T',
	"grow":               'g',
	"latest-time":        'o',
	"password":           'P',
	"compression-method": 'Z',
	"exclude":            'x',
	"include":            'i',
}

// parseZipArgs parses a zip argv (args[0] is the command name) and returns the
// archive it writes: the first operand ("" when that operand is not a literal,
// or there is none). zip's option grammar has one- and two-character short
// options and unique-prefix long options, so rather than blocking the
// dangerous ones (-TT runs a command, -@ reads unvalidated names from stdin,
// -m deletes the inputs, -b/-O/-lf write elsewhere) only a fixed set of
// options is accepted, spelled out in full.
func parseZipArgs(args []string) (string, error) {
	archive, haveArchive := "", false
	// nextValue consumes args[*i+1] as an option's value, rejecting one that
	// looks like an option (zip might parse it as one).
	nextValue := func(i *int, opt string) error {
		if *i+1 >= len(args) {
			return nil
		}
		*i++
		if v := args[*i]; strings.HasPrefix(v, "-") {
			return fmt.Errorf("zip option %s value %q looks like an option", opt, v)
		}
		return nil
	}
	// list handles -x/-i: its patterns follow up to the next option. zip moves
	// options ahead of operands, so a list before the archive would swallow it;
	// requiring the archive first keeps the first operand the archive.
	list := func(opt string) error {
		if !haveArchive {
			return fmt.Errorf("zip option %s must come after the archive name", opt)
		}
		return nil
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			// Operand ("" is a non-literal word in the static pass). The first is
			// the archive; the rest are inputs or list patterns.
			if !haveArchive {
				archive, haveArchive = arg, true
			}
		case arg == "--":
			// Still scanned past: a stray option there only makes the check stricter.
		case strings.HasPrefix(arg, "--"):
			name, _, hasValue := strings.Cut(arg[2:], "=")
			short, ok := zipLongFlags[strings.TrimSuffix(name, "-")]
			if !ok {
				return "", fmt.Errorf("zip option %q is not allowed (allowed: -0..-9 -q -r -R -j -y -X -D -u -f -d -v -T -g -o -P -Z -x -i, or their full long names)", arg)
			}
			switch {
			case zipListFlags[short]:
				if err := list(arg); err != nil {
					return "", err
				}
			case zipValueFlags[short] && !hasValue:
				if err := nextValue(&i, arg); err != nil {
					return "", err
				}
			}
		default:
			flags := arg[1:]
			for j := 0; j < len(flags); j++ {
				c := flags[j]
				if j+1 < len(flags) && zipTwoCharOptions[flags[j:j+2]] {
					return "", fmt.Errorf("zip option -%s is not allowed", flags[j:j+2])
				}
				if zipListFlags[c] || zipValueFlags[c] {
					opt := "-" + string(c)
					if zipListFlags[c] {
						if err := list(opt); err != nil {
							return "", err
						}
					} else if j == len(flags)-1 {
						if err := nextValue(&i, opt); err != nil {
							return "", err
						}
					}
					break // the rest of the cluster is the value
				}
				if !zipFlags[c] {
					return "", fmt.Errorf("zip option -%c is not allowed (allowed: -0..-9 -q -r -R -j -y -X -D -u -f -d -v -T -g -o -P -Z -x -i)", c)
				}
			}
		}
	}
	return archive, nil
}

// validateZipArgs allows zip with a fixed set of options (see parseZipArgs).
// The archive it writes is write-checked by validateArchiveWrites.
func validateZipArgs(_ *Sandbox, args []*syntax.Word) error {
	_, err := parseZipArgs(wordLits(args))
	return err
}

// validateArchiveWrites checks that tar, unzip, and zip write only inside the
// write set. An extracting tar or unzip writes into the working directory
// (always checked, since what an archive holds lands there unless redirected,
// and the check should not hinge on getting that redirection right) plus every
// -C/--directory (tar) or -d (unzip) destination; zip writes its archive.
// Parse errors are left to the argument validators.
func validateArchiveWrites(cmdName string, args []string, workDir string, write []resolvedAllowedPath) error {
	var dirs []string
	switch cmdName {
	case "tar":
		inv, err := parseTarArgs(args)
		if err != nil || !inv.extract {
			return nil
		}
		// tar changes directory for each -C in turn, so a relative value is
		// relative to the one before it.
		cur := workDir
		for _, d := range inv.dirs {
			if d == "" {
				cur = ""
				continue
			}
			if cur == "" {
				continue // follows a non-literal -C; checked at runtime
			}
			if filepath.IsAbs(d) {
				cur = d
			} else {
				cur = filepath.Join(cur, d)
			}
			dirs = append(dirs, cur)
		}
	case "unzip":
		inv, err := parseUnzipArgs(args)
		if err != nil || !inv.extract {
			return nil
		}
		for _, d := range inv.dirs {
			if d != "" {
				dirs = append(dirs, d)
			}
		}
	case "zip":
		// zip writes only the archive (and a temporary file beside it).
		archive, err := parseZipArgs(args)
		if err != nil || archive == "" || archive == "-" {
			return nil
		}
		return checkPathBoundary(archive, archive, workDir, true, write)
	default:
		return nil
	}
	if err := checkPathBoundary(".", ".", workDir, true, write); err != nil {
		return fmt.Errorf("%s extracts into the working directory: %w", cmdName, err)
	}
	for _, d := range dirs {
		if err := checkPathBoundary(d, d, workDir, true, write); err != nil {
			return err
		}
	}
	return nil
}
