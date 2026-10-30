package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
)

// scp and rsync are allowed once one of the ssh section's hosts allows writes
// (write: true), and then copy only to and from such hosts: every remote
// operand (and rsync's remote --files-from) must name one, and every jump host
// must be listed. They run ssh to the host, which runs scp's or rsync's own
// program there, a remote command the read-only check could not hold.
//
// The options that run a program here (scp -S and -D, rsync -e other than
// ssh with ssh's allowed options), forward the agent (scp -A), reach an
// rsync daemon (host::module, rsync://, --port, --password-file, ...), or
// read rules from files the path checks do not see (rsync's merge filter
// rules and -F) are refused, as are the ones that follow symlinks out of the
// files sent (scp -r and rsync -L, -k, --copy-unsafe-links from a local
// source) or write through them on the local side (rsync -K into a local
// destination), and rsync's batch modes.
//
// Local paths are held to the path boundary: what the copy reads (local
// sources, -i, --exclude-from, ...) to the read set, what it writes (a local
// destination, --log-file, --backup-dir, ...) to the write set (see
// copyReads and writeTargets). Remote paths are left alone.

// copyOperand is an scp or rsync operand.
type copyOperand struct {
	word   string
	remote bool
	host   string // the remote host, as ssh is given it (no user@, brackets)
	daemon bool   // rsync: host::module or rsync://, an rsync daemon
}

// copyArgs is an scp or rsync command line taken apart.
type copyArgs struct {
	name     string // "scp" or "rsync"
	sources  []copyOperand
	dest     *copyOperand // nil when there is none (rsync lists its source)
	jumps    []string     // -J and ProxyJump values
	hosts    []string     // other remote hosts the copy reaches (rsync --files-from=host:)
	reads    []string     // local files the options read (-i, --exclude-from, ...)
	writes   []string     // local files the options write (--log-file, ...)
	refusal  error        // the first option refused, after the whole parse
	noCopy   bool         // --version, --help: nothing is copied
	recurses bool         // scp -r

	// rsync's options that depend on which side is local.
	followsLinks  string   // -L, -k, --copy-unsafe-links: the sender follows symlinks
	keepDirlinks  string   // -K: the receiver writes through symlinked directories
	trustSender   bool     // --trust-sender
	removeSources bool     // --remove-source-files
	destWrites    []string // --backup-dir, --temp-dir, --link-dest: on the receiver
	destReads     []string // --compare-dest, --copy-dest: on the receiver
	partialDir    string   // --partial-dir: on the receiver
}

// refuse records the first refused option; the parse goes on so the path
// checks still see every local file.
func (c *copyArgs) refuse(format string, a ...any) {
	if c.refusal == nil {
		c.refusal = fmt.Errorf(format, a...)
	}
}

// localSources returns the local source operands.
func (c *copyArgs) localSources() []string {
	var out []string
	for _, o := range c.sources {
		if !o.remote {
			out = append(out, o.word)
		}
	}
	return out
}

// localDest returns the local destination operand, or "".
func (c *copyArgs) localDest() string {
	if c.dest == nil || c.dest.remote {
		return ""
	}
	return c.dest.word
}

// parseCopyArgs parses an scp or rsync argv (command name at index 0). An
// error means the command line could not be taken apart; an option it refuses
// is in the result's refusal instead.
func parseCopyArgs(args []string) (copyArgs, error) {
	switch args[0] {
	case "scp":
		return parseSCPArgs(args)
	case "rsync":
		return parseRsyncArgs(args)
	}
	return copyArgs{}, fmt.Errorf("%s is not scp or rsync", args[0])
}

// scp's options (OpenSSH 9.6 getopt string
// "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:"). Options end at the first
// operand.
const (
	scpFlagsNoValue   = "12346ABCTdfOpqRrstv"
	scpFlagsWithValue = "DFJMPSciloX"
)

var scpRefusedFlags = map[byte]string{
	'A': "forwards the ssh agent to the remote host",
	'D': "runs a local SFTP server program",
	'S': "names the program scp runs for the connection",
	'd': "is scp's server mode",
	'f': "is scp's server mode",
	't': "is scp's server mode",
	'M': "is not an scp option",
	'1': "is not supported",
}

// parseSCPArgs parses an scp argv.
func parseSCPArgs(args []string) (copyArgs, error) {
	c := copyArgs{name: "scp"}
	var ssh sshArgs // collects -o's ProxyJump values
	i := 1
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
	bundle:
		for j := 1; j < len(a); j++ {
			ch := a[j]
			if why, ok := scpRefusedFlags[ch]; ok {
				c.refuse("scp option -%c is not allowed: %s", ch, why)
			}
			if strings.IndexByte(scpFlagsNoValue, ch) >= 0 {
				if ch == 'r' {
					c.recurses = true
				}
				continue
			}
			if strings.IndexByte(scpFlagsWithValue, ch) < 0 {
				return c, fmt.Errorf("scp option -%c is not allowed: unknown option", ch)
			}
			val := a[j+1:]
			if val == "" {
				if i+1 >= len(args) {
					return c, fmt.Errorf("scp option -%c needs a value", ch)
				}
				i++
				val = args[i]
			}
			switch ch {
			case 'i':
				c.reads = append(c.reads, val)
			case 'F':
				if val != "none" {
					c.refuse("scp option -F %s is not allowed: a config file can name programs for ssh to run here (ProxyCommand, LocalCommand); only -F none is", val)
				}
			case 'J':
				if val != "none" {
					c.jumps = append(c.jumps, val)
				}
			case 'o':
				if err := ssh.configOption(val); err != nil {
					c.refuse("scp: %w", err)
				}
			}
			break bundle
		}
	}
	c.jumps = append(c.jumps, ssh.jumps...)
	ops := args[i:]
	if len(ops) < 2 {
		// scp prints its usage.
		c.noCopy = true
		return c, nil
	}
	for _, w := range ops[:len(ops)-1] {
		c.sources = append(c.sources, scpOperand(w))
	}
	dest := scpOperand(ops[len(ops)-1])
	c.dest = &dest
	if c.recurses && len(c.localSources()) > 0 {
		c.refuse("scp -r from a local directory is not allowed: scp follows the symlinks in it, out of the files it was given; copy directories with rsync -r, which copies symlinks as symlinks")
	}
	return c, nil
}

// scpOperand classifies an scp operand the way scp does: remote when it has a
// colon before any slash (a leading colon is part of a file name; brackets
// hold an IPv6 address), as [user@]host:path or scp://[user@]host[:port]/path.
func scpOperand(w string) copyOperand {
	o := copyOperand{word: w}
	colon := scpColon(w)
	if colon < 0 {
		return o
	}
	o.remote = true
	if rest, ok := strings.CutPrefix(w, "scp://"); ok {
		// scp://[user@]host[:port][/path]: the user ends at the first @.
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			rest = rest[at+1:]
		}
		if strings.HasPrefix(rest, "[") {
			if end := strings.IndexByte(rest, ']'); end > 0 {
				o.host = rest[1:end]
				return o
			}
		}
		if end := strings.IndexAny(rest, ":/"); end >= 0 {
			rest = rest[:end]
		}
		o.host = rest
		return o
	}
	host := w[:colon]
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	o.host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return o
}

// scpColon returns the index of the colon that ends an scp operand's host, or
// -1 for a local path (OpenSSH's colon()).
func scpColon(s string) int {
	if strings.HasPrefix(s, ":") {
		return -1
	}
	bracket := strings.HasPrefix(s, "[")
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '@' && i+1 < len(s) && s[i+1] == '[':
			bracket = true
		case s[i] == ']' && i+1 < len(s) && s[i+1] == ':' && bracket:
			return i + 1
		case s[i] == ':' && !bracket:
			return i
		case s[i] == '/':
			return -1
		}
	}
	return -1
}

// rsyncOption is how the rsync validator treats one of rsync's options.
type rsyncOption int

const (
	rsyncFlag         rsyncOption = iota // no value
	rsyncValue                           // a value that names no local file
	rsyncRefused                         // never allowed (rsyncRefusedOptions has the reason)
	rsyncReadFile                        // a local file read (--exclude-from, "-" for stdin)
	rsyncFilesFrom                       // --files-from: a local file, or host:file
	rsyncWriteFile                       // a local file written (--log-file)
	rsyncDestWrite                       // a directory on the receiver, relative to the destination, written
	rsyncDestRead                        // a directory on the receiver, relative to the destination, read
	rsyncPartialDir                      // --partial-dir
	rsyncRsh                             // -e/--rsh
	rsyncFilter                          // -f/--filter
	rsyncFollowLinks                     // -L, -k, --copy-unsafe-links (no value)
	rsyncKeepDirlinks                    // -K (no value)
	rsyncTrustSender                     // --trust-sender (no value)
	rsyncRemoveSource                    // --remove-source-files (no value)
	rsyncNoCopy                          // --version, --help (no value)
)

// rsyncLongOptions are rsync 3.2.7's long options (its popt table). popt
// takes a long option's value after = or as the next word, and matches only
// whole names.
var rsyncLongOptions = map[string]rsyncOption{
	"help": rsyncNoCopy, "version": rsyncNoCopy,
	"verbose": rsyncFlag, "no-verbose": rsyncFlag, "no-v": rsyncFlag,
	"info": rsyncValue, "debug": rsyncValue, "stderr": rsyncValue,
	"msgs2stderr": rsyncFlag, "no-msgs2stderr": rsyncFlag,
	"quiet": rsyncFlag, "motd": rsyncFlag, "no-motd": rsyncFlag, "stats": rsyncFlag,
	"human-readable": rsyncFlag, "no-human-readable": rsyncFlag, "no-h": rsyncFlag,
	"dry-run": rsyncFlag, "archive": rsyncFlag,
	"recursive": rsyncFlag, "no-recursive": rsyncFlag, "no-r": rsyncFlag,
	"inc-recursive": rsyncFlag, "no-inc-recursive": rsyncFlag, "i-r": rsyncFlag, "no-i-r": rsyncFlag,
	"dirs": rsyncFlag, "no-dirs": rsyncFlag, "no-d": rsyncFlag, "old-dirs": rsyncFlag, "old-d": rsyncFlag,
	"perms": rsyncFlag, "no-perms": rsyncFlag, "no-p": rsyncFlag, "executability": rsyncFlag,
	"acls": rsyncFlag, "no-acls": rsyncFlag, "no-A": rsyncFlag,
	"xattrs": rsyncFlag, "no-xattrs": rsyncFlag, "no-X": rsyncFlag,
	"times": rsyncFlag, "no-times": rsyncFlag, "no-t": rsyncFlag,
	"atimes": rsyncFlag, "no-atimes": rsyncFlag, "no-U": rsyncFlag,
	"open-noatime": rsyncFlag, "no-open-noatime": rsyncFlag,
	"crtimes": rsyncFlag, "no-crtimes": rsyncFlag, "no-N": rsyncFlag,
	"omit-dir-times": rsyncFlag, "no-omit-dir-times": rsyncFlag, "no-O": rsyncFlag,
	"omit-link-times": rsyncFlag, "no-omit-link-times": rsyncFlag, "no-J": rsyncFlag,
	"modify-window": rsyncValue,
	"super":         rsyncFlag, "no-super": rsyncFlag, "fake-super": rsyncFlag,
	"owner": rsyncFlag, "no-owner": rsyncFlag, "no-o": rsyncFlag,
	"group": rsyncFlag, "no-group": rsyncFlag, "no-g": rsyncFlag,
	"no-D": rsyncFlag, "devices": rsyncFlag, "no-devices": rsyncFlag, "copy-devices": rsyncFlag,
	"write-devices": rsyncFlag, "no-write-devices": rsyncFlag,
	"specials": rsyncFlag, "no-specials": rsyncFlag,
	"links": rsyncFlag, "no-links": rsyncFlag, "no-l": rsyncFlag,
	"copy-links": rsyncFollowLinks, "copy-unsafe-links": rsyncFollowLinks,
	"safe-links": rsyncFlag, "munge-links": rsyncFlag, "no-munge-links": rsyncFlag,
	"copy-dirlinks": rsyncFollowLinks, "keep-dirlinks": rsyncKeepDirlinks,
	"hard-links": rsyncFlag, "no-hard-links": rsyncFlag, "no-H": rsyncFlag,
	"relative": rsyncFlag, "no-relative": rsyncFlag, "no-R": rsyncFlag,
	"implied-dirs": rsyncFlag, "no-implied-dirs": rsyncFlag, "i-d": rsyncFlag, "no-i-d": rsyncFlag,
	"chmod": rsyncValue, "ignore-times": rsyncFlag, "size-only": rsyncFlag,
	"one-file-system": rsyncFlag, "no-one-file-system": rsyncFlag, "no-x": rsyncFlag,
	"update": rsyncFlag, "existing": rsyncFlag, "ignore-non-existing": rsyncFlag, "ignore-existing": rsyncFlag,
	"max-size": rsyncValue, "min-size": rsyncValue, "max-alloc": rsyncValue,
	"sparse": rsyncFlag, "no-sparse": rsyncFlag, "no-S": rsyncFlag, "preallocate": rsyncFlag,
	"inplace": rsyncFlag, "no-inplace": rsyncFlag,
	"append": rsyncFlag, "append-verify": rsyncFlag, "no-append": rsyncFlag,
	"del": rsyncFlag, "delete": rsyncFlag, "delete-before": rsyncFlag, "delete-during": rsyncFlag,
	"delete-delay": rsyncFlag, "delete-after": rsyncFlag, "delete-excluded": rsyncFlag,
	"delete-missing-args": rsyncFlag, "ignore-missing-args": rsyncFlag,
	"remove-sent-files": rsyncRemoveSource, "remove-source-files": rsyncRemoveSource,
	"force": rsyncFlag, "no-force": rsyncFlag, "ignore-errors": rsyncFlag, "no-ignore-errors": rsyncFlag,
	"max-delete": rsyncValue,
	"filter":     rsyncFilter, "exclude": rsyncValue, "include": rsyncValue,
	"exclude-from": rsyncReadFile, "include-from": rsyncReadFile,
	"cvs-exclude": rsyncFlag,
	"whole-file":  rsyncFlag, "no-whole-file": rsyncFlag, "no-W": rsyncFlag,
	"checksum": rsyncFlag, "no-checksum": rsyncFlag, "no-c": rsyncFlag,
	"checksum-choice": rsyncValue, "cc": rsyncValue, "block-size": rsyncValue,
	"compare-dest": rsyncDestRead, "copy-dest": rsyncDestRead, "link-dest": rsyncDestWrite,
	"fuzzy": rsyncFlag, "no-fuzzy": rsyncFlag, "no-y": rsyncFlag,
	"compress": rsyncFlag, "old-compress": rsyncFlag, "new-compress": rsyncFlag,
	"no-compress": rsyncFlag, "no-z": rsyncFlag,
	"compress-choice": rsyncValue, "zc": rsyncValue, "skip-compress": rsyncValue,
	"compress-level": rsyncValue, "zl": rsyncValue,
	"progress": rsyncFlag, "no-progress": rsyncFlag, "partial": rsyncFlag, "no-partial": rsyncFlag,
	"partial-dir":   rsyncPartialDir,
	"delay-updates": rsyncFlag, "no-delay-updates": rsyncFlag,
	"prune-empty-dirs": rsyncFlag, "no-prune-empty-dirs": rsyncFlag, "no-m": rsyncFlag,
	"log-file": rsyncWriteFile, "log-file-format": rsyncValue,
	"out-format": rsyncValue, "log-format": rsyncValue,
	"itemize-changes": rsyncFlag, "no-itemize-changes": rsyncFlag, "no-i": rsyncFlag,
	"bwlimit": rsyncValue, "no-bwlimit": rsyncFlag,
	"backup": rsyncFlag, "no-backup": rsyncFlag, "backup-dir": rsyncDestWrite, "suffix": rsyncValue,
	"list-only":  rsyncFlag,
	"read-batch": rsyncRefused, "write-batch": rsyncRefused, "only-write-batch": rsyncRefused,
	"files-from": rsyncFilesFrom, "from0": rsyncFlag, "no-from0": rsyncFlag,
	"old-args": rsyncFlag, "no-old-args": rsyncFlag,
	"secluded-args": rsyncFlag, "no-secluded-args": rsyncFlag,
	"protect-args": rsyncFlag, "no-protect-args": rsyncFlag, "no-s": rsyncFlag,
	"trust-sender": rsyncTrustSender,
	"numeric-ids":  rsyncFlag, "no-numeric-ids": rsyncFlag,
	"usermap": rsyncValue, "groupmap": rsyncValue, "chown": rsyncValue,
	"timeout": rsyncValue, "no-timeout": rsyncFlag,
	"contimeout": rsyncRefused, "no-contimeout": rsyncFlag,
	"fsync":      rsyncFlag,
	"stop-after": rsyncValue, "time-limit": rsyncValue, "stop-at": rsyncValue,
	"rsh": rsyncRsh, "rsync-path": rsyncValue, "temp-dir": rsyncDestWrite,
	"iconv": rsyncValue, "no-iconv": rsyncFlag,
	"ipv4": rsyncFlag, "ipv6": rsyncFlag,
	"8-bit-output": rsyncFlag, "no-8-bit-output": rsyncFlag, "no-8": rsyncFlag,
	"mkpath": rsyncFlag, "no-mkpath": rsyncFlag, "qsort": rsyncFlag,
	"copy-as": rsyncValue,
	"address": rsyncRefused, "port": rsyncRefused, "sockopts": rsyncRefused,
	"password-file": rsyncRefused, "early-input": rsyncRefused,
	"blocking-io": rsyncFlag, "no-blocking-io": rsyncFlag,
	"outbuf": rsyncValue, "remote-option": rsyncValue,
	"protocol": rsyncValue, "checksum-seed": rsyncValue,
	"server": rsyncRefused, "sender": rsyncRefused,
	"config": rsyncRefused, "daemon": rsyncRefused, "dparam": rsyncRefused,
	"detach": rsyncRefused, "no-detach": rsyncRefused,
}

// rsyncValueOptions are the refused long options that take a value, so the
// parse can step over it.
var rsyncValueOptions = []string{
	"read-batch", "write-batch", "only-write-batch", "contimeout", "address", "port",
	"sockopts", "password-file", "early-input", "config", "dparam",
}

// rsyncRefusedOptions gives the reason each refused long option is refused.
var rsyncRefusedOptions = map[string]string{
	"read-batch":       "batch files are not supported; run the transfer itself",
	"write-batch":      "batch files are not supported; run the transfer itself",
	"only-write-batch": "batch files are not supported; run the transfer itself",
	"contimeout":       "applies to an rsync daemon, which is not allowed",
	"address":          "applies to an rsync daemon, which is not allowed",
	"port":             "applies to an rsync daemon, which is not allowed",
	"sockopts":         "applies to an rsync daemon, which is not allowed",
	"password-file":    "applies to an rsync daemon, which is not allowed",
	"early-input":      "applies to an rsync daemon, which is not allowed",
	"server":           "is rsync's server mode",
	"sender":           "is rsync's server mode",
	"config":           "runs an rsync daemon",
	"daemon":           "runs an rsync daemon",
	"dparam":           "runs an rsync daemon",
	"detach":           "runs an rsync daemon",
	"no-detach":        "runs an rsync daemon",
}

// rsyncShortOptions maps rsync's short options to their long names; -D, -F,
// -P are aliases of several and listed apart.
var rsyncShortOptions = map[byte]string{
	'V': "version", 'v': "verbose", 'q': "quiet", 'h': "human-readable", 'n': "dry-run",
	'a': "archive", 'r': "recursive", 'd': "dirs", 'p': "perms", 'E': "executability",
	'A': "acls", 'X': "xattrs", 't': "times", 'U': "atimes", 'N': "crtimes",
	'O': "omit-dir-times", 'J': "omit-link-times", '@': "modify-window", 'o': "owner",
	'g': "group", 'l': "links", 'L': "copy-links", 'k': "copy-dirlinks", 'K': "keep-dirlinks",
	'H': "hard-links", 'R': "relative", 'I': "ignore-times", 'x': "one-file-system",
	'u': "update", 'S': "sparse", 'f': "filter", 'C': "cvs-exclude", 'W': "whole-file",
	'c': "checksum", 'B': "block-size", 'y': "fuzzy", 'z': "compress", 'm': "prune-empty-dirs",
	'i': "itemize-changes", 'b': "backup", '0': "from0", 's': "secluded-args",
	'e': "rsh", 'T': "temp-dir", '4': "ipv4", '6': "ipv6", '8': "8-bit-output", 'M': "remote-option",
	'D': "devices", 'P': "partial",
	'F': "", // dir-merge /.rsync-filter
}

// rsyncTakesValue reports whether a long option takes a value.
func rsyncTakesValue(name string) bool {
	switch rsyncLongOptions[name] {
	case rsyncValue, rsyncReadFile, rsyncFilesFrom, rsyncWriteFile, rsyncDestWrite,
		rsyncDestRead, rsyncPartialDir, rsyncRsh, rsyncFilter:
		return true
	case rsyncRefused:
		return slices.Contains(rsyncValueOptions, name)
	}
	return false
}

// parseRsyncArgs parses an rsync argv. popt reads options anywhere among the
// operands, until "--".
func parseRsyncArgs(args []string) (copyArgs, error) {
	c := copyArgs{name: "rsync"}
	var ops []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			ops = append(ops, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			ops = append(ops, a)
			continue
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			name, val, hasVal := strings.Cut(name, "=")
			if _, known := rsyncLongOptions[name]; !known {
				return c, fmt.Errorf("rsync option --%s is not allowed: unknown option", name)
			}
			if !rsyncTakesValue(name) {
				if hasVal {
					return c, fmt.Errorf("rsync option --%s takes no value", name)
				}
				c.option(name, "")
				continue
			}
			if !hasVal {
				if i+1 >= len(args) {
					return c, fmt.Errorf("rsync option --%s needs a value", name)
				}
				i++
				val = args[i]
			}
			c.option(name, val)
			continue
		}
		for j := 1; j < len(a); j++ {
			ch := a[j]
			name, ok := rsyncShortOptions[ch]
			if !ok {
				return c, fmt.Errorf("rsync option -%c is not allowed: unknown option", ch)
			}
			if ch == 'F' {
				c.refuse("rsync option -F is not allowed: it merges filter rules from .rsync-filter files, in the directories above the transfer too; use --exclude-from or --include-from")
				continue
			}
			if !rsyncTakesValue(name) {
				c.option(name, "")
				continue
			}
			// The rest of the word is the value (popt drops a leading =),
			// else the next word.
			val := strings.TrimPrefix(a[j+1:], "=")
			if j+1 == len(a) {
				if i+1 >= len(args) {
					return c, fmt.Errorf("rsync option -%c needs a value", ch)
				}
				i++
				val = args[i]
			}
			c.option(name, val)
			break
		}
	}
	if err := c.rsyncOperands(ops); err != nil {
		return c, err
	}
	c.rsyncSides()
	return c, nil
}

// option records one rsync option (by its long name) and its value.
func (c *copyArgs) option(name, val string) {
	switch rsyncLongOptions[name] {
	case rsyncRefused:
		c.refuse("rsync option --%s is not allowed: %s", name, rsyncRefusedOptions[name])
	case rsyncNoCopy:
		c.noCopy = true
	case rsyncReadFile:
		if val != "-" {
			c.reads = append(c.reads, val)
		}
	case rsyncFilesFrom:
		if val == "" || val == "-" {
			return
		}
		if o := rsyncOperand(val); o.remote {
			if o.daemon {
				c.refuse("rsync --files-from=%s is not allowed: it names an rsync daemon", val)
			} else if o.host != "" {
				c.hosts = append(c.hosts, o.host)
			}
			return
		}
		c.reads = append(c.reads, val)
	case rsyncWriteFile:
		c.writes = append(c.writes, val)
	case rsyncDestWrite:
		c.destWrites = append(c.destWrites, val)
	case rsyncDestRead:
		c.destReads = append(c.destReads, val)
	case rsyncPartialDir:
		c.partialDir = val
	case rsyncRsh:
		c.rsh(val)
	case rsyncFilter:
		if rsyncMergeRule(val) {
			c.refuse("rsync filter rule %q is not allowed: it merges rules from files the path checks do not see; use --exclude-from or --include-from", val)
		}
	case rsyncFollowLinks:
		c.followsLinks = "--" + name
	case rsyncKeepDirlinks:
		c.keepDirlinks = "--" + name
	case rsyncTrustSender:
		c.trustSender = true
	case rsyncRemoveSource:
		c.removeSources = true
	}
}

// rsyncMergeRule reports whether a filter rule merges rules from a file: a
// merge (".") or dir-merge (":") rule, by its short or long name.
func rsyncMergeRule(rule string) bool {
	rule = strings.TrimLeft(rule, " \t")
	if strings.HasPrefix(rule, ".") || strings.HasPrefix(rule, ":") {
		return true
	}
	for _, name := range []string{"merge", "dir-merge"} {
		if rest, ok := strings.CutPrefix(rule, name); ok && (rest == "" || strings.IndexByte(" ,_", rest[0]) >= 0) {
			return true
		}
	}
	return false
}

// rsh checks an -e/--rsh value: ssh, with options ssh's own check allows
// (the agent's ssh is the one that runs). rsync splits the value on
// whitespace and its own quoting, so quotes and backslashes are refused.
func (c *copyArgs) rsh(val string) {
	if strings.ContainsAny(val, `'"\`) {
		c.refuse("rsync -e %q is not allowed: write the ssh options without quotes or backslashes", val)
		return
	}
	words := strings.Fields(val)
	if len(words) == 0 || words[0] != "ssh" {
		c.refuse("rsync -e %q is not allowed: the remote shell must be ssh (rsync -e 'ssh -p 2222')", val)
		return
	}
	// Parse the options as ssh would, ahead of the host rsync adds.
	const host = "lite-sandbox-host"
	argv := append(slices.Clone(words), host)
	p, err := parseSSHArgs(argv)
	if err == nil && (p.dest != host || p.cmdIdx != len(argv) || p.endOpts) {
		err = fmt.Errorf("give ssh only options")
	}
	if err != nil {
		c.refuse("rsync -e %q is not allowed: %v", val, err)
		return
	}
	c.jumps = append(c.jumps, p.jumps...)
	for _, i := range p.pathIdx {
		c.reads = append(c.reads, argv[i])
	}
}

// rsyncOperands sorts rsync's operands into sources and a destination the
// way rsync does: a remote first source makes every source remote and the
// last operand the local destination (unless it starts with ":", another
// remote source); a local one makes every source local and the last operand
// the destination, local or remote. A lone operand is listed.
func (c *copyArgs) rsyncOperands(ops []string) error {
	if len(ops) == 0 {
		c.noCopy = true
		return nil
	}
	first := rsyncOperand(ops[0])
	last := ops[len(ops)-1]
	srcs := ops
	if len(ops) > 1 && !(first.remote && strings.HasPrefix(last, ":")) {
		srcs = ops[:len(ops)-1]
		if last == "" {
			last = "."
		}
		dest := rsyncOperand(last)
		c.dest = &dest
	}
	for _, w := range srcs {
		o := rsyncOperand(w)
		if o.remote && o.host == "" {
			// ":path" is another file from the first source's host.
			o.host = first.host
		}
		c.sources = append(c.sources, o)
	}
	return nil
}

// rsyncOperand classifies an rsync operand the way rsync does
// (check_for_hostspec): remote when [user@]host comes before a colon, with no
// slash before it (brackets may hold an IPv6 address at the host's start);
// host::module and rsync://host/module name a daemon. The host may be empty
// (":path").
func rsyncOperand(w string) copyOperand {
	o := copyOperand{word: w}
	if len(w) >= 8 && strings.EqualFold(w[:8], "rsync://") {
		o.remote, o.daemon = true, true
		return o
	}
	hostStart := 0
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case '/':
			return o
		case ':':
			o.remote = true
			o.host = strings.TrimSuffix(strings.TrimPrefix(w[hostStart:i], "["), "]")
			o.daemon = strings.HasPrefix(w[i+1:], ":")
			return o
		case '@':
			hostStart = i + 1
		case '[':
			if i != hostStart {
				return o
			}
			end := strings.IndexAny(w[i:], "]/")
			if end < 0 || w[i+end] != ']' || end == 1 {
				return o
			}
			if i+end+1 < len(w) && w[i+end+1] != ':' && w[i+end+1] != '/' {
				return o
			}
			i += end
		}
	}
	return o
}

// rsyncSides refuses the options that depend on which side is local: those
// that follow symlinks out of a local source, write through symlinks in a
// local destination, or drop the checks of what a remote sender sends; and
// collects what the receiver's directories (--backup-dir, ...) read and write
// when the destination is local.
func (c *copyArgs) rsyncSides() {
	if c.noCopy {
		return
	}
	localSender := len(c.localSources()) > 0
	if c.followsLinks != "" && localSender {
		c.refuse("rsync %s from a local source is not allowed: it follows symlinks out of the files it was given", c.followsLinks)
	}
	dest := c.localDest()
	if dest == "" {
		return
	}
	if c.keepDirlinks != "" {
		c.refuse("rsync %s into a local destination is not allowed: it writes through symlinked directories there", c.keepDirlinks)
	}
	if c.trustSender {
		c.refuse("rsync --trust-sender into a local destination is not allowed: it drops rsync's checks of the files a remote sender sends")
	}
	// A relative directory is relative to the destination directory: the
	// destination itself, or its parent when it names a file.
	for _, dirs := range []struct {
		vals []string
		into *[]string
	}{{c.destWrites, &c.writes}, {c.destReads, &c.reads}} {
		for _, d := range dirs.vals {
			if filepath.IsAbs(d) {
				*dirs.into = append(*dirs.into, d)
				continue
			}
			*dirs.into = append(*dirs.into, filepath.Join(dest, d), filepath.Join(filepath.Dir(dest), d))
		}
	}
	switch {
	case c.partialDir == "":
	case filepath.IsAbs(c.partialDir):
		c.writes = append(c.writes, c.partialDir)
	case strings.HasPrefix(filepath.Clean(c.partialDir), ".."):
		// Relative to each file's directory, at every depth of the tree.
		c.refuse("rsync --partial-dir=%s is not allowed: a relative partial directory is made beside each file, so it must stay inside the destination; name a directory under it, or an absolute one", c.partialDir)
	}
}

// copyReads returns the local files an scp or rsync invocation reads, and
// copyWrites the ones it writes, or nil when the command line cannot be
// taken apart (the generic path checks apply then).
func copyReads(args []string) []string {
	c, err := parseCopyArgs(args)
	if err != nil {
		return nil
	}
	return append(c.localSources(), c.reads...)
}

func copyWrites(args []string) []string {
	c, err := parseCopyArgs(args)
	if err != nil {
		return nil
	}
	out := slices.Clone(c.writes)
	if d := c.localDest(); d != "" {
		out = append(out, d)
	}
	if c.removeSources {
		out = append(out, c.localSources()...)
	}
	return out
}

// copyNonPathArgIndices returns every index of an scp or rsync argv when it
// can be taken apart: its local files are checked by copyReads and
// copyWrites instead, and its remote paths are not local files.
func copyNonPathArgIndices(args []string) map[int]bool {
	if _, err := parseCopyArgs(args); err != nil {
		return nil
	}
	skip := make(map[int]bool, len(args))
	for i := 1; i < len(args); i++ {
		skip[i] = true
	}
	return skip
}

// sshpassCopyArgs returns the scp or rsync argv sshpass runs, or nil.
func sshpassCopyArgs(args []string) []string {
	cmdIdx, _, _, err := parseSSHPassArgs(args)
	if err != nil || cmdIdx >= len(args) || !slices.Contains(config.SSHCopyCommands, args[cmdIdx]) {
		return nil
	}
	return args[cmdIdx:]
}

// validateCopyReads checks the local files scp and rsync read (directly or
// run by sshpass) against the read set.
func validateCopyReads(cmdName string, args []string, workDir string, read []resolvedAllowedPath) error {
	if cmdName == "sshpass" {
		if args = sshpassCopyArgs(args); args == nil {
			return nil
		}
	}
	for _, r := range copyReads(args) {
		if r == "" {
			continue // non-literal (re-checked after expansion)
		}
		if err := checkBoundary(r, r, workDir, false, read); err != nil {
			return err
		}
	}
	return nil
}

// checkCopyGlobs refuses an unquoted glob or brace the local shell could
// expand into an option or a remote operand: one before the word's first
// slash. After a slash it can only name more files under that directory.
func checkCopyGlobs(argv []string, glob []bool) error {
	for i := 1; i < len(argv); i++ {
		if !glob[i] {
			continue
		}
		w := argv[i]
		slash := strings.IndexByte(w, '/')
		if slash < 0 || strings.IndexAny(w, "*?[{") < slash {
			return fmt.Errorf("%s %s: an unquoted glob or brace before the first / could expand into an option or a host; start it with a directory (./*.log), or quote a remote path", argv[0], w)
		}
	}
	return nil
}

// copyHostFix is the remedy a refusal names for a host scp and rsync may not
// reach.
func copyHostFix(host string) string {
	return fmt.Sprintf("lite-sandbox config ssh hosts add %s --write", host)
}

// checkCopyArgv validates an scp or rsync argv against the ssh section.
func checkCopyArgv(argv []string, cfg *config.SSHConfig) error {
	name := argv[0]
	c, err := parseCopyArgs(argv)
	if err != nil {
		return err
	}
	if c.refusal != nil {
		return c.refusal
	}
	if c.noCopy {
		return nil
	}
	for _, o := range append(slices.Clone(c.sources), derefOperand(c.dest)...) {
		if o.daemon {
			return fmt.Errorf("%s %s is not allowed: it names an rsync daemon; copy over ssh (host:path)", name, o.word)
		}
	}
	for _, h := range sshJumpHostsAll(c.jumps) {
		if !cfg.AllowsHost(h) {
			return tagRule(ruleArgValidator, name, fmt.Errorf("%s through %q is not allowed: it is not one of the ssh hosts; the user can add it with `%s`", name, h, sshHostsFix(h)))
		}
	}
	var hosts []string
	for _, o := range append(slices.Clone(c.sources), derefOperand(c.dest)...) {
		if o.remote {
			hosts = append(hosts, o.host)
		}
	}
	for _, h := range append(hosts, c.hosts...) {
		entry := cfg.Host(h)
		switch {
		case entry == nil:
			// As for ssh, the remedy is in the message only (see
			// checkSSHArgv).
			return tagRule(ruleArgValidator, name, fmt.Errorf("%s with %q is not allowed: it is not one of the ssh hosts; the user can add it, allowing writes, with `%s`", name, h, copyHostFix(h)))
		case !entry.Writes():
			return tagRule(ruleArgValidator, name, fmt.Errorf("%s with %q is not allowed: scp and rsync copy only to and from ssh hosts that allow writes, and %s is held to read-only commands; the user can allow writes with `%s`", name, h, entry.Host, copyHostFix(entry.Host)))
		}
	}
	return nil
}

func derefOperand(o *copyOperand) []copyOperand {
	if o == nil {
		return nil
	}
	return []copyOperand{*o}
}

// validateCopyCommand is scp's and rsync's argument validator. Like ssh's,
// it applies once the ssh section lists a host, and leaves them to the
// whitelist (which lists them once a host allows writes) otherwise, so
// denylist mode runs them as it always has.
func validateCopyCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig().SSH
	if !cfg.HostsConfigured() {
		return nil
	}
	argv, glob, err := sshLiterals(args)
	if err != nil {
		return err
	}
	if err := checkCopyGlobs(argv, glob); err != nil {
		return err
	}
	return checkCopyArgv(argv, cfg)
}
