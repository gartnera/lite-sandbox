package bash_sandboxed

import (
	"fmt"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
)

// ssh and sshpass are allowed once the config's ssh section lists a host
// (config.SSHConfig), and then only to the listed hosts: the destination and
// every jump host must be one of them, exactly as typed (an alias of
// ~/.ssh/config or a host name). The remote command is held to read-only
// commands unless the destination's hosts entry widens it (see
// validators_ssh_remote.go).
//
// The options that make ssh reach anything but the destination, or run
// something on this machine, are refused: port and socket forwarding (-L, -R,
// -D, -W, -w), agent and X11 forwarding (-A, -X, -Y), GSSAPI delegation (-K),
// a PKCS#11 library (-I, which ssh loads into itself), an alternative config
// file (-F, whose ProxyCommand or LocalCommand would run here), connection
// sharing (-M, -S, -O), going to the background (-f), and a log file (-E).
// -o takes only the keys in sshOptionPolicy; the others (ProxyCommand,
// LocalCommand, KnownHostsCommand, Hostname, IdentityAgent, SendEnv, ...) are
// refused.
//
// The parse follows ssh's own: options up to the destination, options again
// after it up to the command, and "--" ending them.

// sshFlagsNoValue and sshFlagsWithValue are ssh's options (getopt string
// "1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XYy").
const (
	sshFlagsNoValue   = "1246afgkqnstvxACGKMNTVXYy"
	sshFlagsWithValue = "bceilmopBDEFIJLOPQRSWw"
)

// sshRefusedFlags are the options that are never allowed, with the reason.
var sshRefusedFlags = map[byte]string{
	'A': "forwards the ssh agent to the remote host",
	'X': "forwards the X11 display",
	'Y': "forwards the X11 display",
	'K': "delegates GSSAPI credentials to the remote host",
	'g': "lets remote hosts connect to forwarded ports",
	'f': "keeps ssh running in the background after the command returns",
	'M': "starts a connection-sharing master",
	'O': "controls a connection-sharing master",
	'D': "forwards ports (a SOCKS proxy to anywhere the remote host reaches)",
	'L': "forwards a local port to anywhere the remote host reaches",
	'R': "forwards a remote port to this machine",
	'W': "forwards stdin and stdout to another host",
	'w': "forwards a tunnel device",
	'E': "writes a log file; use -v, which logs to stderr",
	'I': "loads a PKCS#11 library into ssh",
}

// sshOptionPolicy lists the -o keys (lowercase) that are allowed. A nil
// value allows any value; otherwise the value must be one of those listed
// (compared case-insensitively). ProxyJump is checked like -J.
var sshOptionPolicy = map[string][]string{
	"addressfamily":                   nil,
	"batchmode":                       nil,
	"bindaddress":                     nil,
	"bindinterface":                   nil,
	"casignaturealgorithms":           nil,
	"challengeresponseauthentication": nil,
	"checkhostip":                     nil,
	"ciphers":                         nil,
	"clearallforwardings":             nil,
	"compression":                     nil,
	"connectionattempts":              nil,
	"connecttimeout":                  nil,
	"escapechar":                      nil,
	"exitonforwardfailure":            nil,
	"fingerprinthash":                 nil,
	"gssapiauthentication":            nil,
	"hashknownhosts":                  nil,
	"hostkeyalgorithms":               nil,
	"identitiesonly":                  nil,
	"ipqos":                           nil,
	"kbdinteractiveauthentication":    nil,
	"kexalgorithms":                   nil,
	"loglevel":                        nil,
	"logverbose":                      nil,
	"macs":                            nil,
	"numberofpasswordprompts":         nil,
	"obscurekeystroketiming":          nil,
	"passwordauthentication":          nil,
	"port":                            nil,
	"preferredauthentications":        nil,
	"pubkeyacceptedalgorithms":        nil,
	"pubkeyacceptedkeytypes":          nil,
	"pubkeyauthentication":            nil,
	"rekeylimit":                      nil,
	"remotecommand":                   nil,
	"requesttty":                      nil,
	"requiredrsasize":                 nil,
	"serveralivecountmax":             nil,
	"serveraliveinterval":             nil,
	"sessiontype":                     nil,
	"setenv":                          nil,
	"stdinnull":                       nil,
	"stricthostkeychecking":           nil,
	"tcpkeepalive":                    nil,
	"updatehostkeys":                  nil,
	"user":                            nil,
	"verifyhostkeydns":                nil,
	"visualhostkey":                   nil,
	"proxyjump":                       nil,
	// Off switches only.
	"addkeystoagent":            {"no"},
	"controlmaster":             {"no"},
	"forkafterauthentication":   {"no"},
	"forwardagent":              {"no"},
	"forwardx11":                {"no"},
	"forwardx11trusted":         {"no"},
	"gssapidelegatecredentials": {"no"},
	"permitlocalcommand":        {"no"},
	"tunnel":                    {"no"},
	"controlpath":               {"none"},
	"proxycommand":              {"none"},
	"identityagent":             {"none"},
	"userknownhostsfile":        {"/dev/null", "none"},
	"globalknownhostsfile":      {"/dev/null", "none"},
}

// sshArgs is an ssh command line taken apart the way ssh does.
type sshArgs struct {
	dest    string   // the destination as given
	jumps   []string // -J and -o ProxyJump values
	noDest  bool     // -V or -Q: ssh exits without connecting
	endOpts bool     // "--" ended the options
	cmdIdx  int      // index of the first word of the remote command, or len(args)
	pathIdx []int    // indices of words that name a local file (-i's value)

	// What the session runs, for the remote command check.
	noSession     bool     // -G (prints the config), -N or SessionType=none: nothing runs
	subsystem     bool     // -s or SessionType=subsystem: the command names a subsystem
	stdinNull     bool     // -n or StdinNull=yes: a login shell reads no commands
	tty           bool     // -t or RequestTTY=yes/force: the remote side gets a terminal
	remoteCommand bool     // -o RemoteCommand
	setEnv        []string // -o SetEnv values
}

// parseSSHArgs parses args (command name at index 0) and returns the
// destination, jump hosts, and the remote command's position, or the reason
// the invocation is refused.
func parseSSHArgs(args []string) (sshArgs, error) {
	p := sshArgs{cmdIdx: len(args)}
	terminated := false
	i := 1
	for i < len(args) {
		a := args[i]
		if !terminated && a == "--" {
			terminated = true
			p.endOpts = true
			i++
			continue
		}
		if !terminated && len(a) > 1 && a[0] == '-' {
			next, err := p.parseBundle(args, i)
			if err != nil {
				return p, err
			}
			i = next
			continue
		}
		if p.dest == "" && !p.noDest {
			p.dest = a
			i++
			continue
		}
		p.cmdIdx = i
		break
	}
	if p.dest == "" && !p.noDest {
		return p, fmt.Errorf("ssh needs a destination")
	}
	return p, nil
}

// parseBundle parses the option word args[i] (one or more bundled short
// options) and returns the index of the next word.
func (p *sshArgs) parseBundle(args []string, i int) (int, error) {
	a := args[i]
	for j := 1; j < len(a); j++ {
		c := a[j]
		if why, ok := sshRefusedFlags[c]; ok {
			return 0, fmt.Errorf("ssh option -%c is not allowed: %s", c, why)
		}
		if strings.IndexByte(sshFlagsNoValue, c) >= 0 {
			switch c {
			case 'V':
				p.noDest = true
			case 'G', 'N':
				p.noSession = true
			case 's':
				p.subsystem = true
			case 'n':
				p.stdinNull = true
			case 't':
				p.tty = true
			}
			continue
		}
		if strings.IndexByte(sshFlagsWithValue, c) < 0 {
			return 0, fmt.Errorf("ssh option -%c is not allowed: unknown option", c)
		}
		// The rest of the word is the value, else the next word.
		val, next, valIdx := a[j+1:], i+1, i
		if val == "" {
			if i+1 >= len(args) {
				return 0, fmt.Errorf("ssh option -%c needs a value", c)
			}
			val, next, valIdx = args[i+1], i+2, i+1
		} else if c == 'i' && j != 1 {
			// -qi/path: the path checks read the word as -q's value.
			return 0, fmt.Errorf("ssh option -i must not be bundled with other options; write it as its own -i %s", val)
		}
		if err := p.optionValue(c, val, valIdx); err != nil {
			return 0, err
		}
		return next, nil
	}
	return i + 1, nil
}

func (p *sshArgs) optionValue(c byte, val string, idx int) error {
	switch c {
	case 'i':
		p.pathIdx = append(p.pathIdx, idx)
	case 'F':
		if val != "none" {
			return fmt.Errorf("ssh option -F %s is not allowed: a config file can name programs for ssh to run here (ProxyCommand, LocalCommand); only -F none is", val)
		}
	case 'S':
		if val != "none" {
			return fmt.Errorf("ssh option -S %s is not allowed: connection sharing; only -S none is", val)
		}
	case 'J':
		if val != "none" {
			p.jumps = append(p.jumps, val)
		}
	case 'Q':
		p.noDest = true
	case 'o':
		return p.configOption(val)
	}
	return nil
}

// configOption checks one -o value against sshOptionPolicy.
func (p *sshArgs) configOption(opt string) error {
	opt = strings.TrimSpace(opt)
	end := strings.IndexAny(opt, " \t=")
	if end < 0 {
		return fmt.Errorf("ssh option -o %q has no value", opt)
	}
	key := strings.ToLower(opt[:end])
	val := strings.Trim(strings.TrimLeft(opt[end:], " \t="), `"`)
	allowed, ok := sshOptionPolicy[key]
	if !ok {
		hint := ""
		switch key {
		case "identityfile", "certificatefile":
			hint = "; pass the key with -i"
		case "hostname":
			hint = "; connect to the host by a name the ssh section lists"
		}
		return fmt.Errorf("ssh option -o %s is not allowed: only the options that keep ssh connecting to the destination, and running nothing on this machine, are%s", opt[:end], hint)
	}
	if allowed != nil && !slices.ContainsFunc(allowed, func(v string) bool { return strings.EqualFold(v, val) }) {
		return fmt.Errorf("ssh option -o %s=%s is not allowed: only %s", opt[:end], val, strings.Join(allowed, " or "))
	}
	switch key {
	case "proxyjump":
		if !strings.EqualFold(val, "none") {
			p.jumps = append(p.jumps, val)
		}
	case "sessiontype":
		p.noSession = p.noSession || strings.EqualFold(val, "none")
		p.subsystem = p.subsystem || strings.EqualFold(val, "subsystem")
	case "stdinnull":
		p.stdinNull = p.stdinNull || strings.EqualFold(val, "yes")
	case "requesttty":
		p.tty = p.tty || strings.EqualFold(val, "yes") || strings.EqualFold(val, "force")
	case "remotecommand":
		p.remoteCommand = !strings.EqualFold(val, "none")
	case "setenv":
		p.setEnv = append(p.setEnv, val)
	}
	return nil
}

// sshDestinationHost returns the host of an ssh destination:
// [user@]host or ssh://[user@]host[:port].
func sshDestinationHost(dest string) string {
	if rest, ok := strings.CutPrefix(dest, "ssh://"); ok {
		if i := strings.LastIndexByte(rest, '@'); i >= 0 {
			rest = rest[i+1:]
		}
		return stripSSHPort(rest)
	}
	if i := strings.LastIndexByte(dest, '@'); i >= 0 {
		dest = dest[i+1:]
	}
	return dest
}

// sshJumpHosts returns the hosts of a -J/ProxyJump value: comma-separated
// [user@]host[:port] or ssh:// destinations.
func sshJumpHosts(v string) []string {
	var out []string
	for _, hop := range strings.Split(v, ",") {
		if rest, ok := strings.CutPrefix(hop, "ssh://"); ok {
			hop = rest
		}
		if i := strings.LastIndexByte(hop, '@'); i >= 0 {
			hop = hop[i+1:]
		}
		out = append(out, stripSSHPort(hop))
	}
	return out
}

// stripSSHPort drops a :port from host[:port] or [v6]:port; a bare IPv6
// address (several colons, no brackets) is returned whole.
func stripSSHPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			return h[1:end]
		}
		return h
	}
	if strings.Count(h, ":") == 1 {
		h, _, _ = strings.Cut(h, ":")
	}
	return h
}

// sshHostsFix is the remedy a refusal names for a host the section does not
// list.
func sshHostsFix(host string) string {
	return fmt.Sprintf("lite-sandbox config ssh hosts add %s", host)
}

// checkSSHArgv validates an ssh argv against the ssh section.
func checkSSHArgv(argv []string, cfg *config.SSHConfig) error {
	p, err := parseSSHArgs(argv)
	if err != nil {
		return err
	}
	hosts := slices.Clone(sshJumpHostsAll(p.jumps))
	if !p.noDest {
		hosts = append([]string{sshDestinationHost(p.dest)}, hosts...)
	}
	for _, h := range hosts {
		if !cfg.AllowsHost(h) {
			// The remedy is in the message only, not the audit record's fix:
			// the agent picks the host it tries, so the report must not
			// propose adding it.
			return tagRule(ruleArgValidator, "ssh", fmt.Errorf("ssh to %q is not allowed: it is not one of the ssh hosts; the user can add it with `%s`", h, sshHostsFix(h)))
		}
	}
	if p.noDest {
		return nil
	}
	if err := checkSSHRemote(p, argv, cfg.Host(sshDestinationHost(p.dest))); err != nil {
		return tagRule(ruleArgValidator, "ssh", err)
	}
	return nil
}

func sshJumpHostsAll(jumps []string) []string {
	var out []string
	for _, j := range jumps {
		out = append(out, sshJumpHosts(j)...)
	}
	return out
}

// sshLiterals returns the words' values, and whether each is an unquoted glob
// or brace the local shell expands. A word that is only known after expansion
// is refused: the remote command is checked as written (and again on the
// runtime layer's expanded argv), and the hook modes run the command with no
// runtime layer.
//
// The runtime layer passes the expanded argv as words with no position
// (literalWords), whose values are taken as they are.
func sshLiterals(args []*syntax.Word) ([]string, []bool, error) {
	argv := make([]string, len(args))
	glob := make([]bool, len(args))
	for i, w := range args {
		if !w.Pos().IsValid() {
			argv[i] = w.Lit()
			continue
		}
		v, err := remoteWordValue(w)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: a variable, substitution, or $'...' in its words is not allowed: write them out, so the command it runs can be checked", args[0].Lit())
		}
		argv[i], glob[i] = v.val, v.glob
	}
	return argv, glob, nil
}

// checkSSHGlobs refuses a glob the local shell would expand in the remote
// command (from index cmdIdx of the ssh argv): it would turn into this
// machine's file names.
func checkSSHGlobs(argv []string, glob []bool, cmdIdx int) error {
	for i := cmdIdx; i < len(argv); i++ {
		if glob[i] {
			return fmt.Errorf("ssh %s: an unquoted glob or brace expands on this machine; quote it for the remote shell ('cat /var/log/*.log')", argv[i])
		}
	}
	return nil
}

// validateSSHCommand is ssh's argument validator. Without a host in the ssh
// section it leaves ssh to the whitelist (which does not list it then), so
// denylist mode runs ssh as it always has.
func validateSSHCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig().SSH
	if !cfg.HostsConfigured() {
		return nil
	}
	argv, glob, err := sshLiterals(args)
	if err != nil {
		return err
	}
	if err := checkSSHArgv(argv, cfg); err != nil {
		return err
	}
	p, _ := parseSSHArgs(argv)
	return checkSSHGlobs(argv, glob, p.cmdIdx)
}

// sshpass takes the password only from the environment (-e reads
// $SSHPASS), which the agent loads without seeing it:
//
//	export SSHPASS=$(cat ~/secrets/build-box.pw)
//	sshpass -e ssh build-box uptime
//
// -p would put the password in the command line the agent writes, and the
// other sources (-f, -d, and stdin with no option) are refused so there is one
// way to do it. $SSHPASS reaches sshpass alone: every other command's
// environment leaves it out (stripSSHPass).

// sshpassFix is the remedy a refused sshpass invocation names.
const sshpassFix = "load the password into the environment without printing it (export SSHPASS=$(cat <file>)) and run sshpass -e ssh ..."

// parseSSHPassArgs returns the index in args of the command sshpass runs
// (len(args) when there is none: -h, -V), the indices of sshpass's own words
// that are not local paths (the prompt), and whether -e was given.
// (getopt string "+f:d:p:P:heVv": options end at the first operand.)
func parseSSHPassArgs(args []string) (cmdIdx int, nonPath []int, env bool, err error) {
	i := 1
	for i < len(args) {
		a := args[i]
		if a == "--" {
			return i + 1, nonPath, env, nil
		}
		if len(a) < 2 || a[0] != '-' {
			return i, nonPath, env, nil
		}
		next := i + 1
		for j := 1; j < len(a); j++ {
			switch c := a[j]; c {
			case 'h', 'V':
				return len(args), nonPath, env, nil
			case 'v':
			case 'e':
				// sshpass 1.10 takes an optional variable name (-e[NAME]):
				// -eh or -eV would name a variable there, not ask for help,
				// and sshpass would then run whatever command follows.
				if j+1 < len(a) {
					return 0, nil, false, fmt.Errorf("sshpass option -e must be written on its own (sshpass 1.10 reads %q as the name of the password's variable); %s", a[j+1:], sshpassFix)
				}
				env = true
			case 'P':
				valIdx := i
				if j+1 == len(a) {
					if i+1 >= len(args) {
						return 0, nil, false, fmt.Errorf("sshpass option -P needs a value")
					}
					valIdx, next = i+1, i+2
				}
				nonPath = append(nonPath, valIdx)
				j = len(a)
			case 'p', 'f', 'd':
				return 0, nil, false, fmt.Errorf("sshpass option -%c is not allowed: the password comes from the environment only; %s", c, sshpassFix)
			default:
				return 0, nil, false, fmt.Errorf("sshpass option -%c is not allowed: unknown option", c)
			}
		}
		i = next
	}
	return len(args), nonPath, env, nil
}

// validateSSHPassCommand is sshpass's argument validator: like ssh's, it
// applies once the ssh section lists a host, and then sshpass takes the
// password from $SSHPASS (-e) and may only run ssh, whose arguments are
// checked as ssh's.
func validateSSHPassCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig().SSH
	if !cfg.HostsConfigured() {
		return nil
	}
	argv, glob, err := sshLiterals(args)
	if err != nil {
		return err
	}
	cmdIdx, _, env, err := parseSSHPassArgs(argv)
	if err != nil {
		return err
	}
	if cmdIdx >= len(argv) {
		return nil
	}
	if !env {
		return fmt.Errorf("sshpass without -e is not allowed: it would read the password from stdin; %s", sshpassFix)
	}
	if argv[cmdIdx] != "ssh" {
		return fmt.Errorf("sshpass may only run ssh, not %q", argv[cmdIdx])
	}
	if err := checkSSHArgv(argv[cmdIdx:], cfg); err != nil {
		return err
	}
	p, _ := parseSSHArgs(argv[cmdIdx:])
	return checkSSHGlobs(argv[cmdIdx:], glob[cmdIdx:], p.cmdIdx)
}

// validateSSHWrappedInput refuses an ssh or sshpass that a wrapper (xargs,
// find -exec) runs with words of its input, unless no input word can be read
// as an option, a host, or sshpass's command. ssh reads options again after
// the destination, so an input -oProxyCommand=... or -oHostname=... would
// escape the host check, and words appended to a sshpass with no command
// become the command it runs.
//
// With replace strings (xargs -I, -i, --replace, BSD -J; find's {}) the
// input replaces them in the words, so a word holding one must be part of
// the remote command, where ssh reads no options. Without (xargs's default)
// the input is appended: an ssh that names a remote command (or ends its
// options with --) takes it as more of that command. When the destination's
// remote command is held to read-only commands, the input may not reach the
// remote command at all: it is checked before the wrapper runs, and the
// remote shell would run the input as part of it. wrapper names the wrapper
// for messages. Applies once the ssh section lists a host, like the ssh
// validator.
func validateSSHWrappedInput(s *Sandbox, wrapper string, replace []string, args []*syntax.Word) error {
	if len(args) == 0 || !s.getConfig().SSH.HostsConfigured() {
		return nil
	}
	argv, _, err := sshLiterals(args)
	if err != nil {
		return err
	}
	name := argv[0]
	if name != "ssh" && name != "sshpass" {
		return nil
	}
	sshStart := 0
	if name == "sshpass" {
		cmdIdx, _, _, err := parseSSHPassArgs(argv)
		if err != nil {
			return err
		}
		if cmdIdx >= len(argv) {
			return fmt.Errorf("%s sshpass without a command is not allowed: the input %s adds would be the command sshpass runs", wrapper, wrapper)
		}
		sshStart = cmdIdx
	}
	p, err := parseSSHArgs(argv[sshStart:])
	if err != nil {
		return err
	}
	host := s.getConfig().SSH.Host(sshDestinationHost(p.dest))
	readOnly := !p.noDest && !p.noSession && host != nil && !host.Writes()
	errReadOnly := func() error {
		return fmt.Errorf("%s %s with its input in the remote command is not allowed: the command to %s is held to read-only commands, and the remote shell would run the input as part of it; run ssh for each input yourself, or the user can lift the check with --write", wrapper, name, host.Host)
	}
	if len(replace) > 0 {
		for i, w := range argv[1:] {
			i++ // index in argv
			if !slices.ContainsFunc(replace, func(r string) bool { return strings.Contains(w, r) }) {
				continue
			}
			j := i - sshStart // index in the ssh argv
			if i > sshStart && (j > p.cmdIdx || (j == p.cmdIdx && p.endOpts)) && !p.noDest {
				if readOnly {
					return errReadOnly()
				}
				continue
			}
			return fmt.Errorf("%s %s with its input replacing %q is not allowed: ssh could read the input as an option or a host; put the replace string in the remote command only (xargs -I{} ssh host cmd {})", wrapper, name, w)
		}
		return nil
	}
	if p.noDest {
		return nil
	}
	if readOnly {
		return errReadOnly()
	}
	if p.endOpts || p.cmdIdx < len(argv[sshStart:]) {
		return nil
	}
	return fmt.Errorf("%s %s without a remote command is not allowed: ssh reads the words %s appends after the destination as options; name the command (xargs ssh host cmd) or end the options with --", wrapper, name, wrapper)
}

// validateSSHUnderXargs is validateSSHWrappedInput for an ssh or sshpass
// that xargs runs; xargsOpts are xargs's own words before the command (xargs
// itself included), which set its replace strings.
func validateSSHUnderXargs(s *Sandbox, xargsOpts, args []*syntax.Word) error {
	if len(args) == 0 || !s.getConfig().SSH.HostsConfigured() {
		return nil
	}
	if name := args[0].Lit(); name != "ssh" && name != "sshpass" {
		return nil
	}
	opts, _, err := sshLiterals(xargsOpts)
	if err != nil {
		return err
	}
	return validateSSHWrappedInput(s, "xargs", xargsReplaceStrings(opts), args)
}

// xargsReplaceStrings returns the replace strings an xargs invocation's own
// words (opts, "xargs" first) set: -I R, -IR, BSD -J R, GNU -i[R] and
// --replace[=R] (both "{}" without R).
func xargsReplaceStrings(opts []string) []string {
	var out []string
	for i := 1; i < len(opts); i++ {
		a := opts[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			break
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			name, val, hasVal := strings.Cut(name, "=")
			if name != "" && strings.HasPrefix("replace", name) {
				if !hasVal {
					val = "{}"
				}
				out = append(out, val)
			}
			continue
		}
	bundle:
		for j := 1; j < len(a); j++ {
			rest := a[j+1:]
			switch c := a[j]; c {
			case 'I', 'J':
				if rest == "" && i+1 < len(opts) {
					i++
					rest = opts[i]
				}
				out = append(out, rest)
				break bundle
			case 'i':
				if rest == "" {
					rest = "{}"
				}
				out = append(out, rest)
				break bundle
			case 'e', 'l':
				// GNU optional values: the rest of the word.
				break bundle
			default:
				if xargsArgConsumingFlags["-"+string(c)] {
					if rest == "" {
						i++
					}
					break bundle
				}
			}
		}
	}
	return out
}

// sshNonPathArgIndices returns the indices of an ssh argv that are not local
// paths: everything but -i's value, so the destination, option values, and
// the remote command (cat /etc/hosts reads the remote host's file) are left
// to the validator. An invocation the parse refuses still runs in denylist
// mode without hosts (the validator leaves it alone there), so the values of
// all the options that name a local file (-i, -F, -E, -S) stay checked.
func sshNonPathArgIndices(args []string) map[int]bool {
	skip := make(map[int]bool, len(args))
	for i := 1; i < len(args); i++ {
		skip[i] = true
	}
	pathIdx := sshLocalPathIndices(args)
	if p, err := parseSSHArgs(args); err == nil {
		pathIdx = p.pathIdx
	}
	for _, i := range pathIdx {
		delete(skip, i)
	}
	return skip
}

// sshLocalPathIndices returns the indices of the words that hold the value of
// an ssh option naming a local file (-i, -F, -E, -S), the option word itself
// when the value is attached (-F./cfg), scanning the options before and after
// the destination the way ssh does, without refusing any.
func sshLocalPathIndices(args []string) []int {
	var out []int
	seenDest := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if len(a) < 2 || a[0] != '-' {
			if seenDest {
				break // the remote command
			}
			seenDest = true
			continue
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			if strings.IndexByte(sshFlagsWithValue, c) < 0 {
				continue
			}
			valIdx := i
			if j+1 == len(a) {
				i++
				valIdx = i
			}
			if strings.IndexByte("iFES", c) >= 0 && valIdx < len(args) {
				out = append(out, valIdx)
			}
			break
		}
	}
	return out
}

// sshpassNonPathArgIndices is sshNonPathArgIndices for sshpass: its prompt,
// and the ssh it runs.
func sshpassNonPathArgIndices(args []string) map[int]bool {
	cmdIdx, nonPath, _, err := parseSSHPassArgs(args)
	if err != nil {
		return nil
	}
	skip := make(map[int]bool)
	for _, i := range nonPath {
		skip[i] = true
	}
	if cmdIdx < len(args) && args[cmdIdx] == "ssh" {
		for i := range sshNonPathArgIndices(args[cmdIdx:]) {
			skip[cmdIdx+i] = true
		}
	}
	return skip
}
