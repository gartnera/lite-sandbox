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
// ~/.ssh/config or a host name). The remote command is not checked; it runs
// on a host the user listed.
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
	cmdIdx  int      // index of the first word of the remote command, or len(args)
	pathIdx []int    // indices of words that name a local file (-i's value)
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
			if c == 'V' {
				p.noDest = true
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
	if key == "proxyjump" && !strings.EqualFold(val, "none") {
		p.jumps = append(p.jumps, val)
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
	return nil
}

func sshJumpHostsAll(jumps []string) []string {
	var out []string
	for _, j := range jumps {
		out = append(out, sshJumpHosts(j)...)
	}
	return out
}

// sshLiterals returns the words' values, and false when one is only known
// after expansion: the runtime layer re-runs the validator on the expanded
// argv.
func sshLiterals(args []*syntax.Word) ([]string, bool) {
	argv := make([]string, len(args))
	for i, w := range args {
		v, ok := ghLiteral(w)
		if !ok {
			return nil, false
		}
		argv[i] = v
	}
	return argv, true
}

// validateSSHCommand is ssh's argument validator. Without a host in the ssh
// section it leaves ssh to the whitelist (which does not list it then), so
// denylist mode runs ssh as it always has.
func validateSSHCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig().SSH
	if !cfg.HostsConfigured() {
		return nil
	}
	argv, ok := sshLiterals(args)
	if !ok {
		return nil
	}
	return checkSSHArgv(argv, cfg)
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
	argv, ok := sshLiterals(args)
	if !ok {
		return nil
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
	return checkSSHArgv(argv[cmdIdx:], cfg)
}

// sshNonPathArgIndices returns the indices of an ssh argv that are not local
// paths: everything but -i's value, so the destination, option values, and
// the remote command (cat /etc/hosts reads the remote host's file) are left
// to the validator.
func sshNonPathArgIndices(args []string) map[int]bool {
	skip := make(map[int]bool, len(args))
	for i := 1; i < len(args); i++ {
		skip[i] = true
	}
	p, _ := parseSSHArgs(args)
	for _, i := range p.pathIdx {
		delete(skip, i)
	}
	return skip
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
