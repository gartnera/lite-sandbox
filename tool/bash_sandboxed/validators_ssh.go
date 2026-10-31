package bash_sandboxed

import (
	"fmt"
	"slices"
	"strconv"
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
// something on this machine, are refused: stdio and tunnel forwarding (-W,
// -w), agent and X11 forwarding (-A, -X, -Y), GSSAPI delegation (-K), a
// PKCS#11 library (-I, which ssh loads into itself), an alternative config
// file (-F, whose ProxyCommand or LocalCommand would run here), going to the
// background (-f), and a log file (-E). -o takes only the keys in
// sshOptionPolicy; the others (ProxyCommand, LocalCommand, KnownHostsCommand,
// Hostname, IdentityAgent, SendEnv, ...) are refused.
//
// Port forwarding (-L, -R, -D and their -o forms) and connection sharing (-M,
// -S, -O, ControlMaster, ControlPath, ControlPersist) are allowed to a host
// that allows writes only (checkSSHSharing), and are checked here as far as
// they touch this machine: a local listener binds to loopback, no forward
// names a local Unix socket, and a control socket's path holds %C, so a
// client can only reach a master to the host it names (see controlPath).
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
	'f': "keeps ssh running in the background after the command returns; use run_in_background, or ControlPersist for a connection-sharing master",
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
	// Forwarding and connection sharing, checked further in configOption and
	// allowed to a host that allows writes only (checkSSHSharing). ask and
	// autoask would run ssh-askpass here.
	"localforward":   nil,
	"remoteforward":  nil,
	"dynamicforward": nil,
	"controlpath":    nil,
	"controlpersist": nil,
	"controlmaster":  {"yes", "no", "auto"},
	// Off switches only.
	"addkeystoagent":            {"no"},
	"forkafterauthentication":   {"no"},
	"forwardagent":              {"no"},
	"forwardx11":                {"no"},
	"forwardx11trusted":         {"no"},
	"gssapidelegatecredentials": {"no"},
	"permitlocalcommand":        {"no"},
	"tunnel":                    {"no"},
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

	// Forwarding and connection sharing (checkSSHSharing).
	forwards    []string // -L, -R, -D and their -o forms, as "-L spec"
	controlPath string   // -S or -o ControlPath, unless none
	masters     int      // -M count; ControlMaster yes or auto counts one
	persist     bool     // -o ControlPersist
	controlCmd  string   // -O's command
}

// sharing describes the forwarding and connection sharing the command line
// asks for, or "" when it asks for none.
func (p sshArgs) sharing() string {
	var what []string
	if len(p.forwards) > 0 {
		what = append(what, "port forwarding ("+strings.Join(p.forwards, ", ")+")")
	}
	if p.controlPath != "" || p.masters > 0 || p.persist || p.controlCmd != "" {
		what = append(what, "connection sharing (-M, -S, -O, ControlMaster, ControlPath, ControlPersist)")
	}
	return strings.Join(what, " and ")
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
			case 'M':
				p.masters++
				if p.masters > 1 {
					return 0, fmt.Errorf("ssh option -M given twice is not allowed: it asks for confirmation with ssh-askpass, a program run on this machine; give -M once")
				}
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
		return p.setControlPath(val, "-S")
	case 'L', 'R', 'D':
		return p.addForward(c, val)
	case 'O':
		if !slices.Contains(sshControlCommands, val) {
			return fmt.Errorf("ssh option -O %s is not allowed: only -O %s", val, strings.Join(sshControlCommands, ", "))
		}
		p.controlCmd = val
		// The master runs the command; this ssh runs no session.
		p.noSession = true
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
	rawVal := strings.TrimLeft(opt[end:], " \t=")
	val := strings.Trim(rawVal, `"`)
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
		return fmt.Errorf("ssh option -o %s=%s is not allowed: %s may only be %s", opt[:end], strconv.Quote(rawVal), opt[:end], strings.Join(allowed, " or "))
	}
	switch key {
	case "localforward", "remoteforward":
		// LocalForward takes the listener and the target as two words, which
		// ssh joins with a colon.
		// RemoteForward may give the listener alone (a SOCKS proxy).
		kind := map[string]byte{"localforward": 'L', "remoteforward": 'R'}[key]
		f := strings.Fields(val)
		switch {
		case len(f) == 1 && kind == 'R':
			return p.addForward(kind, f[0])
		case len(f) != 2:
			return fmt.Errorf("ssh option -o %s=%s is not allowed: give the listener and the target (%s=\"8080 localhost:80\")", opt[:end], strconv.Quote(rawVal), opt[:end])
		}
		return p.addForward(kind, f[0]+":"+f[1])
	case "dynamicforward":
		return p.addForward('D', val)
	case "controlpath":
		return p.setControlPath(val, "-o ControlPath")
	case "controlmaster":
		if !strings.EqualFold(val, "no") {
			p.masters = max(p.masters, 1)
		}
	case "controlpersist":
		p.persist = !strings.EqualFold(val, "no")
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

// sshControlCommands are the -O commands allowed. proxy is left out: it hands
// this ssh's stdio to the master as a raw connection.
var sshControlCommands = []string{"check", "conninfo", "channels", "forward", "cancel", "exit", "stop"}

// setControlPath records a control socket path (-S or -o ControlPath). ssh
// expands ~, ${VAR}, and %-tokens in it; only %C (a hash of the local host,
// remote host, port, user, and jump hosts) and %% are allowed, and %C is
// required. A client given a path reaches whatever master listens there,
// whichever host it names, so a fixed path would let `ssh -S sock other-host
// cmd` be checked as other-host's command while it runs on the master's host;
// with %C the client's path is computed from the host it names, so it only
// finds a master to that host. The path is a file ssh creates, so it is also
// checked against the write set (sshControlPathWrites).
func (p *sshArgs) setControlPath(val, what string) error {
	if strings.EqualFold(val, "none") {
		p.controlPath = ""
		return nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("ssh option %s %s is not allowed: %s; use a path in the working directory with %%C in its name (%s cm-%%C)", what, val, why, what)
	}
	switch {
	case strings.HasPrefix(val, "~"):
		return refuse("ssh expands ~ itself")
	case strings.Contains(val, "$"):
		return refuse("ssh expands environment variables in it")
	}
	hasC := false
	for i := 0; i < len(val); i++ {
		if val[i] != '%' {
			continue
		}
		if i+1 >= len(val) {
			return refuse("it ends in a lone %")
		}
		switch val[i+1] {
		case 'C':
			hasC = true
		case '%':
		default:
			return refuse(fmt.Sprintf("ssh expands %%%c in it; only %%C and %%%% are allowed", val[i+1]))
		}
		i++
	}
	if !hasC {
		return refuse("without %C a client could reach a master to a different host than the one it names")
	}
	p.controlPath = val
	return nil
}

// addForward records a -L, -R, or -D spec (or its -o form) after checking the
// part of it on this machine: a local listener (-L, -D) binds to loopback, and
// nothing listens on or connects to a local Unix socket. The remote side (-R's
// listener, -L's target) is the remote host's business.
func (p *sshArgs) addForward(kind byte, spec string) error {
	refuse := func(why string) error {
		return fmt.Errorf("ssh option -%c %s is not allowed: %s", kind, spec, why)
	}
	f, err := sshForwardFields(spec)
	if err != nil {
		return refuse(err.Error())
	}
	// What ssh's parse_forward makes of the fields: the local listener's
	// address and whether it is a socket (-L, -D), and whether the local
	// target is a socket (-R).
	var listenAddr *string
	listenPath, localTargetPath := false, false
	switch kind {
	case 'D':
		switch len(f) {
		case 1:
			listenPath = f[0].path
		case 2:
			listenAddr = &f[0].arg
		default:
			return refuse("give [bind_address:]port")
		}
	case 'L':
		switch len(f) {
		case 2: // port:remote_socket, or local_socket:remote_socket
			listenPath = f[0].path
		case 3: // local_socket:host:port, bind:port:remote_socket, port:host:port
			switch {
			case f[0].path:
				listenPath = true
			case f[2].path:
				listenAddr = &f[0].arg
			}
		case 4:
			listenAddr = &f[0].arg
		default:
			return refuse("give [bind_address:]port:host:hostport")
		}
	case 'R':
		switch len(f) {
		case 1, 2: // [bind:]port: a SOCKS proxy from the remote host, or port:local_socket
			localTargetPath = len(f) == 2 && f[1].path
		case 3, 4: // ...:host:port or ...:local_socket
			localTargetPath = f[len(f)-1].path
		default:
			return refuse("give [bind_address:]port:host:hostport")
		}
	}
	switch {
	case listenPath:
		return refuse("a local Unix socket listener is not supported; forward a loopback port")
	case localTargetPath:
		return refuse("forwarding to a local Unix socket is not allowed: it could reach any socket on this machine (docker's, an agent's)")
	case listenAddr != nil && !isLoopbackBind(*listenAddr):
		return refuse(fmt.Sprintf("binding %q would open the port to other machines; bind localhost, 127.0.0.1, or ::1, or leave the address out", *listenAddr))
	}
	p.forwards = append(p.forwards, fmt.Sprintf("-%c %s", kind, spec))
	return nil
}

// sshForwardField is one colon-separated field of a forwarding spec.
type sshForwardField struct {
	arg  string
	path bool // a Unix socket path: it has a slash
}

// sshForwardFields splits a forwarding spec as ssh's parse_fwd_field does: on
// colons, a field in square brackets taken whole, and a field with a slash
// read as a Unix socket path. Backslash escapes are refused rather than
// followed.
func sshForwardFields(spec string) ([]sshForwardField, error) {
	if strings.Contains(spec, `\`) {
		return nil, fmt.Errorf("backslashes are not supported in it")
	}
	var out []sshForwardField
	rest := strings.TrimLeft(spec, " \t")
	for rest != "" {
		if len(out) == 4 {
			return nil, fmt.Errorf("it has more than four fields")
		}
		if rest[0] == '[' {
			end := strings.IndexByte(rest, ']')
			if end < 0 || (end+1 < len(rest) && rest[end+1] != ':') {
				return nil, fmt.Errorf("a bracketed field is not closed")
			}
			arg := rest[1:end]
			out = append(out, sshForwardField{arg: arg, path: strings.Contains(arg, "/")})
			rest = rest[min(end+2, len(rest)):]
			continue
		}
		arg, after, found := strings.Cut(rest, ":")
		out = append(out, sshForwardField{arg: arg, path: strings.Contains(arg, "/")})
		rest = after
		if found && rest == "" {
			// A trailing colon: ssh reads it as the end of the spec.
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("it is empty")
	}
	return out, nil
}

// isLoopbackBind reports whether a local forward's bind address keeps the
// listener on this machine. An empty address and * mean every interface.
func isLoopbackBind(addr string) bool {
	switch strings.ToLower(addr) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// checkSSHSharing refuses forwarding and connection sharing to a host that
// does not allow writes: a forward reaches past the remote command check
// (anything the remote host reaches, or this machine from there), and a
// connection-sharing master is a connection the check no longer sees.
// Starting a master (-M, ControlMaster) needs a control path given here, so
// it is never a socket the user's ssh config places outside the sandbox.
func checkSSHSharing(p sshArgs, host *config.SSHHost) error {
	what := p.sharing()
	if what == "" {
		return nil
	}
	if !host.Writes() {
		return fmt.Errorf("ssh with %s to %s is not allowed: only to a host that allows writes; the user can allow it with `lite-sandbox config ssh hosts add %s --write`", what, host.Host, host.Host)
	}
	if (p.masters > 0 || p.persist) && p.controlPath == "" {
		return fmt.Errorf("ssh starting a connection-sharing master is not allowed without a control path: give one in the working directory with %%C in its name (-S cm-%%C)")
	}
	return nil
}

// sshControlPathWrites returns the control socket an ssh argv creates or
// connects to, for the write-set check.
func sshControlPathWrites(args []string) []string {
	p, err := parseSSHArgs(args)
	if err != nil || p.controlPath == "" {
		return nil
	}
	return []string{p.controlPath}
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
	host := cfg.Host(sshDestinationHost(p.dest))
	if err := checkSSHSharing(p, host); err != nil {
		return tagRule(ruleArgValidator, "ssh", err)
	}
	if err := checkSSHRemote(p, argv, host); err != nil {
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
func sshLiterals(args []*syntax.Word) ([]string, []bool, error) {
	argv := make([]string, len(args))
	glob := make([]bool, len(args))
	for i, w := range args {
		v, bad := literalWord(w)
		if bad != nil {
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
// checked as ssh's, or, once a host allows writes, scp or rsync, checked as
// theirs.
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
	if slices.Contains(config.SSHCopyCommands, argv[cmdIdx]) {
		if !cfg.WriteHostsConfigured() {
			return commandNotAllowed(argv[cmdIdx])
		}
		if err := checkCopyGlobs(argv[cmdIdx:], glob[cmdIdx:]); err != nil {
			return err
		}
		return checkCopyArgv(argv[cmdIdx:], cfg)
	}
	if argv[cmdIdx] != "ssh" {
		return fmt.Errorf("sshpass may only run ssh, scp, or rsync, not %q", argv[cmdIdx])
	}
	if err := checkSSHArgv(argv[cmdIdx:], cfg); err != nil {
		return err
	}
	p, _ := parseSSHArgs(argv[cmdIdx:])
	return checkSSHGlobs(argv[cmdIdx:], glob[cmdIdx:], p.cmdIdx)
}

// validateSSHWrappedInput refuses an ssh or sshpass that a wrapper (xargs,
// find -exec) runs with words of its input, unless no input word can be read
// as an option, a host, or sshpass's command, and any scp or rsync a wrapper
// runs (errCopyWrapped). ssh reads options again after
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
	if slices.Contains(config.SSHCopyCommands, name) {
		return errCopyWrapped(wrapper, name)
	}
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
		if slices.Contains(config.SSHCopyCommands, argv[cmdIdx]) {
			return errCopyWrapped(wrapper, argv[cmdIdx])
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

// errCopyWrapped refuses an scp or rsync that a wrapper runs with words of
// its input: rsync reads options anywhere, and an input word with a colon
// is a remote operand, so the input could name a host or an option the
// check never sees.
func errCopyWrapped(wrapper, name string) error {
	return fmt.Errorf("%s %s is not allowed: the input %s adds could name a host or an option; run %s directly (rsync takes a list of remote files with --files-from)", wrapper, name, wrapper, name)
}

// validateSSHUnderXargs is validateSSHWrappedInput for an ssh or sshpass
// that xargs runs; xargsOpts are xargs's own words before the command (xargs
// itself included), which set its replace strings.
func validateSSHUnderXargs(s *Sandbox, xargsOpts, args []*syntax.Word) error {
	if len(args) == 0 || !s.getConfig().SSH.HostsConfigured() {
		return nil
	}
	if name := args[0].Lit(); name != "ssh" && name != "sshpass" && !slices.Contains(config.SSHCopyCommands, name) {
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
	sp := wrapperSpecs["xargs"].opts
	sp.stopAtOperand = true
	var out []string
	for _, o := range sp.scan(opts).opts {
		switch {
		case o.name == "I" || o.name == "J":
			out = append(out, o.value)
		case o.name == "i" && o.hasValue:
			out = append(out, o.value)
		case o.name == "i":
			out = append(out, "{}")
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
// and the ssh, scp, or rsync it runs.
func sshpassNonPathArgIndices(args []string) map[int]bool {
	cmdIdx, nonPath, _, err := parseSSHPassArgs(args)
	if err != nil {
		return nil
	}
	skip := make(map[int]bool)
	for _, i := range nonPath {
		skip[i] = true
	}
	if cmdIdx < len(args) {
		var inner map[int]bool
		switch args[cmdIdx] {
		case "ssh":
			inner = sshNonPathArgIndices(args[cmdIdx:])
		case "scp", "rsync":
			inner = copyNonPathArgIndices(args[cmdIdx:])
		}
		for i := range inner {
			skip[cmdIdx+i] = true
		}
	}
	return skip
}
