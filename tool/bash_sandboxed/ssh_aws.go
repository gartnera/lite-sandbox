package bash_sandboxed

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

// A hosts entry with aws_credentials: true gets the brokered AWS credentials
// on the host: ssh forwards a loopback port there to the profile's IMDS
// server here, and the remote command runs with
// AWS_EC2_METADATA_SERVICE_ENDPOINT pointing at it, the way
//
//	ssh -o ExitOnForwardFailure=yes -R 127.0.0.1:<port>:127.0.0.1:<imds> box \
//	    'export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:<port>/ ...; <command>'
//
// would by hand. The argv is rewritten once every check has passed (the
// remote command check saw the command as written), for ssh and for the ssh
// sshpass runs, when they are invoked by name.
//
// The forward reaches one thing: an IMDS server lite-sandbox runs. Its port
// comes from the sandbox's own routing table (the default profile's, or the
// one AWS_PROFILE selects, as for any other command), never from the
// command's environment, so a command can't point the forward at another
// local port. The values put in the remote command are ours or held to
// characters no shell treats specially.

// sshAWSRemotePort picks the loopback port the forward listens on at the
// remote host: random, below Linux's default ephemeral range, so concurrent
// sessions to one host don't collide. A port that is taken there fails the
// command (ExitOnForwardFailure) rather than leaving the endpoint dead.
var sshAWSRemotePort = func() int { return 20000 + rand.IntN(12000) }

// awsEnvValue is what a region or timeout forwarded into the remote command
// may hold: nothing a shell reads as syntax, so it needs no quoting.
var awsEnvValue = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// sshPrepareExec is ssh's prepareExec: it adds the AWS credential forward for
// a destination whose entry asks for it.
func sshPrepareExec(ctx context.Context, s *Sandbox, args []string, _ execEnv) []string {
	return s.sshAWSForward(ctx, args)
}

// sshpassPrepareExec is sshpass's: the same, for the ssh it runs.
func sshpassPrepareExec(ctx context.Context, s *Sandbox, args []string, _ execEnv) []string {
	cmdIdx, _, _, err := parseSSHPassArgs(args)
	if err != nil || cmdIdx >= len(args) || args[cmdIdx] != "ssh" {
		return args
	}
	return slices.Concat(args[:cmdIdx], s.sshAWSForward(ctx, args[cmdIdx:]))
}

// sshAWSForward returns the ssh argv (command name first) with the AWS
// credential forward added, or argv unchanged when the destination's entry
// doesn't ask for it, no credentials are brokered, or the invocation runs no
// remote command (-N, -O, a subsystem, a login shell, -o RemoteCommand).
func (s *Sandbox) sshAWSForward(ctx context.Context, argv []string) []string {
	cfg := s.getConfig().SSH
	if !cfg.HostsConfigured() {
		return argv
	}
	p, err := parseSSHArgs(argv)
	if err != nil || p.noDest || p.noSession || p.subsystem || p.remoteCommand || p.cmdIdx >= len(argv) {
		return argv
	}
	if !cfg.Host(sshDestinationHost(p.dest)).ForwardsAWSCredentials() {
		return argv
	}
	env := map[string]string{}
	if hc := interp.HandlerCtx(ctx); hc.Env != nil {
		hc.Env.Each(func(name string, vr expand.Variable) bool {
			if isExportedEnvVar(vr) {
				env[name] = vr.String()
			}
			return true
		})
	}
	t, ok := s.sshAWSTarget(env)
	if !ok {
		return argv
	}
	return sshWithAWSForward(argv, p.cmdIdx, sshAWSRemotePort(), t)
}

// sshAWSTarget is what to forward for a command whose exported environment is
// env: the local IMDS port and the region and metadata timeout the command
// would get here.
type sshAWSTarget struct {
	imdsPort, region, timeout string
}

// sshAWSTarget resolves the IMDS server the command would use here (the
// default profile's, or the AWS_PROFILE it selects), from the sandbox's own
// endpoints. ok is false when no credentials are brokered or the selected
// profile isn't one of them (commandEnv refuses the command then).
func (s *Sandbox) sshAWSTarget(env map[string]string) (sshAWSTarget, bool) {
	s.mu.RLock()
	endpoint := s.imdsEndpoint
	s.mu.RUnlock()
	if endpoint == "" {
		return sshAWSTarget{}, false
	}
	env = maps.Clone(env)
	// The endpoint is the sandbox's: a command's own value is dropped, so
	// it can't aim the forward elsewhere. routeAWSProfile replaces it with
	// the selected profile's, from the same table.
	env["AWS_EC2_METADATA_SERVICE_ENDPOINT"] = endpoint
	if err := s.routeAWSProfile(env); err != nil {
		return sshAWSTarget{}, false
	}
	u, err := url.Parse(env["AWS_EC2_METADATA_SERVICE_ENDPOINT"])
	if err != nil {
		return sshAWSTarget{}, false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host != "127.0.0.1" {
		return sshAWSTarget{}, false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return sshAWSTarget{}, false
	}
	t := sshAWSTarget{imdsPort: port, timeout: awsMetadataTimeoutSeconds}
	if v := env["AWS_METADATA_SERVICE_TIMEOUT"]; v != "" {
		if _, err := strconv.ParseUint(v, 10, 32); err == nil {
			t.timeout = v
		}
	}
	// AWS_REGION wins over AWS_DEFAULT_REGION, as in the SDKs; one that
	// isn't a plain word is left out rather than replaced by the other.
	region := env["AWS_REGION"]
	if region == "" {
		region = env["AWS_DEFAULT_REGION"]
	}
	if awsEnvValue.MatchString(region) {
		t.region = region
	}
	return t, true
}

// sshWithAWSForward returns argv with the forward's options put first (ssh
// takes the first value of an option, so ExitOnForwardFailure can't be turned
// back off) and the exports put before the remote command, which starts at
// cmdIdx. ssh joins the remote command's words with spaces, so the exports
// are one more word.
func sshWithAWSForward(argv []string, cmdIdx, remotePort int, t sshAWSTarget) []string {
	opts := []string{
		"-o", "ExitOnForwardFailure=yes",
		"-R", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%s", remotePort, t.imdsPort),
	}
	exports := fmt.Sprintf("export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:%d/ AWS_METADATA_SERVICE_TIMEOUT=%s", remotePort, t.timeout)
	if t.region != "" {
		exports += fmt.Sprintf(" AWS_REGION=%s AWS_DEFAULT_REGION=%s", t.region, t.region)
	}
	return slices.Concat(argv[:1], opts, argv[1:cmdIdx], []string{exports + ";"}, argv[cmdIdx:])
}
