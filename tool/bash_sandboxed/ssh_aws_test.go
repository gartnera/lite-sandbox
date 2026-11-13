package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// argvPrinter writes a fake program that prints its arguments, one per line,
// into dir as name.
func argvPrinter(t *testing.T, dir, name string) {
	t.Helper()
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSSHAWSCredentialForward(t *testing.T) {
	bin := t.TempDir()
	argvPrinter(t, bin, "ssh")
	argvPrinter(t, bin, "sshpass")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_METADATA_SERVICE_TIMEOUT", "AWS_PROFILE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	orig := sshAWSRemotePort
	sshAWSRemotePort = func() int { return 25350 }
	t.Cleanup(func() { sshAWSRemotePort = orig })

	yes := true
	cfg := &config.Config{SSH: &config.SSHConfig{Hosts: []config.SSHHost{
		{Host: "dev-box", AWSCredentials: &yes, Commands: []string{"aws sts"}},
		{Host: "scratch", AWSCredentials: &yes, Write: &yes},
		{Host: "plain"},
	}}}
	newSandbox := func() *Sandbox {
		s := newTestSandboxWithConfig(cfg)
		s.SetIMDSEndpoint("http://127.0.0.1:4242/")
		s.SetIMDSRegion("us-west-2")
		s.SetIMDSProfiles(map[string]IMDSTarget{
			"ro":  {Endpoint: "http://127.0.0.1:4242/", Region: "us-west-2"},
			"dev": {Endpoint: "http://127.0.0.1:5353/", Region: "eu-central-1"},
		})
		return s
	}
	fwd := func(imds string) []string {
		return []string{"-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:25350:127.0.0.1:" + imds}
	}
	exports := func(region string) string {
		e := "export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:25350/ AWS_METADATA_SERVICE_TIMEOUT=30"
		if region != "" {
			e += " AWS_REGION=" + region + " AWS_DEFAULT_REGION=" + region
		}
		return e + ";"
	}
	cat := func(parts ...any) []string {
		var out []string
		for _, p := range parts {
			switch v := p.(type) {
			case string:
				out = append(out, v)
			case []string:
				out = append(out, v...)
			}
		}
		return out
	}

	tests := []struct {
		name    string
		command string
		noIMDS  bool
		want    []string
	}{
		{name: "forwarded", command: "ssh dev-box aws sts get-caller-identity",
			want: cat(fwd("4242"), "dev-box", exports("us-west-2"), "aws", "sts", "get-caller-identity")},
		{name: "options kept before the destination", command: "ssh -p 2222 me@dev-box -- uptime",
			want: cat(fwd("4242"), "-p", "2222", "me@dev-box", "--", exports("us-west-2"), "uptime")},
		{name: "case-insensitive host match", command: "ssh DEV-BOX uptime",
			want: cat(fwd("4242"), "DEV-BOX", exports("us-west-2"), "uptime")},
		{name: "selected profile", command: "AWS_PROFILE=dev ssh dev-box uptime",
			want: cat(fwd("5353"), "dev-box", exports("eu-central-1"), "uptime")},
		{name: "explicit region", command: "AWS_REGION=ap-south-1 ssh dev-box uptime",
			want: cat(fwd("4242"), "dev-box", exports("ap-south-1"), "uptime")},
		{name: "a region that is not a plain word is left out", command: "AWS_REGION='x;id' ssh dev-box uptime",
			want: cat(fwd("4242"), "dev-box", exports(""), "uptime")},
		{name: "the command's endpoint can't aim the forward", command: "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:22/ ssh dev-box uptime",
			want: cat(fwd("4242"), "dev-box", exports("us-west-2"), "uptime")},
		{name: "sshpass", command: "SSHPASS=x sshpass -e ssh dev-box uptime",
			want: cat("-e", "ssh", fwd("4242"), "dev-box", exports("us-west-2"), "uptime")},
		{name: "write host with its own forward", command: "ssh -L 8080:localhost:80 scratch uptime",
			want: cat(fwd("4242"), "-L", "8080:localhost:80", "scratch", exports("us-west-2"), "uptime")},

		{name: "host without aws_credentials", command: "ssh plain uptime", want: []string{"plain", "uptime"}},
		{name: "no session", command: "ssh -N dev-box", want: []string{"-N", "dev-box"}},
		{name: "no remote command", command: "ssh -n dev-box", want: []string{"-n", "dev-box"}},
		{name: "not brokered", command: "ssh dev-box uptime", noIMDS: true, want: []string{"dev-box", "uptime"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSandbox()
			if tt.noIMDS {
				s = newTestSandboxWithConfig(cfg)
			}
			dir := t.TempDir()
			out, err := s.Execute(context.Background(), tt.command, dir, []string{dir}, []string{dir})
			if err != nil {
				t.Fatalf("%s: %v\n%s", tt.command, err, out)
			}
			got := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
				t.Errorf("%s:\n got %q\nwant %q", tt.command, got, tt.want)
			}
		})
	}

	// The remote command check still sees the command as written.
	s := newSandbox()
	dir := t.TempDir()
	if _, err := s.Execute(context.Background(), "ssh dev-box aws s3 rm s3://b/k", dir, []string{dir}, []string{dir}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("aws on a read-only host: %v", err)
	}
	// So does the -R check: the agent's own forward to a read-only host.
	if _, err := s.Execute(context.Background(), "ssh -R 9000:localhost:4242 dev-box uptime", dir, []string{dir}, []string{dir}); err == nil {
		t.Error("-R to a read-only host allowed")
	}
}
