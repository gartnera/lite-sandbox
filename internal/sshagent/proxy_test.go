package sshagent

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func frame(body ...[]byte) []byte {
	var b []byte
	for _, p := range body {
		b = append(b, p...)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func sshString(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

func sessionBindMsg(forwarding bool) []byte {
	f := byte(0)
	if forwarding {
		f = 1
	}
	return frame([]byte{msgExtension}, sshString(sessionBind), sshString("hostkey"), sshString("sid"), sshString("sig"), []byte{f})
}

func TestFilter(t *testing.T) {
	allowed := [][]byte{
		frame([]byte{msgRequestIdentities}),
		frame([]byte{msgSignRequest}, sshString("key"), sshString("data"), []byte{0, 0, 0, 0}),
		sessionBindMsg(false),
	}
	for _, m := range allowed {
		var st connState
		if why := st.filter(m, false); why != "" {
			t.Errorf("type %d refused: %s", m[4], why)
		}
	}
	refused := [][]byte{
		frame([]byte{msgAddIdentity}, sshString("ssh-ed25519")),
		frame([]byte{msgAddIDConstrained}),
		frame([]byte{msgRemoveIdentity}, sshString("key")),
		frame([]byte{msgRemoveAllIdentites}),
		frame([]byte{msgAddSmartcardKey}),
		frame([]byte{msgRemoveSmartcardKey}),
		frame([]byte{msgLock}, sshString("pw")),
		frame([]byte{msgUnlock}, sshString("pw")),
		frame([]byte{msgExtension}, sshString("query")),
		frame([]byte{msgExtension}, []byte{0, 0, 9}),
		frame([]byte{msgExtension}, sshString(sessionBind), sshString("only-one")),
		frame([]byte{1}), // SSH1 request identities
		frame([]byte{99}),
	}
	for _, m := range refused {
		var st connState
		if why := st.filter(m, false); why == "" {
			t.Errorf("message %v allowed", m[4:])
		}
	}
}

func sshsigData(ns string) []byte {
	b := append([]byte(sshsigMagic), sshString(ns)...)
	return append(b, append(sshString(""), append(sshString("sha512"), sshString("hash")...)...)...)
}

func TestFilterSSHSIG(t *testing.T) {
	sign := func(data []byte) []byte {
		return frame([]byte{msgSignRequest}, sshString("key"), sshString(string(data)), []byte{0, 0, 0, 0})
	}
	tests := []struct {
		data       []byte
		gitSigning bool
		allowed    bool
	}{
		{sshString("session-id"), false, true}, // authentication
		{sshsigData("git"), false, false},
		{sshsigData("git"), true, true},
		{sshsigData("file"), true, false},
		{sshsigData("git@example.com"), true, false},
		{[]byte("SSHSIG\x00\x00"), true, false}, // malformed
	}
	for _, tt := range tests {
		var st connState
		if got := st.filter(sign(tt.data), tt.gitSigning) == ""; got != tt.allowed {
			t.Errorf("sign %q (git signing %v): allowed=%v", tt.data, tt.gitSigning, got)
		}
	}
	var st connState
	if st.filter(frame([]byte{msgSignRequest}, []byte{0, 0}), true) == "" {
		t.Error("malformed sign request allowed")
	}
}

func TestFilterRefusesForwardedConnection(t *testing.T) {
	var st connState
	if why := st.filter(sessionBindMsg(true), false); why == "" {
		t.Fatal("forwarding session-bind allowed")
	}
	if why := st.filter(frame([]byte{msgRequestIdentities}), false); why == "" {
		t.Error("listing keys allowed on a forwarded connection")
	}
	if why := st.filter(frame([]byte{msgSignRequest}, sshString("k"), sshString("d"), []byte{0, 0, 0, 0}), true); why == "" {
		t.Error("signing allowed on a forwarded connection")
	}
}

func TestReadMessageBounds(t *testing.T) {
	for _, in := range []string{"", "\x00\x00", "\x00\x00\x00\x00", "\x00\x10\x00\x01x", "\x00\x00\x00\x05ab"} {
		if _, err := readMessage(strings.NewReader(in)); err == nil {
			t.Errorf("readMessage(%q) succeeded", in)
		}
	}
}

// startAgent runs a real ssh-agent holding one fresh ed25519 key and returns
// its socket and the key's public half.
func startAgent(t *testing.T) (sock, pub string) {
	t.Helper()
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	// A short directory: unix socket paths are limited to ~104 bytes.
	dir, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "a.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Process.Kill(); agent.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	key := filepath.Join(dir, "id")
	run(t, "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test-key", "-f", key)
	run(t, sock, "ssh-add", "-q", key)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	return sock, key + ".pub"
}

func run(t *testing.T, sock string, name string, args ...string) string {
	t.Helper()
	out, err := command(sock, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func command(sock, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	return cmd
}

func TestProxyWithRealAgent(t *testing.T) {
	agentSock, pub := startAgent(t)
	p, err := Start(filepath.Dir(agentSock), agentSock)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if fi, err := os.Stat(p.Socket()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("proxy socket: %v, %v", fi, err)
	}

	// Listing works through the proxy.
	if out := run(t, p.Socket(), "ssh-add", "-l"); !strings.Contains(out, "test-key") {
		t.Fatalf("ssh-add -l through the proxy: %s", out)
	}
	// SSHSIG signing: never outside the git namespace, in it only while git
	// signing is on.
	data := filepath.Join(t.TempDir(), "data")
	os.WriteFile(data, []byte("hello"), 0o600)
	for _, ns := range []string{"file", "git"} {
		if out, err := command(p.Socket(), "ssh-keygen", "-Y", "sign", "-f", pub, "-n", ns, data).CombinedOutput(); err == nil {
			t.Errorf("signing in namespace %s with git signing off succeeded: %s", ns, out)
		}
	}
	p.AllowGitSigning(true)
	if out, err := command(p.Socket(), "ssh-keygen", "-Y", "sign", "-f", pub, "-n", "file", data).CombinedOutput(); err == nil {
		t.Errorf("signing in namespace file succeeded: %s", out)
	}
	run(t, p.Socket(), "ssh-keygen", "-Y", "sign", "-f", pub, "-n", "git", data)
	if _, err := os.Stat(data + ".sig"); err != nil {
		t.Fatalf("no git signature written: %v", err)
	}

	// Changing the agent does not.
	other := filepath.Join(t.TempDir(), "other")
	run(t, "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "planted", "-f", other)
	if out, err := command(p.Socket(), "ssh-add", other).CombinedOutput(); err == nil {
		t.Errorf("ssh-add of a key through the proxy succeeded: %s", out)
	}
	if out, err := command(p.Socket(), "ssh-add", "-D").CombinedOutput(); err == nil {
		t.Errorf("ssh-add -D through the proxy succeeded: %s", out)
	}
	if out, err := command(p.Socket(), "ssh-add", "-x").CombinedOutput(); err == nil {
		t.Errorf("locking through the proxy succeeded: %s", out)
	}
	out := run(t, agentSock, "ssh-add", "-l")
	if !strings.Contains(out, "test-key") || strings.Contains(out, "planted") {
		t.Errorf("the real agent changed: %s", out)
	}

	// Close removes the socket and its directory.
	dir := filepath.Dir(p.Socket())
	p.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("proxy directory left behind: %v", err)
	}
}

func TestProxyWithoutAgent(t *testing.T) {
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not installed")
	}
	dir, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p, err := Start(dir, filepath.Join(dir, "missing.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// The agent is unreachable: requests fail rather than hang.
	if out, err := command(p.Socket(), "ssh-add", "-l").CombinedOutput(); err == nil {
		t.Errorf("ssh-add -l succeeded with no agent: %s", out)
	}
}
