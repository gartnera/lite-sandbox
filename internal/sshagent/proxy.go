// Package sshagent serves a restricted view of the user's ssh agent: a unix
// socket that forwards to the real agent only the requests ssh needs to
// authenticate with the keys the agent already holds.
//
// The ssh agent protocol (draft-ietf-sshm-ssh-agent) is a sequence of
// requests, each answered by one response, framed as a 4-byte big-endian
// length followed by a type byte and the payload. The proxy reads each
// request from its client and forwards it only when it is
//
//   - SSH_AGENTC_REQUEST_IDENTITIES: list the public keys;
//   - SSH_AGENTC_SIGN_REQUEST: sign with one of them (how ssh authenticates);
//   - SSH_AGENTC_EXTENSION "session-bind@openssh.com", which binds the
//     connection to the server's host key and session (OpenSSH 8.9+ sends it
//     before signing), for the client's own connection only.
//
// Everything else is answered SSH_AGENT_FAILURE without reaching the agent:
// adding keys (a planted key would then be offered and used for the user),
// removing them, locking and unlocking the agent, smartcard keys, and every
// other extension. A connection bound for forwarding (session-bind with
// is_forwarding set, which ssh sends when it relays the agent to a remote
// host) gets nothing at all from then on, so the keys cannot be used from a
// remote host the agent was forwarded to.
package sshagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Message types, from the ssh agent protocol.
const (
	msgFailure            = 5
	msgRequestIdentities  = 11
	msgSignRequest        = 13
	msgAddIdentity        = 17
	msgRemoveIdentity     = 18
	msgRemoveAllIdentites = 19
	msgAddSmartcardKey    = 20
	msgRemoveSmartcardKey = 21
	msgLock               = 22
	msgUnlock             = 23
	msgAddIDConstrained   = 25
	msgAddSmartcardConstr = 26
	msgExtension          = 27
)

// sessionBind is the one extension the proxy forwards.
const sessionBind = "session-bind@openssh.com"

// maxMessageLen bounds a message, as OpenSSH's agent does (AGENT_MAX_LEN).
const maxMessageLen = 256 * 1024

var failure = []byte{0, 0, 0, 1, msgFailure}

// Proxy is a running restricted agent socket.
type Proxy struct {
	upstream string
	dir      string
	socket   string
	ln       net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Start creates a private directory under baseDir, listens on agent.sock in
// it, and serves the restricted agent there in the background, forwarding to
// the agent socket upstream.
func Start(baseDir, upstream string) (*Proxy, error) {
	if upstream == "" {
		return nil, errors.New("no ssh agent socket to forward to")
	}
	dir, err := os.MkdirTemp(baseDir, "ls-ssh-agent-")
	if err != nil {
		return nil, fmt.Errorf("creating ssh agent proxy directory: %w", err)
	}
	// The socket's real path: the OS sandbox masks and grants it by path, and
	// sandbox-exec matches the resolved one (macOS's $TMPDIR is under the
	// /var -> /private/var link).
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	socket := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("listening on %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	p := &Proxy{upstream: upstream, dir: dir, socket: socket, ln: ln, conns: make(map[net.Conn]struct{})}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Socket returns the path of the restricted agent socket.
func (p *Proxy) Socket() string { return p.socket }

// Upstream returns the path of the real agent socket it forwards to.
func (p *Proxy) Upstream() string { return p.upstream }

// Close stops the proxy, drops its connections, and removes its directory.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	err := p.ln.Close()
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	os.RemoveAll(p.dir)
	return err
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			c.Close()
			return
		}
		p.conns[c] = struct{}{}
		p.wg.Add(1)
		p.mu.Unlock()
		go func() {
			defer p.wg.Done()
			p.handle(c)
			p.mu.Lock()
			delete(p.conns, c)
			p.mu.Unlock()
		}()
	}
}

// handle serves one client connection: each request is checked by filter,
// and an allowed one is relayed to the client's own connection to the real
// agent, opened on its first allowed request, with the agent's response sent
// back.
func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	var up net.Conn
	defer func() {
		if up != nil {
			up.Close()
		}
	}()
	var st connState
	for {
		req, err := readMessage(client)
		if err != nil {
			return
		}
		if why := st.filter(req); why != "" {
			slog.Info("ssh agent proxy refused a request", "reason", why)
			if _, err := client.Write(failure); err != nil {
				return
			}
			continue
		}
		if up == nil {
			up, err = net.Dial("unix", p.upstream)
			if err != nil {
				slog.Warn("ssh agent proxy cannot reach the agent", "socket", p.upstream, "error", err)
				up = nil
				if _, err := client.Write(failure); err != nil {
					return
				}
				continue
			}
		}
		resp, err := relay(up, req)
		if err != nil {
			up.Close()
			up = nil
			resp = failure
		}
		if _, err := client.Write(resp); err != nil {
			return
		}
	}
}

// relay sends req to the agent and returns its response.
func relay(up net.Conn, req []byte) ([]byte, error) {
	if _, err := up.Write(req); err != nil {
		return nil, err
	}
	return readMessage(up)
}

// readMessage reads one framed message, length prefix included.
func readMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMessageLen {
		return nil, fmt.Errorf("ssh agent message of %d bytes", n)
	}
	msg := make([]byte, 4+n)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// connState is what the filter remembers about one client connection.
type connState struct {
	// forwarded is set once the connection is bound for forwarding.
	forwarded bool
}

// filter returns why the request msg (framed) must not reach the agent, or
// "" when it may.
func (st *connState) filter(msg []byte) string {
	if st.forwarded {
		return "the connection relays the agent to a remote host (agent forwarding)"
	}
	body := msg[4:]
	switch body[0] {
	case msgRequestIdentities, msgSignRequest:
		return ""
	case msgExtension:
		name, rest, ok := readString(body[1:])
		if !ok {
			return "malformed extension request"
		}
		if string(name) != sessionBind {
			return fmt.Sprintf("extension %q", name)
		}
		forwarding, ok := sessionBindForwarding(rest)
		if !ok {
			return "malformed session-bind request"
		}
		if forwarding {
			st.forwarded = true
			return "session-bind for agent forwarding"
		}
		return ""
	case msgAddIdentity, msgAddIDConstrained, msgAddSmartcardKey, msgAddSmartcardConstr:
		return "adding a key"
	case msgRemoveIdentity, msgRemoveAllIdentites, msgRemoveSmartcardKey:
		return "removing keys"
	case msgLock, msgUnlock:
		return "locking or unlocking the agent"
	}
	return fmt.Sprintf("message type %d", body[0])
}

// sessionBindForwarding parses the rest of a session-bind request (host key,
// session identifier, signature, is_forwarding) and returns is_forwarding.
func sessionBindForwarding(b []byte) (bool, bool) {
	for range 3 {
		var ok bool
		if _, b, ok = readString(b); !ok {
			return false, false
		}
	}
	if len(b) != 1 {
		return false, false
	}
	return b[0] != 0, true
}

// readString reads one ssh string (a uint32 length and that many bytes).
func readString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
