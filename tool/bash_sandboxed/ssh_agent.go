package bash_sandboxed

import (
	"context"
	"slices"

	"mvdan.cc/sh/v3/interp"

	"github.com/gartnera/lite-sandbox/config"
)

// The ssh agent reaches ssh, sshpass, and git's remote commands, and nothing
// else, once the config has an ssh section (config.SSHConfig):
//
//   - the server serves a restricted agent socket (internal/sshagent) in
//     front of the user's agent and hands both to SetSSHAgent;
//   - UpdateConfig grants the socket those commands get (the proxy's, or the
//     real one with unrestricted_agent) to them alone, as a command scope
//     (config.Config.WithSSHAgent), so they run in an OS sandbox worker of
//     their own that can reach it;
//   - every other worker masks both sockets (sshAgentMasks), and the agent's
//     own worker masks the one it was not granted;
//   - only git's remote commands go to that worker (scopedInvocation): a
//     local git keeps running in the shared worker with the project's hooks,
//     while one run in the agent's worker gets them switched off
//     (scopedGitEnv), so code the project's .git names cannot reach the agent.
//
// Without the OS sandbox there are no workers to keep the socket from; the
// commands run on the host get SSH_AUTH_SOCK pointed at the agent socket the
// config grants (sshAgentHostEnv), which a command that knows the real path
// can bypass.

// SetSSHAgent records the restricted agent socket the server serves (proxy,
// "" when none runs) and the real agent socket it forwards to (upstream), and
// re-applies the current config with them.
func (s *Sandbox) SetSSHAgent(proxy, upstream string) {
	s.mu.Lock()
	s.sshAgentProxy, s.sshAgentUpstream = proxy, upstream
	cfg, workDir := s.inputCfg, s.workerWorkDir
	s.mu.Unlock()
	if cfg != nil {
		s.UpdateConfig(cfg, workDir)
	}
}

// sshAgentGrant returns the agent socket cfg grants ssh, sshpass, and git's
// remote commands: the real agent's with unrestricted_agent, else the
// restricted proxy's; "" when the agent is off or there is none.
func (s *Sandbox) sshAgentGrant(cfg *config.Config) string {
	if !cfg.SSH.AgentEnabled() {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cfg.SSH.AgentUnrestricted() {
		return s.sshAgentUpstream
	}
	return s.sshAgentProxy
}

// sshAgentMasks returns the agent sockets a worker built from cfg must mask:
// the proxy's whenever it runs, and the real agent's whenever the config has
// an ssh section, except a socket cfg grants the worker outright (the agent's
// own worker, whose config ForScope made the scoped grant an ordinary one).
func (s *Sandbox) sshAgentMasks(cfg *config.Config) []string {
	s.mu.RLock()
	proxy, upstream := s.sshAgentProxy, s.sshAgentUpstream
	s.mu.RUnlock()
	var socks []string
	if proxy != "" {
		socks = append(socks, proxy)
	}
	if upstream != "" && cfg.SSH != nil {
		socks = append(socks, upstream)
	}
	granted := cfg.ExpandedInternalReadablePaths()
	return slices.DeleteFunc(socks, func(p string) bool { return slices.Contains(granted, p) })
}

// isSSHAgentScope reports whether scope is the one that carries the agent
// socket.
func (s *Sandbox) isSSHAgentScope(scope config.CommandScope) bool {
	s.mu.RLock()
	sock := s.sshAgentSocket
	s.mu.RUnlock()
	return sock != "" && slices.ContainsFunc(scope.Entries, func(e config.PathEntry) bool { return e.Path == sock })
}

// scopedInvocation reports whether an invocation of a command a scoped grant
// names runs in its scope's worker. Every one does, except git in the agent's
// scope, which goes there only to reach a remote (gitContactsRemote): a local
// git needs no agent, and keeps the project's hooks, which the agent's worker
// switches off.
func (s *Sandbox) scopedInvocation(args []string) bool {
	if len(args) == 0 || !s.isScopedCommand(args[0]) {
		return false
	}
	if args[0] != "git" {
		return true
	}
	scope, _, ok := s.commandScope("git")
	if !ok || !s.isSSHAgentScope(scope) {
		return true
	}
	return gitContactsRemote(args)
}

// gitContactsRemote reports whether a git invocation (expanded argv) contacts
// a remote, and so may start ssh: a subcommand or flag the git validator
// classifies remote_read or remote_write (fetch, pull, push, clone,
// ls-remote, archive --remote, ...), or git submodule, whose update and
// sync fetch.
func gitContactsRemote(args []string) bool {
	words := literalWords(args)
	sub, idx, err := findSubcommand("git", words, gitGlobalValueFlags)
	if err != nil || sub == "" {
		return false
	}
	if sub == "submodule" {
		return true
	}
	spec, ok := gitSubcommands[sub]
	if !ok {
		return false
	}
	rest := words[idx+1:]
	perm := spec.perm
	if spec.actions != nil {
		if p, ok := spec.actions[gitAction(rest)]; ok {
			perm = p
		}
	}
	if perm == gitRemoteRead || perm == gitRemoteWrite {
		return true
	}
	for _, w := range rest {
		lit := w.Lit()
		if lit == "--" {
			break
		}
		if name, ok := matchGitFlag(lit, spec.flags); ok {
			if p := spec.flags[name].perm; p == gitRemoteRead || p == gitRemoteWrite {
				return true
			}
		}
	}
	return false
}

// sshAgentScopedEnv sets what the agent's worker gives its commands on top of
// a scoped worker's environment: SSH_AUTH_SOCK at the granted socket, and the
// agent's SSHPASS, which sshpass -e reads (a scoped command otherwise gets
// none of the agent's variables).
func (s *Sandbox) sshAgentScopedEnv(ctx context.Context, scope config.CommandScope, env map[string]string) {
	if !s.isSSHAgentScope(scope) {
		return
	}
	s.mu.RLock()
	env["SSH_AUTH_SOCK"] = s.sshAgentSocket
	s.mu.RUnlock()
	delete(env, "SSHPASS")
	if vr := interp.HandlerCtx(ctx).Env.Get("SSHPASS"); isExportedEnvVar(vr) {
		env["SSHPASS"] = vr.String()
	}
}

// sshAgentHostEnv points a sandboxed command run on the host (no OS sandbox)
// at the agent socket the config grants, or drops SSH_AUTH_SOCK when the ssh
// section turns the agent off. Without an ssh section it is left alone.
func (s *Sandbox) sshAgentHostEnv(env map[string]string) {
	cfg := s.getConfig()
	if cfg.SSH == nil {
		return
	}
	s.mu.RLock()
	sock := s.sshAgentSocket
	s.mu.RUnlock()
	if sock == "" {
		delete(env, "SSH_AUTH_SOCK")
		return
	}
	env["SSH_AUTH_SOCK"] = sock
}
