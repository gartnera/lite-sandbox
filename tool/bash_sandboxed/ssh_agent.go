package bash_sandboxed

import (
	"context"
	"log/slog"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/gartnera/lite-sandbox/config"
)

// The ssh agent reaches ssh, sshpass, and git's remote commands (and, with
// git_signing, the git commands that sign), and nothing else, once the config
// has an ssh section (config.SSHConfig):
//
//   - the server serves a restricted agent socket (internal/sshagent) in
//     front of the user's agent and hands both to SetSSHAgent;
//   - UpdateConfig grants the socket those commands get (the proxy's, or the
//     real one with unrestricted_agent) to them alone, as a command scope
//     (config.Config.WithSSHAgent), so they run in an OS sandbox worker of
//     their own that can reach it;
//   - every other worker masks both sockets (sshAgentMasks), and the agent's
//     own worker masks the one it was not granted;
//   - only git's remote commands, and with git_signing those that sign, go to
//     that worker (workerScope): other git commands keep running in the
//     shared worker with the project's hooks, while one run in the agent's
//     worker gets them switched off (scopedGitEnv), with what else git lets
//     the environment switch off. That does not cover a filter, merge, or
//     diff driver the project's .git/config defines (nor a credential helper
//     scoped to a URL), which does run there and can reach the agent; the
//     restricted agent limits what it can do with it.
//
// Without the OS sandbox there are no workers to keep the socket from; the
// commands run on the host get SSH_AUTH_SOCK pointed at the agent socket the
// config grants (sshAgentHostEnv), which a command that knows the real path
// can bypass.

// SSHAgentProxy is the restricted agent the server serves
// (*sshagent.Proxy).
type SSHAgentProxy interface {
	Socket() string
	AllowGitSigning(on bool)
}

// SetSSHAgent records the restricted agent the server serves (nil when none
// runs) and the real agent socket it forwards to (upstream), and re-applies
// the current config with them.
func (s *Sandbox) SetSSHAgent(proxy SSHAgentProxy, upstream string) {
	s.mu.Lock()
	s.sshAgent = proxy
	s.sshAgentProxy, s.sshAgentUpstream = "", upstream
	if proxy != nil {
		s.sshAgentProxy = proxy.Socket()
	}
	cfg, workDir := s.inputCfg, s.workerWorkDir
	s.mu.Unlock()
	if cfg != nil {
		s.UpdateConfig(cfg, workDir)
	}
}

// applySSHAgentConfig tells the restricted agent whether cfg signs git
// commits and tags. Called by UpdateConfig.
func (s *Sandbox) applySSHAgentConfig(cfg *config.Config) {
	s.mu.RLock()
	proxy := s.sshAgent
	s.mu.RUnlock()
	if proxy != nil {
		proxy.AllowGitSigning(cfg.SSH.GitSigningEnabled())
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

// sshpassScope is the worker sshpass runs in when no scope names it (the
// agent is off or there is none): a worker of its own, with nothing granted,
// whose process namespace keeps the password in sshpass's environment from
// the programs in the shared worker (/proc/<pid>/environ).
var sshpassScope = config.CommandScope{Key: "sshpass", Commands: []string{"sshpass"}}

// workerScope returns the scope whose worker runs an invocation, with the
// config it belongs to, and false for the shared worker. A scoped grant's
// commands run in their scope's worker, except git in the agent's scope,
// which goes there only to reach a remote (gitContactsRemote) or, with
// git_signing, to sign (gitMaySign): the rest needs no agent, and keeps the
// project's hooks, which the agent's worker switches off. sshpass, once hosts
// are listed, always runs in a worker of its own.
func (s *Sandbox) workerScope(args []string) (config.CommandScope, *config.Config, bool) {
	if len(args) == 0 {
		return config.CommandScope{}, nil, false
	}
	scope, cfg, ok := s.commandScope(args[0])
	if ok && args[0] == "git" && s.isSSHAgentScope(scope) &&
		!gitContactsRemote(args) && !(cfg.SSH.GitSigningEnabled() && gitMaySign(args)) {
		ok = false
	}
	if !ok && args[0] == "sshpass" && cfg.SSH.HostsConfigured() {
		return sshpassScope, cfg, true
	}
	return scope, cfg, ok
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

// gitSigningSubcommands are the git subcommands that sign the commits or tags
// they make (with -S/-s, or commit.gpgSign/tag.gpgSign).
var gitSigningSubcommands = []string{"commit", "tag", "merge", "rebase", "cherry-pick", "revert", "am", "commit-tree"}

// gitMaySign reports whether a git invocation (expanded argv) may sign a
// commit or tag.
func gitMaySign(args []string) bool {
	sub, _, err := findSubcommand("git", literalWords(args), gitGlobalValueFlags)
	return err == nil && slices.Contains(gitSigningSubcommands, sub)
}

// gitIdentityEnv are the agent's variables a git in the agent's worker keeps
// (a scoped command gets none of the agent's variables otherwise): who and
// when a commit records, none of which names a program.
var gitIdentityEnv = []string{
	"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
	"GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE",
}

// sshScopedEnv adjusts a scoped worker's environment (the server's) for args:
// $SSHPASS reaches sshpass alone (stripSSHPass), from the agent's environment
// when it set one; rsync runs without $HOME (stripRsyncHome); the agent's
// worker gets SSH_AUTH_SOCK at the granted socket, the agent's commit
// identity for git, and, when git signs there, the signing configuration
// (gitSigningConfig).
func (s *Sandbox) sshScopedEnv(ctx context.Context, args []string, scope config.CommandScope, cfg *config.Config, env map[string]string) {
	hc := interp.HandlerCtx(ctx)
	if args[0] == "sshpass" {
		if vr := hc.Env.Get("SSHPASS"); isExportedEnvVar(vr) {
			env["SSHPASS"] = vr.String()
		}
	} else {
		stripSSHPass(args, env)
	}
	stripRsyncHome(args, env)
	if !s.isSSHAgentScope(scope) {
		return
	}
	s.mu.RLock()
	env["SSH_AUTH_SOCK"] = s.sshAgentSocket
	s.mu.RUnlock()
	if args[0] != "git" {
		return
	}
	for _, k := range gitIdentityEnv {
		if vr := hc.Env.Get(k); isExportedEnvVar(vr) {
			env[k] = vr.String()
		}
	}
	if cfg.SSH.GitSigningEnabled() {
		appendGitConfig(env, gitSigningConfig(env))
	}
}

// signsInScope reports whether git in scope signs: the agent's scope, with
// git_signing on. Its worker then leaves commit.gpgSign and tag.gpgSign as
// the user set them (scopedGitEnv).
func (s *Sandbox) signsInScope(scope config.CommandScope, cfg *config.Config) bool {
	return cfg.SSH.GitSigningEnabled() && s.isSSHAgentScope(scope)
}

// stripSSHPass drops $SSHPASS from the environment of every command but
// sshpass, so the password the agent loaded for it reaches no other program.
func stripSSHPass(args []string, env map[string]string) {
	if len(args) == 0 || args[0] != "sshpass" {
		delete(env, "SSHPASS")
	}
}

// stripRsyncHome drops $HOME from the environment of rsync (run directly, by
// sshpass, or under a wrapper; see rsyncInvocation), on every path a command
// runs by: popt, which parses rsync's options, reads aliases from
// $HOME/.popt, and an alias can add any option or operand, -e with any
// program or a host included, past the rsync validator. env HOME=... rsync,
// which would set it again, is refused (validateEnvArgs). The ssh that rsync
// starts finds ~/.ssh by the user's passwd entry, not $HOME; rsync -C loses
// ~/.cvsignore.
func stripRsyncHome(args []string, env map[string]string) {
	if rsyncInvocation(args) != nil {
		delete(env, "HOME")
	}
}

// gitSigningGlobalKeys are the signing settings that name a program git runs
// to sign. In the agent's worker they are pinned to the user's own values
// (system and global config, read outside any repository), at the
// command-line level where they outrank the repository's .git/config, which
// sandboxed commands can write.
var gitSigningGlobalKeys = []struct{ key, fallback string }{
	{"gpg.ssh.program", "ssh-keygen"},
	{"gpg.ssh.defaultKeyCommand", ""},
}

// gitSigningConfig returns the git configuration a signing git in the agent's
// worker runs with: ssh signatures (the agent signs nothing else), made by the
// user's own signing program. env is the worker's environment, whose PATH
// and git variables the lookup uses.
func gitSigningConfig(env map[string]string) [][2]string {
	keys := make([]string, len(gitSigningGlobalKeys))
	for i, k := range gitSigningGlobalKeys {
		keys[i] = k.key
	}
	user := gitUserConfig(env, keys)
	out := [][2]string{{"gpg.format", "ssh"}}
	for _, k := range gitSigningGlobalKeys {
		v, ok := user[strings.ToLower(k.key)]
		if !ok {
			v = k.fallback
		}
		out = append(out, [2]string{k.key, v})
	}
	return out
}

// gitUserConfig reads keys from the user's system and global git config, the
// way git would outside any repository, in one git run. The result is keyed
// by the lowercase key name; a key set more than once has its last value, as
// git reads it.
func gitUserConfig(env map[string]string, keys []string) map[string]string {
	out := make(map[string]string)
	git, err := exec.LookPath("git")
	if err != nil {
		return out
	}
	quoted := make([]string, len(keys))
	for i, k := range keys {
		quoted[i] = regexp.QuoteMeta(strings.ToLower(k))
	}
	cmd := exec.Command(git, "config", "-z", "--get-regexp", "^("+strings.Join(quoted, "|")+")$")
	cmd.Dir = "/"
	for k, v := range env {
		switch k {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_CEILING_DIRECTORIES":
			continue
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Env = append(cmd.Env, "GIT_CEILING_DIRECTORIES=/")
	stdout, err := cmd.Output()
	if err != nil {
		if _, exit := err.(*exec.ExitError); !exit {
			slog.Warn("reading git signing config", "error", err)
		}
		return out
	}
	// -z: each entry is the key, a newline, the value, and a NUL.
	for _, entry := range strings.Split(string(stdout), "\x00") {
		if k, v, ok := strings.Cut(entry, "\n"); ok {
			out[k] = v
		}
	}
	return out
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
