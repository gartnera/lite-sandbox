package config

import (
	"os"
	"path/filepath"
	"strings"
)

// sshNonKeyFiles are the well-known files in ~/.ssh that are not private keys
// and stay readable in the sandbox, so ssh can still find its client config
// and verify hosts.
var sshNonKeyFiles = map[string]bool{
	"known_hosts":      true,
	"known_hosts.old":  true,
	"config":           true,
	"authorized_keys":  true,
	"authorized_keys2": true,
}

// SSHPrivateKeyEntries returns one read-denied, every-mode entry per file in
// ~/.ssh that looks like a private key: every regular file except the
// well-known non-key files and *.pub. Detection is by name, not content — a
// key stored under a name that does not end in .pub is masked whatever it
// holds, which errs toward hiding. Each entry is grouped under ~/.ssh, so a
// paths grant on the directory lifts every key at once:
//
//	lite-sandbox config paths allow ~/.ssh --internal
//
// lets the ssh a command spawns read the keys while the agent's own reads of
// them stay refused. The list reflects the directory at the time of the call
// (the OS sandbox worker restarts on every config change, not when a key is
// added; a new key is masked from the next worker start). A missing ~/.ssh
// yields no entries.
func SSHPrivateKeyEntries(home string) []DeniedPath {
	sshDir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []DeniedPath
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if sshNonKeyFiles[name] || strings.HasSuffix(name, ".pub") {
			continue
		}
		keys = append(keys, DeniedPath{
			Path:     filepath.Join(sshDir, name),
			AllModes: true,
			Group:    sshDir,
			Note:     "SSH private key",
		})
	}
	return keys
}
