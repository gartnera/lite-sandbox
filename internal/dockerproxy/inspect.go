package dockerproxy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// createBody is a minimal view of the POST /containers/create request body —
// only the HostConfig fields relevant to sandbox policy. Unknown fields are
// ignored by encoding/json, so the body is forwarded unchanged after validation.
type createBody struct {
	HostConfig hostConfig `json:"HostConfig"`
}

type hostConfig struct {
	Privileged  bool     `json:"Privileged"`
	Binds       []string `json:"Binds"`
	Mounts      []mount  `json:"Mounts"`
	CapAdd      []string `json:"CapAdd"`
	Devices     []any    `json:"Devices"`
	PidMode     string   `json:"PidMode"`
	IpcMode     string   `json:"IpcMode"`
	UsernsMode  string   `json:"UsernsMode"`
	NetworkMode string   `json:"NetworkMode"`
	SecurityOpt []string `json:"SecurityOpt"`
}

type mount struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
}

// validateCreateBody parses a container-create request body and enforces the
// sandbox policy: no privilege escalation, and every host bind-mount source
// must fall within the readable (read-only mounts) or writable (read-write
// mounts) path boundary. Named and anonymous volumes are always permitted.
// A non-nil error means the request must be rejected; its message is surfaced
// to the docker client.
func validateCreateBody(body []byte, workDir string, readPaths, writePaths []string, allowPrivileged bool) error {
	var cb createBody
	if err := json.Unmarshal(body, &cb); err != nil {
		return fmt.Errorf("failed to parse container create request: %v", err)
	}
	hc := cb.HostConfig

	if !allowPrivileged {
		if err := checkPrivilege(hc); err != nil {
			return err
		}
	}

	for _, b := range hc.Binds {
		src, readOnly, isBind := parseBind(b)
		if !isBind {
			continue // named/anonymous volume — allowed
		}
		if err := checkBindSource(src, readOnly, workDir, readPaths, writePaths); err != nil {
			return err
		}
	}

	for _, m := range hc.Mounts {
		if !strings.EqualFold(m.Type, "bind") {
			continue // volume, tmpfs, image, cluster — allowed
		}
		if err := checkBindSource(m.Source, m.ReadOnly, workDir, readPaths, writePaths); err != nil {
			return err
		}
	}

	return nil
}

// checkPrivilege rejects privileged containers and the equivalent escalation
// vectors that would let a container break out of the sandbox boundary.
func checkPrivilege(hc hostConfig) error {
	if hc.Privileged {
		return fmt.Errorf("privileged containers are not allowed in the sandbox")
	}
	if len(hc.CapAdd) > 0 {
		return fmt.Errorf("adding Linux capabilities (--cap-add %s) is not allowed in the sandbox", strings.Join(hc.CapAdd, ","))
	}
	if len(hc.Devices) > 0 {
		return fmt.Errorf("mapping host devices (--device) is not allowed in the sandbox")
	}
	for _, opt := range hc.SecurityOpt {
		if strings.Contains(strings.ToLower(opt), "unconfined") {
			return fmt.Errorf("security-opt %q is not allowed in the sandbox", opt)
		}
	}
	if isHostNamespace(hc.PidMode) {
		return fmt.Errorf("host PID namespace (--pid=host) is not allowed in the sandbox")
	}
	if isHostNamespace(hc.IpcMode) {
		return fmt.Errorf("host IPC namespace (--ipc=host) is not allowed in the sandbox")
	}
	if isHostNamespace(hc.UsernsMode) {
		return fmt.Errorf("host user namespace (--userns=host) is not allowed in the sandbox")
	}
	if isHostNamespace(hc.NetworkMode) {
		return fmt.Errorf("host network namespace (--network=host) is not allowed in the sandbox")
	}
	return nil
}

func isHostNamespace(mode string) bool {
	return strings.EqualFold(mode, "host")
}

// parseBind splits a docker Binds entry ("src:dst[:opts]") into its host
// source, whether it is read-only, and whether it is a host bind mount at all.
// A source that is not an absolute path is a named/anonymous volume (isBind
// false) and is not subject to path validation.
func parseBind(b string) (src string, readOnly, isBind bool) {
	parts := strings.Split(b, ":")
	if len(parts) < 2 {
		return "", false, false
	}
	src = parts[0]
	if !filepath.IsAbs(src) {
		// Bare name => named/anonymous volume, not a host path bind.
		return "", false, false
	}
	if len(parts) >= 3 {
		for _, opt := range strings.Split(parts[2], ",") {
			if opt == "ro" {
				readOnly = true
			}
		}
	}
	return src, readOnly, true
}

// checkBindSource validates a single host bind-mount source against the
// sandbox boundary. Read-only mounts must satisfy the readable paths; writable
// mounts must satisfy the (stricter) writable paths.
func checkBindSource(src string, readOnly bool, workDir string, readPaths, writePaths []string) error {
	resolved := bash_sandboxed.ResolvePath(src, workDir)
	allowed := writePaths
	if readOnly {
		allowed = readPaths
	}
	if !bash_sandboxed.IsUnderAllowedPaths(resolved, allowed) {
		access := "read-write"
		if readOnly {
			access = "read-only"
		}
		return fmt.Errorf("%s bind mount source %q resolves to %q which is outside the sandbox boundary", access, src, resolved)
	}
	return nil
}
