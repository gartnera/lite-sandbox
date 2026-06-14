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
	Privileged        bool     `json:"Privileged"`
	Binds             []string `json:"Binds"`
	Mounts            []mount  `json:"Mounts"`
	CapAdd            []string `json:"CapAdd"`
	Devices           []any    `json:"Devices"`
	DeviceRequests    []any    `json:"DeviceRequests"`
	DeviceCgroupRules []string `json:"DeviceCgroupRules"`
	PidMode           string   `json:"PidMode"`
	IpcMode           string   `json:"IpcMode"`
	UsernsMode        string   `json:"UsernsMode"`
	NetworkMode       string   `json:"NetworkMode"`
	SecurityOpt       []string `json:"SecurityOpt"`
}

type mount struct {
	Type          string         `json:"Type"`
	Source        string         `json:"Source"`
	Target        string         `json:"Target"`
	ReadOnly      bool           `json:"ReadOnly"`
	VolumeOptions *volumeOptions `json:"VolumeOptions"`
}

type volumeOptions struct {
	DriverConfig *driverConfig `json:"DriverConfig"`
}

type driverConfig struct {
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
}

// validateCreateBody parses a container-create request body and enforces the
// sandbox policy: no privilege escalation, and every host bind-mount source
// must fall within the readable (read-only mounts) or writable (read-write
// mounts) path boundary. Named and anonymous volumes are always permitted,
// except local-driver volumes that bind a host path (which are treated as
// binds and validated). A non-nil error means the request must be rejected;
// its message is surfaced to the docker client.
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
		src, readOnly, isBind, err := parseBind(b)
		if err != nil {
			return err
		}
		if !isBind {
			continue // named/anonymous volume — allowed
		}
		if err := checkBindSource(src, readOnly, workDir, readPaths, writePaths); err != nil {
			return err
		}
	}

	for _, m := range hc.Mounts {
		if strings.EqualFold(m.Type, "bind") {
			if err := checkBindSource(m.Source, m.ReadOnly, workDir, readPaths, writePaths); err != nil {
				return err
			}
			continue
		}
		// A volume mount that uses the local driver with a "device" option is a
		// host bind in disguise (type=none,o=bind,device=/host/path), so it must
		// be validated against the boundary like any other bind.
		if err := checkVolumeMount(m, workDir, readPaths, writePaths); err != nil {
			return err
		}
	}

	return nil
}

// validateExecBody enforces policy on POST /containers/{id}/exec. The exec
// config can request Privileged, which (like container create) escalates the
// exec process out of the sandbox's capability set.
func validateExecBody(body []byte, allowPrivileged bool) error {
	if allowPrivileged {
		return nil
	}
	var e struct {
		Privileged bool `json:"Privileged"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("failed to parse exec request: %v", err)
	}
	if e.Privileged {
		return fmt.Errorf("privileged exec is not allowed in the sandbox")
	}
	return nil
}

// volumeCreateBody is a minimal view of POST /volumes/create.
type volumeCreateBody struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
}

// validateVolumeCreateBody enforces policy on POST /volumes/create. The local
// driver accepts a "device" option (with o=bind / type=none) that creates a
// named volume backed by an arbitrary host path — a bind-mount in disguise that
// would otherwise sidestep the create-time bind checks once mounted.
func validateVolumeCreateBody(body []byte, workDir string, readPaths, writePaths []string) error {
	var v volumeCreateBody
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("failed to parse volume create request: %v", err)
	}
	return checkDriverDevice(v.DriverOpts, false, workDir, readPaths, writePaths)
}

// checkVolumeMount validates the host path of a local-driver volume mount that
// binds a device. Volumes without such a device option are ordinary named
// volumes and are allowed.
func checkVolumeMount(m mount, workDir string, readPaths, writePaths []string) error {
	if m.VolumeOptions == nil || m.VolumeOptions.DriverConfig == nil {
		return nil
	}
	return checkDriverDevice(m.VolumeOptions.DriverConfig.Options, m.ReadOnly, workDir, readPaths, writePaths)
}

// checkDriverDevice validates a local-volume-driver "device" option that points
// at an absolute host path, treating it as a bind mount against the boundary.
func checkDriverDevice(opts map[string]string, readOnly bool, workDir string, readPaths, writePaths []string) error {
	device := opts["device"]
	if device == "" || !filepath.IsAbs(device) {
		// No device, or a non-path device (e.g. NFS "addr=...") — not a host bind.
		return nil
	}
	return checkBindSource(device, readOnly, workDir, readPaths, writePaths)
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
	if len(hc.DeviceRequests) > 0 {
		return fmt.Errorf("requesting host devices (--gpus/--device-request) is not allowed in the sandbox")
	}
	if len(hc.DeviceCgroupRules) > 0 {
		return fmt.Errorf("device cgroup rules (--device-cgroup-rule) are not allowed in the sandbox")
	}
	for _, opt := range hc.SecurityOpt {
		if strings.Contains(strings.ToLower(opt), "unconfined") {
			return fmt.Errorf("security-opt %q is not allowed in the sandbox", opt)
		}
	}
	if err := checkNamespace("PID", hc.PidMode); err != nil {
		return err
	}
	if err := checkNamespace("IPC", hc.IpcMode); err != nil {
		return err
	}
	if err := checkNamespace("user", hc.UsernsMode); err != nil {
		return err
	}
	if err := checkNamespace("network", hc.NetworkMode); err != nil {
		return err
	}
	return nil
}

// checkNamespace rejects sharing the host's namespace ("host") or joining
// another container's namespace ("container:<id>"); both break the isolation
// the sandbox relies on. Other modes (default, none, bridge, a network name)
// are allowed.
func checkNamespace(kind, mode string) error {
	if isDisallowedNamespace(mode) {
		return fmt.Errorf("%s namespace mode %q is not allowed in the sandbox", kind, mode)
	}
	return nil
}

func isDisallowedNamespace(mode string) bool {
	return strings.EqualFold(mode, "host") || strings.HasPrefix(strings.ToLower(mode), "container:")
}

// parseBind splits a docker Binds entry ("src:dst[:opts]") into its host
// source, whether it is read-only, and whether it is a host bind mount at all.
// A source that is not an absolute path is a named/anonymous volume (isBind
// false) and is not subject to path validation. An entry whose shape is
// ambiguous — more than three colon-separated fields, or a third field that
// looks like a path rather than mount options (i.e. the host source contained
// a colon) — is rejected fail-closed, so the validated source can never differ
// from the source the daemon actually mounts.
func parseBind(b string) (src string, readOnly, isBind bool, err error) {
	parts := strings.Split(b, ":")
	if len(parts) < 2 {
		return "", false, false, nil // bare name => named/anonymous volume
	}
	if len(parts) > 3 {
		return "", false, false, ambiguousBindErr(b)
	}
	src = parts[0]
	if !filepath.IsAbs(src) {
		return "", false, false, nil // named/anonymous volume, not a host path
	}
	if len(parts) == 3 {
		opts := parts[2]
		// Mount options never contain a path separator; if this field does, the
		// source path contained a ':' and the spec is ambiguous.
		if strings.Contains(opts, "/") {
			return "", false, false, ambiguousBindErr(b)
		}
		for _, opt := range strings.Split(opts, ",") {
			if opt == "ro" {
				readOnly = true
			}
		}
	}
	return src, readOnly, true, nil
}

func ambiguousBindErr(b string) error {
	return fmt.Errorf("ambiguous bind mount %q rejected (host source paths containing ':' are not supported)", b)
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
