package incusproxy

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// Policy is the instance/profile configuration policy the proxy enforces. It
// mirrors the defaults of an Incus restricted project
// (internal/server/project/permissions.go upstream): unprivileged containers
// only, no low-level options, no passthrough devices. Host-path disk devices
// are additionally confined to the sandbox's path boundary.
type Policy struct {
	AllowPrivileged bool
	AllowNesting    bool
	WorkDir         string
	ReadPaths       []string
	WritePaths      []string
	// NetworkType returns the type of a managed network ("" when it does not
	// exist); the server sets it. nil skips the lookup.
	NetworkType func(name string) (string, error)
}

// lowLevelKeys are the instance options Incus's restricted.containers.lowlevel
// and restricted.virtual-machines.lowlevel block (raw.* and
// security.syscalls.* are matched by prefix in checkConfigKey).
var lowLevelKeys = []string{
	"boot.autostart.delay",
	"boot.host_shutdown_action",
	"boot.host_shutdown_timeout",
	"linux.kernel_modules",
	"limits.memory.hugepages",
	"limits.memory.oom_priority",
	"limits.memory.swap",
	"security.devlxd.images", // LXD's name for security.guestapi.images
	"security.guestapi.images",
	"security.idmap.base",
	"security.idmap.size",
	"security.selinux.domain",
	"security.selinux.label_rootfs",
	"security.selinux.level",
	"security.selinux.type",
}

// isSafeVolatileKey reports the volatile.* keys a restricted project lets
// clients set (Incus's isSafeVolatileKey). The others, volatile.idmap.* among
// them, are server state: changing the recorded idmap would map the
// container's root to the host's on the next start.
func isSafeVolatileKey(key string) bool {
	switch key {
	case "volatile.apply_template", "volatile.base_image", "volatile.last_state.power", "volatile.selinux.context":
		return true
	}
	return strings.HasSuffix(key, ".apply_quota") || strings.HasSuffix(key, ".hwaddr")
}

// isTrue matches Incus's util.IsTrue.
func isTrue(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// isFalseOrEmpty matches Incus's util.IsFalseOrEmpty.
func isFalseOrEmpty(v string) bool {
	switch strings.ToLower(v) {
	case "", "false", "0", "no", "off":
		return true
	}
	return false
}

// checkConfigKey rejects one instance or profile config key/value the policy
// does not allow.
func (p *Policy) checkConfigKey(key, value string) error {
	if strings.HasPrefix(key, "volatile.") {
		if isSafeVolatileKey(key) || p.AllowPrivileged {
			return nil
		}
		return fmt.Errorf("setting %q is not allowed in the sandbox", key)
	}
	if p.AllowPrivileged {
		return nil
	}
	switch {
	case key == "security.privileged":
		if isTrue(value) {
			return fmt.Errorf("privileged containers (security.privileged) are not allowed in the sandbox")
		}
	case key == "security.nesting":
		if isTrue(value) && !p.AllowNesting {
			return fmt.Errorf("container nesting (security.nesting) is not allowed in the sandbox")
		}
	case strings.HasPrefix(key, "raw."):
		return fmt.Errorf("low-level option %q is not allowed in the sandbox", key)
	case strings.HasPrefix(key, "security.syscalls.intercept."):
		if !isFalseOrEmpty(value) {
			return fmt.Errorf("syscall interception (%s) is not allowed in the sandbox", key)
		}
	case key == "security.syscalls.deny" || key == "security.syscalls.deny_compat":
		// Only adds to the seccomp denylist.
	case key == "security.syscalls.deny_default":
		if !isTrue(value) {
			return fmt.Errorf("disabling the default syscall denylist (%s) is not allowed in the sandbox", key)
		}
	case strings.HasPrefix(key, "security.syscalls."), strings.HasPrefix(key, "security.bpffs"):
		return fmt.Errorf("low-level option %q is not allowed in the sandbox", key)
	case slices.Contains(lowLevelKeys, key):
		return fmt.Errorf("low-level option %q is not allowed in the sandbox", key)
	}
	return nil
}

// checkDevice rejects one device the policy does not allow.
func (p *Policy) checkDevice(name string, dev map[string]string) error {
	switch typ := dev["type"]; typ {
	case "disk":
		return p.checkDisk(name, dev)
	case "nic":
		// Any NIC except one that takes a host interface away from the host,
		// whether by nictype or by naming a managed physical network.
		if p.AllowPrivileged {
			return nil
		}
		if dev["nictype"] == "physical" {
			return fmt.Errorf("device %q: physical NICs are not allowed in the sandbox", name)
		}
		if network := dev["network"]; network != "" && p.NetworkType != nil {
			typ, err := p.NetworkType(network)
			if err != nil {
				return fmt.Errorf("device %q: looking up network %q: %v", name, network, err)
			}
			if typ == "physical" {
				return fmt.Errorf("device %q: network %q is a physical network, which is not allowed in the sandbox", name, network)
			}
		}
		return nil
	case "none", "tpm":
		return nil
	default:
		if p.AllowPrivileged {
			return nil
		}
		if typ == "" {
			return fmt.Errorf("device %q has no type", name)
		}
		return fmt.Errorf("device %q: %s devices are not allowed in the sandbox", name, typ)
	}
}

// checkDisk validates a disk device. Pool-backed disks (the root disk, custom
// volumes) and the generated config drives are allowed; a host-path source is
// a bind mount and must lie within the sandbox's read (readonly=true) or write
// boundary, whatever allow_privileged says.
func (p *Policy) checkDisk(name string, dev map[string]string) error {
	src := dev["source"]
	if dev["path"] == "" && (src == "cloud-init:config" || src == "agent:config") {
		return nil
	}
	if !p.AllowPrivileged {
		if dev["raw.mount.options"] != "" {
			return fmt.Errorf("device %q: raw.mount.options is not allowed in the sandbox", name)
		}
		if strings.Contains(dev["propagation"], "shared") {
			return fmt.Errorf("device %q: shared mount propagation is not allowed in the sandbox", name)
		}
	}
	if dev["pool"] != "" || src == "" {
		return nil
	}
	if strings.HasPrefix(src, "ceph:") || strings.HasPrefix(src, "cephfs:") {
		if p.AllowPrivileged {
			return nil
		}
		return fmt.Errorf("device %q: ceph disk sources are not allowed in the sandbox", name)
	}
	if !filepath.IsAbs(src) {
		return fmt.Errorf("device %q: disk source %q must be an absolute host path or a storage volume", name, src)
	}
	readOnly := isTrue(dev["readonly"])
	allowed := p.WritePaths
	access := "read-write"
	if readOnly {
		allowed, access = p.ReadPaths, "read-only"
	}
	resolved := bash_sandboxed.ResolvePath(src, p.WorkDir)
	if !bash_sandboxed.IsUnderAllowedPaths(resolved, allowed) {
		return fmt.Errorf("device %q: %s disk source %q resolves to %q which is outside the sandbox boundary", name, access, src, resolved)
	}
	return nil
}

// checkChanges validates the config keys and devices of newCfg/newDevs that
// differ from curCfg/curDevs. Keys and devices left as they are pass whatever
// they hold — they are the daemon's (or the administrator's) and the request
// does not introduce them — which keeps `incus config set` and `config edit`
// working on instances carrying volatile state. Pass nil currents to check
// everything, as on create.
func (p *Policy) checkChanges(newCfg, curCfg map[string]string, newDevs, curDevs map[string]map[string]string) error {
	for _, k := range sortedKeys(newCfg) {
		if cur, ok := curCfg[k]; ok && cur == newCfg[k] {
			continue
		}
		if err := p.checkConfigKey(k, newCfg[k]); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(newDevs) {
		if cur, ok := curDevs[name]; ok && maps.Equal(cur, newDevs[name]) {
			continue
		}
		if err := p.checkDevice(name, newDevs[name]); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
