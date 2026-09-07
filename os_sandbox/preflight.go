package os_sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Preflight checks whether the OS sandbox can run on this host and returns a
// descriptive error when it cannot. On macOS it looks for sandbox-exec; on
// Linux it looks for bwrap and then actually starts a throwaway sandbox, since
// bubblewrap being installed does not mean unprivileged user namespaces are
// permitted (distributions and hardened kernels disable them).
func Preflight(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err != nil {
			return fmt.Errorf("sandbox-exec not found on PATH; it ships with macOS, so PATH is probably missing /usr/bin")
		}
		return nil
	case "linux":
		if _, err := exec.LookPath("bwrap"); err != nil {
			return fmt.Errorf("bubblewrap (bwrap) is not installed; install it with your package manager (e.g. `apt install bubblewrap`, `dnf install bubblewrap`, `pacman -S bubblewrap`)")
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bwrap",
			"--ro-bind", "/", "/",
			"--dev", "/dev",
			"--proc", "/proc",
			"--unshare-all",
			"--die-with-parent",
			"--", "/bin/true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			return fmt.Errorf("bwrap is installed but cannot start a sandbox: %s\n"+
				"This usually means unprivileged user namespaces are disabled. Check with "+
				"`sysctl kernel.unprivileged_userns_clone` (should be 1) or, on newer kernels, "+
				"`sysctl kernel.apparmor_restrict_unprivileged_userns` (should be 0); see docs/security.md", msg)
		}
		return nil
	default:
		return fmt.Errorf("the OS sandbox is not supported on %s", runtime.GOOS)
	}
}
