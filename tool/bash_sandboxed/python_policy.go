package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	montygo "github.com/fugue-labs/monty-go"
)

// montyOsPolicy decides how monty answers the questions a program asks about
// the outside world without touching the filesystem: the clocks, the local
// time zone, sleeps, and the state an unseeded `random` starts from.
//
// None of these cross the path boundary, so the policy is about fidelity, not
// confinement: a program should see what CPython on this machine would show.
//
//   - Clocks read the real time (monty's default, served by the host's clocks
//     through wasi), and random state comes from real entropy.
//   - The local zone is the host's, so naive `datetime.now()` and
//     `time.localtime()` agree with `date` in the shell. monty's own default
//     is UTC, which would put every local timestamp hours off.
//   - A sleep really waits, for as long as asked (see montyMaxSleep).
//   - process_time() reports the run's execution time rather than monty's
//     default of a constant zero, which would make a script timing itself
//     report that everything took no time.
//
// The zone is checked against the runtime once, here, because monty refuses
// to start a run under a zone it does not know: a host zone name that monty's
// compiled-in rules lack must cost the program its local zone, not every
// python invocation.
func montyOsPolicy(r *montygo.Runner) montygo.OsPolicy {
	policy := montygo.OsPolicy{
		Sleep:              montygo.SleepSystem(montyMaxSleep),
		ProcessTimeElapsed: true,
	}
	if name := hostTimeZoneName(); name != "" {
		policy.TimeZone = montygo.TimeZoneNamed(name)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := r.Execute(ctx, "None", nil, montygo.WithOsPolicy(policy)); err == nil {
			return policy
		}
	}
	// No usable name: the zone's current offset, without its DST rules. Right
	// for every timestamp near now, which is nearly every one a script prints.
	abbrev, offset := time.Now().Zone()
	policy.TimeZone = montygo.TimeZoneFixed(offset, abbrev)
	return policy
}

// hostTimeZoneName returns the IANA name of the host's local zone, or "" when
// it cannot be determined. Go's time.Local does not carry the name (it reports
// "Local"), so it is found where the C library would find it: $TZ, then the
// /etc/localtime symlink, whose target ends in the zone's path under a
// zoneinfo directory (/usr/share/zoneinfo/Europe/London on Linux,
// /var/db/timezone/zoneinfo/Europe/London on macOS).
func hostTimeZoneName() string {
	name := strings.TrimPrefix(os.Getenv("TZ"), ":")
	if name == "" {
		target, err := os.Readlink("/etc/localtime")
		if err != nil {
			return ""
		}
		_, after, ok := strings.Cut(filepath.ToSlash(target), "zoneinfo/")
		if !ok {
			return ""
		}
		name = after
	}
	// A POSIX TZ rule ("EST5EDT,M3.2.0,M11.1.0") or a file path is not a
	// zone name; LoadLocation accepts only names the host's database has.
	if _, err := time.LoadLocation(name); err != nil || name == "Local" {
		return ""
	}
	return name
}
