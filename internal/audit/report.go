package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Report is the aggregated view of the audit log.
type Report struct {
	Records int `json:"records"`
	// Blocked counts findings the current mode enforced, by rule.
	Blocked map[string]int `json:"blocked_by_rule"`
	// WouldBlock counts advisory findings (not enforced) by the loosest mode
	// that would have enforced them — i.e. what the next step up would cost.
	WouldBlock map[string]int `json:"would_block_by_mode"`
	// Subjects lists the most frequent subjects per rule (command names for
	// whitelist findings, resolved paths for boundary findings), with counts
	// and whether they were blocked.
	Subjects map[string][]SubjectCount `json:"subjects_by_rule"`
	// Suggestions are config commands that would resolve the most common
	// findings, most impactful first. They are derived from what the agent
	// attempted, so they are proposals for a human to review, never to apply
	// blindly; see Options.Protected and dangerousCommands for what is never
	// proposed.
	Suggestions []Suggestion `json:"suggestions"`
}

// SubjectCount is one aggregated subject within a rule.
type SubjectCount struct {
	Subject string `json:"subject"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
	Example string `json:"example,omitempty"`
}

// Suggestion is a config change that would resolve a group of findings.
type Suggestion struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
	Reason  string `json:"reason"`
}

// Options tunes BuildReport.
type Options struct {
	// Top caps each per-rule subject list; 0 means no cap.
	Top int
	// Protected lists paths that must never be suggested as readable paths:
	// the home directory (which protects only itself) and the deny lists
	// (which protect their subtrees). A boundary finding there is the sandbox
	// doing its job.
	Protected []string
	// CWD, when set, keeps only records whose working directory is CWD or
	// under it — useful once modes differ per directory.
	CWD string
}

type subjectAgg struct {
	count, blocked int
	example, fix   string
}

// BuildReport aggregates recs.
func BuildReport(recs []Record, opts Options) *Report {
	rep := &Report{
		Blocked:    map[string]int{},
		WouldBlock: map[string]int{},
		Subjects:   map[string][]SubjectCount{},
	}
	agg := map[string]map[string]*subjectAgg{} // rule -> subject -> agg
	for _, r := range recs {
		if opts.CWD != "" && !underDir(r.CWD, opts.CWD) {
			continue
		}
		rep.Records++
		if r.Blocked {
			rep.Blocked[r.Rule]++
		} else if len(r.WouldBlockIn) > 0 {
			rep.WouldBlock[r.WouldBlockIn[0]]++
		}
		subj := r.Subject
		if subj == "" {
			subj = r.Message
		}
		if agg[r.Rule] == nil {
			agg[r.Rule] = map[string]*subjectAgg{}
		}
		a := agg[r.Rule][subj]
		if a == nil {
			a = &subjectAgg{example: r.Command, fix: r.Fix}
			agg[r.Rule][subj] = a
		}
		a.count++
		if r.Blocked {
			a.blocked++
		}
	}
	for rule, subjects := range agg {
		var list []SubjectCount
		for subj, a := range subjects {
			list = append(list, SubjectCount{Subject: subj, Count: a.count, Blocked: a.blocked, Example: a.example})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count != list[j].Count {
				return list[i].Count > list[j].Count
			}
			return list[i].Subject < list[j].Subject
		})
		if opts.Top > 0 && len(list) > opts.Top {
			list = list[:opts.Top]
		}
		rep.Subjects[rule] = list
	}
	rep.Suggestions = suggestions(agg, opts.Protected)
	return rep
}

// dangerousCommands are never proposed for `extra-commands add`: a bare entry
// runs through real bash with no validation at all, and these are the
// commands whose whole point is to escape (privilege, network, shells, mounts,
// scheduled execution). The agent chooses what it attempts, and therefore what
// ranks highest in the report, so this list is the floor under that ranking.
var dangerousCommands = map[string]bool{
	"sudo": true, "su": true, "doas": true, "pkexec": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"ssh": true, "scp": true, "sftp": true, "telnet": true, "rsync": true,
	"bash": true, "sh": true, "zsh": true, "dash": true, "fish": true,
	"eval": true, "exec": true, "source": true, "env": true,
	"nsenter": true, "chroot": true, "unshare": true, "mount": true, "umount": true,
	"dd": true, "mkfs": true, "fdisk": true, "crontab": true, "at": true,
	"systemctl": true, "launchctl": true, "osascript": true,
	"chmod": true, "chown": true, "setfacl": true,
}

// systemRoots are directories the report never proposes widening the read
// boundary to. Reading /etc or /usr through the sandbox is what the boundary
// exists to prevent, not a configuration gap.
var systemRoots = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/root", "/boot",
	"/proc", "/sys", "/dev", "/System", "/Library", "/private", "/Applications",
}

// suggestions turns the aggregated subjects into concrete config commands.
// Findings that carry a Fix (whitelist, runtime, local-binary) are grouped by
// it; boundary findings become a readable-paths suggestion for the enclosing
// directory unless that directory is protected or a system root.
func suggestions(agg map[string]map[string]*subjectAgg, protected []string) []Suggestion {
	merged := map[string]*Suggestion{}
	add := func(cmd, reason string, n int) {
		if m, ok := merged[cmd]; ok {
			m.Count += n
			return
		}
		merged[cmd] = &Suggestion{Command: cmd, Count: n, Reason: reason}
	}

	for rule, subjects := range agg {
		for subj, a := range subjects {
			if a.fix == "" {
				continue
			}
			if rule == "command_whitelist" && dangerousCommands[subj] {
				continue
			}
			reason := fmt.Sprintf("%q: %s", subj, ruleReason(rule))
			if rule == "command_whitelist" {
				reason += " (a bare extra_commands entry skips validation; prefer a subcommand-restricted entry such as `" + subj + " <subcommand>`)"
			}
			add(a.fix, reason, a.count)
		}
	}

	// Boundary findings: suggest the directory containing the path, collapsing
	// paths under the same parent so one suggestion covers a whole tree.
	dirs := map[string]int{}
	for subj, a := range agg["path_boundary"] {
		if !filepath.IsAbs(subj) || isProtected(subj, protected) {
			continue
		}
		dir := subj
		if fi, err := os.Stat(subj); err != nil || !fi.IsDir() {
			dir = filepath.Dir(subj)
		}
		if isProtected(dir, protected) {
			continue
		}
		dirs[dir] += a.count
	}
	for dir, n := range dirs {
		add("lite-sandbox config readable-paths add "+dir, "paths under this directory were outside the boundary (use writable-paths add if they are written)", n)
	}

	out := make([]Suggestion, 0, len(merged))
	for _, s := range merged {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Command < out[j].Command
	})
	return out
}

func ruleReason(rule string) string {
	switch rule {
	case "command_whitelist":
		return "not on the allowlist"
	case "runtime_disabled":
		return "its runtime is not enabled"
	case "local_binary":
		return "direct execution of a path"
	}
	return rule
}

// isProtected reports whether a boundary subject must not be suggested as a
// readable path: the home directory itself, anything at or under a protected
// (deny-listed) path, and anything under a system root.
func isProtected(path string, protected []string) bool {
	home, _ := os.UserHomeDir()
	if home != "" && path == home {
		return true
	}
	for _, p := range protected {
		if p == home {
			continue // home only protects itself; its subtree is fine
		}
		if underDir(path, p) {
			return true
		}
	}
	for _, root := range systemRoots {
		if underDir(path, root) {
			return true
		}
	}
	return path == "/"
}

// underDir reports whether path is dir or lies beneath it.
func underDir(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// ParseSince accepts Go durations plus a "d" suffix for days.
func ParseSince(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q (use e.g. 24h or 7d)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 24h or 7d): %w", s, err)
	}
	return d, nil
}

// Sanitize replaces control characters in agent-derived text (command names,
// paths, messages) so a crafted token cannot rewrite what a terminal report
// appears to say. Tabs and newlines are replaced too: report lines are
// single-line by construction.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}
