package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect the audit log of validation findings",
	Long: `The audit log records what the sandbox objected to — with audit enabled in
config (` + "`lite-sandbox config audit enable`" + `), every validation finding is
appended whether or not the current mode blocked it, tagged with the modes
that would. ` + "`audit report`" + ` summarizes it: what is being blocked now (friction
you are paying), what the next stricter mode would block (readiness to move
up), and the config changes that would resolve the most common findings.`,
}

var auditPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the audit log path",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := audit.DefaultPath()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	},
}

var auditClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete the audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := audit.DefaultPath()
		if err != nil {
			return err
		}
		if err := audit.Clear(p); err != nil {
			return err
		}
		fmt.Printf("cleared %s\n", p)
		return nil
	},
}

var (
	auditReportSince string
	auditReportJSON  bool
	auditReportTop   int
)

var auditReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Summarize findings: what is blocked now, what a stricter mode would block, and suggested config",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := audit.DefaultPath()
		if err != nil {
			return err
		}
		var since time.Time
		if auditReportSince != "" {
			d, err := parseSince(auditReportSince)
			if err != nil {
				return err
			}
			since = time.Now().Add(-d)
		}
		recs, err := audit.Read(p, since)
		if err != nil {
			return err
		}
		cfg, _ := loadConfig()
		rep := buildReport(recs, auditReportTop, protectedPaths(cfg))
		if auditReportJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		mode := config.DefaultMode
		if cfg != nil {
			mode = cfg.EffectiveMode()
		}
		printReport(os.Stdout, rep, p, mode, since)
		return nil
	},
}

func init() {
	auditReportCmd.Flags().StringVar(&auditReportSince, "since", "", "only include findings from the last duration, e.g. 24h, 7d")
	auditReportCmd.Flags().BoolVar(&auditReportJSON, "json", false, "print the report as JSON")
	auditReportCmd.Flags().IntVar(&auditReportTop, "top", 10, "how many entries to show per section")
	auditCmd.AddCommand(auditPathCmd)
	auditCmd.AddCommand(auditClearCmd)
	auditCmd.AddCommand(auditReportCmd)
	rootCmd.AddCommand(auditCmd)
}

// parseSince accepts Go durations plus a "d" suffix for days.
func parseSince(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err != nil || days < 0 {
			return 0, fmt.Errorf("invalid --since %q (use e.g. 24h or 7d)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --since %q (use e.g. 24h or 7d): %w", s, err)
	}
	return d, nil
}

// Report is the aggregated view of the audit log.
type Report struct {
	Records int `json:"records"`
	// Blocked counts findings the current mode enforced, by rule.
	Blocked map[string]int `json:"blocked_by_rule"`
	// WouldBlock counts advisory findings (not enforced) by the strictest mode
	// that would have enforced them — i.e. what stepping up would cost.
	WouldBlock map[string]int `json:"would_block_by_mode"`
	// Subjects lists the most frequent subjects per rule (command names for
	// whitelist findings, resolved paths for boundary findings), with counts
	// and whether they were blocked.
	Subjects map[string][]SubjectCount `json:"subjects_by_rule"`
	// Suggestions are config commands that would resolve the most common
	// findings, most impactful first.
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

type subjectAgg struct {
	count, blocked int
	example        string
}

// protectedPaths returns paths the report must never suggest widening the
// boundary to: the home directory itself and everything on the read-deny list.
// A boundary finding there is the sandbox doing its job, not friction to fix.
func protectedPaths(cfg *config.Config) []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, home)
	}
	return append(out, cfg.EffectiveDeniedReadPaths()...)
}

// buildReport aggregates recs. top caps the per-rule subject lists; protected
// lists paths (and their subtrees, except the home directory which only matches
// itself) that never get a readable-paths suggestion.
func buildReport(recs []audit.Record, top int, protected []string) *Report {
	rep := &Report{
		Records:    len(recs),
		Blocked:    map[string]int{},
		WouldBlock: map[string]int{},
		Subjects:   map[string][]SubjectCount{},
	}
	agg := map[string]map[string]*subjectAgg{} // rule -> subject -> agg
	for _, r := range recs {
		if r.Blocked {
			rep.Blocked[r.Rule]++
		} else if len(r.WouldBlockIn) > 0 {
			// Attribute to the loosest mode that would block it: that is the next
			// step up from wherever the user is.
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
			a = &subjectAgg{example: r.Command}
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
		if top > 0 && len(list) > top {
			list = list[:top]
		}
		rep.Subjects[rule] = list
	}
	rep.Suggestions = suggestions(agg, protected)
	return rep
}

// isProtected reports whether a boundary subject must not be suggested as a
// readable path: the home directory itself, or anything at or under a
// protected (read-denied) path.
func isProtected(path string, protected []string) bool {
	home, _ := os.UserHomeDir()
	if home != "" && path == home {
		return true
	}
	for _, p := range protected {
		if p == home {
			continue // home only protects itself; its subtree is fine
		}
		if path == p || strings.HasPrefix(path, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// suggestions turns the aggregated subjects into concrete config commands.
func suggestions(agg map[string]map[string]*subjectAgg, protected []string) []Suggestion {
	var out []Suggestion
	for subj, a := range agg["command_whitelist"] {
		if strings.HasPrefix(subj, "./") || strings.HasPrefix(subj, "../") || strings.HasPrefix(subj, "/") {
			out = append(out, Suggestion{
				Command: "lite-sandbox config local-binary-execution enable",
				Count:   a.count,
				Reason:  fmt.Sprintf("direct execution of %s", subj),
			})
			continue
		}
		out = append(out, Suggestion{
			Command: fmt.Sprintf("lite-sandbox config extra-commands add %s", subj),
			Count:   a.count,
			Reason:  fmt.Sprintf("%q is not on the allowlist", subj),
		})
	}
	for subj, a := range agg["local_binary"] {
		out = append(out, Suggestion{
			Command: "lite-sandbox config local-binary-execution enable",
			Count:   a.count,
			Reason:  fmt.Sprintf("direct execution of %s", subj),
		})
	}
	for subj, a := range agg["runtime_disabled"] {
		rt := runtimeForCommand(subj)
		if rt == "" {
			continue
		}
		out = append(out, Suggestion{
			Command: fmt.Sprintf("lite-sandbox config runtimes %s enable", rt),
			Count:   a.count,
			Reason:  fmt.Sprintf("%q needs the %s runtime", subj, rt),
		})
	}
	// Boundary findings: suggest the directory containing the path. Collapse
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
		out = append(out, Suggestion{
			Command: fmt.Sprintf("lite-sandbox config readable-paths add %s", dir),
			Count:   n,
			Reason:  "paths under this directory were outside the boundary (use writable-paths add if they are written)",
		})
	}
	// Merge duplicate commands (e.g. several scripts -> one local-binary line).
	merged := map[string]*Suggestion{}
	for _, s := range out {
		if m, ok := merged[s.Command]; ok {
			m.Count += s.Count
			continue
		}
		c := s
		merged[s.Command] = &c
	}
	out = out[:0]
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

// runtimeForCommand maps a runtime-gated command to its `config runtimes`
// name. Kept in sync with the runtimeGate registrations in bash_sandboxed.
func runtimeForCommand(cmd string) string {
	switch cmd {
	case "go", "gofmt":
		return "go"
	case "pnpm", "pnpx":
		return "pnpm"
	case "cargo", "rustc", "rustup":
		return "rust"
	case "deno":
		return "deno"
	case "flutter", "dart", "fvm":
		return "flutter"
	case "uv", "uvx":
		return "uv"
	}
	return ""
}

func printReport(w *os.File, rep *Report, path string, mode config.Mode, since time.Time) {
	fmt.Fprintf(w, "Audit log: %s\n", path)
	if !since.IsZero() {
		fmt.Fprintf(w, "Since: %s\n", since.Format(time.RFC3339))
	}
	fmt.Fprintf(w, "Current mode: %s\nFindings: %d\n", mode, rep.Records)
	if rep.Records == 0 {
		fmt.Fprintln(w, "\nNo findings recorded. Is audit enabled? (`lite-sandbox config audit show`)")
		return
	}

	fmt.Fprintln(w, "\nBlocked in the current mode (friction now):")
	if len(rep.Blocked) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, rule := range sortedKeys(rep.Blocked) {
		fmt.Fprintf(w, "  %-20s %d\n", rule, rep.Blocked[rule])
	}

	fmt.Fprintln(w, "\nNot blocked, but would be in a stricter mode (cost of stepping up):")
	if len(rep.WouldBlock) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, m := range sortedKeys(rep.WouldBlock) {
		fmt.Fprintf(w, "  %-20s %d\n", m, rep.WouldBlock[m])
	}

	fmt.Fprintln(w, "\nTop subjects by rule:")
	for _, rule := range sortedKeys(rep.Subjects) {
		fmt.Fprintf(w, "  %s\n", rule)
		for _, sc := range rep.Subjects[rule] {
			flag := ""
			if sc.Blocked > 0 {
				flag = fmt.Sprintf(" (%d blocked)", sc.Blocked)
			}
			fmt.Fprintf(w, "    %5d  %s%s\n", sc.Count, sc.Subject, flag)
		}
	}

	if len(rep.Suggestions) > 0 {
		fmt.Fprintln(w, "\nSuggested config changes (most findings first):")
		for _, s := range rep.Suggestions {
			fmt.Fprintf(w, "  %5d  %s\n         %s\n", s.Count, s.Command, s.Reason)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
