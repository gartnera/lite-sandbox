package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
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
up), and the config changes that would resolve the most common findings.

Suggestions are derived from what the agent attempted, so they are proposals to
review, not to apply blindly. Privilege, network, and shell commands are never
proposed, nor is widening the boundary to the home directory, a deny-listed
path, or a system directory.`,
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
	auditReportCWD   string
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
			d, err := audit.ParseSince(auditReportSince)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			since = time.Now().Add(-d)
		}
		recs, err := audit.Read(p, since)
		if err != nil {
			return err
		}
		cfg, _ := loadConfig()
		opts := audit.Options{Top: auditReportTop, Protected: protectedPaths(cfg)}
		if auditReportCWD != "" {
			opts.CWD = resolveDirArg(auditReportCWD)
		}
		rep := audit.BuildReport(recs, opts)
		if auditReportJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		mode := config.DefaultMode
		if cfg != nil {
			mode = cfg.EffectiveMode()
		}
		printReport(os.Stdout, rep, p, mode, since, opts.CWD)
		return nil
	},
}

func init() {
	auditReportCmd.Flags().StringVar(&auditReportSince, "since", "", "only include findings from the last duration, e.g. 24h, 7d")
	auditReportCmd.Flags().BoolVar(&auditReportJSON, "json", false, "print the report as JSON")
	auditReportCmd.Flags().IntVar(&auditReportTop, "top", 10, "how many entries to show per section")
	auditReportCmd.Flags().StringVar(&auditReportCWD, "cwd", "", "only include findings from sessions whose working directory is this directory or under it")
	auditCmd.AddCommand(auditPathCmd)
	auditCmd.AddCommand(auditClearCmd)
	auditCmd.AddCommand(auditReportCmd)
	rootCmd.AddCommand(auditCmd)
}

// protectedPaths returns paths the report must never suggest widening the
// boundary to: the home directory itself plus both deny lists. A boundary
// finding there is the sandbox doing its job, not friction to fix.
func protectedPaths(cfg *config.Config) []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, home)
	}
	out = append(out, cfg.EffectiveDeniedReadPaths()...)
	return append(out, cfg.EffectiveDeniedWritePaths()...)
}

func printReport(w io.Writer, rep *audit.Report, path string, mode config.Mode, since time.Time, cwd string) {
	fmt.Fprintf(w, "Audit log: %s\n", path)
	if !since.IsZero() {
		fmt.Fprintf(w, "Since: %s\n", since.Format(time.RFC3339))
	}
	if cwd != "" {
		fmt.Fprintf(w, "Working directory: %s\n", cwd)
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
			fmt.Fprintf(w, "    %5d  %s%s\n", sc.Count, audit.Sanitize(sc.Subject), flag)
		}
	}

	if len(rep.Suggestions) > 0 {
		fmt.Fprintln(w, "\nSuggested config changes (most findings first; review before applying):")
		for _, s := range rep.Suggestions {
			fmt.Fprintf(w, "  %5d  %s\n         %s\n", s.Count, audit.Sanitize(s.Command), audit.Sanitize(s.Reason))
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
