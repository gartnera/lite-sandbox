package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/internal/ghrelease"
	"github.com/gartnera/lite-sandbox/internal/selfupdate"
	"github.com/gartnera/lite-sandbox/internal/version"
)

var (
	updateVersion string
	updateCheck   bool
	updateForce   bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update lite-sandbox to the latest GitHub release",
	Long: `Downloads the latest lite-sandbox release from GitHub
(https://github.com/` + selfupdate.Repo + `/releases), verifies it against the
release's checksums.txt, and replaces this binary in place.

  lite-sandbox update                  # install the latest release
  lite-sandbox update --check          # only report whether one is available
  lite-sandbox update --version v0.4.0 # install (or roll back to) a specific release

The binary is swapped atomically, so MCP servers already running keep working
on the old build; restart your agent to pick up the new one. Set GITHUB_TOKEN
(or GH_TOKEN) to download through the authenticated GitHub API when the
anonymous rate limit is a problem.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true, // a failed download is not a usage error
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()
		return runUpdate(ctx, cmd)
	},
}

func init() {
	updateCmd.Flags().StringVar(&updateVersion, "version", "", "release to install (e.g. v0.4.0); default: the latest")
	updateCmd.Flags().BoolVar(&updateCheck, "check", false, "report whether an update is available without installing it")
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "reinstall even when the installed version is already the target")
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(ctx context.Context, cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	u := &selfupdate.Updater{Client: &ghrelease.Client{
		Warn: func(format string, args ...any) { fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...) },
	}}

	rel, err := u.Resolve(ctx, updateVersion)
	if err != nil {
		return err
	}
	current := version.Version()
	fmt.Fprintf(out, "installed: %s\n%s: %s\n", current, targetLabel(), rel.Tag)

	if cmp, ok := selfupdate.CompareVersions(current, rel.Tag); ok && !updateForce {
		switch {
		case cmp == 0:
			fmt.Fprintln(out, "already up to date")
			return nil
		case cmp > 0 && updateVersion == "":
			fmt.Fprintln(out, "the installed version is newer than the latest release; pass --version to pick a release or --force to downgrade")
			return nil
		}
	}
	if updateCheck {
		if current == version.Dev || !selfupdate.IsReleaseVersion(current) {
			fmt.Fprintf(out, "this is not a release build; `lite-sandbox update` would install %s\n", rel.Tag)
		} else {
			fmt.Fprintf(out, "update available: run `lite-sandbox update` to install %s\n", rel.Tag)
		}
		return nil
	}

	dest, err := selfupdate.ExecutablePath()
	if err != nil {
		return fmt.Errorf("locating the running binary: %w", err)
	}
	if err := u.Install(ctx, rel, dest); err != nil {
		return err
	}
	fmt.Fprintf(out, "updated %s to %s\n", dest, rel.Tag)
	fmt.Fprintln(out, "restart your agent so its lite-sandbox MCP server runs the new version")
	return nil
}

func targetLabel() string {
	if updateVersion != "" {
		return "requested"
	}
	return "latest"
}
