package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the lite-sandbox version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(cmd.OutOrStdout(), version.String())
	},
}

func init() {
	rootCmd.Version = version.Version()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.AddCommand(versionCmd)
}
