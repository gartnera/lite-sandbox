package cmd

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Manage AWS CLI permission settings",
}

// findAWSOverride returns the AWS section of the existing directory override for
// dir, or nil if no override (or no AWS section within it) is configured. The
// override lookup itself is the generic, section-agnostic one in
// config_overrides.go.
func findAWSOverride(cfg *config.Config, dir string) *config.AWSConfig {
	if o := findOverride(cfg, dir); o != nil {
		return o.AWS
	}
	return nil
}

var awsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current AWS configuration (with --dir, the one in effect there)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		// With --dir the loaded config is already resolved for that directory,
		// so print the mode it ends up with rather than the base plus a list of
		// overrides that do not apply there.
		if configDir != "" {
			fmt.Printf("AWS configuration for %s:\n", resolveDirArg(configDir))
			printAWSMode(cfg.AWS, "  ")
			return nil
		}

		// Directory overrides can set an aws section without a base aws section
		// existing (e.g. `config aws force-profile X --dir Y` with no base), so
		// don't early-return on a nil base — that would hide those overrides. A
		// single pass over cfg.Overrides prints them and, lazily on the first one,
		// the header (plus a note when there is no base to show).
		if cfg.AWS != nil {
			fmt.Println("AWS Configuration:")
			printAWSMode(cfg.AWS, "  ")
		}

		printedHeader := false
		for i := range cfg.Overrides {
			o := &cfg.Overrides[i]
			if o.AWS == nil {
				continue
			}
			if !printedHeader {
				if cfg.AWS != nil {
					fmt.Println()
				} else {
					fmt.Println("AWS: no base configuration (overrides only)")
				}
				fmt.Println("Directory overrides (most specific match wins):")
				printedHeader = true
			}
			fmt.Printf("  %s:\n", o.Path)
			printAWSMode(o.AWS, "    ")
		}

		if cfg.AWS == nil && !printedHeader {
			fmt.Println("AWS: disabled (not configured)")
		}

		return nil
	},
}

// printAWSMode prints the resolved credential mode for an AWS config (base or
// override) with the given indent.
func printAWSMode(a *config.AWSConfig, indent string) {
	switch {
	case a.AllowsRawCredentials():
		fmt.Printf("%sMode: allow_raw_credentials\n", indent)
		fmt.Printf("%sDescription: AWS CLI reads from ~/.aws/credentials directly\n", indent)
		fmt.Printf("%sSecurity: Less secure (long-term credentials)\n", indent)
		fmt.Printf("%s~/.aws: Accessible\n", indent)
	case a.UsesIMDS():
		fmt.Printf("%sMode: force_profile (%s)\n", indent, a.IMDSProfile())
		fmt.Printf("%sDescription: AWS CLI uses IMDS server with temporary credentials\n", indent)
		fmt.Printf("%sSecurity: More secure (1-hour STS tokens)\n", indent)
		if len(a.AllowedProfiles) > 0 {
			fmt.Printf("%sAllowed profiles (via AWS_PROFILE): %s\n", indent, strings.Join(a.AllowedProfiles, ", "))
		}
		fmt.Printf("%s~/.aws: Blocked under the OS sandbox in every mode (a paths grant on ~/.aws lifts it; `config mode show`)\n", indent)
	default:
		fmt.Printf("%sMode: disabled\n", indent)
		fmt.Printf("%sAWS CLI commands are not allowed\n", indent)
	}
}

var awsAllowRawCredentialsCmd = &cobra.Command{
	Use:   "allow-raw-credentials",
	Short: "Allow AWS CLI to read from ~/.aws/credentials directly (less secure)",
	Long: `Enable allow_raw_credentials mode for AWS CLI.

In this mode:
- AWS CLI reads credentials from ~/.aws/credentials directly
- No IMDS server is started
- ~/.aws is NOT blocked (accessible to commands)
- ~/.ssh private keys stay blocked (a paths grant on ~/.ssh is what lifts that)
- Uses long-term credentials (no automatic rotation)

This mode is simpler but less secure. Use for development/testing only.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Enable raw credentials, clear force_profile and its brokered profiles
		t := true
		cfg.AWS.AllowRawCredentials = &t
		cfg.AWS.ForceProfile = ""
		cfg.AWS.AllowedProfiles = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("AWS configured for raw credential access")
		fmt.Println("  ~/.aws/credentials will be readable by AWS CLI")
		fmt.Println("  ~/.ssh private keys will remain blocked")
		return nil
	},
}

var awsForceProfileCmd = &cobra.Command{
	Use:   "force-profile <profile-name>",
	Short: "Force AWS CLI to use IMDS server with specified profile (more secure)",
	Long: `Enable force_profile mode for AWS CLI.

In this mode:
- AWS CLI gets credentials from local IMDS server
- IMDS server uses specified profile to fetch temporary STS credentials
- ~/.aws is BLOCKED (not accessible to commands)
- ~/.ssh private keys are ALWAYS blocked
- Uses temporary 1-hour STS session tokens
- Credentials auto-refresh before expiry

This mode is more secure and recommended for production use.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profile := args[0]

		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Set force_profile, clear allow_raw_credentials. AllowedProfiles is
		// preserved across a profile change.
		cfg.AWS.ForceProfile = profile
		cfg.AWS.AllowRawCredentials = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Printf("AWS configured to force profile: %s\n", profile)
		fmt.Println("  IMDS server will provide temporary credentials")
		fmt.Println("  ~/.aws will be blocked")
		fmt.Println("  ~/.ssh private keys will remain blocked")
		return nil
	},
}

var awsAllowedProfilesCmd = &cobra.Command{
	Use:   "allowed-profiles [profile...]",
	Short: "Set the profiles selectable at runtime via AWS_PROFILE (force_profile mode)",
	Long: `Set allowed_profiles for force_profile (IMDS) mode.

These profiles are additionally selectable per command via AWS_PROFILE=<name>, on
top of the default force_profile (which is always allowed). Each gets its own
brokered IMDS server. Pass no names to clear the list.

Requires force_profile to be in effect — from the base config, or, under --dir,
from that directory's override. Set it first with
"config aws force-profile <profile> [--dir ...]".`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		var profiles []string
		if len(args) > 0 {
			profiles = args
		}

		if cfg.AWS == nil || cfg.AWS.ForceProfile == "" {
			where, dirFlag := "", ""
			if configDir != "" {
				where = " for " + resolveDirArg(configDir)
				dirFlag = " --dir " + configDir
			}
			return fmt.Errorf("allowed_profiles requires force_profile%s; run `lite-sandbox config aws force-profile <profile>%s` first", where, dirFlag)
		}
		cfg.AWS.AllowedProfiles = profiles
		if err := saveConfig(cfg); err != nil {
			return err
		}
		printAllowedProfilesResult(cfg.AWS.ForceProfile, profiles)
		return nil
	},
}

// printAllowedProfilesResult reports the outcome of an allowed-profiles change.
func printAllowedProfilesResult(forceProfile string, profiles []string) {
	where := configScope()
	if len(profiles) == 0 {
		fmt.Printf("Cleared AWS allowed_profiles%s (only %q is selectable)\n", where, forceProfile)
		return
	}
	fmt.Printf("AWS allowed_profiles%s: %s\n", where, strings.Join(profiles, ", "))
	fmt.Printf("  Selectable per command via AWS_PROFILE=<name>; default remains %q\n", forceProfile)
	fmt.Println("  Each must be a real profile in ~/.aws/config on the host")
}

var awsRemoveOverrideCmd = &cobra.Command{
	Use:   "remove-override [dir]",
	Short: "Remove the AWS directory override for the given path (defaults to --dir)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := dirArgOrFlag(args)
		if err != nil {
			return err
		}

		// Edit the stored config directly: this removes a section from an
		// override rather than setting a value inside one.
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		o := findOverride(cfg, dir)
		if o == nil || o.AWS == nil {
			fmt.Printf("No AWS override configured for %s\n", dir)
			return nil
		}

		// Clear only the AWS section, preserving any other sections stored for
		// this directory. Drop the whole override once it sets nothing.
		o.AWS = nil
		if !o.SetsAnySection() {
			removeOverride(cfg, dir)
		}

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("Removed AWS override for %s\n", dir)
		return nil
	},
}

var awsDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable AWS CLI entirely",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		// Clear all AWS settings. Under --dir "unset" would mean "inherit the
		// base", so record an empty section instead: it replaces the base's for
		// that directory and leaves AWS disabled there.
		if configDir != "" {
			cfg.AWS = &config.AWSConfig{}
		} else {
			cfg.AWS = nil
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("AWS disabled")
		fmt.Println("  AWS CLI commands will not be allowed")
		return nil
	},
}

func init() {
	awsCmd.AddCommand(awsShowCmd)
	awsCmd.AddCommand(awsAllowRawCredentialsCmd)
	awsCmd.AddCommand(awsForceProfileCmd)
	awsCmd.AddCommand(awsAllowedProfilesCmd)
	awsCmd.AddCommand(awsRemoveOverrideCmd)
	awsCmd.AddCommand(awsDisableCmd)
	configCmd.AddCommand(awsCmd)
}
