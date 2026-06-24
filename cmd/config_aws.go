package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/spf13/cobra"
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Manage AWS CLI permission settings",
}

// awsOverrideDir holds the --dir flag value shared by the mode commands. When
// set, the command edits the directory override for that path instead of the
// base AWS settings.
var awsOverrideDir string

// resolveDirArg canonicalizes a user-supplied directory to an absolute path so
// inputs like "." or "../sibling" are stored (and matched) as the concrete
// directory the user meant, not re-resolved later against the server's cwd. It
// falls back to the raw input if resolution fails.
func resolveDirArg(dir string) string {
	if resolved := config.ExpandPath(dir); resolved != "" {
		return resolved
	}
	return dir
}

// upsertAWSOverride sets the override for dir to the given mode, replacing any
// existing override for the same path. dir is canonicalized to an absolute path
// first so "." and other relative inputs are stored as a concrete directory
// rather than something that re-resolves against the server's working directory.
func upsertAWSOverride(cfg *config.Config, dir string, allowRaw *bool, forceProfile string) {
	if cfg.AWS == nil {
		cfg.AWS = &config.AWSConfig{}
	}
	if resolved := config.ExpandPath(dir); resolved != "" {
		dir = resolved
	}
	override := config.AWSDirectoryOverride{
		Path:                dir,
		AllowRawCredentials: allowRaw,
		ForceProfile:        forceProfile,
	}
	for i := range cfg.AWS.Overrides {
		if cfg.AWS.Overrides[i].Path == dir {
			cfg.AWS.Overrides[i] = override
			return
		}
	}
	cfg.AWS.Overrides = append(cfg.AWS.Overrides, override)
}

var awsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current AWS configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			fmt.Println("AWS: disabled (not configured)")
			return nil
		}

		fmt.Println("AWS Configuration:")
		printAWSMode(cfg.AWS, "  ")

		if len(cfg.AWS.Overrides) > 0 {
			fmt.Println("\nDirectory overrides (most specific match wins):")
			for _, o := range cfg.AWS.Overrides {
				fmt.Printf("  %s:\n", o.Path)
				printAWSMode(&config.AWSConfig{
					AllowRawCredentials: o.AllowRawCredentials,
					ForceProfile:        o.ForceProfile,
				}, "    ")
			}
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
		fmt.Printf("%s~/.ssh: Private keys blocked\n", indent)
	case a.UsesIMDS():
		fmt.Printf("%sMode: force_profile (%s)\n", indent, a.IMDSProfile())
		fmt.Printf("%sDescription: AWS CLI uses IMDS server with temporary credentials\n", indent)
		fmt.Printf("%sSecurity: More secure (1-hour STS tokens)\n", indent)
		fmt.Printf("%s~/.aws: Blocked\n", indent)
		fmt.Printf("%s~/.ssh: Private keys blocked\n", indent)
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
- ~/.ssh private keys are ALWAYS blocked
- Uses long-term credentials (no automatic rotation)

This mode is simpler but less secure. Use for development/testing only.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		t := true
		if awsOverrideDir != "" {
			dir := resolveDirArg(awsOverrideDir)
			upsertAWSOverride(cfg, dir, &t, "")
			if err := saveConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("AWS configured for raw credential access in %s\n", dir)
			fmt.Println("  ~/.aws/credentials will be readable by AWS CLI in that directory")
			fmt.Println("  ~/.ssh private keys will remain blocked")
			return nil
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Enable raw credentials, clear force_profile
		cfg.AWS.AllowRawCredentials = &t
		cfg.AWS.ForceProfile = ""

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

		if awsOverrideDir != "" {
			dir := resolveDirArg(awsOverrideDir)
			upsertAWSOverride(cfg, dir, nil, profile)
			if err := saveConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("AWS configured to force profile %q in %s\n", profile, dir)
			fmt.Println("  IMDS server will provide temporary credentials in that directory")
			fmt.Println("  ~/.aws will be blocked")
			fmt.Println("  ~/.ssh private keys will remain blocked")
			return nil
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Set force_profile, clear allow_raw_credentials
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

var awsRemoveOverrideCmd = &cobra.Command{
	Use:   "remove-override <dir>",
	Short: "Remove the AWS directory override for the given path",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := resolveDirArg(args[0])

		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil || len(cfg.AWS.Overrides) == 0 {
			fmt.Printf("No override configured for %s\n", dir)
			return nil
		}

		kept := cfg.AWS.Overrides[:0]
		removed := false
		for _, o := range cfg.AWS.Overrides {
			if o.Path == dir {
				removed = true
				continue
			}
			kept = append(kept, o)
		}
		cfg.AWS.Overrides = kept
		if len(cfg.AWS.Overrides) == 0 {
			cfg.AWS.Overrides = nil
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		if removed {
			fmt.Printf("Removed AWS override for %s\n", dir)
		} else {
			fmt.Printf("No override configured for %s\n", dir)
		}
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

		// Clear all AWS settings
		cfg.AWS = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("AWS disabled")
		fmt.Println("  AWS CLI commands will not be allowed")
		return nil
	},
}

func init() {
	awsAllowRawCredentialsCmd.Flags().StringVar(&awsOverrideDir, "dir", "",
		"Apply this mode only to commands run in this directory (adds a per-directory override)")
	awsForceProfileCmd.Flags().StringVar(&awsOverrideDir, "dir", "",
		"Apply this profile only to commands run in this directory (adds a per-directory override)")

	awsCmd.AddCommand(awsShowCmd)
	awsCmd.AddCommand(awsAllowRawCredentialsCmd)
	awsCmd.AddCommand(awsForceProfileCmd)
	awsCmd.AddCommand(awsRemoveOverrideCmd)
	awsCmd.AddCommand(awsDisableCmd)
	configCmd.AddCommand(awsCmd)
}
