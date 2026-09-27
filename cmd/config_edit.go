package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
)

// editErrorPrefix marks the lines `config edit` puts at the top of the file
// when it reopens a rejected edit. They are stripped again when the editor
// exits, so they never reach the config.
const editErrorPrefix = "# lite-sandbox config edit: "

// editNewConfigTemplate is what `config edit` opens when no config file
// exists yet. Saving it unchanged creates nothing.
const editNewConfigTemplate = `# lite-sandbox configuration. Invalid edits are rejected and nothing is saved.
# Reference: https://github.com/gartnera/lite-sandbox/blob/main/docs/configuration.md
`

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open the config file in your editor, saving the edit only if it is a valid config",
	Long: `Open the config file in $VISUAL, else $EDITOR, else vi.

The edit is made on a temporary copy and written to the config file only once it
parses and validates. Beyond the checks every load applies (an unknown mode, profile,
or profile option; a malformed paths or commands entry), an edit is also rejected for
keys the config does not define, which are almost always typos, and for overrides
that could never apply (no path, a duplicate path, nested overrides). A rejected edit
can be reopened with the error at the top of the file, or abandoned; the config file
is left untouched either way.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := rejectConfigDir(cmd); err != nil {
			return err
		}
		// A rejected edit is not a usage error; don't bury it under the help.
		cmd.SilenceUsage = true
		return editConfig(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), runEditor)
	},
}

func init() {
	configCmd.AddCommand(configEditCmd)
}

// editConfig runs one `config edit` session: it copies the config file (or a
// template, when there is none) to a temporary file, has edit open it, and
// writes the result back only if config.ParseStrict accepts it. A rejected edit
// is reopened while the answer read from in says so; otherwise the edit is
// kept in the temporary file, whose path is reported, and an error returned.
func editConfig(in io.Reader, out, errOut io.Writer, edit func(path string) error) error {
	p, err := config.Path()
	if err != nil {
		return err
	}
	orig, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading config: %w", err)
	}
	start := orig
	if len(bytes.TrimSpace(orig)) == 0 {
		start = []byte(editNewConfigTemplate)
	}

	tmp, err := os.CreateTemp("", "lite-sandbox-config-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	keep := false
	defer func() {
		if !keep {
			os.Remove(tmpPath)
		}
	}()

	content := start
	answers := bufio.NewReader(in)
	for {
		if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
			return err
		}
		if err := edit(tmpPath); err != nil {
			return fmt.Errorf("editor failed, config left unchanged: %w", err)
		}
		raw, err := os.ReadFile(tmpPath)
		if err != nil {
			return err
		}
		edited := stripEditErrors(raw)
		if bytes.Equal(edited, start) || bytes.Equal(edited, orig) {
			fmt.Fprintln(out, "No changes made")
			return nil
		}

		if _, err := config.ParseStrict(edited); err != nil {
			fmt.Fprintf(errOut, "Invalid config: %v\n", err)
			if confirm(answers, errOut, "Edit again? [Y/n] ", true) {
				content = withEditError(edited, err)
				continue
			}
			keep = writeRejected(tmpPath, edited)
			if keep {
				return fmt.Errorf("invalid config not saved (your edit is in %s)", tmpPath)
			}
			return fmt.Errorf("invalid config not saved")
		}

		// Refuse to clobber a change made to the file while the editor was
		// open (another `config` command, a dotfile sync).
		now, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reading config: %w", err)
		}
		if !bytes.Equal(now, orig) {
			keep = writeRejected(tmpPath, edited)
			return fmt.Errorf("%s changed while you were editing; not overwriting it (your edit is in %s)", p, tmpPath)
		}
		if err := config.SaveRaw(edited); err != nil {
			return err
		}
		fmt.Fprintf(out, "Saved %s\n", p)
		return nil
	}
}

// writeRejected leaves an edit that was not saved in the temporary file, with
// no error header, so the person can recover it. It reports whether it did.
func writeRejected(path string, edited []byte) bool {
	return os.WriteFile(path, edited, 0o600) == nil
}

// withEditError prepends err to content as editErrorPrefix comment lines, so
// the person sees why the edit was rejected when the editor reopens it.
func withEditError(content []byte, err error) []byte {
	var b bytes.Buffer
	for _, line := range strings.Split("Invalid config, not saved: "+err.Error(), "\n") {
		b.WriteString(editErrorPrefix + line + "\n")
	}
	b.Write(content)
	return b.Bytes()
}

// stripEditErrors removes the leading lines withEditError added.
func stripEditErrors(content []byte) []byte {
	for bytes.HasPrefix(content, []byte(editErrorPrefix)) {
		i := bytes.IndexByte(content, '\n')
		if i < 0 {
			return nil
		}
		content = content[i+1:]
	}
	return content
}

// confirm asks a yes/no question on out and reads the answer from in; an
// empty answer is def, and EOF (no terminal to ask) is no.
func confirm(in *bufio.Reader, out io.Writer, question string, def bool) bool {
	fmt.Fprint(out, question)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def
	case "y", "yes":
		return true
	}
	return false
}

// runEditor opens path in the person's editor: $VISUAL, else $EDITOR, else vi.
// The value is run through sh, as git does, so an editor spelled with
// arguments ("code --wait") works.
func runEditor(path string) error {
	editor := strings.TrimSpace(os.Getenv("VISUAL"))
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if editor == "" {
		editor = "vi"
	}
	c := exec.Command("sh", "-c", editor+` "$@"`, editor, path)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
