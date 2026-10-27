package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/peterh/liner"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

var shellCommand string

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Start an interactive sandbox shell",
	Long: `Start an interactive shell whose commands go through the same validation
(and, when enabled, the same OS sandbox) as the agent's bash tool.

Shell state carries over between commands as in bash: variables, functions,
the working directory (cd), and $?. Lines are edited with the usual readline
keys, history is kept across sessions, Tab completes command names and paths,
and Ctrl-C interrupts the running command rather than the shell.

With -c, the shell runs the given command and exits with its status. When
standard input is not a terminal, the shell reads commands from it without
prompting, so a script can be piped in.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := runShell(cmd.Flags().Changed("command"), shellCommand)
		if err != nil {
			return err
		}
		// After runShell's deferred cleanup (sandbox worker, IMDS, docker
		// proxy) has run.
		if status != 0 {
			os.Exit(status)
		}
		return nil
	},
}

func init() {
	shellCmd.Flags().StringVarP(&shellCommand, "command", "c", "", "run this command and exit with its status")
	rootCmd.AddCommand(shellCmd)
}

// runShell runs the shell until its input ends or a command exits it, and
// returns the status the shell exits with: the last command's, as bash does.
func runShell(hasCommand bool, command string) (int, error) {
	sandbox := bash_sandboxed.NewSandbox()
	defer startSSHAgentProxy(sandbox)()

	workDir, err := os.Getwd()
	if err != nil {
		return 1, fmt.Errorf("failed to get working directory: %w", err)
	}

	// Resolve per-directory overrides once for the shell's working directory, so
	// the sandbox, IMDS, and docker proxy below all get the same effective config.
	cfg, err := config.LoadForDirectory(workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load config, using defaults: %v\n", err)
	} else {
		sandbox.UpdateConfig(cfg, workDir)
	}
	defer sandbox.Close()

	// Start IMDS server if AWS uses IMDS (force_profile is set). cfg is already
	// resolved for workDir, so per-directory overrides take effect.
	var awsCfg *config.AWSConfig
	if cfg != nil {
		awsCfg = cfg.AWS
	}
	imdsLC := &imdsLifecycle{sandbox: sandbox}
	if err := imdsLC.apply(awsCfg); err != nil {
		return 1, err
	}
	defer imdsLC.stop()
	if endpoint := imdsLC.endpoint(); endpoint != "" {
		// Also set in process environment for subprocesses
		os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
	}

	// Pin allowed paths to the initial working directory so cd can't escape the sandbox.
	startDir := workDir
	readPaths := append([]string{startDir}, sandbox.ConfigReadPaths()...)
	writePaths := []string{startDir}

	// Start docker proxy if docker is enabled and usable, validating bind mounts
	// against the same path boundary the shell enforces. The docker command is
	// only permitted under the OS sandbox unless allow_unsandboxed is set.
	if cfg != nil && cfg.Docker.DockerEnabled() && (cfg.OSSandboxEnabled() || cfg.Docker.AllowsUnsandboxed()) {
		endpoint, cleanup, err := startDockerProxy(cfg, sandbox, readPaths, writePaths, startDir, func(endpoint string) {
			slog.Debug("starting docker proxy", "host", endpoint)
		})
		if err != nil {
			return 1, err
		}
		defer cleanup()

		os.Setenv("DOCKER_HOST", endpoint)
	}

	// Commands read the shell's stdin, except when the shell reads a script
	// from it: a terminal is shared, the shell reading at the prompt and the
	// command while it runs, but a piped script is the shell's alone.
	stdinTTY := term.IsTerminal(int(os.Stdin.Fd()))
	cmdStdin := os.Stdin
	if !hasCommand && !stdinTTY {
		cmdStdin = nil
	}
	sess, err := sandbox.NewSession(workDir, readPaths, writePaths, cmdStdin, os.Stdout, os.Stderr)
	if err != nil {
		return 1, err
	}

	// Ctrl-C interrupts the running command (runLine), never the shell. At an
	// interactive prompt liner reads it as a key instead.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)

	sh := &shell{sandbox: sandbox, sess: sess, interrupts: interrupts}
	if hasCommand {
		// Read only to ask for approval, which needs a terminal.
		sh.in = &plainLines{scanner: bufio.NewScanner(os.Stdin), interactive: stdinTTY}
		status, _, _ := sh.runLine(command)
		return status, nil
	}
	if stdinTTY && term.IsTerminal(int(os.Stdout.Fd())) {
		in := newLinerLines(sandbox, sess)
		defer in.Close()
		sh.in = in
	} else {
		// Without line editing; a terminal still gets prompts, on stderr.
		sh.in = &plainLines{scanner: bufio.NewScanner(os.Stdin), interactive: stdinTTY}
	}
	return sh.loop()
}

// shell is the read-eval loop around a session.
type shell struct {
	sandbox    *bash_sandboxed.Sandbox
	sess       *bash_sandboxed.Session
	in         lineSource
	interrupts chan os.Signal
	status     int
}

// errPromptAborted is a line source's report that the user pressed Ctrl-C at
// the prompt.
var errPromptAborted = errors.New("prompt aborted")

// lineSource is where the shell reads command lines from: the terminal, with
// line editing, or a piped script.
type lineSource interface {
	// ReadLine returns the next line, io.EOF at the end of input, or
	// errPromptAborted. prompt is shown only by an interactive source.
	ReadLine(prompt string) (string, error)
	// Interactive reports whether a user is typing the lines.
	Interactive() bool
	// AddHistory records a command the user entered.
	AddHistory(command string)
	// Suspend hands the terminal to a command; Resume takes it back.
	Suspend()
	Resume()
}

func (sh *shell) loop() (int, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	for {
		command, err := sh.readCommand(parser)
		if errors.Is(err, errPromptAborted) {
			sh.status = 130
			continue
		}
		if errors.Is(err, io.EOF) {
			if sh.in.Interactive() {
				fmt.Fprintln(os.Stderr, "exit")
			}
			return sh.status, nil
		}
		if err != nil {
			return sh.status, fmt.Errorf("input error: %w", err)
		}
		if strings.TrimSpace(command) == "" {
			continue
		}
		status, exited, interrupted := sh.runLine(command)
		sh.status = status
		if exited || (interrupted && !sh.in.Interactive()) {
			return status, nil
		}
	}
}

// readCommand reads one command, which may span lines: it keeps reading
// while the text so far parses as incomplete (an open quote, a trailing |,
// an unfinished if or loop).
func (sh *shell) readCommand(parser *syntax.Parser) (string, error) {
	command, err := sh.in.ReadLine(sh.prompt())
	if err != nil {
		return "", err
	}
	multiLine := false
	for {
		_, perr := parser.Parse(strings.NewReader(command), "")
		if perr == nil || !syntax.IsIncomplete(perr) {
			break
		}
		next, err := sh.in.ReadLine("> ")
		if errors.Is(err, io.EOF) {
			// Run what there is, and let the parser report what is missing.
			break
		}
		if err != nil {
			return "", err
		}
		command += "\n" + next
		multiLine = true
	}
	if strings.TrimSpace(command) != "" {
		for _, entry := range historyEntries(parser, command, multiLine) {
			sh.in.AddHistory(entry)
		}
	}
	return command, nil
}

// historyEntries are the history lines for a command. History entries are
// single lines, so a multi-line command is reprinted on one line where its
// syntax allows; one that holds a newline itself (a heredoc, a quoted
// newline) keeps its lines as typed, one entry each.
func historyEntries(parser *syntax.Parser, command string, multiLine bool) []string {
	if !multiLine {
		return []string{command}
	}
	lines := strings.Split(command, "\n")
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return lines
	}
	var b strings.Builder
	if err := syntax.NewPrinter(syntax.SingleLine(true)).Print(&b, f); err != nil {
		return lines
	}
	entry := strings.TrimSpace(b.String())
	if strings.Contains(entry, "\n") {
		return lines
	}
	return []string{entry}
}

// runLine runs one command line in the session. Ctrl-C while it runs cancels
// it. It returns the line's exit status, whether it exited the shell, and
// whether it was interrupted.
func (sh *shell) runLine(command string) (status int, exited, interrupted bool) {
	ctx := context.Background()

	// The user typing the command is the one an ask entry asks.
	if prompted := sh.sandbox.AskCommands(command); len(prompted) > 0 {
		if !sh.in.Interactive() {
			fmt.Fprintf(os.Stderr, "%s\nlite-sandbox: not run: approval needs an interactive shell\n", askReason(prompted))
			return 1, false, false
		}
		answer, err := sh.in.ReadLine(askReason(prompted) + "\nRun it? [y/N] ")
		if err != nil {
			return 1, false, errors.Is(err, errPromptAborted)
		}
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return 1, false, false
		}
		ctx = bash_sandboxed.WithApproval(ctx)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Drop a Ctrl-C that arrived while no command was running.
	select {
	case <-sh.interrupts:
	default:
	}
	stop := make(chan struct{})
	interruptedCh := make(chan bool, 1)
	go func() {
		select {
		case <-sh.interrupts:
			cancel()
			interruptedCh <- true
		case <-stop:
			interruptedCh <- false
		}
	}()

	sh.in.Suspend()
	status, exited, err := sh.sess.Run(ctx, command)
	sh.in.Resume()
	close(stop)
	interrupted = <-interruptedCh

	if interrupted {
		// The terminal echoed ^C; end its line.
		fmt.Fprintln(os.Stderr)
		return 130, exited, true
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "lite-sandbox: %v\n", err)
	}
	return status, exited, false
}

// prompt is the interactive prompt: the working directory, with the home
// directory shown as ~, and a long path cut to its last element so the line
// keeps room to type.
func (sh *shell) prompt() string {
	home, _ := os.UserHomeDir()
	width := 0
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width = w
	}
	return shellPrompt(sh.sess.Dir(), home, width)
}

func shellPrompt(dir, home string, width int) string {
	display := dir
	if home != "" && (dir == home || strings.HasPrefix(dir, home+string(filepath.Separator))) {
		display = "~" + strings.TrimPrefix(dir, home)
	}
	prompt := "sandbox:" + display + "$ "
	if width > 0 && len(prompt) > width/2 {
		prompt = "sandbox:…/" + filepath.Base(dir) + "$ "
	}
	return prompt
}

// plainLines reads lines from stdin without line editing or history: a
// piped script, or a terminal when stdout is not one (interactive, prompting
// on stderr as bash does).
type plainLines struct {
	scanner     *bufio.Scanner
	interactive bool
}

func (p *plainLines) ReadLine(prompt string) (string, error) {
	if p.interactive {
		fmt.Fprint(os.Stderr, prompt)
	}
	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	return p.scanner.Text(), nil
}

func (p *plainLines) Interactive() bool { return p.interactive }
func (p *plainLines) AddHistory(string) {}
func (p *plainLines) Suspend()          {}
func (p *plainLines) Resume()           {}

// linerLines reads lines from the terminal with liner's line editing,
// history and completion.
type linerLines struct {
	state *liner.State
	// cookedMode is the terminal's mode before liner, which commands run
	// in; lineMode is liner's, restored for the next prompt.
	cookedMode  liner.ModeApplier
	lineMode    liner.ModeApplier
	historyPath string
}

func newLinerLines(sandbox *bash_sandboxed.Sandbox, sess *bash_sandboxed.Session) *linerLines {
	l := &linerLines{historyPath: shellHistoryPath()}
	l.cookedMode, _ = liner.TerminalMode()
	l.state = liner.NewLiner()
	l.lineMode, _ = liner.TerminalMode()
	l.state.SetCtrlCAborts(true)
	l.state.SetMultiLineMode(true)
	l.state.SetTabCompletionStyle(liner.TabPrints)
	c := &completer{sandbox: sandbox, sess: sess}
	l.state.SetWordCompleter(c.complete)
	if l.historyPath != "" {
		if f, err := os.Open(l.historyPath); err == nil {
			_, _ = l.state.ReadHistory(f)
			f.Close()
		}
	}
	return l
}

func (l *linerLines) ReadLine(prompt string) (string, error) {
	// liner prompts on a single line; a multi-line prompt's leading lines are
	// printed first.
	if i := strings.LastIndexByte(prompt, '\n'); i >= 0 {
		fmt.Fprintln(os.Stderr, prompt[:i])
		prompt = prompt[i+1:]
	}
	line, err := l.state.Prompt(prompt)
	if errors.Is(err, liner.ErrPromptAborted) {
		return "", errPromptAborted
	}
	return line, err
}

func (l *linerLines) Interactive() bool { return true }

func (l *linerLines) AddHistory(command string) {
	l.state.AppendHistory(command)
}

func (l *linerLines) Suspend() {
	if l.cookedMode != nil {
		_ = l.cookedMode.ApplyMode()
	}
}

func (l *linerLines) Resume() {
	if l.lineMode != nil {
		_ = l.lineMode.ApplyMode()
	}
}

// Close saves the history and gives the terminal back its original mode.
func (l *linerLines) Close() {
	if l.historyPath != "" {
		if err := os.MkdirAll(filepath.Dir(l.historyPath), 0o700); err == nil {
			if f, err := os.OpenFile(l.historyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600); err == nil {
				_, _ = l.state.WriteHistory(f)
				f.Close()
			}
		}
	}
	l.state.Close()
}

// shellHistoryPath is where the shell keeps its history:
// $LITE_SANDBOX_HISTFILE, else lite-sandbox/shell_history under the XDG state
// directory ($XDG_STATE_HOME, default ~/.local/state). "" disables it.
func shellHistoryPath() string {
	if p, ok := os.LookupEnv("LITE_SANDBOX_HISTFILE"); ok {
		return p
	}
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "lite-sandbox", "shell_history")
}
