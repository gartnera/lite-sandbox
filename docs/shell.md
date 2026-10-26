# Interactive shell

`lite-sandbox shell` opens an interactive shell for you to use. Its commands
go through the same validation as the agent's `bash` tool, and through the OS
sandbox too when that is enabled. Use it to see what the sandbox allows under
your current config, or to run commands under the agent's restrictions.

```bash
lite-sandbox shell                  # interactive
lite-sandbox shell -c 'ls | wc -l'  # run one command, exit with its status
lite-sandbox shell < script.sh      # run commands from a pipe or file, without prompts
```

The shell resolves the config, including per-directory overrides, for the
directory it starts in. That directory is the shell's read and write boundary,
plus any read grants in the config. You can `cd` freely within the boundary.
A `cd` that would leave it is refused, and so is a bare `cd` when `$HOME` is
outside it.

## Like a shell

- **State carries over between commands.** Variables, exported variables,
  functions, the working directory, and `$?` all persist from one command to
  the next. A function defined in one command can be called by the next.
  `cd` works anywhere in a command line (`cd src && ls`).
- **`exit [N]`** leaves the shell with status N. At end of input (Ctrl-D at an
  empty prompt) the shell exits with the last command's status, as bash does.
- **Output streams as it is produced**, and commands read the terminal. On the
  host, programs like `less` get the real terminal. Under the OS sandbox,
  commands run in the sandbox worker, which is detached from the terminal:
  they read no input from it (as if from `/dev/null`) and can't open
  `/dev/tty`, so interactive programs and prompts (ssh asking for a password)
  fail rather than wait. Input from a pipe still reaches them (`echo hi | cat`),
  and so does the terminal for the shell's own `read` builtin.
- **Ctrl-C** interrupts the running command, not the shell. At the prompt,
  Ctrl-C discards the current line.
- **Unfinished commands continue on a `> ` prompt.** This covers an open
  quote, a trailing `|`, and an unfinished `if` or loop.

## Line editing, history, and completion

When stdin and stdout are both terminals, lines are edited with
[liner](https://github.com/peterh/liner):

- The usual readline keys work: Ctrl-A/Ctrl-E, Ctrl-W, Ctrl-K/Ctrl-U,
  Ctrl-Y, Alt-B/Alt-F, and Ctrl-L.
- Up/Down step through history, keeping what you have already typed as a
  prefix. Ctrl-R searches history.
- Tab completes the word under the cursor. Where a command starts, it offers
  the command names your config allows plus the shell's functions. Anywhere
  else it offers file paths, including `~/`. A second Tab lists the
  candidates.

History is saved to `$XDG_STATE_HOME/lite-sandbox/shell_history`
(`~/.local/state/lite-sandbox/shell_history` by default). Set
`LITE_SANDBOX_HISTFILE` to use another file, or to an empty string to keep no
history. A multi-line command is saved on one line when its syntax allows. A
command containing a newline (a heredoc or a quoted newline) is saved one line
per entry.

If stdout is not a terminal, the shell still prompts, on stderr, but without
line editing.

## Approvals

A command matching a `commands` entry with `ask: true` (see
[configuration](configuration.md#commands-that-ask-first)) asks
`Run it? [y/N]` before it runs. With `-c` it asks too, if stdin is a
terminal. Commands read from a pipe can't be approved, so they are refused.

## Differences from bash

- Commands run in the sandbox's interpreter ([`mvdan.cc/sh`](https://github.com/mvdan/sh)),
  not bash, and only the commands the config allows run. The interpreter
  implements most of bash. It has no job control (`fg`, `bg`, Ctrl-Z) and no
  aliases.
- After Ctrl-C, `$?` holds the interrupted command's own exit status, not
  bash's 130.
- A bare `commands` allow runs in real `bash -c`. That bash is a separate
  process, so variables it sets and `cd`s it does don't carry over.
- Under the OS sandbox, keys you type while a command runs go to that command,
  even if it never reads them. In bash they would be kept for the next
  prompt.
- The OS sandbox worker logs at the shell's log level (warnings and up by
  default). Pass `--log-level info` to see its startup and per-command lines.
