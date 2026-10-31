import type { EngineInterface, Register } from 'claude-code'

// The approval prompt for lite-sandbox config requests and for commands whose
// commands entry has ask: true, in place of Claude Code's permission dialog.
//
// Pairs with `lite-sandbox install claude --external-approval`: the hook then
// neither asks nor records an approval ticket, and the server refuses a config
// request or prompted command unless one exists. This mod asks you, rewrites
// the request from the toggles you pick, and on your yes runs
// `lite-sandbox approve`, which records the ticket for exactly the call that
// goes on. Anything else — Deny, a dismissed picker, an error — denies the
// call, and without a ticket the server would refuse it anyway.

const TOOL = 'mcp__lite-sandbox__bash'
const BIN = 'lite-sandbox'

type DryRun = {
  kind: 'config' | 'command' | 'none'
  command?: string
  args?: string[]
  prompted?: string[]
}

const DENY = 'Deny'
const APPROVE = 'Approve'

/** A config request's subcommand words: the arguments before any flag-led target. */
function subcommand(args: string[]): string[] {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? ''
    if (a === '--dir') {
      i++
      continue
    }
    if (a.startsWith('-')) continue
    out.push(a)
  }
  return out
}

/** Families whose targets are paths or commands: one per request. */
function targetsOf(words: string[]): { verb: string; targets: string[] } | undefined {
  const [family, verb, ...targets] = words
  if ((family === 'paths' || family === 'commands') && verb && ['allow', 'ask', 'deny', 'remove'].includes(verb)) {
    return { verb: `${family} ${verb}`, targets }
  }
  return undefined
}

const hasFlag = (args: string[], flag: string) => args.some(a => a === flag || a.startsWith(flag + '='))
const withoutFlag = (args: string[], flag: string) => args.filter(a => a !== flag && !a.startsWith(flag + '='))
const withFlag = (args: string[], flag: string) => (hasFlag(args, flag) ? args : [...args, flag])

function quote(s: string): string {
  return /^[A-Za-z0-9_./:=@~+,-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`
}

async function lite(
  $: EngineInterface,
  argv: string[],
  cwd: string,
): Promise<{ ok: true; out: DryRun } | { ok: false; err: string }> {
  const r = await $.process.run([BIN, ...argv], { cwd, timeoutMs: 15_000 })
  if (r.exitCode !== 0) return { ok: false, err: (r.stderr || r.stdout).trim() }
  return { ok: true, out: JSON.parse(r.stdout) as DryRun }
}

export const register: Register = on => {
  on('tool.call', { tool: TOOL }, async ($, e, next) => {
    const command = (e as { command?: unknown }).command
    if (typeof command !== 'string') return next(e)
    const cwd = await $.session.cwd()

    const dry = await lite($, ['approve', '--dry-run', '--cwd', cwd, command], cwd)
    if (!dry.ok) {
      // Malformed or failing validation: the hook and server refuse it with
      // their own message. An `approve` this binary lacks is worth saying.
      if (/unknown command "approve"/.test(dry.err)) {
        $.ui.toast(`lite-sandbox prompt: the \`${BIN}\` on PATH has no \`approve\` subcommand; update it`)
      }
      return next(e)
    }
    if (dry.out.kind === 'none') return next(e)

    // A command whose commands entry has ask: true: a plain yes or no.
    if (dry.out.kind === 'command') {
      let answer: string
      try {
        answer = await $.ui.ask(
          `Run this command? It runs ${(dry.out.prompted ?? []).map(p => `\`${p}\``).join(', ')}, which your sandbox config asks about each time.\n\n  ${command}`,
          { options: [APPROVE, DENY], header: 'Sandbox cmd' },
        )
      } catch {
        return { deny: 'The user dismissed the lite-sandbox approval prompt.' }
      }
      if (answer !== APPROVE) return { deny: denial(answer) }
      const ok = await lite($, ['approve', '--cwd', cwd, command], cwd)
      if (!ok.ok) return { deny: `lite-sandbox approve failed: ${ok.err}` }
      return next(e)
    }

    // A config request: toggles for the one path or command it names.
    let args = dry.out.args ?? []
    const words = subcommand(args)
    const t = targetsOf(words)
    if (t && t.targets.length !== 1) {
      return {
        deny: `Request one ${words[0] === 'paths' ? 'path' : 'command'} per \`lite-sandbox config ${t.verb}\` call, so the user can decide each on its own.`,
      }
    }

    const choices = choicesFor(t?.verb, args)
    const requested = choices.find(c => c.requested)
    // The requested choice first, marked; Deny last. At most four options.
    const ordered = [...choices.filter(c => c.requested), ...choices.filter(c => !c.requested)]
    const labelOf = (c: Choice) => (c === requested ? `${c.label} (requested)` : c.label)
    const options = [...ordered.map(labelOf), DENY]

    const what = t ? `${t.verb} ${t.targets[0]}` : words.join(' ')
    const question =
      `Claude asks to change lite-sandbox's config: ${what}.\n` +
      `Pick how to approve it, or Deny (or type a note under Other) to refuse.\n\n  ${dry.out.command}`

    let answer: string
    try {
      answer = await $.ui.ask(question, { options, header: 'Sandbox cfg' })
    } catch {
      return { deny: 'The user dismissed the lite-sandbox approval prompt.' }
    }
    const choice = ordered.find(c => labelOf(c) === answer)
    if (!choice) return { deny: denial(answer) }

    const rewritten = [BIN, 'config', ...choice.apply(args)].map(quote).join(' ')
    const ok = await lite($, ['approve', '--cwd', cwd, ...(choice.global ? ['--global'] : []), rewritten], cwd)
    if (!ok.ok) return { deny: `lite-sandbox approve failed: ${ok.err}` }

    $.ui.toast(`lite-sandbox: approved ${ok.out.command}${choice.global ? ' (global)' : ''}`)
    return next({ ...e, command: rewritten })
  }).catch(() => ({ deny: 'The lite-sandbox approval prompt failed, so the request was not approved.' }))
}

/** One way to approve a config request: what it is called and how it rewrites the arguments. */
type Choice = { label: string; apply: (args: string[]) => string[]; requested: boolean; global?: boolean }

/** The approval choices for a config request (Deny is added by the caller): three at most. */
function choicesFor(verb: string | undefined, args: string[]): Choice[] {
  const write = hasFlag(args, '--write')
  const internal = hasFlag(args, '--internal')
  const noSandbox = hasFlag(args, '--no-sandbox')
  const strip = (a: string[], ...flags: string[]) => flags.reduce(withoutFlag, a)

  if (verb === 'paths allow') {
    return [
      { label: 'Read-only', apply: a => strip(a, '--write', '--internal'), requested: !write && !internal },
      { label: 'Read + write', apply: a => withFlag(strip(a, '--internal'), '--write'), requested: write && !internal },
      {
        label: 'Internal only (OS sandbox layer)',
        apply: a => withFlag(a, '--internal'),
        requested: internal,
      },
    ]
  }
  if (verb === 'commands allow') {
    return [
      { label: 'Allow (in the OS sandbox)', apply: a => strip(a, '--no-sandbox'), requested: !noSandbox },
      { label: 'Allow outside the OS sandbox', apply: a => withFlag(a, '--no-sandbox'), requested: noSandbox },
      {
        label: 'Ask me each time',
        apply: a => {
          const out = strip(a, '--no-sandbox')
          const i = out.indexOf('allow', out.indexOf('commands'))
          return out.map((w, j) => (j === i ? 'ask' : w))
        },
        requested: false,
      },
    ]
  }
  const choices: Choice[] = [{ label: APPROVE, apply: a => a, requested: true }]
  if (!hasFlag(args, '--dir')) choices.push({ label: 'Approve globally', apply: a => a, requested: false, global: true })
  return choices
}

function denial(answer: string): string {
  return answer && answer !== DENY ? `The user denied this lite-sandbox request: ${answer}` : 'The user denied this lite-sandbox request.'
}
