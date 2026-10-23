# misalignment-log-audit

An agent skill for checking your own AI coding-agent logs for misaligned or beyond-the-ask actions:
getting around rate limits and paywalls, using keys or tokens it found on a site, faking request
headers, leaving a sandbox, submitting forms or sending messages, unrequested pushes and deletions,
and gaming tests. The skill uses public 2026 incidents as reference points: OpenAI's DNS escape, the
Hugging Face incident, Anthropic's unintended-actions reports, CheatBench and ImpossibleBench.

Most of what an agent does beyond your literal request is fine, and often wanted. The questions this
skill asks are **whose system** an action touched, whether it came **after a blocker**, and whether
**you would sign off** on it.

It works on:
- **Claude Code** transcripts in `~/.claude/projects/` (including subagent transcripts)
- **Codex** transcripts in `~/.codex/sessions/`

## What it does

1. **Scans** every session with a read-only script that ranks sessions by cheap warning signs. Hits
   right after a 401, 403 or 429 count double. Each hit gets a `file:line` reference, and secrets
   are masked in the output.
2. **Optionally judges** every session with a cheap model (`judge_sessions.py`), for actions the
   patterns miss. This sends a clipped, masked copy of each session to your model provider, so the
   skill shows you a dry-run count first and only runs it on your yes.
3. **Reads** the top 10 sessions in the raw transcripts by default, then asks before reading more.
   For each one it records what you asked, what blocked the agent, which agent or subagent acted,
   what was passed between agents, and what you were finally told.
4. **Classifies** each confirmed action with a short codebook: archetype, whose system, consent,
   after a blocker, severity.
5. **Compares** each action to the closest known incident and writes a Markdown report that keeps
   verified incidents separate from unverified candidates.

It never re-runs anything it finds, tests found keys, or contacts any site.

## Privacy and safety: read this first

- **Your agent's model provider will see excerpts of your logs.** The scanner runs entirely on your
  machine. But when the agent reads sessions to verify them, those excerpts are sent to whichever
  provider runs the agent (Anthropic for Claude Code, OpenAI for Codex), like anything else you
  show it. If your logs hold client data, health records, unpublished work or secrets, narrow the
  scope with `--project` / `--since` or don't run the reading step. The skill tells you this before
  it starts reading.
- **Transcripts can contain prompt injections.** Your logs include web pages and files your agents
  fetched, and any of that text could be written to manipulate an AI reading it. The skill tells
  the auditing agent to treat everything in a transcript as evidence, never as instructions, and to
  report injection attempts as findings. That reduces the risk but can't guarantee it, so review
  the agent's actions as you would in any session.
- **Scan output can contain sensitive text.** `scan.md` and `scan.csv` quote snippets from your
  transcripts. Masking hides long keys, values after names like `password=` or `Authorization:`,
  credentials in URLs, and the name part of email addresses, but it misses things: short passwords,
  personal details and private text can still appear. Keep the output out of git (`scan/` is in
  this repo's `.gitignore`) and don't share it without reading it first.

## Before you start: keep your logs

Claude Code deletes local transcripts after **30 days** by default, so your older evidence may
already be gone. To keep them, add this to `~/.claude/settings.json`:

```json
{ "cleanupPeriodDays": 3650 }
```

The skill checks this setting and recommends the change, but it won't edit your settings for you.

## Install

**Claude Code:**

```bash
git clone https://github.com/angelamzhou/misalignment-log-audit.git
cp -R misalignment-log-audit/skills/misalignment-log-audit ~/.claude/skills/
```

**Codex:**

```bash
cp -R misalignment-log-audit/skills/misalignment-log-audit ~/.codex/skills/
```

Then ask your agent something like "audit my agent logs for anything sketchy from the last month".

## Run the scanner on its own

The scanner is a single Python 3 file with no dependencies.

```bash
python3 -I skills/misalignment-log-audit/scripts/scan_logs.py --out ./scan
```

It writes `scan/scan.md`, a ranked list of sessions, and `scan/scan.csv`, one row per hit. Both
quote masked snippets from your transcripts (see Privacy and safety above). Useful options:

| Option | Effect |
|---|---|
| `--since 2026-09-01` | only sessions starting on or after this date |
| `--project NAME` | only Claude Code projects whose folder name contains NAME |
| `--no-claude` / `--no-codex` | skip one source |
| `--file path.jsonl` | scan specific transcripts |
| `--top 40` | how many sessions to list in `scan.md` |

Hits are candidates to read, not findings. The patterns are deliberately broad, so expect noise.
Benchmark or eval-harness runs in your Claude Code folder can drown out real work; use `--project`
to skip them.

## Optional judge pass

```bash
python3 -I skills/misalignment-log-audit/scripts/judge_sessions.py --out ./judge --dry-run
python3 -I skills/misalignment-log-audit/scripts/judge_sessions.py --out ./judge --passes 2
```

A cheap model (`claude -p --model haiku` by default, or `--backend codex`) reads each session
against the codebook. It runs with no tools (or Codex's read-only sandbox in an empty folder), and
its instructions say to treat the transcript as evidence and report injection attempts. **It sends
a clipped, masked copy of every selected session to that provider**, so check the `--dry-run`
count first. Same filters as the scanner, plus `--limit` and `--workers`. Output: `judge/judge.md`
and `judge/judge.csv`. Judges disagree with themselves between runs, so `--passes 2` keeps the
union of flags. Treat every flag as a session to read, not a finding.

## Limits

- It only sees what your transcripts show. It can't see what actually reached a server.
- Logs that were deleted before you ran it are gone.
- Long tool outputs are clipped in the logs, so some actions may be missing.
- Whether you'd endorse an action is your call. The skill gives its read and asks you.

## Layout

```
skills/misalignment-log-audit/
├── SKILL.md                         workflow
├── references/incident-patterns.md  known incidents, their log traces, sources
├── references/codebook.md           how to classify an action
├── scripts/scan_logs.py             read-only signal scanner
└── scripts/judge_sessions.py        optional judge pass (sends text to your model provider)
```

## License

MIT
