# Claude-specific addendum

This file carries **Claude-only** behavior. Cross-agent project rules live in
`AGENTS.md` (read by every coding agent that follows the
[agents.md](https://agents.md) convention — Claude, Codex, Cursor, Continue,
Aider, Windsurf).

Read `AGENTS.md` first. Everything below adds Claude-specific notes that the
agents.md spec doesn't cover.

## Memory

- Claude Code auto-loads `MEMORY.md` from the per-project memory directory
  (managed by Claude — not in this repo). Treat it as authoritative for audit
  history, current release state, and positioning context.
- Save new memories after every merge, tag, release, audit, or new user
  feedback. Don't wait to be asked.
- When saving a date in a memory, write it absolute (`2026-03-05`), not
  relative ("Thursday"). Memory is read later in a different context.
- Before recommending a file, function, or flag from memory, verify it still
  exists in the current code. Stale memory should be updated, not acted on.

## Tools

- Use the `Skill` tool to invoke registered skills the user typed as
  `/<name>`. Never invent skill names.
- Use `Agent` (subagent) when a task is open-ended, requires many tool calls,
  or would burn the main context. Use `Explore` for read-only searches.
- For background long-running commands (server boot, watch scripts), use
  `Bash run_in_background: true` and rely on the harness notification — do
  not poll with sleep loops.

## Communication

- One-sentence preface before the first tool call in a turn; short updates
  only at finding / direction-change / blocker moments. End-of-turn summary
  is one or two sentences.
- For exploratory questions, give a 2-3 sentence recommendation + the main
  tradeoff before implementing.
