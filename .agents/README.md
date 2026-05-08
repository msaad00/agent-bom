# Shared Agent Setup

This directory is the repo-owned source of truth for assistant and agent
behavior in agent-bom.

Use `.agents/` for configuration and guidance that should apply across tools.
Do not put durable shared guidance only in `.claude/`, `.cursor/`, `.vscode/`,
or another provider-specific directory.

## Layout

- `AGENTS.md`: canonical shared root instructions.
- `config.json`: shared bootstrap and MCP configuration for tool-specific shims.
- `skills/`: shared, tool-neutral implementation guidance for recurring
  workflows.

The repo root `AGENTS.md` is a discovery shim that points to
`.agents/AGENTS.md`, so tools can find the guide without duplicating it.

## When To Edit

Edit `.agents/AGENTS.md` when the standing engineering or product operating
contract changes.

Edit `.agents/config.json` when you need to change shared bootstrap commands,
default development commands, or repo-owned MCP servers.

Do not hand-edit generated provider files once generation exists. Edit the
canonical files in `.agents/` and regenerate the shims.
