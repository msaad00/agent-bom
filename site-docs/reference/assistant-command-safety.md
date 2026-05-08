# Assistant Command Safety

AI assistants are now a command-delivery surface. A risky workflow does not
need a malicious binary download page; it can start with a plausible shell
command copied from a chat answer, issue comment, repo instruction file, or MCP
tool description.

This page is a safety checklist for agent-bom users. It does not claim that
agent-bom can prove any arbitrary command is safe. It helps teams find the
agent, MCP, credential, package, and runtime context around the command before
they run it broadly.

## Before Running A Suggested Command

| Question | Agent-bom check | What to do with the result |
|---|---|---|
| Did the command come from a repo instruction file or skill? | `agent-bom skills scan .` | Review command execution, credential access, URL, and trust-bypass findings. |
| Which MCP clients and servers could execute similar commands? | `agent-bom agents -p . -f json -o agent-bom-agents.json` | Identify exposed tools, server packages, and credential env-var names. |
| Does the command download and execute remote content? | code review plus `agent-bom code scan .` where applicable | Treat pipe-to-shell, curl/wget, encoded scripts, and installers as high risk. |
| Does an MCP server expose shell, filesystem, browser, network, or database tools? | `agent-bom agents --enforce -p .` | Prefer proxy/gateway enforcement before enabling broad assistant access. |
| Will the command touch AI provider keys? | inventory env-var names and provider secret owners | Rotate or scope credentials before testing in shared environments. |

## Red Flags

- `curl ... | sh`, `wget ... | bash`, `python -c`, `osascript`, PowerShell
  download-and-execute patterns, or base64-decoded script execution.
- Requests to disable browser, OS, endpoint, or assistant safety prompts.
- Commands that read shell profiles, `.env`, cloud credential files, keychains,
  SSH keys, browser profiles, or package manager tokens.
- MCP server instructions that combine file read, command execution, and
  network egress.
- Tool descriptions that instruct the assistant to ignore policy, hide output,
  or send data to an external URL.

## Safer Review Flow

```bash
agent-bom skills scan . -f json -o agent-bom-skills.json
agent-bom agents -p . --enforce -f html -o agent-bom-command-review.html
```

If the command belongs to an MCP workflow, put the target server behind the
proxy before testing:

```bash
agent-bom proxy --log audit.jsonl --block-undeclared -- <server-command>
```

The artifact you want is not a blanket "safe" verdict. It is a packet showing:

- the exact command source
- the assistant or MCP client involved
- the MCP server and tools reachable from that assistant
- credential environment variable names exposed to the server
- package and vulnerability context
- any runtime audit, block, or alert evidence

## What To Put In A PR Or Incident Note

- The command or instruction source, sanitized if needed.
- The `agent-bom` command used to inspect the repo or endpoint.
- The generated artifact path.
- Whether the evidence is static scan, runtime proxy/gateway, provider log, or
  operator assertion.
- The decision: allowed for local test, blocked, needs sandbox, needs provider
  key rotation, or needs owner review.

## Product Boundaries

agent-bom helps with evidence and enforcement around AI-agent infrastructure. It
does not replace endpoint detection, browser protection, provider audit logs,
or human review for arbitrary shell scripts.
