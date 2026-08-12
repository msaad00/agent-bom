# Support

agent-bom is an Apache-2.0 open-source project maintained by a very small team.
This page says where to ask, and — honestly — what to expect back.

## Before you ask

Most first-run confusion has an answer already written down:

| Question | Read |
|---|---|
| How do I run it at all? | [Quick start](README.md#quick-start) |
| Why did the scan exit `1`? | [Exit-code contract](site-docs/reference/exit-codes.md) — a non-zero exit is a verdict, not a crash |
| What does the demo output mean? | [First-run guide](docs/FIRST_RUN.md) |
| How do I deploy the control plane? | [Deployment overview](site-docs/deployment/overview.md) |
| How do I connect a cloud account? | [Cloud connections](docs/CLOUD_CONNECT.md) |
| What does agent-bom actually read? | [Security policy](SECURITY.md#security-design) |

## Where to ask

Pick the one channel that matches what you have. Cross-posting the same
question to several does not make it get answered sooner.

| What you have | Where it goes |
|---|---|
| **A security vulnerability in agent-bom** | **Not** a public issue — [private advisory](https://github.com/msaad00/agent-bom/security/advisories/new). See [SECURITY.md](SECURITY.md), which is the one channel with a committed response time. |
| A reproducible bug | [Open an issue](https://github.com/msaad00/agent-bom/issues/new/choose) — `Bug Report`, or `Runtime / Proxy Bug` for gateway and proxy behavior |
| A finding you believe is wrong | [Open an issue](https://github.com/msaad00/agent-bom/issues/new/choose) — `Inaccurate Finding`. These are the most useful reports we get. |
| Docs that confused you | [Open an issue](https://github.com/msaad00/agent-bom/issues/new/choose) — `Docs Confusion` |
| A feature or integration request | [Open an issue](https://github.com/msaad00/agent-bom/issues/new/choose) — `Feature Request` / `Integration Request` |
| An open-ended question, or "am I holding it wrong?" | [GitHub Discussions](https://github.com/msaad00/agent-bom/discussions) |
| Wanting to talk to other users | [Discord](https://discord.gg/3YmYPqKZh5) — `#support` for usage, `#contributors` for PR questions |
| Wanting to contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) |

## What to expect

Being straight about this, because a vague promise is worse than a modest one:

- **There is no support SLA for issues, Discussions, or Discord.** The one
  exception is a reported security vulnerability, which has a stated
  acknowledgement and triage commitment in [SECURITY.md](SECURITY.md).
- Maintenance happens in bursts around releases. A quiet week is normal and does
  not mean your issue was dismissed.
- Issues with a reproduction get answered first, by a wide margin. An issue
  saying "the scan is wrong" without the command and output usually cannot be
  acted on at all.
- We may close an issue as stale if it cannot be reproduced and the thread has
  gone quiet. Reopening it with a reproduction is welcome and not a faux pas.
- Discord is peer support. Maintainers read it, but it is not a ticket queue and
  nothing there is tracked.

## Making a report we can act on

Paste the output of:

```bash
agent-bom --version
agent-bom scan --demo --offline
```

`--demo --offline` is deterministic and uses only bundled data, so it is safe to
paste and it tells us whether your install works at all. Then add the command
that actually went wrong and what you expected instead.

Redact before pasting: agent-bom prints credential *environment variable names*
as blast-radius context, never their values, but your own paths and repository
names may still be sensitive.

## Commercial and procurement questions

Support boundaries, patch cadence, and escalation paths for evaluation and
procurement are documented in
[docs/ENTERPRISE_SUPPORT_MODEL.md](docs/ENTERPRISE_SUPPORT_MODEL.md). Publishing
that document is not an offer of a commercial support contract.
