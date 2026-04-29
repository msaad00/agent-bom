# OpenClaw / ClawHub Skill Publishing

`agent-bom` keeps the public ClawHub surface intentionally small.

Published skills:
- `agent-bom-scan`
- `agent-bom-registry`
- `agent-bom-compliance`
- `agent-bom-runtime`
- `agent-bom-discover-aws`
- `agent-bom-vulnerability-intel`

These are the only skills pushed by release automation. They are:
- focused enough for individual and team use
- small enough to review and understand quickly
- explicit about credentials, file reads, network calls, and guardrails

Not published to ClawHub:
- the oversized omnibus root skill in [`SKILL.md`](SKILL.md)
- internal or narrower sub-skills such as `discover`, `analyze`, `enforce`, `monitor`, `scan-infra`, and `troubleshoot`

Reason:
- public marketplace skills should be curated, guardrailed, and easy to audit
- broader internal skill composition can stay in-repo without becoming the default public install surface

When updating versions for release, update only the published skill frontmatter unless a private/internal skill is intentionally being prepared for publication:
- [`scan/SKILL.md`](scan/SKILL.md)
- [`registry/SKILL.md`](registry/SKILL.md)
- [`compliance/SKILL.md`](compliance/SKILL.md)
- [`runtime/SKILL.md`](runtime/SKILL.md)
- [`discover-aws/SKILL.md`](discover-aws/SKILL.md)
- [`vulnerability-intel/SKILL.md`](vulnerability-intel/SKILL.md)
