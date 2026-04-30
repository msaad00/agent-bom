# Contributing agent-bom skills

Bundled skills are part of the product trust boundary. A skill must describe
what it can read, write, call, persist, and mutate before it can ship.

Use `integrations/openclaw/discover/SKILL.md` or
`integrations/openclaw/discover-aws/SKILL.md` as the reference shape. Do not
copy a shorter third-party skill template for bundled agent-bom skills.

## Required frontmatter

Every bundled skill must declare these fields under `metadata.openclaw`:

- `requires.bins`
- `requires.env`
- `requires.credentials`
- `credential_policy`
- `credential_handling`
- `optional_env`
- `optional_bins`
- `data_flow`
- `file_reads`
- `file_writes`
- `network_endpoints`
- `telemetry`
- `persistence`
- `privilege_escalation`
- `autonomous_invocation`

Each `network_endpoints` entry must name the endpoint, purpose, and whether
authentication is used. Use an empty list when no network call is made.

## Required body sections

Every bundled skill must include:

- a clear purpose and supported product surface
- mode guidance, including the default mode
- guardrails for what the skill may and may not do
- privacy and data handling guidance
- verification or provenance guidance
- the expected output artifact and schema, when the skill emits one

## Review rules

Reviewers should reject bundled skills that:

- ask users to paste raw cloud keys, API tokens, or session secrets into chat
- Never print raw credential values, raw URL credentials, or launch arguments
  with tokens
- mutate cloud, repository, endpoint, or control-plane resources unless the
  skill is explicitly a human-approved remediation skill
- call private agent-bom internals when an existing CLI, API, or MCP command
  provides the same product contract
- treat AI prose as compliance evidence
- emit inventory, SBOM, SARIF, or policy artifacts without schema validation
- drop `discovery_provenance`, `permissions_used`, or redaction state

## Remediation skills

Write-capable remediation skills have a higher bar than read-only discovery or
scan skills:

- `autonomous_invocation` must be `never`
- dry-run must be the default
- every writable file type must be enumerated in `file_writes`
- writes must stay inside the project root
- branch creation, package manager execution, and PR opening must be explicit
- `network_endpoints` must include GitHub and package registries used by the
  remediation workflow
- each apply attempt must produce an audit record

Do not ship a remediation skill that describes patch or PR behavior before the
corresponding CLI/API behavior exists and is tested.
