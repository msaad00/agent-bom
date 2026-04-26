# Enterprise Support, Patch, And Disclosure Model

This document defines the support and response model for self-hosted
`agent-bom` deployments. It is written for procurement and security review. It
does not create a paid support contract, hosted-service SLA, or legal DPA.

## Support Channels

| Channel | Use for | Boundary |
|---|---|---|
| GitHub issues | bugs, feature requests, documentation gaps, non-sensitive operational questions | public, best-effort OSS support |
| GitHub Security Advisories | suspected product vulnerabilities, exploit details, bypasses, sensitive reports | private security disclosure path |
| Customer-owned incident process | compromised hosts, leaked customer credentials, IdP events, cloud account incidents | operated by the deploying organization |

Do not post secrets, customer data, exploit details, private logs, or tenant
identifiers in public GitHub issues.

## Supported Version Window

For the open-source project, the supported version is the latest released tag.
Security fixes target the latest release line first. Older releases are not
maintained as long-term support branches unless a separate commercial or
customer-specific agreement exists.

| Version line | OSS support posture |
|---|---|
| Latest release | security fixes and compatibility fixes target this line |
| Previous releases | upgrade guidance only unless a coordinated security embargo requires a temporary backport |
| Unreleased `main` | development branch, not a supported production version |

Operators should pin exact release tags and verify release artifacts with
`docs/RELEASE_VERIFICATION.md` before production rollout.

## Patch Cadence

| Patch type | Target behavior |
|---|---|
| Critical security fix | patched release as soon as practical after validation; coordinated with GHSA/CVE publication when warranted |
| High security fix | patched release after triage, regression tests, and release verification pass |
| Medium/low security fix | next scheduled patch or minor release unless active exploitation changes priority |
| Non-security bug fix | regular release cadence, prioritized by impact and reproducibility |
| Documentation-only clarification | can ship independently when it reduces operator risk or procurement ambiguity |

Release notes should call out security-impacting changes explicitly under a
security or hardening heading. Use concrete language: what changed, who is
affected, whether the default posture changed, and whether operators must rotate
secrets, update policy, or change deployment configuration.

## Vulnerability Severity And Response Targets

Security reports are triaged with CVSS-style severity and product-specific
context. The targets below are response goals, not contractual SLAs.

| Severity | Examples | Target response |
|---|---|---|
| Critical | remote code execution in default control-plane path, auth bypass, tenant isolation bypass with cross-tenant data exposure | acknowledge within 48 hours; triage within 5 business days; urgent patch target after validated fix |
| High | sandbox escape in agent-bom-managed process, privilege escalation, stored secret exposure, reliable policy bypass | acknowledge within 48 hours; triage within 5 business days; patch in the next security release |
| Medium | denial-of-service requiring authenticated access, detector bypass with limited impact, hardening gap in non-default mode | acknowledge within 48 hours; triage within 5 business days; schedule into a normal patch train |
| Low | documentation ambiguity, warning-quality issue, non-sensitive information exposure, defense-in-depth polish | acknowledge and track publicly or privately as appropriate |

Active exploitation, public proof-of-concept code, or a credible downstream
supply-chain risk can raise priority regardless of the initial severity.

## Responsible Disclosure

Report suspected vulnerabilities privately through GitHub Security Advisories:

<https://github.com/msaad00/agent-bom/security/advisories/new>

The disclosure flow is:

1. Reporter submits a private advisory with affected version, impact, and
   reproduction details.
2. Maintainer acknowledges receipt and assigns an initial severity.
3. Maintainer validates the issue, prepares a private fix branch, and requests
   a CVE/GHSA when warranted.
4. Patch, release notes, and advisory publication are coordinated so users can
   upgrade before exploit details are broadly amplified.
5. Reporter credit is included unless anonymity is requested.

The coordinated disclosure embargo policy remains the source of truth in
`SECURITY.md`.

## Customer Incident Versus Product Vulnerability

`agent-bom` is a self-hosted product. The deploying organization owns the
runtime environment, network, identity provider, cloud accounts, data stores,
secrets, endpoint controls, monitoring, and incident response.

| Scenario | Primary owner |
|---|---|
| A bug in agent-bom allows auth bypass, cross-tenant leakage, policy bypass, or sandbox escape | agent-bom security disclosure process |
| A customer cloud credential is leaked outside agent-bom | customer incident process |
| A customer's IdP, ingress, service mesh, or KMS is misconfigured | customer platform/security team |
| A vulnerable dependency affects agent-bom release artifacts | agent-bom security disclosure process |
| A customer-operated database, bucket, or backup is exposed | customer incident process |

When a customer incident reveals a product weakness, open a private security
advisory with the product-specific evidence and keep customer incident data out
of public issues.

## Escalation Path For Self-Hosted Deployments

For production-impacting self-hosted issues:

1. Confirm the release tag, commit SHA, deployment mode, and whether local
   changes are present.
2. Capture non-secret posture from `/v1/auth/policy`,
   `/v1/auth/secrets/lifecycle`, `/v1/posture/enrichment`, `/readyz`, and
   `/metrics`.
3. Attach sanitized logs, sanitized Helm values, and failing command output.
4. Use a public GitHub issue for non-sensitive bugs or a private security
   advisory for vulnerability evidence.
5. Keep raw secrets, tenant data, customer identifiers, kubeconfigs, and cloud
   credentials out of all public artifacts.

## Release Note Security Language

Security-impacting release notes should include:

- affected surface
- previous behavior
- new behavior
- default posture
- operator action required
- linked issue or advisory
- validation summary

Example:

```md
Security: MCP sandbox mounts now reject sensitive host paths by default. Prior
versions allowed broader operator-supplied mounts in isolated mode. Operators
using custom `--sandbox-mount` values should verify that only intended
read-only project paths are mounted. Refs #1905.
```

## Non-Claims

This model does not claim SOC 2, ISO 27001 certification, FedRAMP
authorization, hosted SaaS availability SLAs, 24/7 pager coverage, or customer
incident-response ownership. Those require separate legal, operational, and
external attestation work.
