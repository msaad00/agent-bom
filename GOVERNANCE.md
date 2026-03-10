# Governance

## Decision-making model

agent-bom uses a **BDFL (Benevolent Dictator For Life)** model during its
initial growth phase. The project lead makes final decisions on architecture,
releases, and roadmap priority. As the contributor base grows, the model will
evolve toward a multi-maintainer consensus approach.

## Roles

| Role | Person | Scope |
|------|--------|-------|
| **Project Lead** | Wagdy Saad ([@msaad00](https://github.com/msaad00)) | Architecture, releases, security advisories, roadmap |
| **Release Manager** | Wagdy Saad | PyPI, Docker Hub, GHCR, GitHub Releases, Sigstore signing |
| **Security Contact** | Wagdy Saad | Triage via [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new) |

## Becoming a committer

1. **Contributor** — anyone who opens a PR. No special access required.
2. **Trusted Contributor** — after 3+ merged PRs, may be granted triage
   permissions (label, assign, close stale issues).
3. **Committer** — after sustained, high-quality contributions (typically 10+
   merged PRs across different modules), may be granted write access with
   branch protection still enforced (1 required review, no force push).

Promotion decisions are made by the Project Lead.

## Access continuity (bus-factor mitigation)

| Asset | Recovery plan |
|-------|--------------|
| **GitHub repo** | Organization transfer docs stored offline. A trusted contributor with triage access can request GitHub support for org admin recovery. |
| **PyPI** | [`agent-bom`](https://pypi.org/project/agent-bom/) — CI publishes via OIDC trusted publisher (no long-lived tokens). A co-maintainer will be added when the first committer is promoted. |
| **Docker Hub** | [`agentbom/agent-bom`](https://hub.docker.com/r/agentbom/agent-bom) — published via CI. Recovery follows Docker Hub's account recovery process. |
| **Domain / DNS** | No custom domain currently. GitHub Pages serves docs. |
| **Signing keys** | Releases signed via Sigstore (keyless, OIDC-bound). No long-lived GPG keys to lose. |

The project actively seeks co-maintainers. If you are interested, open an
issue or reach out to the project lead.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md)
(Contributor Covenant 2.1).

## Amendments

This governance document may be updated by the Project Lead. Significant
changes (e.g., switching from BDFL to multi-maintainer) will be discussed in
a GitHub Discussion before taking effect.
