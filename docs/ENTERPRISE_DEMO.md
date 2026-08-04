# Synthetic enterprise evidence demo

The bundled **Northstar Health AI** estate is a fictional, deterministic data
set for showing how agent-bom joins evidence across cloud, identity, data, AI,
and runtime systems. It contains no customer telemetry and is not an audit
verdict. Do not combine this fixture with live customer collection.

## First command: inspect the evidence offline

```bash
agent-bom demo story --output enterprise-demo-story.json
```

The terminal prints the primary incident path and collection limits. The JSON
artifact contains the normalized events, cross-vendor correlations, source
health, tenant ID, source-run IDs, evidence hashes, and graph projections. Raw
provider payloads are intentionally excluded.

The primary story follows one trace through:

```text
GitHub Actions → AWS CloudTrail → Kubernetes Audit → MCP Gateway
               → Snowflake Access History → OpenTelemetry GenAI
```

It proves a GitHub deployment assumed an AWS workload identity, reached a
Kubernetes copilot and an MCP SQL tool, read a synthetic PHI-classified
Snowflake table, and was blocked before model egress. Separate correlations
show an Azure privilege change, partial GCP credential activity, and an
enforced multi-provider remediation. GCP remains `partial` with
`rate_limited_after_page_2`; the demo never turns missing evidence into a
complete posture claim.

## Open the dashboard locally

```bash
agent-bom serve --demo-estate --allow-insecure-no-auth
```

Open `http://127.0.0.1:8422/demo-estate`. The anonymous viewer flag is suitable
only for a loopback, single-user demonstration. The page uses the same
versioned read model as the CLI and `GET /v1/demo-estate/story`; it does not
maintain a second UI-only copy of the scenario.

Next steps from the story page:

- open **Security graph** to inspect identity and resource relationships;
- open **Runtime traces** to inspect tool-call enforcement;
- open **Findings** to move from evidence to remediation.

## Run the packaged Kubernetes profile

Create the `agent-bom-control-plane` Secret described in
`deploy/helm/agent-bom/examples/control-plane-auth-secret.example.yaml`, then:

```bash
python scripts/install_helm_profile.py synthetic-enterprise-story --print-command
python scripts/install_helm_profile.py synthetic-enterprise-story
```

The profile is single-node SQLite, seeds only the synthetic estate, disables
the scanner, and grants anonymous viewer access. Change the example ingress
host before installation. For a shared or persistent environment, remove
`AGENT_BOM_ALLOW_UNAUTHENTICATED_API`, configure API-key or OIDC authentication,
and keep synthetic and live collection in separate deployments.

Validate the rendered profile without installing it:

```bash
python scripts/validate_helm_profiles.py --profile synthetic-enterprise-story
```

## Evidence contract

The checked-in guard fails when any of these surfaces drift:

```bash
python scripts/check_enterprise_demo_surfaces.py
```

It verifies fixture packaging, hashes, counts, tenant propagation, the blocked
primary path, partial GCP collection, raw-payload exclusion, CLI/API/UI wiring,
the Helm profile, and this runbook. CI also inspects the built wheel for the
versioned enterprise JSONL fixture and smokes the hosted demo story endpoint.
