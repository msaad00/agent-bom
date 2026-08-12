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
artifact contains normalized events, cross-vendor correlations, source health,
tenant ID, source-run IDs, evidence hashes, and graph projections. Raw provider
payloads are intentionally excluded.

The `events`, `correlations` and `findings` lists are **bounded, ranked slices**
of an estate an order of magnitude larger — the incident first, then the top of
the population — so the incident stays visible instead of being buried in a
six-thousand-row dump. The artifact's `bounds` block states the limit, the
returned count and the true total for each list, and `summary` /
`finding_summary` always carry the unbounded totals:

```json
"bounds": {
  "events":       {"returned": 200, "total": 12171, "limit": 200, "truncated": true},
  "correlations": {"returned":  50, "total":  2322, "limit":  50, "truncated": true},
  "findings":     {"returned": 100, "total":  2682, "limit": 100, "truncated": true}
}
```

The same bounds are served by `GET /v1/demo-estate/story` and rendered by the
dashboard, so no surface reports a page size as a total.

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

## Posture findings over the estate

The estate also carries posture findings, so the correlation is demonstrated at
estate scale rather than only along the hand-authored incident. Each finding
resolves to a chain:

```text
finding → inventoried asset → identity that can act on it
        → configuration that failed → attack path → compliance control
```

Three properties are enforced by `scripts/check_enterprise_demo_surfaces.py`
and `tests/test_demo_estate_findings.py`, because each has regressed before:

- **The asset is the inventoried one.** A finding's asset identifier is the
  estate's own `asset_id`, so there is no second identifier scheme to reconcile
  and every finding on one asset shares one canonical id.
- **Unrated is a bucket, not a gap.** Controls that cannot be evaluated are
  emitted as `CIS_ERROR` with no severity and counted under `unrated`. The
  severity histogram always sums to the total.
- **Bounded views report unbounded totals.** The CLI, the API story, and the
  dashboard each render a bounded page led by the incident, and each states how
  many rows it shows against the estate's real total.

Controls come from the same benchmark catalogs the live cloud scanners use, and
findings are produced by the same `cloud_cis_check_to_finding` converter, so the
demo shows the product's real control vocabulary rather than a demo-only
approximation. Findings are also seeded into the demo scan job, so
`/v1/findings`, its facets, the posture tiles, and every export read one
derivation.

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
