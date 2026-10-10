# Scanner importers

agent-bom reads reports that other scanners already wrote and normalizes them
into the same `Finding` model, asset identities, and outputs as its own scans.
Importers parse files only: they never run the producing tool, never reach
the network, and never need cloud credentials.

## Built-in importers

| Importer | Produce the report | Import it | Imported by default | Skipped by default |
|---|---|---|---|---|
| Prowler v4/v5 (JSON-OCSF) | `prowler aws --output-formats json-ocsf` | `agent-bom agents --external-scan prowler-output.ocsf.json` | `FAIL` (posture finding), `MANUAL` (not-evaluated finding) | `PASS`, muted (`status: Suppressed`) |
| AWS Security Hub (ASFF) | `aws securityhub get-findings --output json > securityhub.json` | `agent-bom agents --external-scan securityhub.json` | Active findings; `Vulnerabilities[]` become one CVE finding per vulnerability | `RecordState: ARCHIVED`, `Workflow.Status: SUPPRESSED/RESOLVED`, `Compliance.Status: PASSED` |

The format is detected from the JSON shape; no extra flag is needed. The same
files work with `agent-bom findings push <file> --api-url …` and with the MCP
`ingest_external_scan` tool. Every skip rule that fires is reported as a scan
notice with a count, so nothing is dropped silently. To change what is
imported, change the producing tool's own filters (for example
`prowler --status FAIL`, or an ASFF `--filters` expression).

What each finding carries:

- **Provenance**: `sources: ["external:prowler"]` or `["external:aws-securityhub"]`,
  plus `evidence.external_tool`, the Prowler version, or the Security Hub
  `ProductName`/`ProductArn`/`GeneratorId` of the original producer.
- **Stable identity**: the finding id is derived from the tool name and the
  source finding id (`finding_info.uid`, ASFF `Id`), so re-importing the same
  report updates the same findings instead of creating new ones. Duplicate
  records in one report collapse to one finding.
- **Asset and scope**: the resource ARN/UID is the asset identifier; provider,
  account (`aws:<account-id>`) and region are first-class fields. The same ARN
  reported by both tools resolves to the same asset.
- **Severity**: the vendor label is normalized to the canonical bands and kept
  as `vendor_severity`. Security Hub's `Severity.Normalized` is the fallback.
- **Compliance references**: vendor-asserted mappings (`unmapped.compliance`,
  `Compliance.RelatedRequirements`) are kept as evidence and as controls
  namespaced under the tool (`prowler:cis_3_0`). They are not presented as
  agent-bom's own framework mapping.

Posture results use finding source `CLOUD_SECURITY`; vulnerability results use
`EXTERNAL`.

## Limits

Reports are read with the shared parser size limit
(`AGENT_BOM_MAX_MANIFEST_BYTES`, default 100 MiB) and at most 100,000 records
per file; split larger exports. Every field is treated as untrusted: strings
are length-bounded and passed through the same credential redaction as other
evidence, unexpected types are ignored, and a malformed report fails with an
error instead of producing partial output.

## Transparency manifest

Every importer publishes an `ImporterManifest`:

| Field | Meaning |
|---|---|
| `name` | Stable registry name |
| `tool`, `display_name` | Producing tool, used in provenance labels |
| `formats`, `detection` | Accepted formats and the exact detection rule |
| `credentials_required` | `None` for file-based importers |
| `network_access` | `False` for every built-in importer |
| `data_retained` | Input fields that survive into findings |
| `default_filters` | Records skipped by default |

```python
from agent_bom.parsers.importers import importer_manifests

for manifest in importer_manifests():
    print(manifest["name"], manifest["network_access"], manifest["default_filters"])
```

Before relying on an importer, an operator can read its manifest and see what
it reads, what it keeps, and what it skips.

## Add a scanner importer

An importer is an object with a `manifest`, a cheap `sniff(data)` that claims
only its own shape, and a `parse(data)` that returns an `ExternalScanImport`.
The built-in importers in `src/agent_bom/parsers/importers/` are the
reference; the shared helpers in `_common.py` handle bounds, redaction, scope
and finding identity.

```python
"""acme_agent_bom/importer.py: import Acme Cloud Scanner JSON."""

from agent_bom.finding import FindingType
from agent_bom.parsers.importers._common import CloudRecord, records, skipped_notice, text, to_finding
from agent_bom.parsers.importers.base import ExternalScanImport, ImporterManifest


class AcmeImporter:
    manifest = ImporterManifest(
        name="acme",
        display_name="Acme Cloud Scanner",
        tool="acme",
        formats=("acme-json",),
        detection='JSON object with "acme_version" and an "issues" list.',
        data_retained="issue id, rule, title, severity, account, region, resource id.",
        default_filters="issues with state=closed are skipped.",
    )

    def sniff(self, data: object) -> bool:
        return isinstance(data, dict) and "acme_version" in data and isinstance(data.get("issues"), list)

    def parse(self, data: object) -> ExternalScanImport:
        imported = ExternalScanImport(format="acme", tool_names=["acme"])
        skipped = {"closed issue(s)": 0}
        for row in records(data["issues"], label="Acme"):
            if text(row.get("state")).lower() == "closed":
                skipped["closed issue(s)"] += 1
                continue
            imported.findings.append(
                to_finding(
                    CloudRecord(
                        tool="acme",
                        native_id=text(row.get("id"), 256),
                        title=text(row.get("title"), 300),
                        severity=text(row.get("severity"), 40) or "unknown",
                        provider=text(row.get("cloud"), 40).lower(),
                        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
                        account=text(row.get("account"), 64),
                        region=text(row.get("region"), 64),
                        resource_id=text(row.get("resource"), 512),
                        evidence={"check_id": text(row.get("rule"), 120)},
                    )
                )
            )
        imported.notices.extend(skipped_notice("Acme", skipped))
        return imported


def registration() -> AcmeImporter:
    return AcmeImporter()
```

Register it from the plugin package's `pyproject.toml`:

```toml
[project.entry-points."agent_bom.importers"]
acme = "acme_agent_bom.importer:registration"
```

Third-party importers load only when the operator sets
`AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS=true`. They are tried after every
built-in format, cannot replace a built-in importer name, and a load failure
becomes a sanitized warning instead of breaking the scan. Loading a plugin
imports its Python code; install only packages you trust. The manifest
describes an importer but does not sandbox it.

Checklist for a new importer:

1. `sniff` returns `False` for every shape it does not own, including empty
   lists, and never raises on unexpected types.
2. `parse` raises `ValueError` for malformed input, bounds every string with
   `text(...)`, and goes through `records(...)` for the record cap.
3. Native ids feed `CloudRecord.native_id` so finding ids stay stable across
   re-imports.
4. Every default skip rule is counted in `skipped_notice(...)` and stated in
   `default_filters`.
5. Tests cover detection, mapping, skip rules, malformed fields and stable ids
   (see `tests/test_scanner_importers.py`).

A built-in importer is added to `builtin_importers()` in
`src/agent_bom/parsers/importers/__init__.py` with a fixture under
`tests/fixtures/importers/`.
