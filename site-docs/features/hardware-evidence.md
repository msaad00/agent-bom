# Hardware/Firmware Evidence Ingest

agent-bom has strong software and model supply-chain coverage. The remaining
hardware supply-chain gap is **evidence that already exists outside agent-bom**:
vendor hardware/firmware SBOMs, signed firmware attestations, BMC/BIOS inventory
exports, and CMDB/EDR feeds.

`agent-bom ingest hardware` maps that operator-provided evidence onto the unified
graph so a host, its firmware (BIOS/BMC/NIC), its GPUs, and any firmware or
GPU-driver advisory become first-class, traversable nodes.

!!! note "Evidence ingest, not firmware scanning"
    This is **not** a firmware scanner. agent-bom does not probe BMC/IPMI, read
    BIOS, or run any device-side agent. It ingests a JSON document you already
    have and projects it onto the graph. Generating that evidence (vendor
    inventory exports, signed attestations, OCSF/CMDB feeds) is out of scope.

## Usage

```bash
# Map evidence onto the graph and stream the graph JSON to stdout
agent-bom ingest hardware evidence.json

# Human-readable summary instead of the raw graph
agent-bom ingest hardware evidence.json -f table

# Write the graph export to a file
agent-bom ingest hardware evidence.json -o hardware-graph.json
```

## Sensitive identifiers are redacted by default

Device and GPU **serial numbers are hashed by default** — only a stable,
salt-free SHA-256 `serial_fingerprint` is stored, and the raw value is dropped
(`serial_redacted: true`). The fingerprint is stable enough to correlate the
same device across evidence files without revealing the serial. No raw firmware
signature blobs are stored — only the attestation posture (signed/verified),
declared algorithm, and provenance.

To retain raw serials (for example on a single-tenant operator workstation),
opt in explicitly:

```bash
agent-bom ingest hardware evidence.json --capture-serials
```

## Input contract — `agent-bom.hardware-evidence/v1`

```json
{
  "schema_version": "agent-bom.hardware-evidence/v1",
  "source": "vendor-inventory-export",
  "hosts": [
    {
      "host_id": "stable-operator-id",
      "hostname": "gpu-node-01",
      "vendor": "Acme",
      "model": "PowerEdge R760",
      "serial": "ABC123",
      "bios_version": "2.10.1",
      "bmc_version": "7.10.30",
      "firmware": [
        { "component": "nic-firmware", "version": "22.5.1", "vendor": "Acme", "signed": true }
      ],
      "gpus": [
        { "model": "A100", "driver_version": "550.54.15", "cuda_version": "12.4", "serial": "GPU-abc", "mig_mode": "enabled" }
      ],
      "attestation": {
        "source": "tpm-quote",
        "signed": true,
        "verified": true,
        "provenance": "vendor-signed",
        "signature_algorithm": "ecdsa-p256"
      },
      "advisories": [
        { "id": "CVE-2024-0001", "severity": "high", "affects": "bios", "fixed_version": "2.11.0", "title": "BIOS privilege escalation" },
        { "id": "NV-2024-0002", "severity": "critical", "affects": "gpu:A100", "title": "GPU driver OOB write" }
      ]
    }
  ]
}
```

`host_id` is optional; the hostname is used when it is absent. Every field except
the host identifier is optional.

### Graph mapping

| Evidence | Graph node | Notes |
|----------|-----------|-------|
| Host | `RESOURCE` (`resource_kind=hardware_host`) | Carries vendor/model, BIOS/BMC versions, attestation posture, redacted serial |
| BIOS / BMC / firmware component | `RESOURCE` (`resource_kind=firmware`) | Linked to the host with `PART_OF` |
| GPU | `RESOURCE` (`resource_kind=gpu`) | Driver/CUDA/MIG attributes; linked to the host with `PART_OF` |
| Advisory | `VULNERABILITY` | Linked with `AFFECTS` to the precise asset |

The advisory `affects` selector connects an advisory to the asset it impacts:
`host`, `bios`, `bmc`, `firmware:<component>`, or `gpu:<model>`. Unknown or empty
selectors fall back to the host so an advisory is never orphaned. This is what
lets a firmware or GPU-driver advisory connect to the affected host/GPU asset.

### Compliance evidence

Host and firmware nodes carry `compliance_tags` derived from the attestation
state — `hardware-attestation-verified`,
`hardware-attestation-signed-unverified`, or `hardware-attestation-unverified` —
and firmware components are tagged `firmware-signed` / `firmware-unsigned`. These
flow through the graph as durable, queryable compliance evidence alongside
software findings.
