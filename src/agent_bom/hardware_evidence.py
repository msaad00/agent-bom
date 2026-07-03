"""Hardware/firmware attestation evidence ingest (#1891).

agent-bom is **not** a firmware scanner. This module ingests evidence that
already exists outside agent-bom — vendor hardware/firmware SBOMs, signed
firmware attestations, BMC/BIOS inventory exports, CMDB/EDR exports — and maps
it onto the unified graph so a host, its firmware (BIOS/BMC/NIC), its GPUs, and
any firmware/GPU-driver advisory become first-class, traversable nodes.

Design notes
------------
* **Reuses existing graph vocabulary.** Hosts, firmware components, and GPUs are
  modelled as :class:`~agent_bom.graph.types.EntityType.RESOURCE` nodes carrying
  a ``resource_kind`` attribute (``hardware_host`` / ``firmware`` / ``gpu``).
  Advisories reuse :class:`EntityType.VULNERABILITY`. No new graph types are
  invented.
* **Sensitive identifiers are hashed by default.** Device and GPU serial numbers
  are never stored raw unless the caller explicitly opts in
  (``capture_serials=True``). The redacted form is a salt-free SHA-256
  fingerprint, which is stable enough to correlate the same device across
  evidence files without revealing the serial.
* **Evidence, not scanning.** Nothing here probes a device. The input is an
  operator-provided JSON document conforming to the versioned contract below.

Input contract — ``agent-bom.hardware-evidence/v1``::

    {
      "schema_version": "agent-bom.hardware-evidence/v1",
      "source": "vendor-inventory-export",      # optional provenance label
      "hosts": [
        {
          "host_id": "stable-operator-id",       # optional; falls back to hostname
          "hostname": "gpu-node-01",
          "vendor": "Acme",
          "model": "PowerEdge R760",
          "serial": "ABC123",                    # hashed unless capture_serials
          "bios_version": "2.10.1",
          "bmc_version": "7.10.30",
          "firmware": [
            {"component": "nic-firmware", "version": "22.5.1", "vendor": "Acme",
             "signed": true}
          ],
          "gpus": [
            {"model": "A100", "driver_version": "550.54.15", "cuda_version": "12.4",
             "serial": "GPU-abc", "mig_mode": "enabled"}
          ],
          "attestation": {
            "source": "tpm-quote", "signed": true, "verified": true,
            "provenance": "vendor-signed", "signature_algorithm": "ecdsa-p256"
          },
          "advisories": [
            {"id": "CVE-2024-0001", "severity": "high", "affects": "bios",
             "fixed_version": "2.11.0", "title": "BIOS privilege escalation"},
            {"id": "NV-2024-0002", "severity": "critical", "affects": "gpu:A100",
             "title": "GPU driver OOB write"}
          ]
        }
      ]
    }

``affects`` targets (advisory → asset edge): ``host``, ``bios``, ``bmc``,
``firmware:<component>``, ``gpu:<model>``. Unknown/empty targets fall back to the
host so an advisory is never orphaned.
"""

from __future__ import annotations

import hashlib
from typing import Any

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.node import stable_node_id
from agent_bom.graph.severity import normalize_severity

SCHEMA_VERSION = "agent-bom.hardware-evidence/v1"
_SUPPORTED_SCHEMAS = frozenset({SCHEMA_VERSION})

# Resource subtypes carried on RESOURCE nodes so the generic inventory type stays
# semantically precise without inventing new graph vocabulary.
RESOURCE_KIND_HOST = "hardware_host"
RESOURCE_KIND_FIRMWARE = "firmware"
RESOURCE_KIND_GPU = "gpu"

_DATA_SOURCE = "hardware-attestation-ingest"


class HardwareEvidenceError(ValueError):
    """Raised when a hardware/firmware evidence document is malformed."""


def _fingerprint(value: str) -> str:
    """Stable, salt-free SHA-256 fingerprint used to redact sensitive serials."""
    return "sha256:" + hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _redact_serial(serial: str, *, capture_serials: bool) -> dict[str, Any]:
    """Return the attributes representing a serial under the active redaction policy.

    By default only a fingerprint is emitted and the raw serial is dropped. With
    ``capture_serials=True`` the raw value is retained alongside the fingerprint.
    """
    serial = (serial or "").strip()
    if not serial:
        return {}
    attrs: dict[str, Any] = {"serial_fingerprint": _fingerprint(serial)}
    if capture_serials:
        attrs["serial"] = serial
    else:
        attrs["serial_redacted"] = True
    return attrs


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _host_key(host: dict[str, Any]) -> str:
    key = _str(host.get("host_id")) or _str(host.get("hostname"))
    if not key:
        raise HardwareEvidenceError("each host requires a 'host_id' or 'hostname'")
    return key


def _attestation_tags(attestation: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """Derive compliance tags + safe attributes from an attestation block.

    Raw signature blobs are never stored — only the verification posture and the
    declared algorithm/source, which is what compliance evidence needs.
    """
    if not isinstance(attestation, dict):
        return [], {}
    signed = bool(attestation.get("signed"))
    verified = bool(attestation.get("verified"))
    attrs = {
        "attestation_source": _str(attestation.get("source")),
        "attestation_signed": signed,
        "attestation_verified": verified,
        "attestation_provenance": _str(attestation.get("provenance")),
        "signature_algorithm": _str(attestation.get("signature_algorithm")),
    }
    attrs = {k: v for k, v in attrs.items() if v not in ("", None)}
    if verified and signed:
        tags = ["hardware-attestation-verified"]
    elif signed:
        tags = ["hardware-attestation-signed-unverified"]
    else:
        tags = ["hardware-attestation-unverified"]
    return tags, attrs


def _normalize_severity(raw: Any) -> str:
    return normalize_severity(_str(raw))


def build_hardware_graph(
    evidence: dict[str, Any],
    *,
    capture_serials: bool = False,
    tenant_id: str = "",
    scan_id: str = "",
) -> UnifiedGraph:
    """Map a hardware/firmware evidence document onto a :class:`UnifiedGraph`.

    Args:
        evidence: A document conforming to ``agent-bom.hardware-evidence/v1``.
        capture_serials: When ``False`` (default) device/GPU serials are hashed
            and the raw value dropped. When ``True`` the raw serial is retained.
        tenant_id: Optional tenant scoping recorded on the graph.
        scan_id: Optional scan/run id recorded on the graph.

    Raises:
        HardwareEvidenceError: If the document is malformed or the schema version
            is unsupported.
    """
    if not isinstance(evidence, dict):
        raise HardwareEvidenceError("evidence must be a JSON object")
    schema = _str(evidence.get("schema_version"))
    if schema not in _SUPPORTED_SCHEMAS:
        raise HardwareEvidenceError(f"unsupported schema_version {schema!r}; expected one of {sorted(_SUPPORTED_SCHEMAS)}")
    hosts = evidence.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise HardwareEvidenceError("evidence requires a non-empty 'hosts' array")

    document_source = _str(evidence.get("source"))
    graph = UnifiedGraph(tenant_id=tenant_id, scan_id=scan_id)

    for host in hosts:
        if not isinstance(host, dict):
            raise HardwareEvidenceError("each host must be a JSON object")
        _ingest_host(graph, host, document_source=document_source, capture_serials=capture_serials)

    return graph


def _ingest_host(
    graph: UnifiedGraph,
    host: dict[str, Any],
    *,
    document_source: str,
    capture_serials: bool,
) -> None:
    host_key = _host_key(host)
    host_id = stable_node_id(RESOURCE_KIND_HOST, host_key)
    label = _str(host.get("hostname")) or host_key

    attest_tags, attest_attrs = _attestation_tags(host.get("attestation", {}))
    host_attrs: dict[str, Any] = {
        "resource_kind": RESOURCE_KIND_HOST,
        "hostname": _str(host.get("hostname")),
        "vendor": _str(host.get("vendor")),
        "model": _str(host.get("model")),
        "bios_version": _str(host.get("bios_version")),
        "bmc_version": _str(host.get("bmc_version")),
        "evidence_source": document_source,
    }
    host_attrs.update(attest_attrs)
    host_attrs.update(_redact_serial(_str(host.get("serial")), capture_serials=capture_serials))
    host_attrs = {k: v for k, v in host_attrs.items() if v not in ("", None)}

    graph.add_node(
        UnifiedNode(
            id=host_id,
            entity_type=EntityType.RESOURCE,
            label=label,
            attributes=host_attrs,
            compliance_tags=attest_tags,
            data_sources=[_DATA_SOURCE],
        )
    )

    # Map of advisory `affects` selector -> graph node id, so advisories connect
    # to the precise asset. The host is always registered as a fallback target.
    targets: dict[str, str] = {"host": host_id}

    # ── BIOS / BMC firmware as dedicated components ──
    for component, version_key in (("bios", "bios_version"), ("bmc", "bmc_version")):
        version = _str(host.get(version_key))
        if not version:
            continue
        node_id = _add_firmware_node(graph, host_id, host_key, component=component, version=version, attrs={}, tags=attest_tags)
        targets[component] = node_id

    # ── Additional firmware components ──
    for fw in host.get("firmware", []) or []:
        if not isinstance(fw, dict):
            continue
        component = _str(fw.get("component"))
        if not component:
            continue
        signed = bool(fw.get("signed"))
        node_id = _add_firmware_node(
            graph,
            host_id,
            host_key,
            component=component,
            version=_str(fw.get("version")),
            attrs={
                "vendor": _str(fw.get("vendor")),
                "signed": signed,
            },
            tags=["firmware-signed"] if signed else ["firmware-unsigned"],
        )
        targets[f"firmware:{component.lower()}"] = node_id

    # ── GPUs ──
    for index, gpu in enumerate(host.get("gpus", []) or []):
        if not isinstance(gpu, dict):
            continue
        model = _str(gpu.get("model")) or f"gpu-{index}"
        gpu_id = stable_node_id(RESOURCE_KIND_GPU, host_key, model, str(index))
        gpu_attrs: dict[str, Any] = {
            "resource_kind": RESOURCE_KIND_GPU,
            "model": model,
            "driver_version": _str(gpu.get("driver_version")),
            "cuda_version": _str(gpu.get("cuda_version")),
            "mig_mode": _str(gpu.get("mig_mode")),
            "evidence_source": document_source,
        }
        gpu_attrs.update(_redact_serial(_str(gpu.get("serial")), capture_serials=capture_serials))
        gpu_attrs = {k: v for k, v in gpu_attrs.items() if v not in ("", None)}
        graph.add_node(
            UnifiedNode(
                id=gpu_id,
                entity_type=EntityType.RESOURCE,
                label=f"{model} (GPU)",
                attributes=gpu_attrs,
                data_sources=[_DATA_SOURCE],
            )
        )
        # GPU is part of the host.
        graph.add_edge(UnifiedEdge(source=gpu_id, target=host_id, relationship=RelationshipType.PART_OF))
        targets[f"gpu:{model.lower()}"] = gpu_id

    # ── Advisories → affected asset ──
    for advisory in host.get("advisories", []) or []:
        if not isinstance(advisory, dict):
            continue
        _ingest_advisory(graph, advisory, host_id=host_id, targets=targets)


def _add_firmware_node(
    graph: UnifiedGraph,
    host_id: str,
    host_key: str,
    *,
    component: str,
    version: str,
    attrs: dict[str, Any],
    tags: list[str],
) -> str:
    node_id = stable_node_id(RESOURCE_KIND_FIRMWARE, host_key, component)
    node_attrs: dict[str, Any] = {
        "resource_kind": RESOURCE_KIND_FIRMWARE,
        "component": component,
        "version": version,
    }
    node_attrs.update({k: v for k, v in attrs.items() if v not in ("", None)})
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.RESOURCE,
            label=f"{component} {version}".strip(),
            attributes=node_attrs,
            compliance_tags=list(tags),
            data_sources=[_DATA_SOURCE],
        )
    )
    # Firmware is part of the host.
    graph.add_edge(UnifiedEdge(source=node_id, target=host_id, relationship=RelationshipType.PART_OF))
    return node_id


def _ingest_advisory(
    graph: UnifiedGraph,
    advisory: dict[str, Any],
    *,
    host_id: str,
    targets: dict[str, str],
) -> None:
    advisory_id = _str(advisory.get("id"))
    if not advisory_id:
        raise HardwareEvidenceError("each advisory requires an 'id'")
    selector = _str(advisory.get("affects")).lower()
    target_id = targets.get(selector, host_id)
    severity = _normalize_severity(advisory.get("severity"))

    vuln_id = stable_node_id(EntityType.VULNERABILITY.value, advisory_id, target_id)
    attrs = {
        "cve_id": advisory_id,
        "affects": selector or "host",
        "fixed_version": _str(advisory.get("fixed_version")),
        "title": _str(advisory.get("title")),
        "evidence_source": _DATA_SOURCE,
    }
    attrs = {k: v for k, v in attrs.items() if v not in ("", None)}
    graph.add_node(
        UnifiedNode(
            id=vuln_id,
            entity_type=EntityType.VULNERABILITY,
            label=advisory_id,
            severity=severity,
            attributes=attrs,
            data_sources=[_DATA_SOURCE],
        )
    )
    # Advisory AFFECTS the precise hardware/firmware/GPU asset.
    graph.add_edge(
        UnifiedEdge(
            source=vuln_id,
            target=target_id,
            relationship=RelationshipType.AFFECTS,
            evidence={"source": _DATA_SOURCE},
        )
    )
