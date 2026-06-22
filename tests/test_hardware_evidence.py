"""Tests for hardware/firmware attestation evidence ingest (#1891)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph import EntityType, RelationshipType
from agent_bom.hardware_evidence import (
    RESOURCE_KIND_FIRMWARE,
    RESOURCE_KIND_GPU,
    RESOURCE_KIND_HOST,
    SCHEMA_VERSION,
    HardwareEvidenceError,
    build_hardware_graph,
)


def _evidence(**overrides):
    host = {
        "host_id": "host-stable-1",
        "hostname": "gpu-node-01",
        "vendor": "Acme",
        "model": "PowerEdge R760",
        "serial": "SERIAL-ABC-123",
        "bios_version": "2.10.1",
        "bmc_version": "7.10.30",
        "firmware": [
            {"component": "nic-firmware", "version": "22.5.1", "vendor": "Acme", "signed": True},
        ],
        "gpus": [
            {
                "model": "A100",
                "driver_version": "550.54.15",
                "cuda_version": "12.4",
                "serial": "GPU-XYZ",
                "mig_mode": "enabled",
            },
        ],
        "attestation": {
            "source": "tpm-quote",
            "signed": True,
            "verified": True,
            "provenance": "vendor-signed",
            "signature_algorithm": "ecdsa-p256",
        },
        "advisories": [
            {"id": "CVE-2024-0001", "severity": "high", "affects": "bios", "fixed_version": "2.11.0"},
            {"id": "NV-2024-0002", "severity": "critical", "affects": "gpu:a100"},
        ],
    }
    host.update(overrides)
    return {"schema_version": SCHEMA_VERSION, "source": "vendor-export", "hosts": [host]}


def _nodes_by_kind(graph, kind):
    return [n for n in graph.nodes.values() if n.attributes.get("resource_kind") == kind]


class TestBuildHardwareGraph:
    def test_builds_host_firmware_gpu_nodes(self) -> None:
        graph = build_hardware_graph(_evidence())

        hosts = _nodes_by_kind(graph, RESOURCE_KIND_HOST)
        firmware = _nodes_by_kind(graph, RESOURCE_KIND_FIRMWARE)
        gpus = _nodes_by_kind(graph, RESOURCE_KIND_GPU)

        assert len(hosts) == 1
        assert hosts[0].label == "gpu-node-01"
        # bios + bmc + nic-firmware
        assert len(firmware) == 3
        assert {n.attributes["component"] for n in firmware} == {"bios", "bmc", "nic-firmware"}
        assert len(gpus) == 1
        assert gpus[0].attributes["driver_version"] == "550.54.15"

    def test_all_hardware_nodes_reuse_resource_entity_type(self) -> None:
        graph = build_hardware_graph(_evidence())
        for kind in (RESOURCE_KIND_HOST, RESOURCE_KIND_FIRMWARE, RESOURCE_KIND_GPU):
            for node in _nodes_by_kind(graph, kind):
                assert node.entity_type == EntityType.RESOURCE

    def test_firmware_and_gpu_are_part_of_host(self) -> None:
        graph = build_hardware_graph(_evidence())
        host_id = _nodes_by_kind(graph, RESOURCE_KIND_HOST)[0].id
        part_of = [e for e in graph.edges if e.relationship == RelationshipType.PART_OF]
        # 3 firmware + 1 gpu
        assert len(part_of) == 4
        assert all(e.target == host_id for e in part_of)

    def test_serials_hashed_by_default(self) -> None:
        graph = build_hardware_graph(_evidence())
        host = _nodes_by_kind(graph, RESOURCE_KIND_HOST)[0]
        gpu = _nodes_by_kind(graph, RESOURCE_KIND_GPU)[0]

        assert "serial" not in host.attributes
        assert host.attributes["serial_redacted"] is True
        assert host.attributes["serial_fingerprint"].startswith("sha256:")
        assert "SERIAL-ABC-123" not in json.dumps(graph.to_dict())
        assert "serial" not in gpu.attributes
        assert gpu.attributes["serial_fingerprint"].startswith("sha256:")

    def test_capture_serials_opt_in_retains_raw(self) -> None:
        graph = build_hardware_graph(_evidence(), capture_serials=True)
        host = _nodes_by_kind(graph, RESOURCE_KIND_HOST)[0]
        assert host.attributes["serial"] == "SERIAL-ABC-123"
        assert host.attributes["serial_fingerprint"].startswith("sha256:")

    def test_no_raw_signature_blob_stored(self) -> None:
        evidence = _evidence()
        evidence["hosts"][0]["attestation"]["signature"] = "BIGSECRETSIGBLOB"
        graph = build_hardware_graph(evidence)
        assert "BIGSECRETSIGBLOB" not in json.dumps(graph.to_dict())

    def test_advisory_connects_to_affected_asset(self) -> None:
        graph = build_hardware_graph(_evidence())
        affects = [e for e in graph.edges if e.relationship == RelationshipType.AFFECTS]
        assert len(affects) == 2

        vulns = {n.id: n for n in graph.nodes.values() if n.entity_type == EntityType.VULNERABILITY}
        # The GPU-driver advisory must target the GPU node.
        gpu_id = _nodes_by_kind(graph, RESOURCE_KIND_GPU)[0].id
        gpu_edge = next(e for e in affects if e.target == gpu_id)
        assert vulns[gpu_edge.source].label == "NV-2024-0002"
        assert vulns[gpu_edge.source].severity == "critical"

        # The BIOS advisory must target the bios firmware node.
        bios_id = next(n.id for n in _nodes_by_kind(graph, RESOURCE_KIND_FIRMWARE) if n.attributes["component"] == "bios")
        assert any(e.target == bios_id for e in affects)

    def test_attestation_compliance_tags(self) -> None:
        graph = build_hardware_graph(_evidence())
        host = _nodes_by_kind(graph, RESOURCE_KIND_HOST)[0]
        assert "hardware-attestation-verified" in host.compliance_tags

        unverified = _evidence()
        unverified["hosts"][0]["attestation"] = {"source": "bios-log", "signed": False, "verified": False}
        graph2 = build_hardware_graph(unverified)
        host2 = _nodes_by_kind(graph2, RESOURCE_KIND_HOST)[0]
        assert "hardware-attestation-unverified" in host2.compliance_tags

    def test_advisory_unknown_selector_falls_back_to_host(self) -> None:
        evidence = _evidence()
        evidence["hosts"][0]["advisories"] = [{"id": "CVE-2024-9999", "severity": "low", "affects": "mystery"}]
        graph = build_hardware_graph(evidence)
        host_id = _nodes_by_kind(graph, RESOURCE_KIND_HOST)[0].id
        affects = [e for e in graph.edges if e.relationship == RelationshipType.AFFECTS]
        assert len(affects) == 1
        assert affects[0].target == host_id

    def test_deterministic_node_ids(self) -> None:
        g1 = build_hardware_graph(_evidence())
        g2 = build_hardware_graph(_evidence())
        assert set(g1.nodes) == set(g2.nodes)

    def test_rejects_unknown_schema(self) -> None:
        with pytest.raises(HardwareEvidenceError):
            build_hardware_graph({"schema_version": "bogus/v9", "hosts": [{"hostname": "h"}]})

    def test_rejects_missing_hosts(self) -> None:
        with pytest.raises(HardwareEvidenceError):
            build_hardware_graph({"schema_version": SCHEMA_VERSION, "hosts": []})

    def test_rejects_host_without_identity(self) -> None:
        with pytest.raises(HardwareEvidenceError):
            build_hardware_graph({"schema_version": SCHEMA_VERSION, "hosts": [{"vendor": "Acme"}]})

    def test_rejects_advisory_without_id(self) -> None:
        evidence = _evidence()
        evidence["hosts"][0]["advisories"] = [{"severity": "high", "affects": "bios"}]
        with pytest.raises(HardwareEvidenceError):
            build_hardware_graph(evidence)


class TestHardwareCLI:
    def test_ingest_hardware_emits_graph_json(self, tmp_path) -> None:
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps(_evidence()), encoding="utf-8")

        result = CliRunner().invoke(main, ["ingest", "hardware", str(path)])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert any(n["attributes"].get("resource_kind") == RESOURCE_KIND_HOST for n in payload["nodes"])
        # Serial must not leak in the default (redacted) output.
        assert "SERIAL-ABC-123" not in result.output

    def test_ingest_hardware_capture_serials(self, tmp_path) -> None:
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps(_evidence()), encoding="utf-8")

        result = CliRunner().invoke(main, ["ingest", "hardware", str(path), "--capture-serials"])
        assert result.exit_code == 0, result.output
        assert "SERIAL-ABC-123" in result.output

    def test_ingest_hardware_table_format(self, tmp_path) -> None:
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps(_evidence()), encoding="utf-8")

        result = CliRunner().invoke(main, ["ingest", "hardware", str(path), "-f", "table"])
        assert result.exit_code == 0, result.output
        assert "gpu-node-01" in result.output
        assert "CVE-2024-0001" in result.output

    def test_ingest_hardware_output_file(self, tmp_path) -> None:
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps(_evidence()), encoding="utf-8")
        out = tmp_path / "graph.json"

        result = CliRunner().invoke(main, ["ingest", "hardware", str(path), "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert json.loads(out.read_text())["nodes"]

    def test_ingest_hardware_bad_schema_errors(self, tmp_path) -> None:
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps({"schema_version": "nope", "hosts": []}), encoding="utf-8")

        result = CliRunner().invoke(main, ["ingest", "hardware", str(path)])
        assert result.exit_code != 0
