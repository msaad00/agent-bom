"""Tests for model binary file and manifest detection."""

import json
from pathlib import Path

from agent_bom.model_files import _human_size, scan_model_files, scan_model_manifests


def test_scan_empty_directory(tmp_path: Path):
    """Empty directory returns empty results."""
    results, warnings = scan_model_files(tmp_path)
    assert results == []
    assert warnings == []


def test_scan_safetensors(tmp_path: Path):
    """Detect .safetensors files."""
    (tmp_path / "model.safetensors").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["format"] == "SafeTensors"
    assert results[0]["ecosystem"] == "HuggingFace"
    assert results[0]["security_flags"] == []
    assert warnings == []


def test_scan_gguf(tmp_path: Path):
    """Detect .gguf files."""
    (tmp_path / "llama.gguf").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["format"] == "GGML/GGUF"
    assert results[0]["ecosystem"] == "llama.cpp/Ollama"


def test_scan_pickle_security_flag(tmp_path: Path):
    """Pickle files should get HIGH security flag."""
    (tmp_path / "model.pkl").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert len(results[0]["security_flags"]) == 1
    assert results[0]["security_flags"][0]["severity"] == "HIGH"
    assert results[0]["security_flags"][0]["type"] == "PICKLE_DESERIALIZATION"
    assert any("PICKLE" in w for w in warnings)


def test_scan_joblib_security_flag(tmp_path: Path):
    """Joblib files should get MEDIUM security flag."""
    (tmp_path / "model.joblib").write_bytes(b"\x00" * 100)
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    assert results[0]["security_flags"][0]["severity"] == "MEDIUM"


def test_scan_bin_size_filter(tmp_path: Path):
    """Small .bin files should be filtered out (< 10MB)."""
    (tmp_path / "small.bin").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 0  # Too small


def test_scan_multiple_formats(tmp_path: Path):
    """Multiple model formats in same directory."""
    (tmp_path / "model.onnx").write_bytes(b"\x00" * 100)
    (tmp_path / "model.pt").write_bytes(b"\x00" * 100)
    (tmp_path / "model.h5").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 3
    formats = {r["format"] for r in results}
    assert "ONNX" in formats
    assert "PyTorch" in formats
    assert "HDF5/Keras" in formats


def test_scan_hidden_dirs_excluded(tmp_path: Path):
    """Files in hidden directories should be skipped."""
    hidden = tmp_path / ".cache"
    hidden.mkdir()
    (hidden / "model.safetensors").write_bytes(b"\x00" * 100)
    results, _ = scan_model_files(tmp_path)
    assert len(results) == 0


def test_human_size_formatting():
    """Test human-readable size formatting."""
    assert _human_size(0) == "0 B"
    assert _human_size(500) == "500 B"
    assert _human_size(1024) == "1.0 KB"
    assert _human_size(1024 * 1024) == "1.0 MB"
    assert _human_size(1024 * 1024 * 1024) == "1.0 GB"


def test_scan_model_files_rejects_outside_safe_roots():
    """Unsafe scan roots should be rejected before traversal."""
    results, warnings = scan_model_files("/etc")
    assert results == []
    assert warnings
    assert "escapes safe scan roots" in warnings[0]


def test_scan_model_weight_index_manifest(tmp_path: Path):
    """Sharded weight indexes should surface manifest lineage metadata."""
    (tmp_path / "model.safetensors.index.json").write_text(
        json.dumps(
            {
                "metadata": {"total_size": 1234},
                "weight_map": {
                    "layer1": "model-00001-of-00002.safetensors",
                    "layer2": "model-00002-of-00002.safetensors",
                },
            }
        )
    )
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "weight_index"
    assert manifests[0]["shard_count"] == 2
    assert manifests[0]["total_size_bytes"] == 1234
    assert warnings == []


def test_scan_adapter_manifest_with_base_model(tmp_path: Path):
    """Adapter manifests should surface base-model lineage references."""
    (tmp_path / "adapter_config.json").write_text(json.dumps({"base_model_name_or_path": "meta-llama/Llama-3.1-8B"}))
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "adapter"
    assert manifests[0]["base_model_id"] == "meta-llama/Llama-3.1-8B"
    assert warnings == []


def test_scan_adapter_manifest_without_base_model_flags(tmp_path: Path):
    """Adapter manifests without lineage should be flagged."""
    (tmp_path / "adapter_config.json").write_text(json.dumps({"r": 8}))
    manifests, warnings = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["manifest_type"] == "adapter"
    assert manifests[0]["security_flags"][0]["type"] == "MISSING_BASE_MODEL"
    assert any("MISSING_BASE_MODEL" in warning for warning in warnings)


def test_scan_model_manifests_rejects_outside_safe_roots():
    """Manifest scans should refuse roots outside the safe set."""
    manifests, warnings = scan_model_manifests("/etc")
    assert manifests == []
    assert warnings
    assert "escapes safe scan roots" in warnings[0]


def test_scan_config_manifest_with_repo_id(tmp_path: Path):
    """Model config should surface repo references and model type."""
    (tmp_path / "config.json").write_text(
        json.dumps({"_name_or_path": "Qwen/Qwen2.5-7B-Instruct", "model_type": "qwen2", "architectures": ["Qwen2ForCausalLM"]})
    )
    manifests, _ = scan_model_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0]["repo_id"] == "Qwen/Qwen2.5-7B-Instruct"
    assert manifests[0]["model_type"] == "qwen2"
    assert manifests[0]["architectures"] == ["Qwen2ForCausalLM"]


def test_scan_config_manifest_flags_explicit_floating_revision(tmp_path: Path):
    """Explicit branch-style model revisions should be policy evidence."""
    (tmp_path / "config.json").write_text(json.dumps({"_name_or_path": "Qwen/Qwen2.5-7B-Instruct", "revision": "main"}))
    manifests, warnings = scan_model_manifests(tmp_path)

    assert len(manifests) == 1
    assert manifests[0]["revision"] == "main"
    assert manifests[0]["security_flags"][0]["type"] == "FLOATING_MODEL_REFERENCE"
    assert any("FLOATING_MODEL_REFERENCE" in warning for warning in warnings)


# ── Flag → finding promotion ─────────────────────────────────────────────
# ``model_file_findings`` used to promote exactly one string
# (``MALICIOUS_PICKLE``), silently discarding every other flag the model
# scanners emit — including CRITICAL ``HASH_MISMATCH`` and the ``UNSIGNED``
# evidence that ``--require-model-signatures`` depends on. The guard that
# matters is not any single case but the completeness test below: every flag
# type the scanners can emit must either map to a finding or sit on a
# documented inventory-only allowlist.

import ast  # noqa: E402

import pytest  # noqa: E402

from agent_bom import model_files as model_files_mod  # noqa: E402
from agent_bom import model_pickle_scan  # noqa: E402
from agent_bom.model_files import (  # noqa: E402
    INVENTORY_ONLY_MODEL_FLAGS,
    MODEL_FLAG_PROMOTIONS,
    model_file_findings,
)


def _model_file(*flags: dict) -> dict:
    return {
        "path": "/models/weights.pt",
        "filename": "weights.pt",
        "extension": ".pt",
        "format": "PyTorch",
        "size_bytes": 1024,
        "security_flags": list(flags),
    }


def _literal_strings(node: ast.AST) -> set[str]:
    """Collect string literals from a value node, following ternaries."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _literal_strings(node.body) | _literal_strings(node.orelse)
    return set()


def _emitted_flag_types() -> set[str]:
    """Every ``security_flags`` type that can land on a model-file entry.

    Read from the emitters' SOURCE rather than from a hand-kept list, so a new
    flag type added to any of them fails the completeness test until it is
    explicitly classified as promoted or inventory-only.
    """
    types = {flag["type"] for flag in model_files_mod._SECURITY_FLAGS.values()}
    emitters = {
        model_pickle_scan: {"to_security_flag"},
        model_files_mod: {"verify_model_hash", "check_sigstore_signature"},
    }
    for module, wanted in emitters.items():
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in wanted:
                found.add(node.name)
                for sub in ast.walk(node):
                    if not isinstance(sub, ast.Dict):
                        continue
                    for key, value in zip(sub.keys, sub.values):
                        if isinstance(key, ast.Constant) and key.value == "type":
                            types |= _literal_strings(value)
        assert found == wanted, f"emitter(s) renamed or removed in {module.__name__}: expected {wanted}, found {found}"
    return types


def test_flag_type_extraction_is_not_vacuous() -> None:
    """The completeness guard is only meaningful if it really sees the emitters."""
    emitted = _emitted_flag_types()
    # Anchors from each of the three emitter sites.
    for anchor in ("MALICIOUS_PICKLE", "OVERSIZE_PICKLE_UNSCANNED", "HASH_MISMATCH", "UNSIGNED", "PICKLE_DESERIALIZATION"):
        assert anchor in emitted, f"{anchor} was not discovered — the extraction is broken, not the code"
    assert len(emitted) >= 9


def test_every_emitted_model_flag_is_promoted_or_documented_inventory_only() -> None:
    """No model security flag may be silently dropped.

    This defect has now shipped three times in this file. A flag type that is
    neither promoted to a finding nor listed as inventory-only with a reason
    fails here — adding the flag without deciding its fate is the bug.
    """
    emitted = _emitted_flag_types()
    classified = set(MODEL_FLAG_PROMOTIONS) | set(INVENTORY_ONLY_MODEL_FLAGS)

    unclassified = emitted - classified
    assert not unclassified, (
        f"model security flag(s) {sorted(unclassified)} reach nothing: add them to "
        "MODEL_FLAG_PROMOTIONS or document them in INVENTORY_ONLY_MODEL_FLAGS"
    )
    stale = classified - emitted
    assert not stale, f"classified flag(s) {sorted(stale)} are no longer emitted — remove them"

    # The allowlist must carry a real reason, not an empty placeholder.
    for flag_type, reason in INVENTORY_ONLY_MODEL_FLAGS.items():
        assert reason.strip(), f"{flag_type} is allowlisted without a documented reason"

    # Pin the types whose loss caused user-visible defects.
    for required in ("MALICIOUS_PICKLE", "HASH_MISMATCH", "OVERSIZE_PICKLE_UNSCANNED", "PICKLE_SCAN_ERROR", "UNSIGNED"):
        assert required in MODEL_FLAG_PROMOTIONS, f"{required} must be promoted to a finding"


@pytest.mark.parametrize("flag_type", sorted(MODEL_FLAG_PROMOTIONS))
def test_every_promoted_flag_actually_produces_a_finding(flag_type: str) -> None:
    """Declaring a promotion is not enough — it must reach the findings spine."""
    spec = MODEL_FLAG_PROMOTIONS[flag_type]
    flag = {"severity": spec["default_severity"], "type": flag_type, "description": f"synthetic {flag_type}"}
    findings = model_file_findings([_model_file(flag)], require_model_signatures=True)
    assert len(findings) == 1, f"{flag_type} produced no finding"
    assert findings[0].evidence["detection_type"] == flag_type
    assert findings[0].asset.name == "weights.pt"


def test_inventory_only_flags_produce_no_finding() -> None:
    """Extension-shape warnings stay inventory metadata, not findings."""
    for flag_type in INVENTORY_ONLY_MODEL_FLAGS:
        flag = {"severity": "HIGH", "type": flag_type, "description": "format warning"}
        assert model_file_findings([_model_file(flag)], require_model_signatures=True) == [], (
            f"{flag_type} is documented as inventory-only but produced a finding"
        )


def test_hash_mismatch_becomes_a_critical_finding() -> None:
    """A tampered weight file must not stop at an inventory flag."""
    flag = {
        "severity": "CRITICAL",
        "type": "HASH_MISMATCH",
        "description": "SHA-256 mismatch — expected abc..., got def... File may be tampered.",
    }
    findings = model_file_findings([_model_file(flag)])
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "tampered" in findings[0].description.lower()


def test_severity_comes_from_the_flag_not_a_hardcoded_default() -> None:
    """Severity is read off the flag so the emitter stays the source of truth."""
    high = model_file_findings([_model_file({"severity": "HIGH", "type": "HASH_MISMATCH", "description": "d"})])
    critical = model_file_findings([_model_file({"severity": "CRITICAL", "type": "HASH_MISMATCH", "description": "d"})])
    assert high[0].severity == "high"
    assert critical[0].severity == "critical"


def test_unsigned_is_promoted_only_under_the_signature_policy() -> None:
    """UNSIGNED is inventory metadata until the operator demands signatures."""
    flag = {"severity": "MEDIUM", "type": "UNSIGNED", "description": "No Sigstore signature found."}
    assert model_file_findings([_model_file(flag)]) == []
    gated = model_file_findings([_model_file(flag)], require_model_signatures=True)
    assert len(gated) == 1
    assert gated[0].evidence["detection_type"] == "UNSIGNED"


def test_malicious_pickle_finding_is_the_only_one_marked_malicious() -> None:
    """Honesty: an unsigned or unscanned model is not a confirmed implant."""
    malicious = model_file_findings([_model_file({"severity": "CRITICAL", "type": "MALICIOUS_PICKLE", "description": "payload"})])
    assert malicious[0].is_malicious is True
    assert malicious[0].finding_type.value == "MALICIOUS_MODEL"

    for flag_type in ("HASH_MISMATCH", "OVERSIZE_PICKLE_UNSCANNED", "PICKLE_SCAN_ERROR", "UNSIGNED"):
        spec = MODEL_FLAG_PROMOTIONS[flag_type]
        findings = model_file_findings(
            [_model_file({"severity": spec["default_severity"], "type": flag_type, "description": "d"})],
            require_model_signatures=True,
        )
        assert findings[0].is_malicious is False, f"{flag_type} must not claim a confirmed malicious payload"
        assert findings[0].finding_type.value == "MODEL_INTEGRITY"


def test_multiple_flags_on_one_file_all_reach_findings() -> None:
    """A file can carry several signals; none may be swallowed by the first."""
    findings = model_file_findings(
        [
            _model_file(
                {"severity": "CRITICAL", "type": "MALICIOUS_PICKLE", "description": "payload"},
                {"severity": "CRITICAL", "type": "HASH_MISMATCH", "description": "tampered"},
                {"severity": "HIGH", "type": "PICKLE_DESERIALIZATION", "description": "format"},
            )
        ]
    )
    types = {f.evidence["detection_type"] for f in findings}
    assert types == {"MALICIOUS_PICKLE", "HASH_MISMATCH"}
