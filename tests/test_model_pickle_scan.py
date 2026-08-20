"""Tests for safe pickle opcode disassembly (malicious-model detection).

CRITICAL SAFETY INVARIANT: these tests construct malicious pickles with
``pickle.dumps`` (safe — only serializes) and then scan them with
``pickletools.genops`` (safe — walks opcodes without executing). They MUST
NEVER call ``pickle.load`` / ``pickle.loads`` / ``Unpickler`` / ``torch.load``
/ ``joblib.load`` on the crafted payloads, because that would execute the
embedded ``__reduce__``. The scanner under test never deserializes either.
"""

from __future__ import annotations

import io
import json
import pickle
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom import model_pickle_scan
from agent_bom.cli import main
from agent_bom.model_files import scan_model_files
from agent_bom.model_pickle_scan import scan_pickle_file, scan_pickle_file_flags


class _Pwned:
    """An object whose pickle embeds ``os.system('echo pwned')``.

    Constructing/serializing this is SAFE. Unpickling it WOULD run the command,
    so no test unpickles it — we only disassemble the bytes.
    """

    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


class _EvalPwned:
    def __reduce__(self):
        return (eval, ("__import__('os').listdir('.')",))


def _malicious_bytes() -> bytes:
    # pickle.dumps SERIALIZES; it does not execute __reduce__'s callable.
    return pickle.dumps(_Pwned())


def test_malicious_pickle_flagged_critical_with_os_system(tmp_path: Path):
    p = tmp_path / "model.pkl"
    p.write_bytes(_malicious_bytes())

    results = scan_pickle_file(p)
    assert len(results) == 1
    res = results[0]
    assert res.is_pickle
    assert res.verdict == "malicious"
    assert res.severity == "CRITICAL"
    assert res.has_reduce
    assert "REDUCE" in res.code_exec_opcodes
    # The os.system reference must be captured from the GLOBAL/STACK_GLOBAL operand.
    captured = " ".join(res.dangerous_imports).lower()
    assert "system" in captured
    assert any(mod in captured for mod in ("os", "posix", "nt"))


def test_malicious_pickle_security_flag_shape(tmp_path: Path):
    p = tmp_path / "model.pkl"
    p.write_bytes(_malicious_bytes())
    flags, results = scan_pickle_file_flags(p)
    assert len(flags) == 1
    flag = flags[0]
    assert flag["severity"] == "CRITICAL"
    assert flag["type"] == "MALICIOUS_PICKLE"
    assert "REDUCE" in flag["code_exec_opcodes"]
    assert any("system" in imp.lower() for imp in flag["dangerous_imports"])
    # No raw payload bytes leak into the evidence.
    assert "echo pwned" not in flag["description"]


def test_eval_pickle_flagged(tmp_path: Path):
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_EvalPwned()))
    res = scan_pickle_file(p)[0]
    assert res.verdict == "malicious"
    assert res.severity == "CRITICAL"
    assert any("eval" in imp.lower() for imp in res.dangerous_imports)


def test_benign_list_pickle_is_clean(tmp_path: Path):
    p = tmp_path / "benign.pkl"
    p.write_bytes(pickle.dumps([1, 2, 3]))
    res = scan_pickle_file(p)[0]
    assert res.is_pickle
    assert res.verdict == "clean"
    assert res.severity is None
    assert res.dangerous_imports == []
    assert res.to_security_flag() is None


def test_benign_dict_pickle_is_clean(tmp_path: Path):
    p = tmp_path / "benign2.pkl"
    p.write_bytes(pickle.dumps({"weights": [0.1, 0.2], "bias": 0.5, "name": "tiny"}))
    res = scan_pickle_file(p)[0]
    assert res.verdict == "clean"
    flags, _ = scan_pickle_file_flags(p)
    assert flags == []


def test_torch_style_zip_with_embedded_malicious_pickle(tmp_path: Path):
    """A torch .pt is a ZIP; an embedded malicious data.pkl must be flagged."""
    p = tmp_path / "model.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", _malicious_bytes())
        zf.writestr("archive/version", "3")
        zf.writestr("archive/data/0", b"\x00" * 64)  # fake tensor blob
    p.write_bytes(buf.getvalue())

    results = scan_pickle_file(p)
    malicious = [r for r in results if r.verdict == "malicious"]
    assert malicious, "embedded malicious pickle in zip was not flagged"
    assert malicious[0].member is not None
    assert "data.pkl" in malicious[0].member
    assert malicious[0].severity == "CRITICAL"


def test_torch_style_zip_with_benign_pickle_is_clean(tmp_path: Path):
    p = tmp_path / "clean.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"layer": [1, 2, 3]}))
        zf.writestr("archive/data/0", b"\x00" * 64)
    p.write_bytes(buf.getvalue())

    flags, results = scan_pickle_file_flags(p)
    assert flags == []
    assert all(r.verdict in {"clean", "not_pickle"} for r in results)


def test_truncated_pickle_is_safe(tmp_path: Path):
    """A truncated malicious pickle must not raise and must not crash."""
    full = _malicious_bytes()
    p = tmp_path / "truncated.pkl"
    p.write_bytes(full[: len(full) // 2])  # cut mid-stream
    results = scan_pickle_file(p)  # must not raise
    assert len(results) == 1
    # Truncated-but-still-dangerous import should be at least suspicious, and
    # the scanner must never raise.
    assert results[0].verdict in {"suspicious", "malicious", "clean", "error", "not_pickle", "incomplete"}


def test_garbage_bytes_is_safe(tmp_path: Path):
    p = tmp_path / "garbage.pkl"
    p.write_bytes(b"\xde\xad\xbe\xef\x00\x01\x02not a pickle at all")
    results = scan_pickle_file(p)  # must not raise
    assert len(results) == 1
    assert results[0].verdict in {"error", "not_pickle", "clean"}
    # Whatever the outcome, no crash and no malicious classification.
    assert results[0].severity in {None, "LOW"}


def test_empty_file_is_safe(tmp_path: Path):
    p = tmp_path / "empty.pkl"
    p.write_bytes(b"")
    results = scan_pickle_file(p)
    assert results[0].verdict == "not_pickle"


def test_missing_file_is_safe(tmp_path: Path):
    res = scan_pickle_file(tmp_path / "does-not-exist.pkl")[0]
    assert res.verdict == "error"
    assert res.severity is None or res.severity == "LOW"


def test_scanner_never_calls_pickle_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Hard proof the scanner does not deserialize: trip-wire pickle.load."""

    def _boom(*_a, **_k):
        raise AssertionError("scanner called pickle.load/loads — NO DESERIALIZATION ALLOWED")

    monkeypatch.setattr(pickle, "load", _boom)
    monkeypatch.setattr(pickle, "loads", _boom)
    monkeypatch.setattr(pickle, "Unpickler", _boom)

    p = tmp_path / "model.pkl"
    p.write_bytes(_malicious_bytes())
    # If any deserialization happened, the trip-wire would raise here.
    res = scan_pickle_file(p)[0]
    assert res.verdict == "malicious"


def test_opcode_bound_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A low opcode cap stops the walk early without raising (DoS bound)."""
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_OPCODES", "3")
    p = tmp_path / "big.pkl"
    p.write_bytes(pickle.dumps(list(range(1000))))
    res = scan_pickle_file(p)[0]
    assert res.opcodes_scanned <= 4
    assert res.truncated
    assert res.verdict == "incomplete"


def test_opcode_bound_emits_unscanned_tail_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Hitting the opcode bound is partial analysis, never a clean verdict."""
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_OPCODES", "3")
    p = tmp_path / "bounded.pkl"
    p.write_bytes(pickle.dumps(list(range(1000))))

    flags, results = scan_pickle_file_flags(p)

    assert results[0].truncated is True
    assert "TRUNCATED_PICKLE_UNSCANNED" in {flag["type"] for flag in flags}


def test_truncated_pickle_scan_marks_cli_run_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A bounded model scan must not serialize a complete scan_run."""
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_OPCODES", "3")
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "bounded.pkl").write_bytes(pickle.dumps(list(range(1000))))
    output = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--no-scan",
            "--offline",
            "--no-auto-update-db",
            "--model-files",
            str(model_dir),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_run"]["outcome"] == "partial"
    assert any(issue["source"] == "model-scan" for issue in payload["scan_run"]["issues"])


def test_opcode_bound_becomes_canonical_integrity_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The incomplete disassembly must survive model inventory and promotion."""
    from agent_bom.finding import FindingType
    from agent_bom.model_files import model_file_findings

    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_OPCODES", "3")
    p = tmp_path / "bounded.pkl"
    p.write_bytes(pickle.dumps(list(range(1000))))

    models, _ = scan_model_files(tmp_path)
    findings = model_file_findings(models)

    assert any(finding.finding_type == FindingType.MODEL_INTEGRITY for finding in findings)
    assert any("opcode" in finding.description.lower() for finding in findings)


def test_wired_into_scan_model_files(tmp_path: Path):
    """A normal model scan now reports the malicious-pickle finding end-to-end."""
    (tmp_path / "model.pkl").write_bytes(_malicious_bytes())
    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1
    flags = results[0]["security_flags"]
    # Extension flag (PICKLE_DESERIALIZATION) + content flag (MALICIOUS_PICKLE).
    types = {f["type"] for f in flags}
    assert "MALICIOUS_PICKLE" in types
    crit = [f for f in flags if f["type"] == "MALICIOUS_PICKLE"][0]
    assert crit["severity"] == "CRITICAL"
    assert any("MALICIOUS_PICKLE" in w for w in warnings)


def test_malicious_pickle_becomes_canonical_finding(tmp_path: Path):
    """Content-confirmed malicious models must enter the unified finding stream."""
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.model_files import model_file_findings

    model = tmp_path / "model.pkl"
    model.write_bytes(_malicious_bytes())
    results, _ = scan_model_files(tmp_path)

    findings = model_file_findings(results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type is FindingType.MALICIOUS_MODEL
    assert finding.source is FindingSource.MODEL_SCAN
    assert finding.severity == "critical"
    assert finding.asset.asset_type == "model_file"
    assert finding.asset.location == str(model)
    assert finding.is_malicious is True
    assert finding.is_actionable is True
    assert finding.cwe_ids == ["CWE-502"]
    assert finding.evidence["detector"] == "pickletools-static-disassembly"
    assert finding.security_domain == "aispm"
    assert finding.applicable_frameworks
    assert "echo pwned" not in json.dumps(finding.to_dict())
    assert model_file_findings(results)[0].id == finding.id


def test_unsafe_but_benign_pickle_does_not_become_malicious_finding(tmp_path: Path):
    """The extension-only pickle warning is not a content-confirmed malicious result."""
    from agent_bom.model_files import model_file_findings

    (tmp_path / "benign.pkl").write_bytes(pickle.dumps([1, 2, 3]))
    results, _ = scan_model_files(tmp_path)

    assert model_file_findings(results) == []


def test_scan_cli_gates_on_malicious_model_finding(tmp_path: Path):
    """A malicious model must be visible in JSON and fail the normal CI severity gate."""
    model = tmp_path / "model.pkl"
    model.write_bytes(_malicious_bytes())
    output = tmp_path / "report.json"

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = CliRunner().invoke(
            main,
            [
                "scan",
                "--model-files",
                str(tmp_path),
                "--no-discover",
                "--no-scan",
                "--no-auto-update-db",
                "--fail-on-severity",
                "critical",
                "--format",
                "json",
                "--output",
                str(output),
            ],
            catch_exceptions=False,
        )

    assert result.exit_code == 1
    assert "found critical finding (MALICIOUS_MODEL)" in result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item["finding_type"] == "MALICIOUS_MODEL")
    assert finding["severity"] == "critical"
    assert finding["asset"]["name"] == model.name
    assert finding["evidence"]["deserialized"] is False

    default_gate_output = tmp_path / "default-gate.json"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        default_gate = CliRunner().invoke(
            main,
            [
                "scan",
                "--model-files",
                str(tmp_path),
                "--no-discover",
                "--no-scan",
                "--no-auto-update-db",
                "--format",
                "json",
                "--output",
                str(default_gate_output),
            ],
            catch_exceptions=False,
        )

    assert default_gate.exit_code == 1
    assert "malicious model file model.pkl" in default_gate.output


def test_wired_benign_pickle_only_extension_flag(tmp_path: Path):
    """A benign pickle keeps the extension warning but gets no malicious flag."""
    (tmp_path / "ok.pkl").write_bytes(pickle.dumps([1, 2, 3]))
    results, _ = scan_model_files(tmp_path)
    types = {f["type"] for f in results[0]["security_flags"]}
    assert "MALICIOUS_PICKLE" not in types
    assert "PICKLE_DESERIALIZATION" in types  # the existing extension signal


def test_small_bin_disguised_pickle_is_scanned(tmp_path: Path):
    """A sub-10MB malicious pickle disguised as .bin must still be scanned.

    The .bin ``min_size_mb`` heuristic only classifies generic binaries as model
    files; it must never gate the SECURITY scan, or a small malicious pickle
    would slip through unscanned (CWE-502 evasion).
    """
    payload = _malicious_bytes()
    assert len(payload) < 10 * 1024 * 1024  # below the .bin min_size_mb threshold
    (tmp_path / "pytorch_model.bin").write_bytes(payload)

    results, warnings = scan_model_files(tmp_path)
    assert len(results) == 1, "small malicious .bin was filtered out before scanning"
    types = {f["type"] for f in results[0]["security_flags"]}
    assert "MALICIOUS_PICKLE" in types
    assert any("MALICIOUS_PICKLE" in w for w in warnings)


def test_small_benign_bin_still_filtered(tmp_path: Path):
    """A small generic .bin with no pickle content stays filtered from inventory."""
    (tmp_path / "tokenizer.bin").write_bytes(b"\x00" * 256)
    results, _ = scan_model_files(tmp_path)
    assert results == []


def _short_binunicode(text: str) -> bytes:
    raw = text.encode("utf-8")
    return pickle.SHORT_BINUNICODE + bytes([len(raw)]) + raw


def test_memo_referenced_dangerous_global_flagged(tmp_path: Path):
    """A pickle that hides os.system behind the memo (BINPUT/BINGET) is flagged.

    The dangerous operands are stored in the memo, then six benign padding
    strings are pushed so the dangerous strings are NOT among the last literals,
    and finally replayed via BINGET right before STACK_GLOBAL. A scanner that
    only inspects the last few literal strings would miss this; memo tracking
    recovers the operands.
    """
    parts = [pickle.PROTO + b"\x04"]
    parts.append(_short_binunicode("os") + pickle.BINPUT + b"\x00")
    parts.append(_short_binunicode("system") + pickle.BINPUT + b"\x01")
    # Padding literals so the dangerous strings are not the most recent ones.
    for i in range(6):
        parts.append(_short_binunicode(f"pad{i}") + pickle.BINPUT + bytes([10 + i]))
    # Replay the memoized operands, then resolve the global and call it.
    parts.append(pickle.BINGET + b"\x00")  # push "os"
    parts.append(pickle.BINGET + b"\x01")  # push "system"
    parts.append(pickle.STACK_GLOBAL)
    parts.append(pickle.EMPTY_TUPLE)
    parts.append(pickle.REDUCE)
    parts.append(pickle.STOP)
    p = tmp_path / "memo_evasion.pkl"
    p.write_bytes(b"".join(parts))

    res = scan_pickle_file(p)[0]
    assert res.is_pickle
    assert res.verdict == "malicious"
    assert res.severity == "CRITICAL"
    captured = " ".join(res.dangerous_imports).lower()
    assert "system" in captured
    assert "os" in captured


def test_unrecoverable_stack_global_is_suspicious(tmp_path: Path):
    """A STACK_GLOBAL whose operands cannot be recovered fails safe (suspicious)."""
    payload = pickle.PROTO + b"\x04" + pickle.STACK_GLOBAL + pickle.STOP
    p = tmp_path / "unresolved.pkl"
    p.write_bytes(payload)

    res = scan_pickle_file(p)[0]
    assert res.is_pickle
    assert res.verdict == "suspicious"
    assert res.severity == "HIGH"
    flag = res.to_security_flag()
    assert flag is not None
    assert flag["type"] == "SUSPICIOUS_PICKLE"


def test_module_code_has_no_deserialization_calls():
    """Source-level guard: no deserialization API appears in executable code.

    Parses the module with ``ast`` and inspects only the code (docstrings,
    which legitimately *describe* the no-execution guarantee in prose, are
    stripped out first).
    """
    import ast

    src = Path(model_pickle_scan.__file__).read_text()
    tree = ast.parse(src)
    # Drop the module docstring and every function/class docstring node so the
    # prose that names pickle.load (to explain we DON'T call it) is excluded.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body.pop(0)
    code_only = ast.unparse(tree)
    for forbidden in ("pickle.load", "pickle.loads", "Unpickler", "torch.load", "joblib.load", "find_class"):
        assert forbidden not in code_only, f"scanner must not call {forbidden}"


def test_oversized_zip_member_is_flagged_not_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A pickle larger than the byte cap inside a zip must NOT be silently skipped.

    Padding a pickle past ``AGENT_BOM_PICKLE_MAX_BYTES`` was an evasion: the old
    ``file_size > cap`` guard ``continue``d, dropping the member entirely. The
    fix scans the leading slice (bounded read) and emits an
    OVERSIZE_PICKLE_UNSCANNED finding so the unscanned tail cannot hide a payload.
    """
    # Realistic padding evasion: a highly compressible payload keeps the ZIP
    # itself tiny (so the outer archive read is unaffected) while the member's
    # *uncompressed* size dwarfs the per-pickle byte cap.
    cap = 50_000
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_BYTES", str(cap))
    payload = pickle.dumps(b"\x00" * 2_000_000)  # benign, but uncompressed >> cap
    assert len(payload) > cap
    p = tmp_path / "padded.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", payload)
    archive = buf.getvalue()
    assert len(archive) < cap, "compressed archive must fit under the cap for this test"
    p.write_bytes(archive)

    flags, results = scan_pickle_file_flags(p)
    # The oversized member must produce a result (not be dropped) ...
    oversized = [r for r in results if r.oversize_unscanned]
    assert oversized, "oversized zip member was silently skipped"
    assert oversized[0].declared_size is not None and oversized[0].declared_size > cap
    # ... and a fail-safe finding even though the scanned prefix looked clean.
    types = {f["type"] for f in flags}
    assert "OVERSIZE_PICKLE_UNSCANNED" in types
    over_flag = [f for f in flags if f["type"] == "OVERSIZE_PICKLE_UNSCANNED"][0]
    assert over_flag["severity"] == "HIGH"


def test_normal_zip_member_within_cap_has_no_oversize_flag(tmp_path: Path):
    """A normal-sized benign zip member produces no oversize finding."""
    p = tmp_path / "ok.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"layer": [1, 2, 3]}))
    p.write_bytes(buf.getvalue())
    flags, results = scan_pickle_file_flags(p)
    assert all(not r.oversize_unscanned for r in results)
    assert all(f["type"] != "OVERSIZE_PICKLE_UNSCANNED" for f in flags)


def test_disguised_extension_pickle_is_discovered_and_scanned(tmp_path: Path):
    """A malicious pickle saved under a non-model extension must be discovered.

    Extension-only discovery never iterates ``.txt``; a renamed pickle would slip
    through unscanned. The content sniff (pickle PROTO magic) discovers it.
    """
    (tmp_path / "weights.txt").write_bytes(_malicious_bytes())
    results, warnings = scan_model_files(tmp_path)
    disguised = [r for r in results if r["path"].endswith("weights.txt")]
    assert disguised, "disguised pickle under .txt was never discovered"
    types = {f["type"] for f in disguised[0]["security_flags"]}
    assert "MALICIOUS_PICKLE" in types
    assert any("MALICIOUS_PICKLE" in w for w in warnings)


def test_disguised_pickle_under_model_extension_is_scanned(tmp_path: Path):
    """A pickle renamed to a non-pickle MODEL extension (.safetensors) is scanned.

    The file is still inventoried once (under its spoofed extension) but the
    content findings are attached to that same entry, not duplicated.
    """
    (tmp_path / "model.safetensors").write_bytes(_malicious_bytes())
    results, _ = scan_model_files(tmp_path)
    entries = [r for r in results if r["path"].endswith("model.safetensors")]
    assert len(entries) == 1, "spoofed-extension pickle was duplicated in inventory"
    types = {f["type"] for f in entries[0]["security_flags"]}
    assert "MALICIOUS_PICKLE" in types


def test_benign_non_pickle_files_are_not_discovered(tmp_path: Path):
    """Plain non-pickle files must not be pulled into the model inventory."""
    (tmp_path / "notes.txt").write_bytes(b"just some text, not a pickle")
    (tmp_path / "data.csv").write_bytes(b"a,b,c\n1,2,3\n")
    results, _ = scan_model_files(tmp_path)
    assert results == []


# ── ZIP containers larger than the byte cap ──────────────────────────────
# A ZIP's central directory lives at the END of the file. Reading only the
# leading ``AGENT_BOM_PICKLE_MAX_BYTES`` bytes into memory destroys it, so
# ``zipfile`` rejects the archive and every embedded pickle goes unscanned.
# Since real models are GB-scale, that made the detector a no-op in
# production. The container must be opened BY PATH; the byte cap belongs on
# each member, not on the whole-file buffer.


def _stored_zip_over(path: Path, *, first_member: bytes, total_bytes: int) -> None:
    """Write an uncompressed .pt whose on-disk size exceeds ``total_bytes``."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
        zf.writestr("archive/data.pkl", first_member)
        zf.writestr("archive/version", "3")
        with zf.open("archive/data/0", "w") as fh:
            written = 0
            chunk = b"\x00" * 65536
            while written <= total_bytes:
                fh.write(chunk)
                written += len(chunk)
    assert path.stat().st_size > total_bytes


def test_zip_container_larger_than_byte_cap_is_still_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A malicious pickle inside a .pt bigger than the cap must still be flagged.

    Regression guard for the silent-miss: truncating the whole-file buffer to
    the cap discarded the ZIP central directory, so the archive was
    unreadable and the payload was reported as a LOW scan error instead of a
    CRITICAL malicious pickle.
    """
    cap = 100_000
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_BYTES", str(cap))
    p = tmp_path / "oversized.pt"
    _stored_zip_over(p, first_member=_malicious_bytes(), total_bytes=cap)

    results = scan_pickle_file(p)
    assert not any(r.verdict == "error" for r in results), (
        "container above the byte cap was rejected as unreadable — central directory was truncated away"
    )
    malicious = [r for r in results if r.verdict == "malicious"]
    assert malicious, "malicious pickle inside an over-cap container was not flagged"
    assert malicious[0].member is not None and "data.pkl" in malicious[0].member
    assert malicious[0].severity == "CRITICAL"

    flags, _ = scan_pickle_file_flags(p)
    assert "MALICIOUS_PICKLE" in {f["type"] for f in flags}


def test_over_cap_container_scan_stays_bounded_per_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Opening the container by path must NOT relax the per-member byte cap.

    The DoS bound moved from the whole file to each member; prove no single
    disassembly is ever handed more than the cap.
    """
    cap = 100_000
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_BYTES", str(cap))
    p = tmp_path / "bomb.pt"
    # Every member is a pickle-looking stream far larger than the cap.
    big_member = pickle.dumps(b"\x00" * (cap * 8))
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for i in range(12):
            zf.writestr(f"archive/shard{i}.pkl", big_member)
    assert p.stat().st_size < cap, "compressed zip bomb should stay small on disk"

    sizes: list[int] = []
    real_stream = model_pickle_scan._scan_opcode_stream

    def _recording(data: bytes, path: str, member: str | None):
        sizes.append(len(data))
        return real_stream(data, path, member)

    monkeypatch.setattr(model_pickle_scan, "_scan_opcode_stream", _recording)
    flags, results = scan_pickle_file_flags(p)

    assert sizes, "no member was disassembled"
    # +2 for the two-byte magic sniff read that precedes the capped body read.
    assert max(sizes) <= cap + 2, f"a member was read past the cap: {max(sizes)} > {cap}"
    assert len(results) <= model_pickle_scan._MAX_EMBEDDED_PICKLES
    # Every oversized member still fails safe rather than being dropped.
    assert all(r.oversize_unscanned for r in results)
    assert {f["type"] for f in flags} == {"OVERSIZE_PICKLE_UNSCANNED"}


def test_unreadable_oversize_member_reports_oversize_not_scan_error():
    """``oversize_unscanned`` must win over ``verdict == "error"``.

    OVERSIZE_PICKLE_UNSCANNED (HIGH) is the fail-safe written to stop padding
    evasion. Checking the error branch first made it unreachable whenever the
    oversized member also failed to read, downgrading the evasion signal to a
    LOW PICKLE_SCAN_ERROR that the finding promoter drops.
    """
    res = model_pickle_scan.PickleScanResult(
        path="/models/evil.pt",
        member="archive/data.pkl",
        verdict="error",
        error="could not read zip member: bad CRC",
        oversize_unscanned=True,
        declared_size=999_999_999,
    )
    flag = res.to_security_flag()
    assert flag is not None
    assert flag["type"] == "OVERSIZE_PICKLE_UNSCANNED"
    assert flag["severity"] == "HIGH"


def test_corrupt_oversize_member_keeps_the_oversize_failsafe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """End-to-end: a member that declares a huge size and cannot be read.

    A hostile archive can advertise an enormous member and then corrupt it so
    decompression fails. That must not silently downgrade to a LOW error.
    """
    cap = 20_000
    monkeypatch.setenv("AGENT_BOM_PICKLE_MAX_BYTES", str(cap))
    p = tmp_path / "corrupt.pt"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(b"\x00" * (cap * 4)))

    # Corrupt ONLY the member's compressed payload, leaving the central
    # directory intact — the archive must stay openable so the failure lands
    # on the member read, which is the branch under test.
    with zipfile.ZipFile(p) as zf:
        info = zf.getinfo("archive/data.pkl")
        header_offset, compress_size = info.header_offset, info.compress_size
    raw = bytearray(p.read_bytes())
    name_len = int.from_bytes(raw[header_offset + 26 : header_offset + 28], "little")
    extra_len = int.from_bytes(raw[header_offset + 28 : header_offset + 30], "little")
    data_start = header_offset + 30 + name_len + extra_len
    for offset in range(data_start, data_start + compress_size):
        raw[offset] ^= 0xFF
    p.write_bytes(bytes(raw))
    with zipfile.ZipFile(p) as zf:  # sanity: the container itself still parses
        assert zf.namelist() == ["archive/data.pkl"]

    flags, results = scan_pickle_file_flags(p)  # must not raise
    assert results, "corrupt oversized member was dropped entirely"
    assert results[0].member == "archive/data.pkl"
    types = {f["type"] for f in flags}
    assert "OVERSIZE_PICKLE_UNSCANNED" in types, f"oversize fail-safe lost, got {types}"


@pytest.mark.slow
def test_real_gb_scale_pt_above_default_cap_fails_the_scan_gate(tmp_path: Path):
    """The production shape: a >256 MiB .pt with a malicious first member.

    Every realistic model artifact is far larger than the 256 MiB default cap.
    This builds a real one on disk (and deletes it in teardown) to prove the
    CLI exits 1 with a MALICIOUS_MODEL finding, exactly as it does for a small
    .pt carrying the identical payload.
    """
    import shutil

    free_bytes = shutil.disk_usage(tmp_path).free
    if free_bytes < 2 * 1024 * 1024 * 1024:
        pytest.skip(f"needs ~300 MiB of scratch space, only {free_bytes // (1 << 20)} MiB free")

    default_cap = model_pickle_scan._MAX_PICKLE_BYTES
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    model = model_dir / "pytorch_model.pt"
    output = tmp_path / "report.json"
    try:
        _stored_zip_over(model, first_member=_malicious_bytes(), total_bytes=default_cap)
        assert model.stat().st_size > default_cap

        with (
            patch("agent_bom.cli.agents.discover_all", return_value=[]),
            patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
            patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    "--model-files",
                    str(model_dir),
                    "--no-discover",
                    "--no-scan",
                    "--no-auto-update-db",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 1, f"a {model.stat().st_size >> 20} MiB malicious model did not fail the gate"
        payload = json.loads(output.read_text(encoding="utf-8"))
        malicious = [f for f in payload["findings"] if f["finding_type"] == "MALICIOUS_MODEL"]
        assert malicious, "no MALICIOUS_MODEL finding for the GB-scale artifact"
        assert malicious[0]["severity"] == "critical"
        assert malicious[0]["evidence"]["deserialized"] is False
    finally:
        model.unlink(missing_ok=True)
