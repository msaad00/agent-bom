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
import pickle
import zipfile
from pathlib import Path

import pytest

from agent_bom import model_pickle_scan
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
    assert results[0].verdict in {"suspicious", "malicious", "clean", "error", "not_pickle"}


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


def test_wired_benign_pickle_only_extension_flag(tmp_path: Path):
    """A benign pickle keeps the extension warning but gets no malicious flag."""
    (tmp_path / "ok.pkl").write_bytes(pickle.dumps([1, 2, 3]))
    results, _ = scan_model_files(tmp_path)
    types = {f["type"] for f in results[0]["security_flags"]}
    assert "MALICIOUS_PICKLE" not in types
    assert "PICKLE_DESERIALIZATION" in types  # the existing extension signal


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
