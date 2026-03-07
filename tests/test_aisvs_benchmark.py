"""Tests for cloud/aisvs_benchmark.py — AISVS v1.0 compliance checks."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_bom.cloud.aisvs_benchmark import (
    AIVSReport,
    _check_ai_4_1,
    _check_ai_4_3,
    _check_ai_5_2,
    _check_ai_6_1,
    _check_ai_6_2,
    _check_ai_7_1,
    run_benchmark,
)
from agent_bom.cloud.aws_cis_benchmark import CheckStatus

# ---------------------------------------------------------------------------
# AIVSReport model
# ---------------------------------------------------------------------------


def _make_report(*statuses: CheckStatus) -> AIVSReport:
    from agent_bom.cloud.aws_cis_benchmark import CISCheckResult

    report = AIVSReport()
    for i, status in enumerate(statuses):
        report.checks.append(
            CISCheckResult(
                check_id=f"AI-{i + 1}.1",
                title=f"Check {i + 1}",
                status=status,
                severity="high",
                cis_section="AI-4 - Model Deployment Security",
            )
        )
    return report


def test_report_pass_count():
    r = _make_report(CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.FAIL)
    assert r.passed == 1
    assert r.failed == 2
    assert r.total == 3


def test_report_pass_rate():
    r = _make_report(CheckStatus.PASS, CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.FAIL)
    assert r.pass_rate == pytest.approx(50.0)


def test_report_pass_rate_empty():
    r = AIVSReport()
    assert r.pass_rate == 0.0


def test_report_to_dict_structure():
    r = _make_report(CheckStatus.PASS)
    d = r.to_dict()
    assert d["benchmark"] == "OWASP AI Security Verification Standard"
    assert d["benchmark_version"] == "1.0"
    assert "passed" in d
    assert "failed" in d
    assert "pass_rate" in d
    assert "checks" in d


def test_report_to_dict_check_has_maestro_layer():
    r = _make_report(CheckStatus.FAIL)
    d = r.to_dict()
    check = d["checks"][0]
    assert "maestro_layer" in check
    assert isinstance(check["maestro_layer"], str)
    assert check["maestro_layer"].startswith("KC")


# ---------------------------------------------------------------------------
# AI-4.1: Model serialization safety
# ---------------------------------------------------------------------------


def test_check_ai_4_1_no_model_dirs():
    with patch("pathlib.Path.exists", return_value=False):
        result = _check_ai_4_1(model_dirs=[])
    # Either NOT_APPLICABLE or PASS (no dirs to scan)
    assert result.check_id == "AI-4.1"
    assert result.status in (CheckStatus.NOT_APPLICABLE, CheckStatus.PASS)


def test_check_ai_4_1_unsafe_file_found(tmp_path):
    unsafe = tmp_path / "model.pkl"
    unsafe.write_bytes(b"fake pickle")
    result = _check_ai_4_1(model_dirs=[str(tmp_path)])
    assert result.status == CheckStatus.FAIL
    assert "model.pkl" in result.evidence or "unsafe" in result.evidence.lower()


def test_check_ai_4_1_safe_files_only(tmp_path):
    safe = tmp_path / "model.safetensors"
    safe.write_bytes(b"fake safetensors")
    result = _check_ai_4_1(model_dirs=[str(tmp_path)])
    assert result.status == CheckStatus.PASS


def test_check_ai_4_1_mixed_files(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"safe")
    (tmp_path / "model.pt").write_bytes(b"unsafe")
    result = _check_ai_4_1(model_dirs=[str(tmp_path)])
    assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# AI-4.3: Ollama not network-exposed
# ---------------------------------------------------------------------------


def test_check_ai_4_3_ollama_not_running():
    with patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=False):
        result = _check_ai_4_3()
    assert result.status == CheckStatus.NOT_APPLICABLE
    assert "not running" in result.evidence.lower()


def test_check_ai_4_3_ollama_localhost_only():
    def fake_tcp(host, port, timeout=3):
        return host == "127.0.0.1"

    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", side_effect=fake_tcp),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value="192.168.1.100"),
    ):
        result = _check_ai_4_3()
    assert result.status == CheckStatus.PASS


def test_check_ai_4_3_ollama_network_exposed():
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=True),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value="192.168.1.100"),
    ):
        result = _check_ai_4_3()
    assert result.status == CheckStatus.FAIL
    assert "192.168.1.100" in result.evidence


# ---------------------------------------------------------------------------
# AI-5.2: No ML tools network-exposed
# ---------------------------------------------------------------------------


def test_check_ai_5_2_no_tools_running():
    with patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=False):
        result = _check_ai_5_2()
    assert result.status == CheckStatus.NOT_APPLICABLE


def test_check_ai_5_2_jupyter_localhost_only():
    def fake_tcp(host, port, timeout=3):
        # Jupyter running on 127.0.0.1:8888 but NOT on network IP
        return host == "127.0.0.1" and port == 8888

    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", side_effect=fake_tcp),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value="192.168.1.100"),
    ):
        result = _check_ai_5_2()
    assert result.status == CheckStatus.PASS


def test_check_ai_5_2_jupyter_network_exposed():
    def fake_tcp(host, port, timeout=3):
        return port == 8888  # Reachable on any host

    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", side_effect=fake_tcp),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value="192.168.1.100"),
    ):
        result = _check_ai_5_2()
    assert result.status == CheckStatus.FAIL
    assert "Jupyter" in result.evidence


# ---------------------------------------------------------------------------
# AI-6.1 / AI-6.2: Vector store auth + exposure
# ---------------------------------------------------------------------------


def test_check_ai_6_1_no_vector_dbs():
    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[]):
        result = _check_ai_6_1()
    assert result.status == CheckStatus.NOT_APPLICABLE


def test_check_ai_6_1_all_authenticated():
    from agent_bom.cloud.vector_db import VectorDBResult

    mock_db = VectorDBResult(
        db_type="qdrant",
        host="127.0.0.1",
        port=6333,
        is_reachable=True,
        requires_auth=True,
        version="1.7.4",
        collection_count=0,
        is_loopback=True,
    )
    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[mock_db]):
        result = _check_ai_6_1()
    assert result.status == CheckStatus.PASS


def test_check_ai_6_1_unauthenticated_db():
    from agent_bom.cloud.vector_db import VectorDBResult

    mock_db = VectorDBResult(
        db_type="qdrant",
        host="127.0.0.1",
        port=6333,
        is_reachable=True,
        requires_auth=False,
        version="1.7.4",
        collection_count=3,
        is_loopback=True,
        risk_flags=["no_auth", "collections_exposed"],
    )
    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[mock_db]):
        result = _check_ai_6_1()
    assert result.status == CheckStatus.FAIL
    assert "qdrant" in result.evidence


def test_check_ai_6_2_all_loopback():
    from agent_bom.cloud.vector_db import VectorDBResult

    mock_db = VectorDBResult(
        db_type="weaviate",
        host="127.0.0.1",
        port=8080,
        is_reachable=True,
        requires_auth=True,
        version="1.24.0",
        collection_count=0,
        is_loopback=True,
    )
    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[mock_db]):
        result = _check_ai_6_2()
    assert result.status == CheckStatus.PASS


def test_check_ai_6_2_network_exposed():
    from agent_bom.cloud.vector_db import VectorDBResult

    mock_db = VectorDBResult(
        db_type="weaviate",
        host="0.0.0.0",
        port=8080,
        is_reachable=True,
        requires_auth=True,
        version="1.24.0",
        collection_count=0,
        is_loopback=False,
        risk_flags=["network_exposed"],
        metadata={"exposed_on": "10.0.0.5"},
    )
    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[mock_db]):
        result = _check_ai_6_2()
    assert result.status == CheckStatus.FAIL
    assert "weaviate" in result.evidence


# ---------------------------------------------------------------------------
# AI-7.1: No malicious packages
# ---------------------------------------------------------------------------


def test_check_ai_7_1_no_malicious():
    result = _check_ai_7_1()
    # Should pass unless test env has one of the known-bad packages
    assert result.check_id == "AI-7.1"
    assert result.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.ERROR)


def test_check_ai_7_1_detects_malicious_package():
    import importlib.metadata as _meta

    class FakeDist:
        @property
        def metadata(self):
            return {"Name": "tensor-flow"}

    with patch.object(_meta, "distributions", return_value=[FakeDist()]):
        result = _check_ai_7_1()
    assert result.status == CheckStatus.FAIL
    assert "tensor-flow" in result.evidence


def test_check_ai_7_1_clean_environment():
    import importlib.metadata as _meta

    class FakeDist:
        @property
        def metadata(self):
            return {"Name": "torch"}

    with patch.object(_meta, "distributions", return_value=[FakeDist()]):
        result = _check_ai_7_1()
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# run_benchmark
# ---------------------------------------------------------------------------


def test_run_benchmark_returns_report():
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=False),
        patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[]),
    ):
        report = run_benchmark()
    assert isinstance(report, AIVSReport)
    assert report.total > 0


def test_run_benchmark_filter_by_check_id():
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=False),
        patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[]),
    ):
        report = run_benchmark(checks=["AI-4.3"])
    assert report.total == 1
    assert report.checks[0].check_id == "AI-4.3"


def test_run_benchmark_to_dict_has_maestro_layer():
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=False),
        patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[]),
    ):
        report = run_benchmark(checks=["AI-4.3"])
    d = report.to_dict()
    check = d["checks"][0]
    assert "maestro_layer" in check
    assert check["maestro_layer"].startswith("KC")
