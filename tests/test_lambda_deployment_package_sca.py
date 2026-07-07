"""Regression: Lambda SCA must scan the function's own deployment package,
not just its layers. Most functions vendor dependencies inline into the zip,
so the layer-only path silently missed the common case.
"""

from __future__ import annotations

import io
import zipfile

import agent_bom.http_client as http_client
from agent_bom.cloud import aws
from agent_bom.models import Package


def _zip_with_requests() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requests/__init__.py", "# code")
        zf.writestr("requests-2.25.0.dist-info/METADATA", "Name: requests\nVersion: 2.25.0\n")
    return buf.getvalue()


class _FakeLambdaClient:
    def __init__(self, *, with_code: bool):
        self._with_code = with_code

    def get_function(self, FunctionName):  # noqa: N803 (boto3 kwarg)
        payload = {"Configuration": {"Runtime": "python3.12", "Layers": []}}
        if self._with_code:
            payload["Code"] = {"Location": "https://example.test/code.zip"}
        return payload


class _FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, name, region_name=None):
        return self._client


def test_lambda_scans_inline_deployment_package(monkeypatch):
    monkeypatch.setattr(http_client, "fetch_bytes", lambda url, timeout=60: _zip_with_requests())
    session = _FakeSession(_FakeLambdaClient(with_code=True))
    warnings: list[str] = []

    pkgs = aws._extract_lambda_packages(session, "arn:aws:lambda:us-east-2:1:function:fn", "us-east-2", warnings)

    assert any(p.name == "requests" and p.version == "2.25.0" for p in pkgs), pkgs
    assert warnings == []


def test_lambda_no_code_location_is_graceful(monkeypatch):
    monkeypatch.setattr(http_client, "fetch_bytes", lambda url, timeout=60: b"")
    session = _FakeSession(_FakeLambdaClient(with_code=False))
    warnings: list[str] = []
    pkgs = aws._extract_lambda_packages(session, "arn:aws:lambda:us-east-2:1:function:fn", "us-east-2", warnings)
    assert pkgs == []
    assert warnings == []


def test_dedupe_packages_collapses_layer_and_code_duplicates():
    dupes = [
        Package(name="requests", version="2.25.0", ecosystem="pypi"),
        Package(name="Requests", version="2.25.0", ecosystem="pypi"),  # case-insensitive
        Package(name="urllib3", version="1.26.0", ecosystem="pypi"),
    ]
    out = aws._dedupe_packages(dupes)
    assert len(out) == 2
    assert {p.name.lower() for p in out} == {"requests", "urllib3"}
