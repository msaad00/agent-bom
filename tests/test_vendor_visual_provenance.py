"""Official diagram assets stay pinned to first-party sources and exact bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "images" / "vendor" / "provenance.json"

ALLOWED_SOURCE_HOSTS = {
    "arch-center.azureedge.net",
    "aws.amazon.com",
    "cloud.google.com",
    "d1.awsstatic.com",
    "learn.microsoft.com",
    "services.google.com",
}


def test_vendor_diagram_assets_have_first_party_pinned_provenance() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["neutral_icon_policy"]
    assert {asset["vendor"] for asset in data["assets"]} == {
        "Amazon Web Services",
        "Google Cloud",
        "Microsoft Azure",
    }

    for asset in data["assets"]:
        path = ROOT / asset["path"]
        assert path.is_file(), asset["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == asset["sha256"]
        for key in ("source_page", "source_archive"):
            parsed = urlparse(asset[key])
            assert parsed.scheme == "https"
            assert parsed.hostname in ALLOWED_SOURCE_HOSTS
        assert asset["source_path"].endswith(".svg")
        assert asset["terms"]
