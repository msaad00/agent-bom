"""Official diagram assets stay pinned to first-party sources and exact bytes."""

from __future__ import annotations

import hashlib
import json
import re
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

# The manifest carries two kinds of asset, told apart by which pin they use.
#
# First-party assets come out of a vendor's own downloadable icon archive, so
# their guarantee is the source host: the bytes provably came from the vendor.
#
# Icon-set assets are Simple Icons vectors, which no vendor publishes and whose
# host therefore cannot be first-party. Their guarantee is instead an exact
# upstream commit plus a declared redistributable license — a different pin, not
# a weaker one. Keeping them in the same manifest under one shared byte-hash
# check is what stops either kind from drifting.
FIRST_PARTY_VENDORS = {
    "Amazon Web Services",
    "Google Cloud",
    "Microsoft Azure",
}
ICON_SET_VENDORS = {
    "Amazon Web Services",
    "ClickHouse",
    "Databricks",
    "GitHub Copilot",
    "Google Cloud",
    "Kubernetes",
    "Microsoft Azure",
    "Okta",
    "Snowflake",
    "Windsurf",
}
REPOSITORY_PINNED_VENDORS = {
    "Anthropic Claude",
    "Cursor",
}
# A mark its owner does not publish as a redistributable diagram asset, and which
# no CC0 icon set carries, is pinned to the exact upstream bytes by URL + sha256
# instead. Modifications must be stated, because the bytes on disk are not the
# bytes upstream serves.
UPSTREAM_PINNED_VENDORS = {
    "OpenAI",
}
UPSTREAM_PINNED_HOSTS = {"upload.wikimedia.org"}
ICON_SET_SOURCE_HOST = "simpleicons.org"
ICON_SET_ALLOWED_LICENSES = {"CC0-1.0"}
_FULL_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _first_party(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_archive" in asset]


def _icon_set(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_repo" in asset and "source_page" in asset]


def _repository_pinned(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_repo" in asset and "source_page" not in asset]


def _upstream_pinned(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_url" in asset and "source_repo" not in asset and "source_archive" not in asset]


def test_vendor_diagram_assets_have_first_party_pinned_provenance() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["neutral_icon_policy"]

    assets = data["assets"]
    first_party = _first_party(assets)
    icon_set = _icon_set(assets)
    repository_pinned = _repository_pinned(assets)
    upstream_pinned = _upstream_pinned(assets)

    # Every asset must declare exactly one pin. An entry with neither is
    # unpinned; an entry with both hides which guarantee actually applies.
    assert len(first_party) + len(icon_set) + len(repository_pinned) + len(upstream_pinned) == len(assets)
    assert not [a for a in assets if "source_archive" in a and "source_repo" in a]

    assert {asset["vendor"] for asset in first_party} == FIRST_PARTY_VENDORS
    assert {asset["vendor"] for asset in icon_set} == ICON_SET_VENDORS
    assert {asset["vendor"] for asset in repository_pinned} == (REPOSITORY_PINNED_VENDORS)
    assert {asset["vendor"] for asset in upstream_pinned} == UPSTREAM_PINNED_VENDORS

    # Shared contract: the bytes on disk are the bytes that were reviewed.
    for asset in assets:
        path = ROOT / asset["path"]
        assert path.is_file(), asset["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == asset["sha256"]
        assert asset["source_path"].endswith(".svg")
        assert asset["terms"]

    for asset in first_party:
        for key in ("source_page", "source_archive"):
            parsed = urlparse(asset[key])
            assert parsed.scheme == "https"
            assert parsed.hostname in ALLOWED_SOURCE_HOSTS

    for asset in icon_set:
        page = urlparse(asset["source_page"])
        assert page.scheme == "https"
        assert page.hostname == ICON_SET_SOURCE_HOST

        # Redistribution rests on the license, so it has to be stated, not implied.
        assert asset["license"] in ICON_SET_ALLOWED_LICENSES

    for asset in icon_set + repository_pinned:
        repo = urlparse(asset["source_repo"])
        assert repo.scheme == "https"
        # A branch or tag can move; only a full commit sha pins the bytes.
        assert _FULL_COMMIT_SHA.match(asset["source_commit"]), asset["path"]

    for asset in upstream_pinned:
        for key in ("source_page", "source_url"):
            parsed = urlparse(asset[key])
            assert parsed.scheme == "https"
        assert urlparse(asset["source_url"]).hostname in UPSTREAM_PINNED_HOSTS
        # These bytes were edited before vendoring, so the edit has to be on record.
        assert asset["modifications"]
