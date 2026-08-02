"""An advisory block with ``versions`` but no ``ranges`` must reach the local DB.

``_parse_osv_entry`` only walked ``affected[].ranges``, so a block that states
its affected releases as a bare ``versions`` list produced no ``affected`` row
at all. The advisory then existed in the DB with no way to match anything —
invisible to every offline and local-DB-first scan.

Measured: ``magento/community-edition@2.4.5-p1`` reports 128 advisories from
live OSV but only 127 from the local DB, because GHSA-fxcr-gvcw-hmqm states
2.4.5-p1 in exactly this shape.

Each listed version becomes its own exact pin (``introduced == last_affected``)
so the row can never match a version the advisory did not name.
"""

from __future__ import annotations

from agent_bom.db.lookup import _version_affected
from agent_bom.db.sync import _parse_osv_entry

ENTRY = {
    "id": "GHSA-fxcr-gvcw-hmqm",
    "summary": "Magento Open Source allows Cross-Site Scripting (XSS)",
    "affected": [
        {
            "package": {"name": "magento/community-edition", "ecosystem": "Packagist"},
            "versions": ["2.4.5-p1"],
        },
        {
            "package": {"name": "magento/community-edition", "ecosystem": "Packagist"},
            "versions": ["2.4.4", "2.4.5"],
        },
        {
            "package": {"name": "magento/community-edition", "ecosystem": "Packagist"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.4.4-p1"}, {"last_affected": "2.4.4-p2"}]}],
        },
    ],
}


def _rows() -> list[dict]:
    parsed = _parse_osv_entry(ENTRY)
    assert parsed is not None
    return parsed[1]


def test_versions_only_blocks_produce_one_exact_pin_each() -> None:
    pins = {(row["introduced"], row["last_affected"]) for row in _rows() if row["fixed"] == ""}
    assert ("2.4.5-p1", "2.4.5-p1") in pins
    assert ("2.4.4", "2.4.4") in pins
    assert ("2.4.5", "2.4.5") in pins


def test_the_range_block_is_still_persisted_unchanged() -> None:
    assert {"introduced": "2.4.4-p1", "fixed": "", "last_affected": "2.4.4-p2"}.items() <= next(
        row for row in _rows() if row["introduced"] == "2.4.4-p1"
    ).items()


def test_an_exact_pin_matches_only_the_named_version() -> None:
    """Non-vacuous: the new row must not widen into its neighbours."""
    row = next(row for row in _rows() if row["introduced"] == "2.4.5-p1")
    # Through the DB read path, exactly as a local-DB lookup would evaluate it.
    assert _version_affected("2.4.5-p1", row["introduced"], None, row["last_affected"], row["ecosystem"]) is True
    assert _version_affected("2.4.5-p2", row["introduced"], None, row["last_affected"], row["ecosystem"]) is False
    assert _version_affected("2.4.5", row["introduced"], None, row["last_affected"], row["ecosystem"]) is False
    assert _version_affected("2.4.4", row["introduced"], None, row["last_affected"], row["ecosystem"]) is False


def test_a_block_with_neither_versions_nor_ranges_adds_nothing() -> None:
    parsed = _parse_osv_entry(
        {
            "id": "GHSA-empty",
            "summary": "x",
            "affected": [{"package": {"name": "acme", "ecosystem": "Packagist"}}],
        }
    )
    assert parsed is not None
    assert parsed[1] == []
