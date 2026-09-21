"""Contract for the published-counts gate (`scripts/check_published_counts.py`).

The gate's whole value is that it never stores the expected number. These tests
pin that: the expectation is derived from the shipped registry and server card,
a stale claim in any published surface is caught, and a number that merely looks
like a count (a scan result, a ring-buffer size) is left alone.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_published_counts.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_published_counts", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


class TestCountsAreDerivedNotStored:
    def test_registry_entry_count_comes_from_the_bundled_registry(self):
        registry = json.loads((ROOT / "src" / "agent_bom" / "mcp_registry.json").read_text(encoding="utf-8"))
        assert gate.derive_counts()["registry entries"] == len(registry["servers"])

    def test_verified_count_comes_from_the_bundled_registry(self):
        registry = json.loads((ROOT / "src" / "agent_bom" / "mcp_registry.json").read_text(encoding="utf-8"))
        expected = sum(1 for entry in registry["servers"].values() if entry.get("verified") is True)
        assert gate.derive_counts()["registry verified entries"] == expected

    def test_mcp_surface_counts_come_from_the_server_card(self):
        counts = gate.derive_counts()
        assert counts["MCP tools"] == len(gate._server_card_list("_SERVER_CARD_TOOLS"))
        assert counts["MCP resources"] == len(gate._server_card_list("_SERVER_CARD_RESOURCES"))
        assert counts["MCP prompts"] == len(gate._server_card_list("_SERVER_CARD_PROMPTS"))

    def test_no_expected_count_is_hardcoded_in_the_gate(self):
        """A literal expectation is the very failure mode this gate exists to stop."""
        source = SCRIPT.read_text(encoding="utf-8")
        counts = gate.derive_counts()
        code = source.split('"""', 2)[-1]  # skip the module docstring, which cites the incident
        for value in counts.values():
            assert f"== {value}" not in code and f"= {value}\n" not in code


class TestStaleClaimsAreCaught:
    def _sweep(self, tmp_path: Path, monkeypatch, text: str, suffix: str = ".md"):
        published = tmp_path / f"surface{suffix}"
        published.write_text(text, encoding="utf-8")
        monkeypatch.setattr(gate, "SEARCH_ROOTS", (published,))
        monkeypatch.setattr(gate, "ROOT", tmp_path)
        return gate.find_stale_claims(gate.derive_counts())

    def test_stale_registry_entry_claim_is_reported(self, tmp_path, monkeypatch):
        problems = self._sweep(tmp_path, monkeypatch, "Look it up in the curated registry (999 servers, 3 verified).\n")
        assert any("999" in p for p in problems)

    def test_registry_architecture_table_count_is_reported(self, tmp_path, monkeypatch):
        problems = self._sweep(tmp_path, monkeypatch, "| Registry | `registry.py` | 999 server security metadata entries |\n")
        assert any("999" in p and "registry entries" in p for p in problems)

    def test_stale_verified_claim_is_reported(self, tmp_path, monkeypatch):
        counts = gate.derive_counts()
        text = f"agent-bom's curated registry ({counts['registry entries']} servers, 3 verified)\n"
        problems = self._sweep(tmp_path, monkeypatch, text)
        assert any("verified" in p and "3" in p for p in problems)

    def test_correct_claim_passes(self, tmp_path, monkeypatch):
        counts = gate.derive_counts()
        text = f"registry ({counts['registry entries']} servers, {counts['registry verified entries']} verified)\n"
        assert self._sweep(tmp_path, monkeypatch, text) == []

    @pytest.mark.parametrize("separator", [" and ", ", and ", ",\nand "])
    @pytest.mark.parametrize("stale_kind", ["MCP resources", "MCP prompts", None])
    def test_resource_and_prompt_lists_allow_serial_commas(self, tmp_path, monkeypatch, separator, stale_kind):
        counts = gate.derive_counts()
        resources = counts["MCP resources"] + (stale_kind == "MCP resources")
        prompts = counts["MCP prompts"] + (stale_kind == "MCP prompts")
        text = f"{counts['MCP tools']} MCP tools, {resources} resources{separator}{prompts} workflow prompts.\n"
        problems = self._sweep(tmp_path, monkeypatch, text)
        if stale_kind is None:
            assert problems == []
        else:
            assert len(problems) == 1
            assert stale_kind in problems[0]

    def test_svg_diagram_label_is_swept(self, tmp_path, monkeypatch):
        """check_release_consistency skips every image suffix; a stale count hid there."""
        svg = '<text>MCP Registry</text>\n<text class="step-desc">999 servers</text>\n'
        problems = self._sweep(tmp_path, monkeypatch, svg, suffix=".svg")
        assert any("999" in p for p in problems)

    def test_html_wrapped_readme_badge_count_is_swept(self, tmp_path, monkeypatch):
        """Inline markup must not hide a stale headline count from the gate."""
        problems = self._sweep(tmp_path, monkeypatch, "<b>999</b> MCP tools\n")
        assert any("999" in p and "MCP tools" in p for p in problems)

    def test_shipped_python_prose_is_swept(self, tmp_path, monkeypatch):
        """Two of the six real stale claims were runtime strings, not docs."""
        source = '"""Browse the 999-entry server security metadata registry."""\n'
        problems = self._sweep(tmp_path, monkeypatch, source, suffix=".py")
        assert any("999" in p for p in problems)


class TestNumbersThatAreNotClaims:
    def _sweep(self, tmp_path, monkeypatch, text: str, suffix: str = ".md"):
        published = tmp_path / f"surface{suffix}"
        published.write_text(text, encoding="utf-8")
        monkeypatch.setattr(gate, "SEARCH_ROOTS", (published,))
        monkeypatch.setattr(gate, "ROOT", tmp_path)
        return gate.find_stale_claims(gate.derive_counts())

    def test_a_scan_result_is_not_a_registry_claim(self, tmp_path, monkeypatch):
        assert self._sweep(tmp_path, monkeypatch, "The scan found 4 MCP servers on my laptop.\n") == []

    def test_a_ring_buffer_size_is_not_a_registry_claim(self, tmp_path, monkeypatch):
        assert self._sweep(tmp_path, monkeypatch, "evicted from the 1000-entry ring buffer\n") == []

    def test_registry_bundle_itself_is_not_swept(self):
        """Each of its entries records that server's own tool count."""
        assert gate.REGISTRY not in gate._files()


class TestRegistryCountRefresh:
    def test_refresh_updates_only_contextual_registry_numbers_and_is_idempotent(self, tmp_path, monkeypatch):
        published = tmp_path / "surface.md"
        published.write_text(
            "The curated registry (9,999 servers, 3 verified).\n"
            "| Registry | `registry.py` | 999 server security metadata entries |\n"
            "A scan found 4 MCP servers on my laptop.\n"
            "Evicted from a 1000-entry ring buffer.\n"
            "999 MCP tools.\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(gate, "SEARCH_ROOTS", (published,))
        monkeypatch.setattr(gate, "ROOT", tmp_path)
        counts = gate.derive_counts()
        assert gate.refresh_registry_counts(counts) == [published]
        text = published.read_text(encoding="utf-8")
        assert f"registry ({counts['registry entries']:,} servers, {counts['registry verified entries']} verified)" in text
        assert f"{counts['registry entries']} server security metadata entries" in text
        assert "4 MCP servers on my laptop" in text
        assert "1000-entry ring buffer" in text
        assert "999 MCP tools" in text
        assert gate.refresh_registry_counts(counts) == []
        problems = gate.find_stale_claims(counts)
        assert len(problems) == 1 and "MCP tools" in problems[0]

    def test_sync_refreshes_and_stages_count_claims_before_committing(self):
        workflow = (ROOT / ".github/workflows/mcp-registry-sync.yml").read_text(encoding="utf-8")
        refresh = workflow.index("--write-registry-counts --changed-paths-file /tmp/registry-count-paths.json")
        stage = workflow.index('["git", "add", "--", "src/agent_bom/mcp_registry.json", *paths]')
        commit = workflow.index("git commit -S")
        assert refresh < stage < commit

    def test_refresh_manifest_lists_only_changed_authored_paths(self, tmp_path, monkeypatch):
        published = tmp_path / "surface.md"
        published.write_text("Bundled registry: 999 MCP servers.\n", encoding="utf-8")
        unrelated = tmp_path / "uv.lock"
        unrelated.write_text("untouched", encoding="utf-8")
        manifest = tmp_path / "changed.json"
        monkeypatch.setattr(gate, "SEARCH_ROOTS", (published,))
        monkeypatch.setattr(gate, "ROOT", tmp_path)
        assert gate.main(["--write-registry-counts", "--changed-paths-file", str(manifest)]) == 0
        assert json.loads(manifest.read_text()) == ["surface.md"]
        assert unrelated.read_text() == "untouched"


class TestTheRepositoryItself:
    def test_every_published_surface_matches_the_shipped_build(self):
        problems = gate.find_stale_claims(gate.derive_counts())
        assert problems == [], "stale published counts:\n" + "\n".join(problems)

    def test_registry_header_agrees_with_the_bundle(self):
        """`_total_servers` is a second answer to one question; keep them equal."""
        gate.derive_counts()  # raises SystemExit if the header disagrees
