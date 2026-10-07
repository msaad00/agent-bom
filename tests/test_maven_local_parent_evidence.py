"""Bounded local POM inheritance must not silently erase dependencies."""

from pathlib import Path

import pytest

from agent_bom.parsers.compiled_parsers import parse_maven_packages
from agent_bom.scanners import state


def pom(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"<project>{content}</project>")


DEP = (
    "<dependencies><dependency><groupId>org.apache.struts</groupId><artifactId>struts2-core</artifactId>"
    "<version>${struts.version}</version></dependency></dependencies>"
)


def test_local_parent_properties_are_resolved_and_child_override_wins(tmp_path):
    pom(tmp_path / "pom.xml", "<properties><struts.version>2.3.20</struts.version></properties><modules><module>app</module></modules>")
    pom(tmp_path / "app/pom.xml", "<parent><relativePath>../pom.xml</relativePath></parent>" + DEP)
    packages = parse_maven_packages(tmp_path)
    assert [(p.name, p.version) for p in packages] == [("org.apache.struts:struts2-core", "2.3.20")]
    pom(tmp_path / "app/pom.xml", "<parent/><properties><struts.version>${safe}</struts.version><safe>2.5.33</safe></properties>" + DEP)
    assert parse_maven_packages(tmp_path)[0].version == "2.5.33"


@pytest.mark.parametrize("relative", ["../outside/pom.xml", "missing/pom.xml", ""])
def test_unavailable_parent_properties_are_explicit_coverage_gap(tmp_path, relative):
    state.reset_scan_warnings()
    root = tmp_path / "project"
    pom(tmp_path / "outside/pom.xml", "<properties><struts.version>2.3.20</struts.version></properties>")
    pom(root / "pom.xml", f"<parent><relativePath>{relative}</relativePath></parent>" + DEP)
    assert parse_maven_packages(root) == []
    assert any("unresolved" in w["detail"] for w in state.peek_coverage_warnings())


def test_parent_cycle_and_file_size_limit_warn_without_unbounded_read(tmp_path, monkeypatch):
    state.reset_scan_warnings()
    pom(tmp_path / "pom.xml", "<parent><relativePath>pom.xml</relativePath></parent>" + DEP)
    assert parse_maven_packages(tmp_path) == []
    assert state.peek_coverage_warnings()
    state.reset_scan_warnings()
    monkeypatch.setenv("AGENT_BOM_MAX_MANIFEST_BYTES", "20")
    assert parse_maven_packages(tmp_path) == []
    assert any("limit" in w["detail"] for w in state.peek_coverage_warnings())


def test_parent_traversal_is_at_most_eight_hops(tmp_path):
    state.reset_scan_warnings()
    for i in range(10):
        parent = (
            f"<parent><relativePath>../p{i + 1}/pom.xml</relativePath></parent>"
            if i < 9
            else "<properties><struts.version>2.3.20</struts.version></properties>"
        )
        pom(tmp_path / f"p{i}/pom.xml", parent + (DEP if i == 0 else ""))
    pom(tmp_path / "pom.xml", "<modules><module>p0</module></modules>")
    assert parse_maven_packages(tmp_path) == []
    assert any("unresolved" in w["detail"] for w in state.peek_coverage_warnings())


def test_untrusted_pom_entities_are_rejected_as_coverage_gap(tmp_path):
    state.reset_scan_warnings()
    (tmp_path / "pom.xml").write_text('<!DOCTYPE project [<!ENTITY version "2.3.20">]><project><name>&version;</name></project>')
    assert parse_maven_packages(tmp_path) == []
    assert state.peek_coverage_warnings()
