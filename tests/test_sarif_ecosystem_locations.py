"""SARIF dependency findings point at the manifest of their own ecosystem (P1 audit fix)."""

from agent_bom.output.sarif import _ecosystem_from_purl, _to_relative_path


def test_ecosystem_from_purl():
    assert _ecosystem_from_purl("pkg:maven/org.apache/log4j@2.14.1") == "maven"
    assert _ecosystem_from_purl("pkg:pypi/requests@2.20.0") == "pypi"
    assert _ecosystem_from_purl("pkg:npm/lodash@4.17.0") == "npm"
    assert _ecosystem_from_purl("pkg:cargo/time@0.1.42") == "cargo"
    assert _ecosystem_from_purl(None) is None
    assert _ecosystem_from_purl("not-a-purl") is None


def test_to_relative_path_picks_ecosystem_manifest(tmp_path):
    # A multi-ecosystem project root with several manifests present.
    for m in ("requirements.txt", "package.json", "pom.xml", "go.mod", "Cargo.toml"):
        (tmp_path / m).write_text("x")
    d = str(tmp_path)
    assert _to_relative_path(d, "maven") == "pom.xml"
    assert _to_relative_path(d, "pypi") == "requirements.txt"
    assert _to_relative_path(d, "npm") == "package.json"
    assert _to_relative_path(d, "go") == "go.mod"
    assert _to_relative_path(d, "cargo") == "Cargo.toml"
    # Unknown/None ecosystem → first-found fallback (not a crash, not maven-only).
    assert _to_relative_path(d, None) in {"pyproject.toml", "package.json", "go.mod", "Cargo.toml", "requirements.txt"}


def test_to_relative_path_falls_back_when_ecosystem_manifest_absent(tmp_path):
    # maven finding but only a requirements.txt present → fall back, don't invent pom.xml.
    (tmp_path / "requirements.txt").write_text("x")
    assert _to_relative_path(str(tmp_path), "maven") == "requirements.txt"
