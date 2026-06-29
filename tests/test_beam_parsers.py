from pathlib import Path

from agent_bom.parsers import parse_hex_packages, parse_pub_packages, scan_project_directory


def test_parse_hex_mix_lock(tmp_path: Path) -> None:
    (tmp_path / "mix.lock").write_text(
        """
%{
  "decimal": {:hex, :decimal, "2.1.1", "checksum", [:mix], [], "hexpm", "outer"},
  "telemetry": {:hex, :telemetry, "1.2.1", "checksum", [:rebar3], [], "hexpm", "outer"}
}
""",
        encoding="utf-8",
    )

    packages = parse_hex_packages(tmp_path)

    assert [(pkg.ecosystem, pkg.name, pkg.version) for pkg in packages] == [
        ("hex", "decimal", "2.1.1"),
        ("hex", "telemetry", "1.2.1"),
    ]
    assert all(pkg.reachability_evidence == "lockfile" for pkg in packages)


def test_parse_pubspec_lock(tmp_path: Path) -> None:
    (tmp_path / "pubspec.lock").write_text(
        """
packages:
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  path:
    dependency: "direct main"
    description:
      name: path
      url: "https://pub.dev"
    source: hosted
    version: "1.9.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
""",
        encoding="utf-8",
    )

    packages = parse_pub_packages(tmp_path)

    assert [(pkg.ecosystem, pkg.name, pkg.version, pkg.is_direct) for pkg in packages] == [
        ("pub", "async", "2.11.0", False),
        ("pub", "path", "1.9.0", True),
    ]


def test_project_scan_detects_hex_and_pub_lockfiles(tmp_path: Path) -> None:
    (tmp_path / "mix.lock").write_text(
        ' %{"decimal": {:hex, :decimal, "2.1.1", "", [], [], "hexpm", ""}}',
        encoding="utf-8",
    )
    (tmp_path / "pubspec.lock").write_text(
        'packages:\n  path:\n    dependency: "direct main"\n    source: hosted\n    version: "1.9.0"\n',
        encoding="utf-8",
    )

    result = scan_project_directory(tmp_path)

    packages = result[tmp_path]
    assert sorted((pkg.ecosystem, pkg.name) for pkg in packages) == [("hex", "decimal"), ("pub", "path")]
