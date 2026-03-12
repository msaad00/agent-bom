"""Tests for Bun, NuGet, and pip-compile parsers."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.parsers.dotnet_parsers import parse_nuget_packages
from agent_bom.parsers.node_parsers import parse_bun_packages
from agent_bom.parsers.python_parsers import parse_pip_compile_inputs

# ---------------------------------------------------------------------------
# Bun parser tests
# ---------------------------------------------------------------------------


def test_parse_bun_lock_basic(tmp_path: Path) -> None:
    """bun.lock with a dependencies section is parsed correctly."""
    (tmp_path / "bun.lock").write_text(
        "lockfileVersion: 0\n"
        "packages:\n"
        '  "react@19.0.0":\n'
        "    resolution: {integrity: sha512-abc}\n"
        "dependencies:\n"
        '  "react": "19.0.0"\n'
        '  "typescript": "5.7.0"\n",\n'
    )

    pkgs = parse_bun_packages(tmp_path)
    names = {p.name for p in pkgs}
    assert "react" in names
    assert "typescript" in names
    assert all(p.ecosystem == "npm" for p in pkgs)


def test_parse_bun_lock_dev_deps(tmp_path: Path) -> None:
    """devDependencies section is parsed and included."""
    (tmp_path / "bun.lock").write_text(
        'lockfileVersion: 0\ndependencies:\n  "react": "19.0.0"\ndevDependencies:\n  "@types/node": "22.0.0"\n'
    )

    pkgs = parse_bun_packages(tmp_path)
    names = {p.name for p in pkgs}
    assert "react" in names
    assert "@types/node" in names
    assert len(pkgs) == 2


def test_parse_bun_lock_purl_format(tmp_path: Path) -> None:
    """purl uses pkg:npm/name@version (scoped packages encoded correctly)."""
    (tmp_path / "bun.lock").write_text(
        'lockfileVersion: 0\ndependencies:\n  "react": "18.3.1"\ndevDependencies:\n  "@types/node": "22.0.0"\n'
    )

    pkgs = parse_bun_packages(tmp_path)
    by_name = {p.name: p for p in pkgs}

    assert by_name["react"].purl == "pkg:npm/react@18.3.1"
    # scoped package: @ must be percent-encoded per PURL spec
    assert by_name["@types/node"].purl == "pkg:npm/%40types/node@22.0.0"


def test_parse_bun_lockb_binary_only(tmp_path: Path) -> None:
    """Only bun.lockb exists (binary) — returns empty list, no exception."""
    (tmp_path / "bun.lockb").write_bytes(b"\x00\x01binary data")

    pkgs = parse_bun_packages(tmp_path)
    assert pkgs == []


def test_parse_bun_no_files(tmp_path: Path) -> None:
    """Empty directory returns empty list."""
    assert parse_bun_packages(tmp_path) == []


# ---------------------------------------------------------------------------
# NuGet parser tests
# ---------------------------------------------------------------------------


def test_parse_nuget_packages_lock_json(tmp_path: Path) -> None:
    """packages.lock.json with direct and transitive packages is parsed."""
    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Microsoft.SemanticKernel": {
                    "type": "Direct",
                    "requested": "[1.14.1, )",
                    "resolved": "1.14.1",
                    "contentHash": "abc123",
                },
                "Newtonsoft.Json": {
                    "type": "Transitive",
                    "resolved": "13.0.3",
                },
            }
        },
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock))

    pkgs = parse_nuget_packages(tmp_path)
    names = {p.name for p in pkgs}
    assert "Microsoft.SemanticKernel" in names
    assert "Newtonsoft.Json" in names
    assert all(p.ecosystem == "nuget" for p in pkgs)


def test_parse_nuget_csproj(tmp_path: Path) -> None:
    """.csproj PackageReference elements are extracted when no lock file exists."""
    csproj = """\
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Microsoft.SemanticKernel" Version="1.14.1" />
    <PackageReference Include="Microsoft.ML" Version="3.0.0" />
  </ItemGroup>
</Project>
"""
    (tmp_path / "MyApp.csproj").write_text(csproj)

    pkgs = parse_nuget_packages(tmp_path)
    names = {p.name for p in pkgs}
    assert "Microsoft.SemanticKernel" in names
    assert "Microsoft.ML" in names
    assert all(p.ecosystem == "nuget" for p in pkgs)


def test_parse_nuget_lock_prefers_resolved_version(tmp_path: Path) -> None:
    """packages.lock.json: uses 'resolved' field, not 'requested' range."""
    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "SomeLib": {
                    "type": "Direct",
                    "requested": "[1.0.0, 2.0.0)",
                    "resolved": "1.5.3",
                }
            }
        },
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock))

    pkgs = parse_nuget_packages(tmp_path)
    assert len(pkgs) == 1
    assert pkgs[0].version == "1.5.3"


def test_parse_nuget_direct_vs_transitive(tmp_path: Path) -> None:
    """Direct packages have is_direct=True; Transitive packages have is_direct=False."""
    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "DirectPkg": {"type": "Direct", "resolved": "2.0.0"},
                "TransitivePkg": {"type": "Transitive", "resolved": "1.0.0"},
            }
        },
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock))

    pkgs = parse_nuget_packages(tmp_path)
    by_name = {p.name: p for p in pkgs}
    assert by_name["DirectPkg"].is_direct is True
    assert by_name["TransitivePkg"].is_direct is False


def test_parse_nuget_purl_format(tmp_path: Path) -> None:
    """purl follows pkg:nuget/name@version format."""
    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Microsoft.SemanticKernel": {
                    "type": "Direct",
                    "resolved": "1.14.1",
                }
            }
        },
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock))

    pkgs = parse_nuget_packages(tmp_path)
    assert pkgs[0].purl == "pkg:nuget/Microsoft.SemanticKernel@1.14.1"


def test_parse_nuget_no_files(tmp_path: Path) -> None:
    """Empty directory returns empty list."""
    assert parse_nuget_packages(tmp_path) == []


# ---------------------------------------------------------------------------
# pip-compile parser tests
# ---------------------------------------------------------------------------


def test_parse_pip_compile_in_file(tmp_path: Path) -> None:
    """requirements.in with unpinned deps is parsed into packages."""
    (tmp_path / "requirements.in").write_text("# Core dependencies\nrequests>=2.28.0\nfastapi\npydantic>=2.0\n")

    pkgs = parse_pip_compile_inputs(tmp_path)
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "fastapi" in names
    assert "pydantic" in names
    assert all(p.ecosystem == "pypi" for p in pkgs)


def test_parse_pip_compile_prefers_txt(tmp_path: Path) -> None:
    """When both .in and compiled .txt exist, .in is skipped (txt takes precedence)."""
    (tmp_path / "requirements.in").write_text("requests>=2.28.0\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    # parse_pip_compile_inputs should skip requirements.in entirely
    pkgs = parse_pip_compile_inputs(tmp_path)
    # No packages returned from .in because compiled txt exists
    assert pkgs == []


def test_parse_pip_compile_constraints(tmp_path: Path) -> None:
    """constraints.txt entries are parsed with is_direct=False."""
    (tmp_path / "constraints.txt").write_text("urllib3==1.26.18\ncertifi==2023.11.17\n")

    pkgs = parse_pip_compile_inputs(tmp_path)
    assert len(pkgs) == 2
    assert all(p.is_direct is False for p in pkgs)
    names = {p.name for p in pkgs}
    assert "urllib3" in names
    assert "certifi" in names


def test_parse_pip_compile_no_files(tmp_path: Path) -> None:
    """No .in or constraints files → empty list."""
    assert parse_pip_compile_inputs(tmp_path) == []
