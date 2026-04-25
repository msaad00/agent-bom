"""Cross-parser package identity and deduplication contracts."""

from __future__ import annotations

import textwrap

from agent_bom.models import Package
from agent_bom.package_utils import canonical_package_key
from agent_bom.parsers import parse_pnpm_lock, parse_yarn_lock
from agent_bom.scanners import deduplicate_packages


def test_npm_lock_parsers_share_canonical_identity(tmp_path):
    yarn_dir = tmp_path / "yarn"
    pnpm_dir = tmp_path / "pnpm"
    yarn_dir.mkdir()
    pnpm_dir.mkdir()
    (yarn_dir / "yarn.lock").write_text(
        textwrap.dedent("""\
            # yarn lockfile v1

            "react@^18.2.0":
              version "18.2.0"
              resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"
              integrity sha512-react
        """)
    )
    (pnpm_dir / "pnpm-lock.yaml").write_text(
        textwrap.dedent("""\
            lockfileVersion: '9.0'
            packages:
              react@18.2.0:
                resolution: {integrity: sha512-react}
        """)
    )

    yarn_pkg = parse_yarn_lock(yarn_dir)[0]
    pnpm_pkg = parse_pnpm_lock(pnpm_dir)[0]

    assert canonical_package_key(yarn_pkg.name, yarn_pkg.version, yarn_pkg.ecosystem, yarn_pkg.purl) == "npm:react@18.2.0"
    assert canonical_package_key(pnpm_pkg.name, pnpm_pkg.version, pnpm_pkg.ecosystem, pnpm_pkg.purl) == "npm:react@18.2.0"
    assert len(deduplicate_packages([yarn_pkg, pnpm_pkg])) == 1


def test_pypi_spelling_variants_share_stable_identity():
    variants = [
        Package(name="Torch.Audio", version="1.0.0", ecosystem="PyPI", purl="pkg:pypi/Torch.Audio@1.0.0"),
        Package(name="torch_audio", version="1.0.0", ecosystem="pypi", purl="pkg:pypi/torch_audio@1.0.0"),
        Package(name="torch-audio", version="1.0.0", ecosystem="pypi"),
    ]

    assert {canonical_package_key(pkg.name, pkg.version, pkg.ecosystem, pkg.purl) for pkg in variants} == {"pypi:torch-audio@1.0.0"}
    assert len({pkg.stable_id for pkg in variants}) == 1
    assert len(deduplicate_packages(variants)) == 1


def test_conda_and_pypi_packages_do_not_merge_by_name_only():
    """Conda and PyPI packages can have different artifacts and must not collapse accidentally."""

    pypi_numpy = Package(name="numpy", version="1.26.0", ecosystem="pypi", purl="pkg:pypi/numpy@1.26.0")
    conda_numpy = Package(name="numpy", version="1.26.0", ecosystem="conda", purl="pkg:conda/numpy@1.26.0")

    assert canonical_package_key(pypi_numpy.name, pypi_numpy.version, pypi_numpy.ecosystem, pypi_numpy.purl) == "pypi:numpy@1.26.0"
    assert canonical_package_key(conda_numpy.name, conda_numpy.version, conda_numpy.ecosystem, conda_numpy.purl) == "conda:numpy@1.26.0"
    assert len(deduplicate_packages([pypi_numpy, conda_numpy])) == 2
