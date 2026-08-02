"""An npm lockfile finding must name the dependency you can actually upgrade.

``parent_package`` / ``dependency_depth`` are set by the registry-expansion
paths (``transitive.py``, ``deps_dev.py``) and consumed by the console tree
(``console_render.py``) and CycloneDX (``agent-bom:parent-package``). The
package-lock.json parser never set them, so a lockfile project produced
``direct=False, parent=None, depth=0`` for every transitive package: the report
said "qs is vulnerable" and could not say "because express depends on it" —
which is the half the remediating engineer acts on.

npm's own resolution is what makes the introducer recoverable: lockfile v2/v3
records each install *location* (``node_modules/a/node_modules/b``) plus each
package's declared ``dependencies``, so walking the root's dependency edges and
resolving each name to its install location reconstructs the introducing path.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.parsers.node_parsers import parse_npm_packages


def _write(tmp_path: Path, lock: dict, manifest: dict | None = None) -> Path:
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    if manifest is not None:
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def _by_name(packages: list) -> dict:
    return {p.name: p for p in packages}


def _hoisted_lock() -> dict:
    """The common shape: express depends on qs, npm hoists qs to the top level."""
    return {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"express": "^4.18.0"}},
            "node_modules/express": {"version": "4.18.2", "dependencies": {"qs": "6.11.0", "cookie": "0.5.0"}},
            "node_modules/qs": {"version": "6.11.0", "dependencies": {"side-channel": "^1.0.4"}},
            "node_modules/cookie": {"version": "0.5.0"},
            "node_modules/side-channel": {"version": "1.0.4"},
        },
    }


def test_hoisted_transitive_names_its_introducer(tmp_path: Path) -> None:
    packages = _by_name(parse_npm_packages(_write(tmp_path, _hoisted_lock(), {"dependencies": {"express": "^4.18.0"}})))

    assert packages["express"].is_direct is True
    assert packages["express"].parent_package is None
    assert packages["express"].dependency_depth == 0

    assert packages["qs"].is_direct is False
    assert packages["qs"].parent_package == "express", "you upgrade express, not qs"
    assert packages["qs"].dependency_depth == 1


def test_depth_accumulates_down_the_chain(tmp_path: Path) -> None:
    packages = _by_name(parse_npm_packages(_write(tmp_path, _hoisted_lock(), {"dependencies": {"express": "^4.18.0"}})))
    assert packages["side-channel"].parent_package == "qs"
    assert packages["side-channel"].dependency_depth == 2


def test_nested_install_resolves_to_the_nearest_copy(tmp_path: Path) -> None:
    """npm nests a conflicting version under its dependant; the nested copy's
    introducer is that dependant, not whatever is hoisted at the root."""
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"a": "1.0.0", "b": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"shared": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"shared": "^2.0.0"}},
            "node_modules/shared": {"version": "1.5.0"},
            "node_modules/b/node_modules/shared": {"version": "2.1.0"},
        },
    }
    packages = parse_npm_packages(_write(tmp_path, lock, {"dependencies": {"a": "1.0.0", "b": "1.0.0"}}))
    shared = sorted((p for p in packages if p.name == "shared"), key=lambda p: p.version)
    assert [p.version for p in shared] == ["1.5.0", "2.1.0"]
    assert shared[0].parent_package == "a"
    assert shared[1].parent_package == "b"


def test_dev_dependency_scope_is_recorded(tmp_path: Path) -> None:
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/jest": {"version": "29.7.0", "dev": True, "dependencies": {"jest-cli": "29.7.0"}},
            "node_modules/jest-cli": {"version": "29.7.0", "dev": True},
        },
    }
    manifest = {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}}
    packages = _by_name(parse_npm_packages(_write(tmp_path, lock, manifest)))
    assert packages["jest"].is_direct is True
    assert packages["jest"].dependency_scope == "dev"
    assert packages["jest-cli"].parent_package == "jest"
    assert packages["jest-cli"].dependency_scope == "dev"
    assert packages["express"].dependency_scope == "runtime"


def test_cycles_do_not_hang_or_inflate_depth(tmp_path: Path) -> None:
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"a": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1.0.0"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1.0.0"}},
        },
    }
    packages = _by_name(parse_npm_packages(_write(tmp_path, lock, {"dependencies": {"a": "1.0.0"}})))
    assert packages["a"].dependency_depth == 0
    assert packages["b"].dependency_depth == 1
    assert packages["b"].parent_package == "a"


def test_unreachable_lockfile_entry_keeps_a_null_parent(tmp_path: Path) -> None:
    """Honesty: an entry no root path reaches gets no invented introducer."""
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"a": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/orphan": {"version": "9.9.9"},
        },
    }
    packages = _by_name(parse_npm_packages(_write(tmp_path, lock, {"dependencies": {"a": "1.0.0"}})))
    assert packages["orphan"].parent_package is None
    assert packages["orphan"].is_direct is False


def test_scoped_packages_resolve(tmp_path: Path) -> None:
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"@scope/parent": "1.0.0"}},
            "node_modules/@scope/parent": {"version": "1.0.0", "dependencies": {"@scope/child": "1.0.0"}},
            "node_modules/@scope/child": {"version": "1.0.0"},
        },
    }
    packages = _by_name(parse_npm_packages(_write(tmp_path, lock, {"dependencies": {"@scope/parent": "1.0.0"}})))
    assert packages["@scope/child"].parent_package == "@scope/parent"
    assert packages["@scope/child"].dependency_depth == 1


def test_lockfile_v1_dependencies_shape_still_parses(tmp_path: Path) -> None:
    """v1 lockfiles have no ``packages`` map — the parser must not regress."""
    lock = {
        "name": "app",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.2", "requires": {"qs": "6.11.0"}},
            "qs": {"version": "6.11.0"},
        },
    }
    packages = _by_name(parse_npm_packages(_write(tmp_path, lock, {"dependencies": {"express": "^4.18.0"}})))
    assert packages["express"].version == "4.18.2"
    assert packages["express"].is_direct is True
    assert packages["qs"].version == "6.11.0"


def test_no_manifest_still_derives_the_graph_from_the_root_entry(tmp_path: Path) -> None:
    """The lockfile's own ``""`` entry carries the root's dependency edges."""
    packages = _by_name(parse_npm_packages(_write(tmp_path, _hoisted_lock())))
    assert packages["express"].is_direct is True
    assert packages["qs"].parent_package == "express"
