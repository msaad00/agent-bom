"""Regression tests for PHP/Swift symbol-reachability accuracy (issue #3678).

Covers three failure classes that produced either false ``function_reachable``
verdicts or missed real reachable CVEs:

* source masking — call-site tokens inside comments, strings and PHP
  heredoc/nowdoc bodies must never be emitted as call sites;
* PHP package mapping via PSR-4/PSR-0 autoload roots (not the vendor segment);
* Swift package mapping via real product/module names (not identity transforms).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.ast_php import (
    build_php_dependency_symbol_reach,
    load_composer_package_map,
    scan_php_file,
)
from agent_bom.ast_source_mask import mask_php_source, mask_source, mask_swift_source
from agent_bom.ast_swift import (
    build_swift_dependency_symbol_reach,
    load_swift_package_map,
    scan_swift_file,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _php_reach(project: Path, rel: str):
    package_map = load_composer_package_map(project)
    *_, analysis = scan_php_file(project / rel, rel, package_map=package_map)
    assert analysis is not None
    reach = build_php_dependency_symbol_reach(
        methods=analysis.functions,
        tool_registrations=analysis.tool_registrations,
        package_map=package_map,
    )
    return reach, analysis, package_map


def _swift_reach(project: Path, rel: str):
    package_map = load_swift_package_map(project)
    *_, analysis = scan_swift_file(project / rel, rel, package_map=package_map)
    assert analysis is not None
    reach = build_swift_dependency_symbol_reach(
        functions=analysis.functions,
        tool_registrations=analysis.tool_registrations,
        package_map=package_map,
    )
    return reach, analysis, package_map


def _write_composer(project: Path, packages: list[dict]) -> None:
    (project / "composer.lock").write_text(
        json.dumps({"packages": packages, "packages-dev": []}),
        encoding="utf-8",
    )


def _write_resolved(project: Path, identities: list[str]) -> None:
    pins = [
        {
            "identity": identity,
            "kind": "remoteSourceControl",
            "location": f"https://github.com/apple/{identity}.git",
            "state": {"version": "1.0.0"},
        }
        for identity in identities
    ]
    (project / "Package.resolved").write_text(
        json.dumps({"pins": pins, "version": 2}),
        encoding="utf-8",
    )


_NIKIC = {"name": "nikic/php-parser", "version": "4.15.0", "autoload": {"psr-4": {"PhpParser\\": "lib/PhpParser"}}}


# --------------------------------------------------------------------------- #
# masker unit tests
# --------------------------------------------------------------------------- #
def test_mask_preserves_offsets_and_blanks_comments():
    src = "a();\n// b();\n/* c();\nd(); */\ne();\n"
    masked = mask_source(src)
    assert len(masked) == len(src)
    assert masked.count("\n") == src.count("\n")
    assert "a()" in masked
    assert "e()" in masked
    assert "b()" not in masked
    assert "c()" not in masked
    assert "d()" not in masked


def test_mask_php_string_and_hash_and_heredoc():
    src = (
        "$x = 'Foo::bar()';\n"
        "# Foo::baz()\n"
        '$y = "Foo::qux()";\n'
        "$t = <<<SQL\nFoo::heredoc()\nSQL;\n"
        "$n = <<<'TXT'\nFoo::nowdoc()\nTXT;\n"
        "Real::call();\n"
    )
    masked = mask_php_source(src)
    for hidden in ("Foo::bar", "Foo::baz", "Foo::qux", "Foo::heredoc", "Foo::nowdoc"):
        assert hidden not in masked
    assert "Real::call" in masked
    assert len(masked) == len(src)


def test_mask_swift_nested_block_and_triple_string():
    src = 'Real.call()\n/* A.one() /* B.two() */ C.three() */\nlet t = """\nD.four()\n"""\n// E.five()\n'
    masked = mask_swift_source(src)
    assert "Real.call" in masked
    for hidden in ("A.one", "B.two", "C.three", "D.four", "E.five"):
        assert hidden not in masked
    assert len(masked) == len(src)


def test_mask_php_hash_inside_string_is_not_a_comment():
    # A '#' inside a string must not terminate string masking early.
    src = "$u = 'http://x#frag'; Real::call();\n"
    masked = mask_php_source(src)
    assert "Real::call" in masked
    assert "http" not in masked


# --------------------------------------------------------------------------- #
# PHP: masking removes false function_reachable
# --------------------------------------------------------------------------- #
def test_php_comment_and_string_yield_no_reach(tmp_path: Path):
    _write_composer(tmp_path, [{"name": "monolog/monolog", "version": "3.0.0", "autoload": {"psr-4": {"Monolog\\": "src/Monolog"}}}])
    (tmp_path / "Server.php").write_text(
        """<?php
namespace App;
use Monolog\\Logger;
class Server {
    public function register() { $this->tool("run", "handle"); }
    public function handle() {
        // Logger::alert("not a real call");
        $sql = "Logger::alert('also not a call')";
    }
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _php_reach(tmp_path, "Server.php")
    assert reach == []


def test_php_heredoc_body_yields_no_reach(tmp_path: Path):
    _write_composer(tmp_path, [_NIKIC])
    (tmp_path / "Server.php").write_text(
        """<?php
namespace App;
use PhpParser\\ParserFactory;
class Server {
    public function register() { $this->tool("run", "handle"); }
    public function handle() {
        $tpl = <<<SQL
        ParserFactory::create() masked in heredoc
        SQL;
    }
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _php_reach(tmp_path, "Server.php")
    assert reach == []


# --------------------------------------------------------------------------- #
# PHP: PSR-4 autoload-root package mapping
# --------------------------------------------------------------------------- #
def test_php_psr4_root_resolves_non_vendor_namespace(tmp_path: Path):
    _write_composer(tmp_path, [_NIKIC])
    (tmp_path / "Server.php").write_text(
        """<?php
namespace App;
use PhpParser\\ParserFactory;
class Server {
    public function register() { $this->tool("run", "handle"); }
    public function handle() {
        $parser = ParserFactory::createForNewestSupportedVersion();
    }
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _php_reach(tmp_path, "Server.php")
    assert len(reach) == 1
    assert reach[0].package == "nikic/php-parser"
    assert reach[0].symbol == "createForNewestSupportedVersion"


def test_php_longest_prefix_wins_over_shorter_root(tmp_path: Path):
    _write_composer(
        tmp_path,
        [
            {"name": "psr/log", "version": "3.0.0", "autoload": {"psr-4": {"Psr\\Log\\": "src"}}},
            {"name": "psr/cache", "version": "3.0.0", "autoload": {"psr-4": {"Psr\\Cache\\": "src"}}},
        ],
    )
    (tmp_path / "Server.php").write_text(
        """<?php
namespace App;
use Psr\\Log\\LoggerInterface;
class Server {
    public function register() { $this->tool("run", "handle"); }
    public function handle() {
        LoggerInterface::emergency("boom");
    }
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _php_reach(tmp_path, "Server.php")
    assert len(reach) == 1
    assert reach[0].package == "psr/log"


def test_php_multi_package_vendor_binds_by_autoload_not_vendor(tmp_path: Path):
    # Two packages share the "symfony" vendor; the vendor-segment heuristic
    # was nondeterministic. PSR-4 roots bind each namespace to its own package.
    _write_composer(
        tmp_path,
        [
            {"name": "symfony/console", "version": "7.0.0", "autoload": {"psr-4": {"Symfony\\Component\\Console\\": "."}}},
            {"name": "symfony/finder", "version": "7.0.0", "autoload": {"psr-4": {"Symfony\\Component\\Finder\\": "."}}},
        ],
    )
    (tmp_path / "Server.php").write_text(
        """<?php
namespace App;
use Symfony\\Component\\Finder\\Finder;
class Server {
    public function register() { $this->tool("run", "handle"); }
    public function handle() {
        Finder::createFromDirectory("/tmp");
    }
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _php_reach(tmp_path, "Server.php")
    assert len(reach) == 1
    assert reach[0].package == "symfony/finder"


# --------------------------------------------------------------------------- #
# PHP: multi-class file keys methods to the enclosing class
# --------------------------------------------------------------------------- #
def test_php_multi_class_methods_key_to_correct_class(tmp_path: Path):
    _write_composer(tmp_path, [_NIKIC])
    (tmp_path / "Multi.php").write_text(
        """<?php
namespace App;
class Alpha {
    public function shared() {}
}
class Beta {
    public function shared() {}
    public function only_beta() {}
}
""",
        encoding="utf-8",
    )
    package_map = load_composer_package_map(tmp_path)
    *_, analysis = scan_php_file(tmp_path / "Multi.php", "Multi.php", package_map=package_map)
    keys = set(analysis.functions)
    assert "Alpha::shared" in keys
    assert "Beta::shared" in keys
    assert "Beta::only_beta" in keys
    assert analysis.functions["Beta::only_beta"].class_name == "Beta"


# --------------------------------------------------------------------------- #
# Swift: product/module package mapping + masking
# --------------------------------------------------------------------------- #
def test_swift_logging_module_resolves_swift_log(tmp_path: Path):
    _write_resolved(tmp_path, ["swift-log"])
    (tmp_path / "Server.swift").write_text(
        """import Logging

func register() {
    server.tool("run", handle)
}
func handle() {
    // Logging.critical("commented out, not a call")
    let logger = Logging.Logger(label: "x")
}
""",
        encoding="utf-8",
    )
    reach, _analysis, package_map = _swift_reach(tmp_path, "Server.swift")
    assert package_map.get("Logging") == "swift-log"
    assert len(reach) == 1
    assert reach[0].package == "swift-log"
    assert reach[0].symbol == "Logger"


def test_swift_nio_module_resolves_swift_nio(tmp_path: Path):
    _write_resolved(tmp_path, ["swift-nio"])
    (tmp_path / "Server.swift").write_text(
        """import NIO

func register() {
    server.tool("run", handle)
}
func handle() {
    let group = NIO.MultiThreadedEventLoopGroup(numberOfThreads: 1)
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _swift_reach(tmp_path, "Server.swift")
    assert len(reach) == 1
    assert reach[0].package == "swift-nio"


def test_swift_product_declaration_maps_module(tmp_path: Path):
    # A package whose module name is only discoverable from Package.swift.
    _write_resolved(tmp_path, ["acme-transport"])
    (tmp_path / "Package.swift").write_text(
        """// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "app",
    targets: [
        .target(name: "App", dependencies: [
            .product(name: "Transport", package: "acme-transport"),
        ]),
    ]
)
""",
        encoding="utf-8",
    )
    (tmp_path / "Server.swift").write_text(
        """import Transport

func register() {
    server.tool("run", handle)
}
func handle() {
    let c = Transport.Client(host: "x")
}
""",
        encoding="utf-8",
    )
    reach, _analysis, package_map = _swift_reach(tmp_path, "Server.swift")
    assert package_map.get("Transport") == "acme-transport"
    assert len(reach) == 1
    assert reach[0].package == "acme-transport"


def test_swift_comment_only_yields_no_reach(tmp_path: Path):
    _write_resolved(tmp_path, ["swift-log"])
    (tmp_path / "Server.swift").write_text(
        """import Logging

func register() {
    server.tool("run", handle)
}
func handle() {
    // Logging.Logger(label: "x")
    let s = "Logging.Logger(label: y)"
}
""",
        encoding="utf-8",
    )
    reach, _analysis, _pmap = _swift_reach(tmp_path, "Server.swift")
    assert reach == []


@pytest.mark.parametrize(
    "identity,module",
    [
        ("swift-log", "Logging"),
        ("swift-nio", "NIO"),
        ("swift-argument-parser", "ArgumentParser"),
        ("swift-crypto", "Crypto"),
    ],
)
def test_swift_common_module_table(tmp_path: Path, identity: str, module: str):
    _write_resolved(tmp_path, [identity])
    package_map = load_swift_package_map(tmp_path)
    assert package_map.get(module) == identity
