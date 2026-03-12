"""Tests for Maven (pom.xml) and Go (go.mod/go.sum) package parsers.

Covers:
- parse_maven_packages: pom.xml parsing, scope handling, PURL format
- _parse_go_mod_requires: go.mod direct/indirect/replace parsing
- parse_go_packages: go.mod + go.sum integration, fallback, replace directives
- scan_project_directory integration for both ecosystems
"""

from __future__ import annotations

import textwrap

from agent_bom.parsers import (
    _parse_go_mod_requires,
    parse_go_packages,
    parse_go_workspace,
    parse_maven_packages,
    scan_project_directory,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

MAVEN_POM_BASIC = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <modelVersion>4.0.0</modelVersion>
        <groupId>com.example</groupId>
        <artifactId>myapp</artifactId>
        <version>1.0.0</version>
        <dependencies>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>2.14.1</version>
            </dependency>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-webmvc</artifactId>
                <version>5.3.18</version>
                <scope>provided</scope>
            </dependency>
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.13.2</version>
                <scope>test</scope>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>no-version</artifactId>
            </dependency>
        </dependencies>
    </project>
""")

MAVEN_POM_NO_NS = textwrap.dedent("""\
    <project>
        <dependencies>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>2.13.0</version>
            </dependency>
        </dependencies>
    </project>
""")

MAVEN_POM_PROPERTY_VERSION = textwrap.dedent("""\
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <dependencies>
            <dependency>
                <groupId>io.netty</groupId>
                <artifactId>netty-all</artifactId>
                <version>${netty.version}</version>
            </dependency>
            <dependency>
                <groupId>com.google.guava</groupId>
                <artifactId>guava</artifactId>
                <version>31.0-jre</version>
            </dependency>
        </dependencies>
    </project>
""")

MAVEN_POM_INVALID = "not valid xml <<<"

GO_MOD_BASIC = textwrap.dedent("""\
    module example.com/myapp

    go 1.21

    require (
        github.com/gin-gonic/gin v1.9.1
        github.com/stretchr/testify v1.8.4 // indirect
        golang.org/x/net v0.17.0 // indirect
    )
""")

GO_MOD_WITH_REPLACE = textwrap.dedent("""\
    module example.com/myapp

    go 1.21

    require (
        github.com/old/package v1.0.0
        github.com/direct/dep v2.3.4
    )

    replace github.com/old/package => github.com/new/package v1.1.0
""")

GO_MOD_SINGLE_LINE = textwrap.dedent("""\
    module example.com/myapp

    go 1.21

    require github.com/pkg/errors v0.9.1
    require github.com/sirupsen/logrus v1.9.3 // indirect
""")

GO_SUM_BASIC = textwrap.dedent("""\
    github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
    github.com/gin-gonic/gin v1.9.1/go.mod h1:hPys/inP3MwrfBnNErQn7CXHq/XCfBFpkAiQCDPF9GE=
    github.com/stretchr/testify v1.8.4 h1:CcVxWJq4gnR6/qe56EiYd8GaYN2/eTYhp0G04YAtO4s=
    github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
""")


# ── parse_maven_packages ──────────────────────────────────────────────────────


class TestParseMavenPackages:
    def test_returns_empty_when_no_pom(self, tmp_path):
        assert parse_maven_packages(tmp_path) == []

    def test_parses_compile_scope_dependency(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.apache.logging.log4j:log4j-core" in names

    def test_compile_scope_is_direct(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = {p.name: p for p in parse_maven_packages(tmp_path)}
        assert pkgs["org.apache.logging.log4j:log4j-core"].is_direct is True

    def test_provided_scope_is_not_direct(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = {p.name: p for p in parse_maven_packages(tmp_path)}
        assert pkgs["org.springframework:spring-webmvc"].is_direct is False

    def test_test_scope_is_not_direct(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = {p.name: p for p in parse_maven_packages(tmp_path)}
        assert pkgs["junit:junit"].is_direct is False

    def test_dependency_without_version_skipped(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        names = {p.name for p in parse_maven_packages(tmp_path)}
        assert "com.example:no-version" not in names

    def test_ecosystem_is_maven(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = parse_maven_packages(tmp_path)
        assert all(p.ecosystem == "maven" for p in pkgs)

    def test_version_correct(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = {p.name: p for p in parse_maven_packages(tmp_path)}
        assert pkgs["org.apache.logging.log4j:log4j-core"].version == "2.14.1"

    def test_purl_format(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = {p.name: p for p in parse_maven_packages(tmp_path)}
        assert pkgs["org.apache.logging.log4j:log4j-core"].purl == ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")

    def test_pom_without_namespace(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_NO_NS)
        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "com.fasterxml.jackson.core:jackson-databind" in names

    def test_property_version_skipped(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_PROPERTY_VERSION)
        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "io.netty:netty-all" not in names
        assert "com.google.guava:guava" in names

    def test_invalid_xml_returns_empty(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_INVALID)
        assert parse_maven_packages(tmp_path) == []

    def test_colon_name_format(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_NO_NS)
        pkgs = parse_maven_packages(tmp_path)
        for p in pkgs:
            assert ":" in p.name, f"Expected group:artifact format, got: {p.name}"


# ── _parse_go_mod_requires ────────────────────────────────────────────────────


class TestParseGoModRequires:
    def test_returns_empty_when_no_go_mod(self, tmp_path):
        direct, indirect, replace = _parse_go_mod_requires(tmp_path / "go.mod")
        assert direct == {}
        assert indirect == {}
        assert replace == {}

    def test_parses_direct_dependencies(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        direct, _, _ = _parse_go_mod_requires(tmp_path / "go.mod")
        assert "github.com/gin-gonic/gin" in direct
        assert direct["github.com/gin-gonic/gin"] == "v1.9.1"

    def test_parses_indirect_dependencies(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        _, indirect, _ = _parse_go_mod_requires(tmp_path / "go.mod")
        assert "github.com/stretchr/testify" in indirect
        assert "golang.org/x/net" in indirect

    def test_indirect_not_in_direct(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        direct, indirect, _ = _parse_go_mod_requires(tmp_path / "go.mod")
        assert "github.com/stretchr/testify" not in direct
        assert "github.com/gin-gonic/gin" not in indirect

    def test_parses_replace_directives(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_WITH_REPLACE)
        _, _, replace = _parse_go_mod_requires(tmp_path / "go.mod")
        assert "github.com/old/package" in replace
        assert replace["github.com/old/package"] == ("github.com/new/package", "v1.1.0")

    def test_parses_single_line_require(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_SINGLE_LINE)
        direct, indirect, _ = _parse_go_mod_requires(tmp_path / "go.mod")
        assert "github.com/pkg/errors" in direct
        assert "github.com/sirupsen/logrus" in indirect


# ── parse_go_packages ─────────────────────────────────────────────────────────


class TestParseGoPackages:
    def test_returns_empty_with_no_files(self, tmp_path):
        assert parse_go_packages(tmp_path) == []

    def test_reads_go_mod_for_packages(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = parse_go_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/stretchr/testify" in names

    def test_direct_dependency_marked_direct(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/gin-gonic/gin"].is_direct is True

    def test_indirect_dependency_not_direct(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/stretchr/testify"].is_direct is False

    def test_version_strips_leading_v(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/gin-gonic/gin"].version == "1.9.1"

    def test_purl_preserves_v_prefix(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/gin-gonic/gin"].purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"

    def test_ecosystem_is_go(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = parse_go_packages(tmp_path)
        assert all(p.ecosystem == "go" for p in pkgs)

    def test_replace_directive_uses_new_module(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_WITH_REPLACE)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert "github.com/old/package" not in pkgs
        assert "github.com/new/package" in pkgs

    def test_replace_preserves_directness(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_WITH_REPLACE)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/new/package"].is_direct is True

    def test_fallback_to_go_sum_without_go_mod(self, tmp_path):
        (tmp_path / "go.sum").write_text(GO_SUM_BASIC)
        pkgs = parse_go_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "github.com/gin-gonic/gin" in names

    def test_go_sum_fallback_deduplicates(self, tmp_path):
        """go.sum has two entries per module (hash + go.mod); only one Package."""
        (tmp_path / "go.sum").write_text(GO_SUM_BASIC)
        pkgs = parse_go_packages(tmp_path)
        names = [p.name for p in pkgs]
        assert names.count("github.com/gin-gonic/gin") == 1

    def test_go_sum_fallback_all_direct(self, tmp_path):
        (tmp_path / "go.sum").write_text(GO_SUM_BASIC)
        pkgs = parse_go_packages(tmp_path)
        assert all(p.is_direct for p in pkgs)

    def test_go_mod_preferred_over_go_sum(self, tmp_path):
        """When both exist, go.mod wins (provides direct/indirect distinction)."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        (tmp_path / "go.sum").write_text(GO_SUM_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        # go.mod marks stretchr/testify as indirect; go.sum-only would mark it direct
        assert pkgs["github.com/stretchr/testify"].is_direct is False


# ── scan_project_directory integration ───────────────────────────────────────


class TestProjectModeMavenGo:
    def test_scans_maven_project(self, tmp_path):
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "org.apache.logging.log4j:log4j-core" in names

    def test_scans_go_mod_project(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "github.com/gin-gonic/gin" in names

    def test_monorepo_maven_and_go(self, tmp_path):
        java_svc = tmp_path / "java-svc"
        go_svc = tmp_path / "go-svc"
        java_svc.mkdir()
        go_svc.mkdir()
        (java_svc / "pom.xml").write_text(MAVEN_POM_NO_NS)
        (go_svc / "go.mod").write_text(GO_MOD_BASIC)
        result = scan_project_directory(tmp_path)
        assert java_svc in result
        assert go_svc in result
        java_names = {p.name for p in result[java_svc]}
        go_names = {p.name for p in result[go_svc]}
        assert "com.fasterxml.jackson.core:jackson-databind" in java_names
        assert "github.com/gin-gonic/gin" in go_names

    def test_maven_and_go_in_same_dir(self, tmp_path):
        """A directory with both pom.xml and go.mod returns packages from both."""
        (tmp_path / "pom.xml").write_text(MAVEN_POM_NO_NS)
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        result = scan_project_directory(tmp_path)
        assert tmp_path in result
        names = {p.name for p in result[tmp_path]}
        assert "com.fasterxml.jackson.core:jackson-databind" in names
        assert "github.com/gin-gonic/gin" in names

    def test_target_dir_skipped(self, tmp_path):
        """Maven target/ build output directory is excluded from scan."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "pom.xml").write_text(MAVEN_POM_NO_NS)
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        result = scan_project_directory(tmp_path)
        assert target not in result

    def test_maven_go_ecosystem_strings(self, tmp_path):
        """OSV ecosystem strings are correct for scanner compatibility."""
        (tmp_path / "pom.xml").write_text(MAVEN_POM_NO_NS)
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        result = scan_project_directory(tmp_path)
        pkgs = result[tmp_path]
        maven_pkgs = [p for p in pkgs if p.ecosystem == "maven"]
        go_pkgs = [p for p in pkgs if p.ecosystem == "go"]
        assert maven_pkgs, "Expected Maven packages"
        assert go_pkgs, "Expected Go packages"


# ── parse_go_workspace ────────────────────────────────────────────────────────

GO_WORK_SINGLE = textwrap.dedent("""\
    go 1.21

    use ./app
""")

GO_WORK_MULTI = textwrap.dedent("""\
    go 1.21

    use (
        ./app
        ./lib
    )
""")

GO_MOD_APP = textwrap.dedent("""\
    module example.com/app

    go 1.21

    require (
        github.com/gin-gonic/gin v1.9.1
        github.com/stretchr/testify v1.8.4 // indirect
    )
""")

GO_MOD_LIB = textwrap.dedent("""\
    module example.com/lib

    go 1.21

    require (
        github.com/pkg/errors v0.9.1
        github.com/gin-gonic/gin v1.9.1
    )
""")


class TestParseGoWorkspace:
    def test_returns_empty_when_no_go_work(self, tmp_path):
        assert parse_go_workspace(tmp_path) == []

    def test_parse_go_workspace_single_module(self, tmp_path):
        """go.work with one use directive returns that module's packages."""
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_SINGLE)
        (app_dir / "go.mod").write_text(GO_MOD_APP)

        pkgs = parse_go_workspace(tmp_path)
        names = {p.name for p in pkgs}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/stretchr/testify" in names

    def test_parse_go_workspace_multi_module(self, tmp_path):
        """go.work with two use directives merges packages from both."""
        app_dir = tmp_path / "app"
        lib_dir = tmp_path / "lib"
        app_dir.mkdir()
        lib_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_MULTI)
        (app_dir / "go.mod").write_text(GO_MOD_APP)
        (lib_dir / "go.mod").write_text(GO_MOD_LIB)

        pkgs = parse_go_workspace(tmp_path)
        names = {p.name for p in pkgs}
        # packages from both modules should be present
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/pkg/errors" in names
        assert "github.com/stretchr/testify" in names

    def test_parse_go_workspace_missing_file(self, tmp_path):
        """No go.work file returns empty list."""
        assert parse_go_workspace(tmp_path) == []

    def test_go_workspace_deduplicates(self, tmp_path):
        """Same package appearing in multiple modules is returned once."""
        app_dir = tmp_path / "app"
        lib_dir = tmp_path / "lib"
        app_dir.mkdir()
        lib_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_MULTI)
        (app_dir / "go.mod").write_text(GO_MOD_APP)
        (lib_dir / "go.mod").write_text(GO_MOD_LIB)

        pkgs = parse_go_workspace(tmp_path)
        gin_pkgs = [p for p in pkgs if p.name == "github.com/gin-gonic/gin"]
        assert len(gin_pkgs) == 1

    def test_go_workspace_direct_wins_over_indirect(self, tmp_path):
        """When a package is direct in one module and indirect in another, is_direct=True."""
        app_dir = tmp_path / "app"
        lib_dir = tmp_path / "lib"
        app_dir.mkdir()
        lib_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_MULTI)
        # app marks testify as indirect; lib marks gin as direct
        (app_dir / "go.mod").write_text(GO_MOD_APP)
        (lib_dir / "go.mod").write_text(GO_MOD_LIB)

        pkgs = {p.name: p for p in parse_go_workspace(tmp_path)}
        # gin is direct in lib, indirect in app (via GO_MOD_APP it's direct) — still True
        assert pkgs["github.com/gin-gonic/gin"].is_direct is True

    def test_go_purl_format_workspace(self, tmp_path):
        """PURLs from workspace modules use pkg:golang/ scheme."""
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_SINGLE)
        (app_dir / "go.mod").write_text(GO_MOD_APP)

        pkgs = {p.name: p for p in parse_go_workspace(tmp_path)}
        assert pkgs["github.com/gin-gonic/gin"].purl.startswith("pkg:golang/")

    def test_go_packages_delegates_to_workspace(self, tmp_path):
        """parse_go_packages() uses workspace mode when go.work is present."""
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (tmp_path / "go.work").write_text(GO_WORK_SINGLE)
        (app_dir / "go.mod").write_text(GO_MOD_APP)

        pkgs = parse_go_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "github.com/gin-gonic/gin" in names

    def test_go_purl_format(self, tmp_path):
        """Verify go.mod packages have pkg:golang/ PURL scheme."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        pkgs = {p.name: p for p in parse_go_packages(tmp_path)}
        assert pkgs["github.com/gin-gonic/gin"].purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"


# ── Maven multi-module ────────────────────────────────────────────────────────

MAVEN_POM_PARENT = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <modelVersion>4.0.0</modelVersion>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
        <packaging>pom</packaging>
        <dependencies>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>2.14.1</version>
            </dependency>
        </dependencies>
        <modules>
            <module>child-a</module>
            <module>child-b</module>
        </modules>
    </project>
""")

MAVEN_POM_CHILD_A = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <modelVersion>4.0.0</modelVersion>
        <artifactId>child-a</artifactId>
        <dependencies>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>2.13.0</version>
            </dependency>
        </dependencies>
    </project>
""")

MAVEN_POM_CHILD_B = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <modelVersion>4.0.0</modelVersion>
        <artifactId>child-b</artifactId>
        <dependencies>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-core</artifactId>
                <version>5.3.18</version>
            </dependency>
        </dependencies>
    </project>
""")


class TestParseMavenMultiModule:
    def test_parse_maven_multi_module(self, tmp_path):
        """Root pom with <modules> parses children's dependencies."""
        child_a = tmp_path / "child-a"
        child_b = tmp_path / "child-b"
        child_a.mkdir()
        child_b.mkdir()
        (tmp_path / "pom.xml").write_text(MAVEN_POM_PARENT)
        (child_a / "pom.xml").write_text(MAVEN_POM_CHILD_A)
        (child_b / "pom.xml").write_text(MAVEN_POM_CHILD_B)

        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.apache.logging.log4j:log4j-core" in names
        assert "com.fasterxml.jackson.core:jackson-databind" in names
        assert "org.springframework:spring-core" in names

    def test_parse_maven_single_module(self, tmp_path):
        """No <modules> section — works exactly as before."""
        (tmp_path / "pom.xml").write_text(MAVEN_POM_BASIC)
        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.apache.logging.log4j:log4j-core" in names

    def test_parse_maven_depth_limit(self, tmp_path):
        """Recursion stops at depth 3 — 4-level nesting returns partial results."""
        # Build 4 levels: root → l1 → l2 → l3 → l4 (l4 should NOT be parsed)
        dirs = [tmp_path]
        module_name = "child"
        for i in range(1, 5):
            d = dirs[-1] / module_name
            d.mkdir()
            dirs.append(d)

        def _pom(module_ref: str | None, dep_artifact: str) -> str:
            modules_block = f"<modules><module>{module_ref}</module></modules>" if module_ref else ""
            return textwrap.dedent(f"""\
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                    <dependencies>
                        <dependency>
                            <groupId>com.example</groupId>
                            <artifactId>{dep_artifact}</artifactId>
                            <version>1.0.0</version>
                        </dependency>
                    </dependencies>
                    {modules_block}
                </project>
            """)

        (dirs[0] / "pom.xml").write_text(_pom(module_name, "level0-dep"))
        (dirs[1] / "pom.xml").write_text(_pom(module_name, "level1-dep"))
        (dirs[2] / "pom.xml").write_text(_pom(module_name, "level2-dep"))
        (dirs[3] / "pom.xml").write_text(_pom(module_name, "level3-dep"))
        (dirs[4] / "pom.xml").write_text(_pom(None, "level4-dep"))

        pkgs = parse_maven_packages(tmp_path)
        names = {p.name for p in pkgs}
        # Levels 0-3 are within depth limit (0,1,2,3), level 4 is excluded
        assert "com.example:level0-dep" in names
        assert "com.example:level1-dep" in names
        assert "com.example:level2-dep" in names
        assert "com.example:level3-dep" in names
        assert "com.example:level4-dep" not in names

    def test_parse_maven_multi_module_deduplicates(self, tmp_path):
        """Same dependency in parent and child appears only once."""
        child_a = tmp_path / "child-a"
        child_a.mkdir()
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent("""\
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>org.apache.logging.log4j</groupId>
                        <artifactId>log4j-core</artifactId>
                        <version>2.14.1</version>
                    </dependency>
                </dependencies>
                <modules><module>child-a</module></modules>
            </project>
        """)
        )
        (child_a / "pom.xml").write_text(
            textwrap.dedent("""\
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>org.apache.logging.log4j</groupId>
                        <artifactId>log4j-core</artifactId>
                        <version>2.14.1</version>
                    </dependency>
                </dependencies>
            </project>
        """)
        )
        pkgs = parse_maven_packages(tmp_path)
        log4j_pkgs = [p for p in pkgs if p.name == "org.apache.logging.log4j:log4j-core"]
        assert len(log4j_pkgs) == 1
