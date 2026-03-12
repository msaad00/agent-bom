"""Tests for Gradle and conda package parsers.

Covers:
- parse_gradle_packages: build.gradle (Groovy), build.gradle.kts (Kotlin),
  gradle/libs.versions.toml, gradle.lockfile
- parse_conda_packages: environment.yml, conda-lock.yml, channel stripping,
  pip sub-section, platform deduplication
"""

from __future__ import annotations

import textwrap

import pytest

from agent_bom.parsers import parse_conda_packages, parse_gradle_packages

# ── Gradle fixtures ──────────────────────────────────────────────────────────

GRADLE_GROOVY = textwrap.dedent("""\
    plugins {
        id 'java'
    }

    dependencies {
        implementation 'org.springframework.boot:spring-boot-starter:3.1.0'
        implementation 'com.google.guava:guava:32.1.3-jre'
        runtimeOnly 'com.h2database:h2:2.1.214'
        testImplementation 'junit:junit:4.13.2'
    }
""")

GRADLE_KOTLIN = textwrap.dedent("""\
    plugins {
        kotlin("jvm") version "1.9.0"
    }

    dependencies {
        implementation("org.springframework.boot:spring-boot-starter:3.1.0")
        implementation("com.google.guava:guava:32.1.3-jre")
        api("io.grpc:grpc-kotlin-stub:1.4.0")
        testImplementation("junit:junit:4.13.2")
    }
""")

GRADLE_VERSION_CATALOG = textwrap.dedent("""\
    [versions]
    kotlin = "1.9.0"
    coroutines = "1.7.3"
    springboot = "3.1.0"

    [libraries]
    kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
    coroutines-core = { group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-core", version.ref = "coroutines" }
    spring-starter = { module = "org.springframework.boot:spring-boot-starter", version.ref = "springboot" }
    guava = { module = "com.google.guava:guava", version = "32.1.3-jre" }

    [plugins]
    kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
""")

GRADLE_LOCKFILE = textwrap.dedent("""\
    # This is a Gradle generated file for dependency locking.
    # Manual edits can break the build and are not advised.
    # This file is expected to be part of source control.
    org.springframework.boot:spring-boot:3.1.0=compileClasspath,runtimeClasspath
    com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath
    org.slf4j:slf4j-api:2.0.7=compileClasspath,runtimeClasspath
    empty=
""")


# ── parse_gradle_packages tests ───────────────────────────────────────────────


class TestParseGradleGroovy:
    def test_parse_gradle_groovy_implementation(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.springframework.boot:spring-boot-starter" in names
        assert "com.google.guava:guava" in names

    def test_parse_gradle_groovy_version_correct(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["org.springframework.boot:spring-boot-starter"].version == "3.1.0"
        assert pkgs["com.google.guava:guava"].version == "32.1.3-jre"

    def test_parse_gradle_skips_test_deps(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert "junit:junit" in pkgs
        assert pkgs["junit:junit"].is_direct is False

    def test_parse_gradle_runtime_only_is_direct(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["com.h2database:h2"].is_direct is True


class TestParseGradleKotlin:
    def test_parse_gradle_kotlin_implementation(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(GRADLE_KOTLIN)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.springframework.boot:spring-boot-starter" in names
        assert "io.grpc:grpc-kotlin-stub" in names

    def test_parse_gradle_kotlin_version_correct(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(GRADLE_KOTLIN)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["io.grpc:grpc-kotlin-stub"].version == "1.4.0"

    def test_parse_gradle_kotlin_test_not_direct(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(GRADLE_KOTLIN)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["junit:junit"].is_direct is False


class TestParseGradleVersionCatalog:
    def test_parse_gradle_version_catalog(self, tmp_path):
        gradle_dir = tmp_path / "gradle"
        gradle_dir.mkdir()
        (gradle_dir / "libs.versions.toml").write_text(GRADLE_VERSION_CATALOG)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.jetbrains.kotlin:kotlin-stdlib" in names
        assert "org.jetbrains.kotlinx:kotlinx-coroutines-core" in names
        assert "org.springframework.boot:spring-boot-starter" in names
        assert "com.google.guava:guava" in names

    def test_parse_gradle_version_catalog_resolves_refs(self, tmp_path):
        gradle_dir = tmp_path / "gradle"
        gradle_dir.mkdir()
        (gradle_dir / "libs.versions.toml").write_text(GRADLE_VERSION_CATALOG)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["org.jetbrains.kotlin:kotlin-stdlib"].version == "1.9.0"
        assert pkgs["org.jetbrains.kotlinx:kotlinx-coroutines-core"].version == "1.7.3"
        assert pkgs["com.google.guava:guava"].version == "32.1.3-jre"

    def test_parse_gradle_version_catalog_group_name_form(self, tmp_path):
        gradle_dir = tmp_path / "gradle"
        gradle_dir.mkdir()
        (gradle_dir / "libs.versions.toml").write_text(GRADLE_VERSION_CATALOG)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        # coroutines-core uses group/name form
        assert "org.jetbrains.kotlinx:kotlinx-coroutines-core" in pkgs


class TestParseGradleLockfile:
    def test_parse_gradle_lockfile(self, tmp_path):
        (tmp_path / "gradle.lockfile").write_text(GRADLE_LOCKFILE)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "org.springframework.boot:spring-boot" in names
        assert "com.google.guava:guava" in names
        assert "org.slf4j:slf4j-api" in names

    def test_parse_gradle_lockfile_version_correct(self, tmp_path):
        (tmp_path / "gradle.lockfile").write_text(GRADLE_LOCKFILE)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        assert pkgs["org.springframework.boot:spring-boot"].version == "3.1.0"

    def test_parse_gradle_lockfile_ignores_empty_line(self, tmp_path):
        (tmp_path / "gradle.lockfile").write_text(GRADLE_LOCKFILE)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        # "empty=" line must not produce a package
        assert "" not in names
        assert any("empty" in n for n in names) is False

    def test_parse_gradle_multiple_configs_lockfile_wins(self, tmp_path):
        """When both build.gradle and gradle.lockfile exist, lockfile wins."""
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        (tmp_path / "gradle.lockfile").write_text(GRADLE_LOCKFILE)
        pkgs = parse_gradle_packages(tmp_path)
        names = {p.name for p in pkgs}
        # lockfile has spring-boot (not spring-boot-starter); DSL has spring-boot-starter
        # lockfile should be canonical
        assert "org.springframework.boot:spring-boot" in names


class TestParseGradlePurlAndEcosystem:
    def test_parse_gradle_purl_format(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = {p.name: p for p in parse_gradle_packages(tmp_path)}
        p = pkgs["com.google.guava:guava"]
        assert p.purl == "pkg:maven/com.google.guava/guava@32.1.3-jre"

    def test_parse_gradle_ecosystem_is_maven(self, tmp_path):
        (tmp_path / "build.gradle").write_text(GRADLE_GROOVY)
        pkgs = parse_gradle_packages(tmp_path)
        assert all(p.ecosystem == "maven" for p in pkgs)

    def test_parse_gradle_no_files(self, tmp_path):
        assert parse_gradle_packages(tmp_path) == []


# ── conda fixtures ────────────────────────────────────────────────────────────

CONDA_ENV_BASIC = textwrap.dedent("""\
    name: ml-env
    channels:
      - conda-forge
      - defaults
    dependencies:
      - python=3.11
      - numpy=1.24.0
      - scipy=1.11.0
      - cudatoolkit=11.8
""")

CONDA_ENV_WITH_PIP = textwrap.dedent("""\
    name: ml-env
    channels:
      - conda-forge
      - nvidia
    dependencies:
      - python=3.11
      - numpy=1.24.0
      - pip:
        - transformers==4.35.0
        - langchain>=0.1.0
        - accelerate==0.24.1
""")

CONDA_ENV_CHANNEL_PREFIX = textwrap.dedent("""\
    name: pytorch-env
    channels:
      - pytorch
      - conda-forge
    dependencies:
      - python=3.11
      - pytorch::pytorch=2.1.0
      - pytorch::torchvision=0.16.0
      - numpy=1.24.0
""")

CONDA_LOCK_YML = textwrap.dedent("""\
    version: 1
    metadata:
      content_hash:
        linux-64: abc123
        osx-arm64: def456
    package:
    - name: numpy
      version: 1.24.0
      manager: conda
      platform: linux-64
      url: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.24.0-py311h.conda
      hash:
        sha256: aabbcc
    - name: numpy
      version: 1.24.0
      manager: conda
      platform: osx-arm64
      url: https://conda.anaconda.org/conda-forge/osx-arm64/numpy-1.24.0-py311h.conda
      hash:
        sha256: ddeeff
    - name: scipy
      version: 1.11.0
      manager: conda
      platform: linux-64
      url: https://conda.anaconda.org/conda-forge/linux-64/scipy-1.11.0.conda
      hash:
        sha256: 112233
    - name: requests
      version: 2.31.0
      manager: pip
      platform: linux-64
      url: https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz
      hash:
        sha256: 445566
""")


# ── parse_conda_packages tests ────────────────────────────────────────────────


class TestParseCondaEnvBasic:
    def test_parse_conda_env_yml_basic(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_BASIC)
        pkgs = parse_conda_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "python" in names
        assert "numpy" in names
        assert "cudatoolkit" in names

    def test_parse_conda_env_yml_version(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_BASIC)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["numpy"].version == "1.24.0"
        assert pkgs["python"].version == "3.11"

    def test_parse_conda_env_yml_ecosystem(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_BASIC)
        pkgs = parse_conda_packages(tmp_path)
        conda_pkgs = [p for p in pkgs if p.ecosystem == "conda"]
        assert len(conda_pkgs) > 0
        assert all(p.ecosystem == "conda" for p in conda_pkgs)

    def test_parse_conda_env_yaml_extension(self, tmp_path):
        """Both .yml and .yaml extensions are detected."""
        (tmp_path / "environment.yaml").write_text(CONDA_ENV_BASIC)
        pkgs = parse_conda_packages(tmp_path)
        assert len(pkgs) > 0


class TestParseCondaEnvPipSection:
    def test_parse_conda_env_pip_section(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_WITH_PIP)
        pkgs = parse_conda_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "transformers" in names
        assert "langchain" in names
        assert "accelerate" in names

    def test_parse_conda_pip_ecosystem_is_pypi(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_WITH_PIP)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["transformers"].ecosystem == "pypi"
        assert pkgs["langchain"].ecosystem == "pypi"

    def test_parse_conda_pip_exact_version(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_WITH_PIP)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["transformers"].version == "4.35.0"
        assert pkgs["accelerate"].version == "0.24.1"

    def test_parse_conda_pip_range_version(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_WITH_PIP)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        # langchain>=0.1.0 → stored as specifier string
        assert "0.1.0" in pkgs["langchain"].version


class TestParseCondaChannelPrefix:
    def test_parse_conda_channel_prefix(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_CHANNEL_PREFIX)
        pkgs = parse_conda_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "pytorch" in names
        assert "torchvision" in names

    def test_parse_conda_channel_stripped_from_name(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_CHANNEL_PREFIX)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        # Name must NOT contain channel prefix
        assert "pytorch::pytorch" not in pkgs
        assert "pytorch" in pkgs

    def test_parse_conda_channel_version_correct(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_CHANNEL_PREFIX)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["pytorch"].version == "2.1.0"
        assert pkgs["torchvision"].version == "0.16.0"


class TestParseCondaLockFile:
    def test_parse_conda_lock_yml(self, tmp_path):
        pytest.importorskip("yaml", reason="PyYAML required for conda-lock.yml parsing")
        (tmp_path / "conda-lock.yml").write_text(CONDA_LOCK_YML)
        pkgs = parse_conda_packages(tmp_path)
        names = {p.name for p in pkgs}
        assert "numpy" in names
        assert "scipy" in names
        assert "requests" in names

    def test_parse_conda_lock_deduplicates_platforms(self, tmp_path):
        """Same package for linux-64 and osx-arm64 should appear only once."""
        pytest.importorskip("yaml", reason="PyYAML required for conda-lock.yml parsing")
        (tmp_path / "conda-lock.yml").write_text(CONDA_LOCK_YML)
        pkgs = parse_conda_packages(tmp_path)
        numpy_pkgs = [p for p in pkgs if p.name == "numpy"]
        assert len(numpy_pkgs) == 1

    def test_parse_conda_lock_manager_determines_ecosystem(self, tmp_path):
        pytest.importorskip("yaml", reason="PyYAML required for conda-lock.yml parsing")
        (tmp_path / "conda-lock.yml").write_text(CONDA_LOCK_YML)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["numpy"].ecosystem == "conda"
        assert pkgs["scipy"].ecosystem == "conda"
        assert pkgs["requests"].ecosystem == "pypi"

    def test_parse_conda_lock_version(self, tmp_path):
        pytest.importorskip("yaml", reason="PyYAML required for conda-lock.yml parsing")
        (tmp_path / "conda-lock.yml").write_text(CONDA_LOCK_YML)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["numpy"].version == "1.24.0"
        assert pkgs["requests"].version == "2.31.0"


class TestParseCondaPurlAndMisc:
    def test_parse_conda_purl_format(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_BASIC)
        pkgs = {p.name: p for p in parse_conda_packages(tmp_path)}
        assert pkgs["numpy"].purl == "pkg:conda/numpy@1.24.0"

    def test_parse_conda_no_files(self, tmp_path):
        assert parse_conda_packages(tmp_path) == []

    def test_parse_conda_all_direct(self, tmp_path):
        (tmp_path / "environment.yml").write_text(CONDA_ENV_BASIC)
        pkgs = parse_conda_packages(tmp_path)
        assert all(p.is_direct for p in pkgs)
