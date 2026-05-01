"""Tests for skill/instruction file parser."""

from __future__ import annotations

from agent_bom.parsers.skills import (
    discover_skill_files,
    parse_skill_file,
    scan_skill_files,
)

# ── parse_skill_file tests ──────────────────────────────────────────────────


def test_parse_npx_commands(tmp_path):
    """Extracts npx package references from code blocks."""
    md = tmp_path / "skill.md"
    md.write_text("# My Skill\n\n```bash\nnpx -y @modelcontextprotocol/server-filesystem /tmp\nnpx @anthropic/mcp-server-github\n```\n")
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "@modelcontextprotocol/server-filesystem" in names
    assert "@anthropic/mcp-server-github" in names
    for pkg in result.packages:
        assert pkg.ecosystem == "npm"


def test_parse_uvx_commands(tmp_path):
    """Extracts uvx package references."""
    md = tmp_path / "skill.md"
    md.write_text("# Python Skill\n\n```bash\nuvx mcp-server-sqlite --db test.db\n```\n")
    result = parse_skill_file(md)
    assert len(result.packages) >= 1
    assert result.packages[0].name == "mcp-server-sqlite"
    assert result.packages[0].ecosystem == "pypi"


def test_parse_pip_install(tmp_path):
    """Extracts pip install package references."""
    md = tmp_path / "setup.md"
    md.write_text("# Setup\n\n```bash\npip install langchain==0.1.0 openai>=1.0\n```\n")
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "langchain" in names
    assert "openai" in names


def test_parse_npm_install(tmp_path):
    """Extracts npm install package references."""
    md = tmp_path / "setup.md"
    md.write_text("# Setup\n\n```bash\nnpm install express@4.18.2 lodash\n```\n")
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "express" in names
    assert "lodash" in names


def test_parse_mcp_json_block(tmp_path):
    """Extracts MCP server configs from JSON code blocks."""
    md = tmp_path / "config.md"
    md.write_text(
        "# MCP Config\n\n"
        "```json\n"
        "{\n"
        '  "mcpServers": {\n'
        '    "filesystem": {\n'
        '      "command": "npx",\n'
        '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],\n'
        '      "env": {"API_KEY": "test"}\n'
        "    }\n"
        "  }\n"
        "}\n"
        "```\n"
    )
    result = parse_skill_file(md)
    assert len(result.servers) >= 1
    assert result.servers[0].name == "filesystem"


def test_parse_credential_env_vars(tmp_path):
    """Detects credential env var references, excludes false positives."""
    md = tmp_path / "config.md"
    md.write_text("# Config\n\nSet OPENAI_API_KEY and ANTHROPIC_API_KEY in your environment.\nAlso set DATABASE_URL and PORT and HOME.\n")
    result = parse_skill_file(md)
    creds = result.credential_env_vars
    assert "OPENAI_API_KEY" in creds
    assert "ANTHROPIC_API_KEY" in creds
    # False positives should be excluded
    assert "PORT" not in creds
    assert "HOME" not in creds


def test_parse_empty_file(tmp_path):
    """Empty file returns empty result."""
    md = tmp_path / "empty.md"
    md.write_text("")
    result = parse_skill_file(md)
    assert result.packages == []
    assert result.servers == []
    assert result.credential_env_vars == []


# ── discover_skill_files tests ──────────────────────────────────────────────


def test_discover_claude_md(tmp_path):
    """Discovers CLAUDE.md in project directory."""
    (tmp_path / "CLAUDE.md").write_text("# Claude instructions")
    found = discover_skill_files(tmp_path)
    assert any(p.name == "CLAUDE.md" for p in found)


def test_discover_skills_directory(tmp_path):
    """Discovers .md files inside skills/ directory."""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "my-skill.md").write_text("# My Skill")
    found = discover_skill_files(tmp_path)
    assert any(p.name == "my-skill.md" for p in found)


def test_discover_nested_skill_md_and_cursor_mdc(tmp_path):
    """Discovers common nested skill layouts and Cursor .mdc rule files."""
    nested_skill = tmp_path / "skills" / "review" / "SKILL.md"
    cursor_rule = tmp_path / ".cursor" / "rules" / "secure-coding.mdc"
    nested_skill.parent.mkdir(parents=True)
    cursor_rule.parent.mkdir(parents=True)
    nested_skill.write_text("# Review skill")
    cursor_rule.write_text("# Cursor rule")

    found = discover_skill_files(tmp_path)
    assert nested_skill in found
    assert cursor_rule in found


def test_discover_cursorrules(tmp_path):
    """Discovers .cursorrules file."""
    (tmp_path / ".cursorrules").write_text("# Cursor rules")
    found = discover_skill_files(tmp_path)
    assert any(p.name == ".cursorrules" for p in found)


# ── scan_skill_files tests ──────────────────────────────────────────────────


def test_scan_deduplicates(tmp_path):
    """scan_skill_files merges and deduplicates across files."""
    content = "```bash\nnpx @modelcontextprotocol/server-filesystem /tmp\n```\n"
    f1 = tmp_path / "skill1.md"
    f2 = tmp_path / "skill2.md"
    f1.write_text(content)
    f2.write_text(content)
    result = scan_skill_files([f1, f2])
    names = [p.name for p in result.packages]
    assert names.count("@modelcontextprotocol/server-filesystem") == 1


def test_explicit_directory_discovery_ignores_generic_markdown(tmp_path):
    """Explicit directory scans should not treat arbitrary repo docs as skill files."""
    (tmp_path / "README.md").write_text("# Generic doc\n")
    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    (github_dir / "PULL_REQUEST_TEMPLATE.md").write_text("# PR template\n")

    skills_dir = tmp_path / "skills"
    skills_dir.mkdir(parents=True)
    (skills_dir / "review.md").write_text("# Skill review\n")
    (tmp_path / "CLAUDE.md").write_text("# Project instructions\n")

    from agent_bom.skills_service import resolve_skill_targets

    resolved = resolve_skill_targets([tmp_path], cwd=tmp_path)
    names = sorted(path.name for path in resolved)

    assert "CLAUDE.md" in names
    assert "review.md" in names
    assert "README.md" not in names
    assert "PULL_REQUEST_TEMPLATE.md" not in names


def test_explicit_directory_discovery_skips_docs_skills_examples(tmp_path):
    docs_skill = tmp_path / "docs" / "skills" / "review.md"
    docs_skill.parent.mkdir(parents=True)
    docs_skill.write_text("# Example skill doc\n")

    from agent_bom.skills_service import resolve_skill_targets

    resolved = resolve_skill_targets([tmp_path], cwd=tmp_path)

    assert docs_skill.resolve() not in resolved


def test_explicit_directory_discovery_skips_virtualenv_and_node_modules(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# Project instructions\n")
    venv_skill = tmp_path / ".venv" / "lib" / "python3.13" / "site-packages" / "pkg" / "skills" / "tool.md"
    node_skill = tmp_path / "ui" / "node_modules" / "pkg" / "AGENTS.md"
    venv_skill.parent.mkdir(parents=True)
    node_skill.parent.mkdir(parents=True)
    venv_skill.write_text("# Third-party skill\n")
    node_skill.write_text("# Third-party agent\n")

    from agent_bom.skills_service import resolve_skill_targets

    resolved = resolve_skill_targets([tmp_path], cwd=tmp_path)
    names = sorted(path.name for path in resolved)

    assert "CLAUDE.md" in names
    assert "tool.md" not in names
    assert "AGENTS.md" not in names


def test_parse_preserves_raw_content(tmp_path):
    """parse_skill_file stores raw text in raw_content dict."""
    md = tmp_path / "CLAUDE.md"
    md.write_text("# My Instructions\nDo not use 0.0.0.0\n")
    from agent_bom.parsers.skills import parse_skill_file

    result = parse_skill_file(md)
    assert str(md) in result.raw_content
    assert "Do not use 0.0.0.0" in result.raw_content[str(md)]


def test_scan_merges_raw_content(tmp_path):
    """scan_skill_files merges raw_content from all files."""
    f1 = tmp_path / "CLAUDE.md"
    f2 = tmp_path / "skill.md"
    f1.write_text("# Claude\nInstructions here")
    f2.write_text("# Skill\nMore instructions")
    from agent_bom.parsers.skills import scan_skill_files

    result = scan_skill_files([f1, f2])
    assert len(result.raw_content) == 2
    assert str(f1) in result.raw_content
    assert str(f2) in result.raw_content


def test_raw_content_truncated(tmp_path):
    """Very large files are truncated to 8000 chars in raw_content."""
    md = tmp_path / "huge.md"
    md.write_text("x" * 20000)
    from agent_bom.parsers.skills import parse_skill_file

    result = parse_skill_file(md)
    assert len(result.raw_content[str(md)]) == 8000


# ── Comment-stripping tests ──────────────────────────────────────────────


def test_parse_pip_install_strips_comments(tmp_path):
    """pip install should NOT extract words from inline comments."""
    md = tmp_path / "setup.md"
    md.write_text(
        "# Setup\n\n"
        "```bash\n"
        "pip install 'agent-bom[aws]'       # AWS Bedrock, Lambda, EKS, SageMaker\n"
        "pip install 'agent-bom[snowflake]'  # Cortex Agents, MCP Servers, Snowpark\n"
        "pip install 'agent-bom[cloud]'      # All providers\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    # Should only extract agent-bom (once, deduplicated)
    assert "agent-bom" in names
    # Comment words should NOT be extracted as packages
    for bad_name in ["AWS", "Bedrock", "Lambda", "EKS", "SageMaker", "Cortex", "Agents", "MCP", "Servers", "Snowpark", "All", "providers"]:
        assert bad_name not in names, f"False positive: '{bad_name}' extracted from comment"


def test_parse_pip_install_extras_with_comment(tmp_path):
    """pip install with extras bracket and comment extracts only the package."""
    md = tmp_path / "setup.md"
    md.write_text("```bash\npip install flask[async]  # web framework with async support\n```\n")
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "flask" in names
    assert "web" not in names
    assert "framework" not in names


def test_parse_npm_install_strips_comments(tmp_path):
    """npm install should NOT extract words from inline comments."""
    md = tmp_path / "setup.md"
    md.write_text("```bash\nnpm install express  # web framework for Node.js\n```\n")
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "express" in names
    assert "web" not in names
    assert "framework" not in names


# ── Frontmatter parsing tests ──────────────────────────────────────────────


def test_parse_frontmatter_full(tmp_path):
    """Parses YAML frontmatter with all metadata fields."""
    md = tmp_path / "SKILL.md"
    md.write_text(
        "---\n"
        "name: my-tool\n"
        "description: A security scanner\n"
        "version: 1.2.3\n"
        "metadata:\n"
        "  openclaw:\n"
        "    requires:\n"
        "      bins:\n"
        "        - my-tool\n"
        "    optional_bins:\n"
        "      - docker\n"
        "      - grype\n"
        "    homepage: https://github.com/example/my-tool\n"
        "    source: https://github.com/example/my-tool\n"
        "    license: MIT\n"
        "    os:\n"
        "      - darwin\n"
        "      - linux\n"
        "    install:\n"
        "      - kind: uv\n"
        "        package: my-tool\n"
        "      - kind: pip\n"
        "        package: my-tool\n"
        "---\n\n"
        "# My Tool\n\nDoes stuff.\n"
    )
    result = parse_skill_file(md)
    meta = result.metadata
    assert meta is not None
    assert meta.name == "my-tool"
    assert meta.description == "A security scanner"
    assert meta.version == "1.2.3"
    assert meta.homepage == "https://github.com/example/my-tool"
    assert meta.source == "https://github.com/example/my-tool"
    assert meta.license == "MIT"
    assert "my-tool" in meta.required_bins
    assert "docker" in meta.optional_bins
    assert "grype" in meta.optional_bins
    assert "uv" in meta.install_methods
    assert "pip" in meta.install_methods
    assert "darwin" in meta.os_support
    assert "linux" in meta.os_support


def test_parse_no_frontmatter(tmp_path):
    """Files without frontmatter have metadata=None."""
    md = tmp_path / "CLAUDE.md"
    md.write_text("# Claude Instructions\n\nDo stuff.\n")
    result = parse_skill_file(md)
    assert result.metadata is None


def test_parse_frontmatter_minimal(tmp_path):
    """Minimal frontmatter with just name and version."""
    md = tmp_path / "SKILL.md"
    md.write_text("---\nname: bare-tool\nversion: 0.1.0\n---\n\n# Bare Tool\n")
    result = parse_skill_file(md)
    meta = result.metadata
    assert meta is not None
    assert meta.name == "bare-tool"
    assert meta.version == "0.1.0"
    assert meta.homepage == ""
    assert meta.source == ""
    assert meta.license == ""
    assert meta.required_bins == []
    assert meta.optional_bins == []


def test_scan_skill_files_merges_metadata(tmp_path):
    """scan_skill_files keeps the first valid metadata."""
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: tool-a\nversion: 1.0.0\n---\n\n# Tool A\n")
    claude = tmp_path / "CLAUDE.md"
    claude.write_text("# Claude\nJust instructions.\n")

    result = scan_skill_files([skill, claude])
    assert result.metadata is not None
    assert result.metadata.name == "tool-a"
