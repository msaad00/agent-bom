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
    md.write_text(
        "# My Skill\n\n"
        "```bash\n"
        "npx -y @modelcontextprotocol/server-filesystem /tmp\n"
        "npx @anthropic/mcp-server-github\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "@modelcontextprotocol/server-filesystem" in names
    assert "@anthropic/mcp-server-github" in names
    for pkg in result.packages:
        assert pkg.ecosystem == "npm"


def test_parse_uvx_commands(tmp_path):
    """Extracts uvx package references."""
    md = tmp_path / "skill.md"
    md.write_text(
        "# Python Skill\n\n"
        "```bash\n"
        "uvx mcp-server-sqlite --db test.db\n"
        "```\n"
    )
    result = parse_skill_file(md)
    assert len(result.packages) >= 1
    assert result.packages[0].name == "mcp-server-sqlite"
    assert result.packages[0].ecosystem == "pypi"


def test_parse_pip_install(tmp_path):
    """Extracts pip install package references."""
    md = tmp_path / "setup.md"
    md.write_text(
        "# Setup\n\n"
        "```bash\n"
        "pip install langchain==0.1.0 openai>=1.0\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "langchain" in names
    assert "openai" in names


def test_parse_npm_install(tmp_path):
    """Extracts npm install package references."""
    md = tmp_path / "setup.md"
    md.write_text(
        "# Setup\n\n"
        "```bash\n"
        "npm install express@4.18.2 lodash\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "express" in names
    assert "lodash" in names


def test_parse_mcp_json_block(tmp_path):
    """Extracts MCP server configs from JSON code blocks."""
    md = tmp_path / "config.md"
    md.write_text(
        '# MCP Config\n\n'
        '```json\n'
        '{\n'
        '  "mcpServers": {\n'
        '    "filesystem": {\n'
        '      "command": "npx",\n'
        '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],\n'
        '      "env": {"API_KEY": "test"}\n'
        '    }\n'
        '  }\n'
        '}\n'
        '```\n'
    )
    result = parse_skill_file(md)
    assert len(result.servers) >= 1
    assert result.servers[0].name == "filesystem"


def test_parse_credential_env_vars(tmp_path):
    """Detects credential env var references, excludes false positives."""
    md = tmp_path / "config.md"
    md.write_text(
        "# Config\n\n"
        "Set OPENAI_API_KEY and ANTHROPIC_API_KEY in your environment.\n"
        "Also set DATABASE_URL and PORT and HOME.\n"
    )
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


def test_discover_cursorrules(tmp_path):
    """Discovers .cursorrules file."""
    (tmp_path / ".cursorrules").write_text("# Cursor rules")
    found = discover_skill_files(tmp_path)
    assert any(p.name == ".cursorrules" for p in found)


# ── scan_skill_files tests ──────────────────────────────────────────────────


def test_scan_deduplicates(tmp_path):
    """scan_skill_files merges and deduplicates across files."""
    content = (
        "```bash\n"
        "npx @modelcontextprotocol/server-filesystem /tmp\n"
        "```\n"
    )
    f1 = tmp_path / "skill1.md"
    f2 = tmp_path / "skill2.md"
    f1.write_text(content)
    f2.write_text(content)
    result = scan_skill_files([f1, f2])
    names = [p.name for p in result.packages]
    assert names.count("@modelcontextprotocol/server-filesystem") == 1


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
    for bad_name in ["AWS", "Bedrock", "Lambda", "EKS", "SageMaker",
                     "Cortex", "Agents", "MCP", "Servers", "Snowpark",
                     "All", "providers"]:
        assert bad_name not in names, f"False positive: '{bad_name}' extracted from comment"


def test_parse_pip_install_extras_with_comment(tmp_path):
    """pip install with extras bracket and comment extracts only the package."""
    md = tmp_path / "setup.md"
    md.write_text(
        "```bash\n"
        "pip install flask[async]  # web framework with async support\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "flask" in names
    assert "web" not in names
    assert "framework" not in names


def test_parse_npm_install_strips_comments(tmp_path):
    """npm install should NOT extract words from inline comments."""
    md = tmp_path / "setup.md"
    md.write_text(
        "```bash\n"
        "npm install express  # web framework for Node.js\n"
        "```\n"
    )
    result = parse_skill_file(md)
    names = [p.name for p in result.packages]
    assert "express" in names
    assert "web" not in names
    assert "framework" not in names
