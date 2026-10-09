"""Credential patterns must not fire inside ordinary identifiers.

The OpenAI ``sk-`` prefix occurs inside common words (``task-``, ``risk-``,
``disk-``), so an unanchored pattern turns CSS class names and schema ids into
CRITICAL credential findings. Every prefix-shaped pattern needs a left token
boundary; the OpenAI pattern also needs a plausibility check because real keys
are random alphanumerics, never a lowercase hyphenated slug.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.runtime.patterns import CREDENTIAL_PATTERNS
from agent_bom.secret_scanner import scan_secrets

_PATTERNS = dict(CREDENTIAL_PATTERNS)


def _names_matching(text: str) -> set[str]:
    return {name for name, pattern in CREDENTIAL_PATTERNS if pattern.search(text)}


@pytest.mark.parametrize(
    "text",
    [
        '<div className="task-management-dashboard-panel">',
        '<p className="risk-campaign-evidence-label">',
        '<span className="disk-usage-summary-indicator-bar">',
        'schema_version: "risk-campaign-verification-queue.v1";',
        "const: risk-campaign-verification.v1",
        'import { RiskCampaignCommandCenter } from "@/components/risk-campaign-command-center";',
        # Prefix at a token start, but the body is a lowercase hyphenated slug.
        '<div className="sk-campaign-evidence-label-wrapper">',
        "sk-campaign-verification-queue-summary",
    ],
)
def test_openai_pattern_ignores_identifiers_and_slugs(text: str) -> None:
    assert not _PATTERNS["OpenAI API Key"].search(text)
    assert "OpenAI API Key" not in _names_matching(text)


@pytest.mark.parametrize(
    "text",
    [
        "OPENAI_API_KEY=" + "sk-" + "abcdefghij1234567890abcdefghij1234567890abcd",
        'OPENAI_KEY = "' + "sk-proj-" + 'abc123def456ghi789jkl012mno345pqr678stu"',
        "key: " + "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z_Ab3dEf6hIj9kLm2n-Op5qRs8tUv1wXy4z",
        # Built by concatenation so no committed line looks like a live key.
        '"' + "sk-" + "Qx7Yq2Lm9Pz4" + "Nw8Vr1Kc6Hd5Gs0Bf" + '"',
        "(" + "sk-" + "Qx7Yq2Lm9Pz4" + "Nw8Vr1Kc6Hd5Gs0Bf" + ")",
    ],
)
def test_openai_pattern_still_detects_real_key_shapes(text: str) -> None:
    assert _PATTERNS["OpenAI API Key"].search(text)


def test_anthropic_key_is_not_reported_as_openai() -> None:
    text = "ANTHROPIC_API_KEY=" + "sk-ant-api03-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb3dEf6hIj9k"
    names = [name for name, pattern in CREDENTIAL_PATTERNS if pattern.search(text)]
    assert names[0] == "Anthropic API Key"
    assert "OpenAI API Key" not in names


@pytest.mark.parametrize(
    ("name", "embedded", "standalone"),
    [
        ("AWS Access Key", "X" + "AKIA" + "IOSFODNN7" + "ABCDEFGH", "id=" + "AKIA" + "IOSFODNN7" + "ABCDEFG"),
        ("GitHub Token", "highp_" + "a" * 36, "token=ghp_" + "A1b2C3d4E5" * 4),
        ("GitLab Token", "xglpat-" + "a1B2c3D4e5" + "F6g7H8i9J0", "glpat-" + "a1B2c3D4e5" + "F6g7H8i9J0"),
        ("Anthropic API Key", "task-ant-" + "a1B2c3D4e5" + "F6g7H8i9J0", "sk-ant-" + "a1B2c3D4e5" + "F6g7H8i9J0"),
        ("Slack Token", "foo" + "xoxb-" + "1234567890", "SLACK=" + "xoxb-" + "1234567890"),
        ("Stripe Key", "test_risk_live_" + "a1B2c3D4e5" + "F6g7H8i9J0", "STRIPE=sk_live_" + "a1B2c3D4e5" + "F6g7H8i9J0"),
        ("Google API Key", "XAIza" + "a1B2c3D4e5F6g7H8i9J0a1B2c3D4e5F6g7H", "key=AIza" + "a1B2c3D4e5F6g7H8i9J0a1B2c3D4e5F6g7H"),
        ("Twilio API Key", "ASK" + "0123456789abcdef" * 2, "TWILIO=SK" + "0123456789abcdef" * 2),
        ("Mailgun API Key", "monkey-" + "a1B2c3D4e5F6g7H8" * 2, "MAILGUN=key-" + "a1B2c3D4e5F6g7H8" * 2),
        ("npm Token", "pnpm_" + "a1B2c3D4e5F6" * 3, "//registry.npmjs.org/:_authToken=npm_" + "a1B2c3D4e5F6" * 3),
        ("Databricks Token", "rapidapi" + "0123456789abcdef" * 2, "DATABRICKS_TOKEN=dapi" + "0123456789abcdef" * 2),
    ],
)
def test_prefix_patterns_require_a_left_token_boundary(name: str, embedded: str, standalone: str) -> None:
    pattern = _PATTERNS[name]
    assert not pattern.search(embedded), f"{name} fired inside an identifier: {embedded}"
    assert pattern.search(standalone), f"{name} lost a real standalone credential: {standalone}"


@pytest.mark.parametrize(
    "dsn",
    [
        "ALEMBIC_DATABASE_URL: postgresql://${POSTGRES_USER:-agent_bom}@postgres:5432/agent_bom",
        "DATABASE_URL=postgres://${DB_USER:-app}@db:5432/app",
    ],
)
def test_connection_string_ignores_shell_default_expansion_userinfo(dsn: str) -> None:
    assert not _PATTERNS["Connection String"].search(dsn)


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://app:hunter2secret@db.internal:5432/app",
        "postgresql://${DB_USER}:hunter2secret@db.internal:5432/app",
    ],
)
def test_connection_string_still_detects_literal_password(dsn: str) -> None:
    assert _PATTERNS["Connection String"].search(dsn)


def test_secret_scan_of_ui_component_reports_no_css_class_credentials(tmp_path: Path) -> None:
    (tmp_path / "panel.tsx").write_text(
        "\n".join(
            [
                'import { X } from "@/components/risk-campaign-command-center";',
                "export function Panel() {",
                "  return (",
                '    <div className="task-management-dashboard-panel">',
                '      <p className="risk-campaign-evidence-label">Evidence</p>',
                '      <span className="disk-usage-summary-indicator-bar" />',
                "    </div>",
                "  );",
                "}",
                'const schema = "risk-campaign-verification-queue.v1";',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text(
        'OPENAI_API_KEY = "' + "sk-proj-" + 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z_Ab3dEf6hIj9kLm2n"\n',
        encoding="utf-8",
    )

    result = scan_secrets(tmp_path)

    by_file = {(finding.file_path, finding.secret_type) for finding in result.findings}
    assert not any(path == "panel.tsx" for path, _ in by_file)
    assert ("config.py", "OpenAI API Key") in by_file
