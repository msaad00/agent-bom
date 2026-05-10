from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_snowflake_backend_parity_doc_names_current_boundaries_and_modes() -> None:
    body = (ROOT / "site-docs" / "deployment" / "backend-parity.md").read_text()

    for required in (
        "Snowflake control-plane parity plan",
        "Source registry | Not implemented",
        "Trend and baseline state | Not implemented",
        "API keys / RBAC | Not implemented",
        "Snowflake Native App / security-lake mode",
        "Postgres / Supabase remains the recommended backend",
    ):
        assert required in body
