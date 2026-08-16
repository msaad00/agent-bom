from __future__ import annotations

from types import SimpleNamespace

import click
import pytest
from rich.console import Console

from agent_bom.cli.agents import _output


def test_configured_iceberg_publication_fails_closed_with_recovery(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_bom.output.iceberg_catalog.maybe_register_iceberg",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("token=secret-value host=/private/catalog")),
    )

    with pytest.raises(click.ClickException) as exc_info:
        _output._register_iceberg_if_configured(
            SimpleNamespace(),
            [],
            Console(file=None),
            quiet=False,
        )

    message = exc_info.value.format_message()
    assert "Iceberg snapshot publication failed" in message
    assert "Parquet file was written" in message
    assert "token=secret-value" not in message
    assert "/private/catalog" not in message
