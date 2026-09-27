"""Compose cloud guidance and authenticated endpoint onboarding under connect."""

import click

from agent_bom.cli._endpoint_connectors import endpoints_group
from agent_bom.cli._entry_points import connect_group, make_up_command


def register_frontdoor(main: click.Group, serve: click.Command) -> None:
    connect_group.add_command(endpoints_group)
    main.add_command(connect_group, "connect")
    main.add_command(make_up_command(serve), "up")
