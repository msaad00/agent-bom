"""JSON and query value types shared by the control-plane client and its mixins."""

from __future__ import annotations

from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
QueryValue: TypeAlias = str | int | float | bool | None
