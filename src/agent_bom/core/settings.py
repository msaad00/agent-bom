"""Typed, validated access to environment settings — the one sanctioned env reader.

``agent_bom.config`` *declares* the documented ``AGENT_BOM_*`` knobs (and
``docs/operations/ENV_VARS.md`` is generated from it); this module is how code
*reads* any environment setting. Outside ``config.py`` and this module, raw
``os.environ.get`` / ``os.getenv`` / ``os.environ[...]`` reads are ratcheted
by ``scripts/check_architecture.py`` (metric ``raw_env_reads``).

Rules every accessor follows:

* **Read at call time.** Nothing is cached, so tests can monkeypatch the
  environment freely and long-running processes see what the process has.
* **Unset and blank are the same.** A variable that is missing, empty, or only
  whitespace yields the caller's default. Values are stripped before parsing.
* **Invalid values fail fast.** With the default ``on_invalid="raise"`` a value
  that cannot be parsed, or falls outside ``minimum``/``maximum``/``choices``,
  raises :class:`SettingError` (a ``ValueError``) naming the variable and the
  accepted values. Server and CLI entry points let it surface as a startup
  error rather than running with a configuration the operator did not ask for.
* **Lenient only where it always was.** ``on_invalid="default"`` exists solely
  for call sites whose historical behavior was to ignore a bad value (for
  example opt-in flags where anything but a truthy word meant "off"). It keeps
  that behavior and logs one warning per variable/value instead of staying
  silent.
* **Errors never echo secrets.** Values of variables whose names look like
  credentials are redacted; other values are truncated and stripped of control
  characters before they appear in an error or log line.
"""

from __future__ import annotations

import logging
import math
import os
import re
from collections.abc import Collection, Iterable
from pathlib import Path
from typing import Literal, overload

logger = logging.getLogger(__name__)

OnInvalid = Literal["raise", "default"]

TRUTHY = frozenset({"1", "true", "yes", "on"})
FALSY = frozenset({"0", "false", "no", "off"})

_SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|_KEY$|DSN|AUTH)", re.IGNORECASE)
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$", re.IGNORECASE)
_DURATION_SECONDS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
_MAX_SHOWN = 64

_warned: set[tuple[str, str]] = set()


class SettingError(ValueError):
    """An environment setting holds a value its reader cannot accept."""

    def __init__(self, name: str, raw: str, expected: str) -> None:
        self.name = name
        self.expected = expected
        super().__init__(f"Invalid value for {name}: {_shown(name, raw)}; expected {expected}")


def _shown(name: str, raw: str) -> str:
    if _SECRET_NAME.search(name):
        return "<redacted>"
    printable = "".join(ch if ch.isprintable() else "?" for ch in raw)
    if len(printable) > _MAX_SHOWN:
        printable = printable[:_MAX_SHOWN] + "..."
    return repr(printable)


def reset_warning_state() -> None:
    """Forget which invalid values were already warned about (tests only)."""
    _warned.clear()


def _invalid(name: str, raw: str, expected: str, on_invalid: OnInvalid, default: object) -> None:
    if on_invalid == "raise":
        raise SettingError(name, raw, expected)
    if (name, raw) not in _warned:
        _warned.add((name, raw))
        logger.warning("Ignoring invalid value for %s: %s; expected %s; using %r", name, _shown(name, raw), expected, default)


@overload
def env_raw(name: str) -> str | None: ...
@overload
def env_raw(name: str, default: str) -> str: ...
def env_raw(name: str, default: str | None = None) -> str | None:
    """The exact, unparsed value (``""`` stays ``""``), else *default*.

    For sites whose semantics must mirror another reader byte-for-byte, such as
    a cloud SDK's own credential resolution. Prefer a typed accessor otherwise.
    """
    return os.environ.get(name, default)


def env_is_set(name: str) -> bool:
    """True when *name* holds a non-blank value."""
    return bool((os.environ.get(name) or "").strip())


def env_opt(name: str) -> str | None:
    """Stripped value, or ``None`` when unset or blank."""
    value = (os.environ.get(name) or "").strip()
    return value or None


def env_str(name: str, default: str = "") -> str:
    """Stripped value, or *default* when unset or blank."""
    return env_opt(name) or default


def env_first(*names: str, default: str = "") -> str:
    """The first non-blank value among *names*, else *default*."""
    for name in names:
        value = env_opt(name)
        if value is not None:
            return value
    return default


def env_bool(name: str, default: bool = False, *, on_invalid: OnInvalid = "raise") -> bool:
    """Accepts 1/true/yes/on and 0/false/no/off, case-insensitively."""
    value = env_opt(name)
    if value is None:
        return default
    normalized = value.lower()
    if normalized in TRUTHY:
        return True
    if normalized in FALSY:
        return False
    _invalid(name, value, "one of 1/true/yes/on or 0/false/no/off", on_invalid, default)
    return default


def env_flag(name: str) -> bool:
    """Opt-in switch: only 1/true/yes/on enable it; anything else leaves it off.

    Unrecognized values keep the historical "off" result but are warned about.
    """
    return env_bool(name, False, on_invalid="default")


def _in_range(value: float, minimum: float | None, maximum: float | None) -> bool:
    return (minimum is None or value >= minimum) and (maximum is None or value <= maximum)


def _range_text(kind: str, minimum: float | None, maximum: float | None) -> str:
    if minimum is not None and maximum is not None:
        return f"{kind} between {minimum:g} and {maximum:g}"
    if minimum is not None:
        return f"{kind} >= {minimum:g}"
    if maximum is not None:
        return f"{kind} <= {maximum:g}"
    return kind


def env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    on_invalid: OnInvalid = "raise",
) -> int:
    """Base-10 integer, optionally bounded (inclusive)."""
    value = env_opt(name)
    if value is None:
        return default
    expected = _range_text("an integer", minimum, maximum)
    try:
        parsed = int(value)
    except ValueError:
        _invalid(name, value, expected, on_invalid, default)
        return default
    if not _in_range(parsed, minimum, maximum):
        _invalid(name, value, expected, on_invalid, default)
        return default
    return parsed


def env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    on_invalid: OnInvalid = "raise",
) -> float:
    """Finite float, optionally bounded (inclusive)."""
    value = env_opt(name)
    if value is None:
        return default
    expected = _range_text("a finite number", minimum, maximum)
    try:
        parsed = float(value)
    except ValueError:
        _invalid(name, value, expected, on_invalid, default)
        return default
    if not math.isfinite(parsed) or not _in_range(parsed, minimum, maximum):
        _invalid(name, value, expected, on_invalid, default)
        return default
    return parsed


def env_duration(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    on_invalid: OnInvalid = "raise",
) -> float:
    """Duration in seconds: a bare number means seconds; ms/s/m/h/d suffixes accepted."""
    value = env_opt(name)
    if value is None:
        return default
    expected = _range_text("a duration such as 30, 30s, 5m, 2h or 1d (seconds)", minimum, maximum)
    match = _DURATION.match(value)
    if not match:
        _invalid(name, value, expected, on_invalid, default)
        return default
    seconds = float(match.group(1)) * _DURATION_SECONDS[(match.group(2) or "s").lower()]
    if not _in_range(seconds, minimum, maximum):
        _invalid(name, value, expected, on_invalid, default)
        return default
    return seconds


def env_enum(name: str, default: str, choices: Collection[str], *, on_invalid: OnInvalid = "raise") -> str:
    """Case-insensitive choice from *choices* (compared lower-cased)."""
    value = env_opt(name)
    if value is None:
        return default
    normalized = value.lower()
    if normalized in choices:
        return normalized
    _invalid(name, value, "one of " + ", ".join(sorted(choices)), on_invalid, default)
    return default


def env_list(name: str, default: Iterable[str] = (), *, sep: str = ",") -> tuple[str, ...]:
    """Split on *sep*, strip each item, drop blanks; *default* when unset or blank."""
    value = env_opt(name)
    if value is None:
        return tuple(default)
    return tuple(item.strip() for item in value.split(sep) if item.strip())


def env_path(name: str, default: Path | None = None) -> Path | None:
    """User-expanded path, or *default* when unset or blank."""
    value = env_opt(name)
    if value is None:
        return default
    return Path(value).expanduser()
