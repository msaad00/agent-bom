"""Typed policy state and reload synchronization shared by gateway policy lanes."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

from agent_bom.security import sanitize_error, sanitize_text

PolicyT = TypeVar("PolicyT")


@dataclass
class GatewayPolicyState(Generic[PolicyT]):
    policy: PolicyT
    source: str
    load_failed: bool
    last_loaded_at: float | None = None
    last_error: str | None = None
    last_mtime: float | None = None


def _load_policy_file(policy_path: Path) -> dict[str, Any]:
    payload = json.loads(policy_path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("gateway policy file must contain a JSON object")
    return payload


class GatewayPolicyReloader(Generic[PolicyT]):
    def __init__(
        self,
        *,
        state: GatewayPolicyState[PolicyT],
        path: Callable[[], Path | None],
        interval: Callable[[], float],
        load: Callable[[Path], PolicyT],
        logger: logging.Logger,
        log_prefix: str,
        sanitize_log: Callable[[object], str],
        invalidate_on_error: bool = False,
    ) -> None:
        self.state = state
        self.lock = asyncio.Lock()
        self._path = path
        self._interval = interval
        self._load = load
        self._logger = logger
        self._log_prefix = log_prefix
        self._sanitize_log = sanitize_log
        self._invalidate_on_error = invalidate_on_error

    async def reload(self, force: bool = False) -> bool:
        path = self._path()
        if path is None:
            return False
        async with self.lock:
            try:
                mtime = path.stat().st_mtime
                if not force and self.state.last_mtime == mtime:
                    return False
                policy = self._load(path)
            except Exception as exc:  # noqa: BLE001 - retain each lane's configured reload posture
                self.state.last_error = sanitize_error(exc)
                if self._invalidate_on_error:
                    self.state.load_failed = True
                self._logger.warning("%s reload failed for %s: %s", self._log_prefix, path, sanitize_text(self._sanitize_log(exc)))
                return False
            self.state.policy = policy
            self.state.last_loaded_at = time.time()
            self.state.last_error = None
            self.state.last_mtime = mtime
            self.state.load_failed = False
        self._logger.info("%s reloaded from %s", self._log_prefix, path)
        return True

    async def run(self) -> None:
        while True:
            await asyncio.sleep(max(self._interval(), 1))
            await self.reload()
