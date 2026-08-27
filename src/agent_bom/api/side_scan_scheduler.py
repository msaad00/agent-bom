"""Scheduler auto-trigger for the cross-cloud (Azure/GCP) side-scan (#4158 Stage 4).

Wave 1+2 shipped the ``run_provider_side_scan`` executor plus the on-demand
surfaces (CLI ``cloud side-scan``, ``POST /v1/cloud/side-scan``, MCP
``cloud_side_scan``, UI ``/cwpp``). This module closes the last surface-alignment
gap — the *scheduler* leg of "scheduler/API/CLI/MCP/UI/graph/export alignment":
a periodic background trigger so a configured target keeps evaluating on a
cadence, exactly like the sibling cloud-connection and findings-export
schedulers.

Design (deliberately thin — reuse, do not build a new subsystem):

* **Opt-in, off by default, two gates.** The loop starts only when
  ``AGENT_BOM_SIDESCAN_SCHEDULER`` is truthy (read live), and each run still
  passes through the executor's own ``AGENT_BOM_SIDESCAN`` gate. A scheduled
  snapshot side-scan is the one deliberate non-read-only capability, so it never
  runs without explicit enablement — never a surprise cloud write.
* **Off the event loop.** ``run_provider_side_scan`` drives a blocking snapshot
  lifecycle (``time.sleep``); each target runs in a worker thread under a
  concurrency semaphore, mirroring how the HTTP route offloads it.
* **Shared durable lifecycle store.** The scheduled path pre-creates the same
  deterministic execution identity and reads back the same selected
  :class:`SideScanStateStore` record the CLI/API/UI read, so terminal
  state is consistent across every surface — no false clean.
* **Honest, fail-soft.** Disabled / unavailable / failed states stay explicit
  per target, and one failing target never sinks the others or the loop.
* **``credentialed_smoke`` unchanged.** No live-cloud claim is introduced;
  credentials are still resolved by the executor from the provider default chain.

Targets are supplied out of band (there is no side-scan target store yet) via
``AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS`` — a path to a JSON file, or inline JSON.
Each entry mirrors the on-demand request body.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bom.config import SIDESCAN_SCHEDULER_MAX_CONCURRENCY, SIDESCAN_SCHEDULER_POLL_SECONDS

logger = logging.getLogger(__name__)

# Only the two cross-cloud providers the shipped executor handles. AWS EBS keeps
# its own entry point (``run_side_scan``) and is out of scope for this trigger.
_SCHEDULABLE_PROVIDERS: frozenset[str] = frozenset({"azure", "gcp"})

_TARGETS_ENV = "AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS"
_ENABLE_ENV = "AGENT_BOM_SIDESCAN_SCHEDULER"


@dataclass(frozen=True)
class ScheduledSideScanTarget:
    """A configured Azure/GCP side-scan target the scheduler re-runs on a cadence."""

    provider: str
    target_id: str
    account_id: str
    location: str
    collector_id: str
    tenant_id: str
    collector_resource_group: str | None = None
    region: str | None = None
    scan_secrets_enabled: bool = True
    idempotency_key: str | None = None

    def run_kwargs(self, *, idempotency_key: str) -> dict[str, Any]:
        """Map the target onto ``run_provider_side_scan`` keyword arguments."""
        return {
            "provider": self.provider,
            "target_id": self.target_id,
            "account_id": self.account_id,
            "location": self.location,
            "collector_id": self.collector_id,
            "tenant_id": self.tenant_id,
            "idempotency_key": idempotency_key,
            "collector_resource_group": self.collector_resource_group,
            "region": self.region,
            "scan_secrets_enabled": self.scan_secrets_enabled,
        }


def sidescan_scheduler_enabled() -> bool:
    """Return whether the cross-cloud side-scan scheduler loop is enabled.

    Read live (not import-time) so tests and operators can toggle it. Default OFF
    so the loop never runs in CLI/dev — only when an operator opts in on the
    control plane. A managed trial can never run this non-read-only capability.
    """
    from agent_bom.api.managed_trial import managed_trial_enabled

    if managed_trial_enabled():
        return False
    raw = os.environ.get(_ENABLE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _coerce_target(raw: Any) -> ScheduledSideScanTarget | None:
    """Build one validated target from a config entry, or None when unusable.

    Fail-soft: an entry with an unsupported provider, a missing required field,
    or (for Azure) no collector resource group is skipped with a warning rather
    than aborting the whole config — a scheduled cloud write must be fully
    specified or not attempted.
    """
    if not isinstance(raw, dict):
        logger.warning("Skipping side-scan scheduler target: not an object")
        return None
    provider = str(raw.get("provider") or "").strip().lower()
    if provider not in _SCHEDULABLE_PROVIDERS:
        logger.warning("Skipping side-scan scheduler target: unsupported provider %r", provider)
        return None
    fields = {
        "target_id": str(raw.get("target_id") or "").strip(),
        "account_id": str(raw.get("account_id") or "").strip(),
        "location": str(raw.get("location") or "").strip(),
        "collector_id": str(raw.get("collector_id") or "").strip(),
        "tenant_id": str(raw.get("tenant_id") or "").strip(),
    }
    missing = [name for name, value in fields.items() if not value]
    if missing:
        logger.warning("Skipping %s side-scan scheduler target: missing %s", provider, ", ".join(missing))
        return None
    collector_resource_group = str(raw.get("collector_resource_group") or "").strip() or None
    if provider == "azure" and collector_resource_group is None:
        logger.warning("Skipping azure side-scan scheduler target %s: collector_resource_group is required", fields["target_id"])
        return None
    region = str(raw.get("region") or "").strip() or None
    scan_secrets_enabled = bool(raw.get("scan_secrets_enabled", True))
    idem = str(raw.get("idempotency_key") or "").strip() or None
    return ScheduledSideScanTarget(
        provider=provider,
        collector_resource_group=collector_resource_group,
        region=region,
        scan_secrets_enabled=scan_secrets_enabled,
        idempotency_key=idem,
        **fields,
    )


def load_scheduled_targets(raw: str | None = None) -> list[ScheduledSideScanTarget]:
    """Load configured side-scan targets from a JSON file path or inline JSON.

    Reads ``AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS`` when *raw* is not supplied.
    Accepts either a filesystem path to a JSON array or inline JSON. Fail-soft:
    an unset var, a missing file, or invalid JSON yields an empty list (the loop
    then does nothing) rather than raising — a misconfiguration is never allowed
    to escalate into a broken control plane.
    """
    source = raw if raw is not None else os.environ.get(_TARGETS_ENV)
    if not source or not source.strip():
        return []
    source = source.strip()
    text = source
    # Probe for a file path, but treat any OS error (e.g. an over-long inline
    # JSON string that cannot be a path) as "not a file" and fall through to
    # parsing the value as inline JSON — never raise on a config probe.
    try:
        candidate = Path(source).expanduser()
        is_file = candidate.is_file()
    except OSError:
        candidate = None
        is_file = False
    if is_file and candidate is not None:
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            logger.warning("Side-scan scheduler targets file unreadable: %s", candidate)
            return []
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Side-scan scheduler targets is not valid JSON; ignoring")
        return []
    if not isinstance(parsed, list):
        logger.warning("Side-scan scheduler targets must be a JSON array; ignoring")
        return []
    targets: list[ScheduledSideScanTarget] = []
    for entry in parsed:
        target = _coerce_target(entry)
        if target is not None:
            targets.append(target)
    return targets


def run_scheduled_side_scan_once(
    target: ScheduledSideScanTarget,
    *,
    state_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run one configured target through the shipped executor; return honest state.

    Pre-creates the deterministic execution identity (idempotency-keyed) exactly
    like the HTTP route so the durable record is readable back after the run, and
    a retry with the same key coalesces. Drives ``run_provider_side_scan`` on a
    fresh event loop — this function is meant to be dispatched into a worker
    thread, and the executor's snapshot lifecycle is blocking.

    Never raises. Honest terminal envelopes:
    - executor OFF (``AGENT_BOM_SIDESCAN`` unset) → ``status=disabled``
    - provider extra / scoped lifecycle credentials unavailable → ``status=unavailable``
    - unexpected failure → ``status=failed`` (executor still ran teardown)
    - otherwise the durable lifecycle status (``scan_complete`` / ``partial`` /
      ``failed``) plus the cleanup flag from the executor result.
    """
    from agent_bom.cloud.side_scan import SideScanConfigError, SideScanDisabledError
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store, new_side_scan_execution
    from agent_bom.cloud.side_scan_targets import run_provider_side_scan

    idem = target.idempotency_key or uuid.uuid4().hex
    execution_id = new_side_scan_execution(
        tenant_id=target.tenant_id,
        provider=target.provider,  # type: ignore[arg-type]
        account_id=target.account_id,
        target_id=target.target_id,
        collector_id=target.collector_id,
        idempotency_key=idem,
    ).execution_id

    base: dict[str, Any] = {
        "provider": target.provider,
        "target_id": target.target_id,
        "tenant_id": target.tenant_id,
        "execution_id": execution_id,
    }

    run_kwargs = target.run_kwargs(idempotency_key=idem)
    if state_db_path is not None:
        run_kwargs["state_db_path"] = state_db_path
    try:
        results = asyncio.run(run_provider_side_scan(**run_kwargs))
    except SideScanDisabledError:
        logger.info("Scheduled side-scan skipped: executor disabled (target %s)", target.target_id)
        return {**base, "status": "disabled"}
    except SideScanConfigError:
        logger.warning("Scheduled side-scan unavailable for %s target %s", target.provider, target.target_id)
        return {**base, "status": "unavailable"}
    except Exception:  # noqa: BLE001 - one bad target never raises to the loop
        logger.error("Scheduled side-scan failed for %s target %s", target.provider, target.target_id)
        return {**base, "status": "failed"}

    record = get_side_scan_state_store(state_db_path=state_db_path).get(
        tenant_id=target.tenant_id,
        execution_id=execution_id,
    )
    cleaned_up = bool(results) and all(getattr(r, "cleaned_up", False) for r in results)
    return {
        **base,
        "status": record.status.value if record is not None else "unknown",
        "cleaned_up": cleaned_up,
    }


async def schedule_provider_side_scans(
    *,
    targets: Sequence[ScheduledSideScanTarget] | None = None,
    max_concurrency: int = SIDESCAN_SCHEDULER_MAX_CONCURRENCY,
    runner: Callable[[ScheduledSideScanTarget], dict[str, Any]] = run_scheduled_side_scan_once,
    require_enabled: bool = True,
) -> list[dict[str, Any]]:
    """Run every configured side-scan target once, off the event loop.

    This is the thin, testable entrypoint an operator's cron or the background
    loop calls. When *targets* is omitted it loads them from config. Each target
    runs in a worker thread under a semaphore so at most *max_concurrency* run at
    once. Returns one honest outcome envelope per target.

    Opt-in gate: with *require_enabled* set (the default) and the scheduler flag
    off, this is a no-op and returns ``[]`` — nothing touches the cloud.
    """
    if require_enabled and not sidescan_scheduler_enabled():
        return []
    resolved_targets = list(targets) if targets is not None else load_scheduled_targets()
    if not resolved_targets:
        return []

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _guarded(target: ScheduledSideScanTarget) -> dict[str, Any]:
        async with semaphore:
            try:
                return await asyncio.to_thread(runner, target)
            except Exception:  # noqa: BLE001 - isolate a raising runner (e.g. injected fake)
                logger.error("Scheduled side-scan runner raised for target %s", target.target_id)
                return {
                    "provider": target.provider,
                    "target_id": target.target_id,
                    "tenant_id": target.tenant_id,
                    "status": "failed",
                }

    return await asyncio.gather(*(_guarded(target) for target in resolved_targets))


async def side_scan_scheduler_loop(
    *,
    poll_seconds: int = SIDESCAN_SCHEDULER_POLL_SECONDS,
    max_backoff: int = 900,
) -> None:
    """Background loop that re-runs configured side-scan targets on a cadence.

    Runs as an asyncio task during API server lifespan. ``poll_seconds`` is the
    cadence between full passes (default hourly). Uses exponential backoff on
    consecutive failures (up to *max_backoff*) so a broken run does not get
    hammered. Per-target failures are already isolated inside the entrypoint and
    never break the loop.
    """
    interval = max(1, poll_seconds)
    consecutive_failures = 0
    while True:
        try:
            outcomes = await schedule_provider_side_scans()
            if outcomes:
                logger.info("Side-scan scheduler ran %d configured target side-scan(s)", len(outcomes))
            consecutive_failures = 0
        except asyncio.CancelledError:
            raise
        except Exception:
            consecutive_failures += 1
            backoff = min(interval * (2**consecutive_failures), max_backoff)
            logger.error(
                "Side-scan scheduler loop error (attempt %d, next retry in %ds)",
                consecutive_failures,
                backoff,
            )
            await asyncio.sleep(backoff)
            continue
        await asyncio.sleep(interval)
