"""Tests for the hardened outbound delivery foundation (``agent_bom.delivery``).

Covers: retry → backoff → dead-letter on persistent failure; idempotency key
prevents double-send; circuit-breaker opens then half-opens a probe; 429/auth
handled + warned + non-blocking; redaction in the delivery log; deterministic
time/jitter injection; and that the webhook_store delivery helper rides the
foundation. OTLP traces emit (configured / no-op) lives in test_prometheus_cov
alongside the metrics path tests but is also smoke-checked here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.delivery import (
    WEBHOOK_SIGNATURE_TIMESTAMP_HEADER,
    BreakerPolicy,
    Delivery,
    DeliveryClient,
    DeliveryError,
    DeliveryStore,
    Destination,
    RetryPolicy,
    SendOutcome,
    redacted_preview,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


class FakeClock:
    """Deterministic, monotonic injectable clock; sleeps advance it."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


class ScriptedSender:
    """Returns queued outcomes in order; records every call."""

    def __init__(self, outcomes: list[SendOutcome]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[str, dict[str, str], bytes]] = []

    def __call__(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> SendOutcome:
        self.calls.append((url, headers, body))
        if self.outcomes:
            return self.outcomes.pop(0)
        return SendOutcome(http_status=500)


def _client(
    tmp_path: Path, sender: ScriptedSender, *, clock: FakeClock, retry: RetryPolicy | None = None, breaker: BreakerPolicy | None = None
) -> DeliveryClient:
    store = DeliveryStore(tmp_path / "delivery.db")
    return DeliveryClient(
        store,
        sender=sender,
        retry=retry or RetryPolicy(max_attempts=4, initial_backoff=1.0, max_backoff=30.0),
        breaker=breaker or BreakerPolicy(failure_threshold=5, cooldown=60.0),
        now=clock.now,
        sleep=clock.sleep,
        rng=lambda: 0.0,  # deterministic: no jitter
    )


def _dest(dest_id: str = "dst1", **kw: object) -> Destination:
    return Destination(destination_id=dest_id, url="https://example.test/hook", **kw)  # type: ignore[arg-type]


def _delivery(dest_id: str = "dst1", *, key: str = "", payload: dict | None = None) -> Delivery:
    return Delivery(destination_id=dest_id, payload=payload or {"hello": "world"}, idempotency_key=key)


# ── Happy path ───────────────────────────────────────────────────────────────


def test_successful_delivery_single_attempt(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)

    result = client.deliver(_dest(), _delivery())

    assert result.delivered is True
    assert result.status == "delivered"
    assert result.attempts == 1
    assert len(sender.calls) == 1
    assert clock.slept == []  # no backoff on first-try success


# ── Retry → backoff → dead-letter ────────────────────────────────────────────


def test_persistent_failure_retries_with_backoff_then_dead_letter(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=503)] * 6)  # always fails
    client = _client(tmp_path, sender, clock=clock, retry=RetryPolicy(max_attempts=4, initial_backoff=1.0, max_backoff=30.0))

    result = client.deliver(_dest(), _delivery())

    assert result.delivered is False
    assert result.status == "dead_letter"
    assert result.attempts == 4
    assert len(sender.calls) == 4  # max_attempts transport attempts
    # Exponential backoff between attempts (3 sleeps for 4 attempts): 1, 2, 4
    assert clock.slept == [1.0, 2.0, 4.0]
    assert result.warning  # actionable, non-empty
    # A durable dead-letter record exists.
    dl = client.dead_letters(destination_id="dst1")
    assert len(dl) == 1
    assert dl[0]["status"] == "dead_letter"


def test_dead_letter_never_raises(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=None, error="connection refused")] * 6)
    client = _client(tmp_path, sender, clock=clock)
    # Must not raise — degrades to dead-letter + warning.
    result = client.deliver(_dest(), _delivery())
    assert result.status == "dead_letter"
    assert "connection" in result.warning.lower() or result.warning


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_idempotency_key_prevents_double_send(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200), SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)

    d = _delivery(key="stable-key-1")
    first = client.deliver(_dest(), d)
    second = client.deliver(_dest(), _delivery(key="stable-key-1"))

    assert first.status == "delivered"
    assert second.status == "deduplicated"
    assert second.delivered is True
    assert len(sender.calls) == 1  # second never hit the wire


def test_default_idempotency_key_is_deterministic_content_hash(tmp_path: Path) -> None:
    a = Delivery(destination_id="d", payload={"x": 1, "y": 2})
    b = Delivery(destination_id="d", payload={"y": 2, "x": 1})  # key order differs
    assert a.idempotency_key == b.idempotency_key
    c = Delivery(destination_id="d", payload={"x": 1, "y": 3})
    assert c.idempotency_key != a.idempotency_key


def test_deduplicated_after_dead_letter_is_not_delivered(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=500)] * 8)
    client = _client(tmp_path, sender, clock=clock)
    first = client.deliver(_dest(), _delivery(key="k"))
    assert first.status == "dead_letter"
    calls_before = len(sender.calls)
    second = client.deliver(_dest(), _delivery(key="k"))
    assert second.status == "deduplicated"
    assert second.delivered is False
    assert len(sender.calls) == calls_before  # no re-send


# ── Auth / 4xx permanent, 429 transient ──────────────────────────────────────


def test_auth_failure_is_permanent_no_retry_and_warned(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=401)] * 4)
    client = _client(tmp_path, sender, clock=clock)
    result = client.deliver(_dest(), _delivery())
    assert result.status == "dead_letter"
    assert result.attempts == 1
    assert len(sender.calls) == 1  # 401 not retried
    assert "auth" in result.warning.lower()
    assert clock.slept == []  # no backoff for permanent error
    dead_letters = client.dead_letters(destination_id="dst1")
    assert dead_letters[0]["attempt"] == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": 11},
        {"initial_backoff": 0},
        {"max_backoff": float("inf")},
        {"backoff_multiplier": 0.5},
        {"jitter_ratio": 1.1},
    ],
)
def test_retry_policy_rejects_unbounded_or_non_finite_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(DeliveryError):
        RetryPolicy(**kwargs)  # type: ignore[arg-type]


def test_429_is_retried_and_warned(tmp_path: Path) -> None:
    clock = FakeClock()
    # 429 three times then succeed.
    sender = ScriptedSender([SendOutcome(http_status=429), SendOutcome(http_status=429), SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    result = client.deliver(_dest(), _delivery())
    assert result.delivered is True
    assert len(sender.calls) == 3
    assert clock.slept == [1.0, 2.0]


def test_429_exhausted_warns_rate_limit(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=429)] * 6)
    client = _client(tmp_path, sender, clock=clock)
    result = client.deliver(_dest(), _delivery())
    assert result.status == "dead_letter"
    assert "rate" in result.warning.lower() or "429" in result.warning


# ── Circuit breaker ──────────────────────────────────────────────────────────


def test_circuit_breaker_opens_then_half_opens_probe(tmp_path: Path) -> None:
    clock = FakeClock()
    store = DeliveryStore(tmp_path / "delivery.db")
    # Each delivery makes 1 failing attempt (max_attempts=1) so failures accrue 1 per deliver.
    sender = ScriptedSender([SendOutcome(http_status=500)] * 20)
    client = DeliveryClient(
        store,
        sender=sender,
        retry=RetryPolicy(max_attempts=1, initial_backoff=1.0),
        breaker=BreakerPolicy(failure_threshold=3, cooldown=60.0),
        now=clock.now,
        sleep=clock.sleep,
        rng=lambda: 0.0,
    )
    # 3 distinct deliveries fail → breaker opens.
    for i in range(3):
        client.deliver(_dest(), _delivery(key=f"k{i}"))
    assert client.circuit_state("dst1") == "open"

    calls_at_open = len(sender.calls)
    # While open, a new delivery short-circuits to dead-letter without a send.
    r = client.deliver(_dest(), _delivery(key="kopen"))
    assert r.status == "circuit_open"
    assert len(sender.calls) == calls_at_open  # no wire call while open

    # Advance past cooldown → half-open; reflected to callers.
    clock.t += 61.0
    assert client.circuit_state("dst1") == "half_open"

    # A half-open probe that succeeds closes the breaker.
    sender.outcomes.insert(0, SendOutcome(http_status=200))
    probe = client.deliver(_dest(), _delivery(key="kprobe"))
    assert probe.delivered is True
    assert client.circuit_state("dst1") == "closed"


def test_circuit_breaker_closed_on_success_resets_failures(tmp_path: Path) -> None:
    clock = FakeClock()
    store = DeliveryStore(tmp_path / "d.db")
    sender = ScriptedSender([SendOutcome(http_status=500), SendOutcome(http_status=200)])
    client = DeliveryClient(
        store,
        sender=sender,
        retry=RetryPolicy(max_attempts=1),
        breaker=BreakerPolicy(failure_threshold=3, cooldown=60.0),
        now=clock.now,
        sleep=clock.sleep,
        rng=lambda: 0.0,
    )
    client.deliver(_dest(), _delivery(key="a"))  # fail (1 failure)
    client.deliver(_dest(), _delivery(key="b"))  # success → reset
    assert client.circuit_state("dst1") == "closed"


# ── Redaction ────────────────────────────────────────────────────────────────


def test_secret_values_not_in_delivery_log(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    payload = {"api_key": "sk-supersecret-123", "user": "alice", "password": "hunter2"}
    client.deliver(_dest(), _delivery(payload=payload))
    log = client.delivery_log(destination_id="dst1")
    assert log
    preview = log[0]["payload_preview"]
    assert "sk-supersecret-123" not in preview
    assert "hunter2" not in preview


def test_redacted_preview_strips_secrets() -> None:
    preview = redacted_preview({"token": "abc123secret", "ok": "visible"})
    assert "abc123secret" not in preview
    assert "visible" in preview


def test_signing_secret_never_logged(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=500)] * 6)
    client = _client(tmp_path, sender, clock=clock)
    dest = Destination(
        destination_id="dst1",
        url="https://example.test/h",
        signing_secret="whsec_topsecret_value",
        auth_scheme="bearer",
        auth_token="bearer-token-xyz",
    )
    client.deliver(dest, _delivery())
    for row in client.delivery_log(destination_id="dst1"):
        blob = str(row)
        assert "whsec_topsecret_value" not in blob
        assert "bearer-token-xyz" not in blob


# ── Signing + auth headers ───────────────────────────────────────────────────


def test_hmac_signature_and_bearer_auth_headers(tmp_path: Path) -> None:
    clock = FakeClock(start=1770000000.0)
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    dest = Destination(destination_id="dst1", url="https://example.test/h", signing_secret="s3cret", auth_scheme="bearer", auth_token="tok")
    client.deliver(dest, _delivery())
    _url, headers, body = sender.calls[0]
    assert headers["x-agent-bom-signature"].startswith("sha256=")
    assert headers["Authorization"] == "Bearer tok"
    assert headers["idempotency-key"]
    assert headers[WEBHOOK_SIGNATURE_TIMESTAMP_HEADER] == "1770000000"
    # Signature binds the timestamp and exact body so receivers can reject stale
    # replayed deliveries.
    import hashlib
    import hmac

    expected = "sha256=" + hmac.new(b"s3cret", b"1770000000." + body, hashlib.sha256).hexdigest()
    assert headers["x-agent-bom-signature"] == expected


def test_no_signature_header_without_secret(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    client.deliver(_dest(), _delivery())
    _url, headers, _body = sender.calls[0]
    assert "x-agent-bom-signature" not in headers


# ── Validation ───────────────────────────────────────────────────────────────


def test_mismatched_destination_id_raises(tmp_path: Path) -> None:
    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    with pytest.raises(DeliveryError):
        client.deliver(_dest("a"), _delivery("b"))


def test_bad_auth_scheme_rejected() -> None:
    with pytest.raises(DeliveryError):
        Destination(destination_id="d", url="https://x.test", auth_scheme="basic")


# ── webhook_store integration ────────────────────────────────────────────────


def test_webhook_store_delivers_through_foundation(tmp_path: Path) -> None:
    from agent_bom.api.webhook_store import WebhookSubscription, deliver_subscription_event

    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    client = _client(tmp_path, sender, clock=clock)
    sub = WebhookSubscription(
        subscription_id="whsub_test",
        tenant_id="tenant-a",
        url="https://example.test/webhook",
        signing_secret="whsec_abc",
    )
    result = deliver_subscription_event(sub, event_type="identity.revoked", payload={"agent": "x"}, client=client)
    assert result.delivered is True
    _url, headers, _body = sender.calls[0]
    assert headers["x-agent-bom-event-type"] == "identity.revoked"
    assert headers["x-agent-bom-tenant-id"] == "tenant-a"
    assert headers[WEBHOOK_SIGNATURE_TIMESTAMP_HEADER] == "1000"
    assert headers["x-agent-bom-signature"].startswith("sha256=")


# ── Backward compatibility (defaults preserve existing behavior) ─────────────


def test_posture_outbox_path_default_unchanged_when_delivery_db_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """The new AGENT_BOM_DELIVERY_DB is opt-in. Without it (and without the
    shared AGENT_BOM_DB), the delivery store falls back to its own default path
    and does NOT change the posture webhook outbox's path resolution."""
    from agent_bom.delivery import default_delivery_store_path
    from agent_bom.posture_streaming import default_webhook_outbox_path

    monkeypatch.delenv("AGENT_BOM_DELIVERY_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTURE_WEBHOOK_OUTBOX_DB", raising=False)

    posture = default_webhook_outbox_path()
    delivery = default_delivery_store_path()
    # Distinct DBs — the foundation does not hijack the existing outbox file.
    assert posture.name == "posture-webhooks.db"
    assert delivery.name == "delivery.db"
    assert posture != delivery


def test_existing_webhook_subscription_api_unchanged(tmp_path: Path) -> None:
    """The webhook_store public surface (create/list/match) is untouched: the
    delivery helper is additive."""
    from agent_bom.api.webhook_store import (
        InMemoryWebhookSubscriptionStore,
        create_subscription,
    )

    store = InMemoryWebhookSubscriptionStore()
    sub = create_subscription(store, tenant_id="t", url="https://hooks.example.test/x", event_types=["identity.revoked"])
    assert sub.signing_secret.startswith("whsec_")
    assert store.matching("t", "identity.revoked") == [sub]
    assert store.matching("t", "budget.exceeded") == []


# ── Shared singleton ─────────────────────────────────────────────────────────


def test_set_and_get_delivery_client_singleton(tmp_path: Path) -> None:
    from agent_bom.delivery import get_delivery_client, set_delivery_client

    clock = FakeClock()
    sender = ScriptedSender([SendOutcome(http_status=200)])
    custom = _client(tmp_path, sender, clock=clock)
    set_delivery_client(custom)
    try:
        assert get_delivery_client() is custom
    finally:
        set_delivery_client(None)


# ── OTLP traces emit (output/prometheus.push_otlp_traces) ────────────────────


def _minimal_report():
    from agent_bom.models import Agent, AgentType, AIBOMReport

    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/t", mcp_servers=[])
    return AIBOMReport(agents=[agent])


def test_otlp_traces_noop_when_endpoint_unset() -> None:
    from agent_bom.output.prometheus import push_otlp_traces

    assert push_otlp_traces("", _minimal_report()) is False
    assert push_otlp_traces("   ", _minimal_report()) is False


def test_otlp_traces_noop_when_packages_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the OTel trace packages are not importable, emit degrades to a no-op
    (returns False) rather than failing a scan."""
    import builtins

    from agent_bom.output import prometheus as prom

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if name.startswith("opentelemetry"):
            raise ImportError("no otel")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert prom.push_otlp_traces("http://collector.local:4318", _minimal_report()) is False


def test_otlp_traces_emits_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("opentelemetry.sdk.trace")
    from unittest.mock import MagicMock, patch

    from agent_bom.output.prometheus import push_otlp_traces

    # Use a resolvable loopback host with the operator private-egress override so
    # the SSRF guard admits the collector; the exporter itself is mocked.
    monkeypatch.setenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "1")
    with patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter") as exporter_cls:
        exporter_cls.return_value = MagicMock()
        ok = push_otlp_traces("http://127.0.0.1:4318", _minimal_report())
        assert ok is True
        # The collector URL is built with the /v1/traces path appended.
        called_endpoint = exporter_cls.call_args.kwargs.get("endpoint", "")
        assert called_endpoint.endswith("/v1/traces")


def test_otlp_traces_rejects_bad_endpoint() -> None:
    pytest.importorskip("opentelemetry.sdk.trace")
    from agent_bom.output.prometheus import push_otlp_traces

    # Non-http(s) scheme is rejected by the outbound URL policy before any send.
    with pytest.raises(RuntimeError):
        push_otlp_traces("ftp://collector.example.com/v1/traces", _minimal_report())
