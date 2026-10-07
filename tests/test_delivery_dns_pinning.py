"""Outbound delivery must validate the addresses actually used by the socket."""

import socket

import httpcore
import pytest

from agent_bom.delivery import http_sender


def test_delivery_rejects_dns_change_between_preflight_and_connect(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", raising=False)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    resolutions = []
    connections = []

    def resolve(host, port, *args, **kwargs):
        resolutions.append(host)
        address = "93.184.216.34" if len(resolutions) == 1 else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 443))]

    def connect(self, host, port, **kwargs):
        connections.append(host)
        raise httpcore.ConnectError("synthetic transport stop")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    result = http_sender("https://hooks.example.test/events", {}, b"{}", 1)
    assert connections == [], "unsafe target reached the socket backend"
    assert result.retryable is False


@pytest.mark.parametrize("address", ["::ffff:169.254.169.254", "100.100.100.200", "fd00:ec2::254"])
@pytest.mark.asyncio
async def test_existing_egress_policy_rejects_all_metadata_forms(address):
    from agent_bom.runtime.egress_transport import PinnedDNSNetworkBackend, UnsafeDestinationError

    class Delegate:
        async def connect_tcp(self, *args, **kwargs):
            pytest.fail("metadata reached socket backend")

    backend = PinnedDNSNetworkBackend(delegate=Delegate(), allow_private_networks=True)
    with pytest.raises(UnsafeDestinationError):
        await backend.connect_tcp(address, 443)


@pytest.mark.parametrize("operator,tenant", [(False, True), (True, False)])
def test_subscription_delivery_requires_both_private_opt_ins(monkeypatch, tmp_path, operator, tenant):
    from agent_bom.api.webhook_store import WebhookSubscription, deliver_subscription_event
    from agent_bom.delivery import DeliveryClient, DeliveryStore, RetryPolicy

    monkeypatch.setenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "1" if operator else "0")
    connections = []

    def connect(self, host, port, **kwargs):
        connections.append(host)
        raise httpcore.ConnectError("synthetic transport stop")

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    subscription = WebhookSubscription(
        subscription_id="sub", tenant_id="t", url="https://127.0.0.1/in", signing_secret="synthetic", allow_private_networks=tenant
    )
    client = DeliveryClient(DeliveryStore(tmp_path / "delivery.db"), retry=RetryPolicy(max_attempts=1))
    result = deliver_subscription_event(subscription, event_type="webhook.test", payload={}, client=client)
    assert connections == []
    assert result.status == "dead_letter"


def test_sync_delivery_pins_public_dns(monkeypatch):
    from agent_bom.runtime.egress_transport import PinnedDNSSyncNetworkBackend

    connected = []
    sentinel = object()
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    )

    def connect(self, host, port, **kwargs):
        connected.append(host)
        return sentinel

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    assert PinnedDNSSyncNetworkBackend().connect_tcp("hooks.example.test", 443) is sentinel
    assert connected == ["93.184.216.34"]


def test_pinned_delivery_client_disables_redirects_and_ambient_proxy():
    from agent_bom.runtime.egress_transport import build_pinned_sync_client

    with build_pinned_sync_client(allow_private_networks=False, timeout=1) as client:
        assert client.follow_redirects is False
        assert client.trust_env is False
