"""The proxy and gateway preserve the same trace metadata and input ownership."""

import copy

import pytest

from agent_bom.gateway_server import _inject_jsonrpc_trace_meta as gateway_inject
from agent_bom.proxy import _inject_jsonrpc_trace_meta as proxy_inject


@pytest.mark.parametrize("inject", [gateway_inject, proxy_inject])
@pytest.mark.parametrize("meta", [None, "malformed", {}, {"application": "kept", "traceparent": "old"}])
def test_trace_injection_copies_metadata_without_mutating_message(inject, meta):
    message = {"jsonrpc": "2.0", "id": 7, "_meta": meta}
    before = copy.deepcopy(message)
    result = inject(message, traceparent="new", tracestate=None, baggage="tenant=one")
    assert message == before
    assert result is not message
    assert result["_meta"] == {**(meta if isinstance(meta, dict) else {}), "traceparent": "new", "baggage": "tenant=one"}
    assert result["_meta"] is not meta


@pytest.mark.parametrize("inject", [gateway_inject, proxy_inject])
@pytest.mark.parametrize("empty", [None, ""])
def test_absent_trace_returns_original_message(inject, empty):
    message = {"jsonrpc": "2.0", "_meta": {"application": "kept"}}
    assert inject(message, traceparent=empty, tracestate=empty, baggage=empty) is message


def test_proxy_trace_arguments_remain_optional():
    message = {"jsonrpc": "2.0"}
    assert proxy_inject(message) is message


def test_gateway_trace_arguments_remain_explicit():
    with pytest.raises(TypeError):
        gateway_inject({"jsonrpc": "2.0"})
