"""Deterministic stdio MCP server used by the proxy characterization tests."""

import json
import sys

record_path = sys.argv[1]
TOOLS = [{"name": "echo"}, {"name": "read_file"}, {"name": "leak"}, {"name": "crash"}, {"name": "delete_file"}]
SECRET = "AKIA" + "IOSFODNN7EXAMPLE"


def reply(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


with open(record_path, "a", encoding="utf-8") as record:
    for raw in sys.stdin:
        record.write(raw if raw.endswith("\n") else raw + "\n")
        record.flush()
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(msg, dict):
            continue
        method = msg.get("method")
        if method == "test/exit":
            sys.exit(0)
        if "id" not in msg:
            continue
        if method == "tools/list":
            reply({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}})
            continue
        name = (msg.get("params") or {}).get("name")
        if name == "crash":
            sys.exit(3)
        if name == "leak":
            text = "key " + SECRET + " contact alice@example.com"
            reply({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}]}})
            continue
        if name == "fail":
            reply({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": "boom " + SECRET}})
            continue
        reply({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": "ok:" + str(name)}]}})
