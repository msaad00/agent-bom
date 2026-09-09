#!/usr/bin/env python3
"""Exercise the actual Helm chart on an explicitly selected disposable kind cluster.

Creates and removes its own namespace. Credentials exist only in memory and
Kubernetes Secrets. A failed probe never produces a successful evidence file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--image", default="agent-bom:runtime-acceptance")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ui-root", type=Path, help="Built standalone UI with Playwright dependencies; enables real browser proof")
    args = parser.parse_args()
    kube = ["kubectl", "--kubeconfig", str(args.kubeconfig)]

    redactions: list[str] = []

    def command(argv, *, data=None):
        try:
            return subprocess.check_output(argv, input=data, text=True, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            diagnostic = error.stderr or "Command failed"
            for credential in redactions:
                diagnostic = diagnostic.replace(credential, "[REDACTED]")
            print(diagnostic, flush=True)
            raise

    context = command([*kube, "config", "current-context"]).strip()
    if not context.startswith("kind-"):
        raise SystemExit("This acceptance probe requires a disposable kind context")
    namespace = "runtime-proof-" + secrets.token_hex(4)
    kubectl = [*kube, "-n", namespace]
    report = {
        "schema_version": "runtime.helm.acceptance.v1",
        "context": context,
        "image": args.image,
        "source_commit": command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
        "source_dirty": bool(command(["git", "-C", str(ROOT), "status", "--porcelain"]).strip()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "topology": {"api_replicas": 2, "gateway_replicas": 1, "gateway_storage": "PVC", "activity_storage": "Postgres"},
    }

    def apply(kind, name, **fields):
        body = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **fields}
        command([*kubectl, "apply", "-f", "-"], data=json.dumps(body))

    def probe(pod, mode, **config):
        source = (ROOT / "scripts/demo/runtime_acceptance_probe.py").read_text()
        program = source + "\nprint(json.dumps(run(" + repr({"mode": mode, **config}) + ")))\n"
        return json.loads(command([*kubectl, "exec", "-i", pod, "--", "python", "-"], data=program))

    def api_pods():
        return json.loads(command([*kubectl, "get", "pods", "-l", "app.kubernetes.io/component=api", "-o", "json"]))["items"]

    command([*kube, "create", "namespace", namespace])
    try:
        print("Deploying isolated Postgres and upstream fixture", flush=True)
        password = secrets.token_urlsafe(24)
        app_password, maintenance_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        api_key, transport_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        redactions.extend([password, app_password, maintenance_password, api_key, transport_key])
        app_url = f"postgresql://agent_bom_app:{app_password}@postgres:5432/agentbom?sslmode=require"
        apply("Secret", "postgres", stringData={"POSTGRES_PASSWORD": password, "POSTGRES_DB": "agentbom"})
        apply("Secret", "db-app", stringData={"AGENT_BOM_POSTGRES_URL": app_url})
        apply(
            "Secret",
            "db-maintenance",
            stringData={
                "AGENT_BOM_POSTGRES_MAINTENANCE_URL": f"postgresql://agent_bom_maintenance:{maintenance_password}@postgres:5432/agentbom?sslmode=require"
            },
        )
        apply(
            "Secret",
            "db-admin",
            stringData={"ALEMBIC_DATABASE_URL": f"postgresql+psycopg://postgres:{password}@postgres:5432/agentbom?sslmode=require"},
        )
        apply(
            "Secret",
            "api-auth",
            stringData={
                "AGENT_BOM_API_KEYS": api_key + ":admin",
                "AGENT_BOM_TRUST_PROXY_AUTH": "1",
                "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER": "runtime-acceptance-proxy",
                "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": secrets.token_urlsafe(32),
                "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY": secrets.token_urlsafe(32),
                "AGENT_BOM_AUDIT_HMAC_KEY": secrets.token_urlsafe(32),
            },
        )
        apply(
            "Secret",
            "gateway-auth",
            stringData={
                "AGENT_BOM_POSTGRES_URL": app_url,
                "AGENT_BOM_GATEWAY_BEARER_TOKEN": transport_key,
                "AGENT_BOM_GATEWAY_BEARER_TOKEN_EXPIRES_AT": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "AGENT_BOM_CONTROL_PLANE_TOKEN": api_key,
            },
        )
        with tempfile.TemporaryDirectory(prefix="runtime-postgres-tls-") as tls_dir:
            certificate, key = Path(tls_dir) / "tls.crt", Path(tls_dir) / "tls.key"
            command(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=postgres",
                    "-keyout",
                    str(key),
                    "-out",
                    str(certificate),
                ]
            )
            redactions.append(key.read_text())
            apply("Secret", "postgres-tls", stringData={"tls.crt": certificate.read_text(), "tls.key": key.read_text()})
        apply(
            "Pod",
            "postgres",
            spec={
                "securityContext": {"fsGroup": 999},
                "volumes": [{"name": "tls", "secret": {"secretName": "postgres-tls", "defaultMode": 416}}],
                "containers": [
                    {
                        "name": "postgres",
                        "image": "postgres:17",
                        "args": ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/certs/tls.crt", "-c", "ssl_key_file=/certs/tls.key"],
                        "volumeMounts": [{"name": "tls", "mountPath": "/certs", "readOnly": True}],
                        "envFrom": [{"secretRef": {"name": "postgres"}}],
                        "ports": [{"containerPort": 5432}],
                        "readinessProbe": {"exec": {"command": ["pg_isready", "-h", "127.0.0.1", "-U", "postgres"]}, "periodSeconds": 2},
                    }
                ],
            },
        )
        command([*kubectl, "label", "pod", "postgres", "app=postgres"])
        apply("Service", "postgres", spec={"selector": {"app": "postgres"}, "ports": [{"port": 5432}]})
        upstream = """import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_POST(self):
  message=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  body=json.dumps({'jsonrpc':'2.0','id':message['id'],'result':{'content':[{'type':'text','text':'synthetic upstream result'}]}}).encode()
  self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
HTTPServer(('0.0.0.0',8100),Handler).serve_forever()
"""
        apply(
            "Pod",
            "upstream",
            spec={
                "containers": [
                    {
                        "name": "upstream",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", upstream],
                        "ports": [{"containerPort": 8100}],
                    }
                ]
            },
        )
        command([*kubectl, "label", "pod", "upstream", "app=upstream"])
        apply("Service", "upstream", spec={"selector": {"app": "upstream"}, "ports": [{"port": 8100}]})
        apply(
            "PersistentVolumeClaim", "gateway-state", spec={"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}
        )
        command([*kubectl, "wait", "--for=condition=Ready", "pod/postgres", "--timeout=180s"])
        # Alembic-only BYO Postgres requires the app login to be provisioned
        # first; migrations reconcile its password and own all schema objects.
        command(
            [*kubectl, "exec", "-i", "postgres", "--", "psql", "-U", "postgres", "-d", "agentbom", "-v", "ON_ERROR_STOP=1"],
            data="""
CREATE ROLE agent_bom_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE agentbom TO agent_bom_app;
GRANT USAGE ON SCHEMA public TO agent_bom_app;
REVOKE CREATE ON SCHEMA public FROM agent_bom_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agent_bom_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO agent_bom_app;
""",
        )
        repository, tag = args.image.rsplit(":", 1)
        values = {
            "image": {"repository": repository, "tag": tag, "pullPolicy": "IfNotPresent"},
            "scanner": {"enabled": False},
            "rbac": {"create": False},
            "tests": {"enabled": False},
            "teardownHooks": {"enabled": False},
            "controlPlane": {
                "enabled": True,
                "observability": {"prometheusRule": {"enabled": False}},
                "ui": {"enabled": False},
                "postgresSecrets": {
                    "enabled": True,
                    "appSecretRef": {"name": "db-app"},
                    "maintenanceSecretRef": {"name": "db-maintenance"},
                    "adminSecretRef": {"name": "db-admin"},
                },
                "api": {
                    "replicas": 2,
                    "envFrom": [{"secretRef": {"name": "api-auth"}}],
                    "env": [{"name": "AGENT_BOM_STATE_DIR", "value": "/tmp/agent-bom"}],
                },
            },
            "gateway": {
                "enabled": True,
                "image": {"repository": repository, "tag": tag},
                "persistence": {"enabled": True, "existingClaim": "gateway-state"},
                "profileEnforcement": "enforce",
                "profileEnvironment": "prod",
                "envFrom": [{"secretRef": {"name": "gateway-auth"}}],
                "controlPlaneDiscovery": {"url": "http://agent-bom-api:8422"},
                "upstreamsYaml": "upstreams:\n  - name: filesystem\n    url: http://upstream:8100\n",
                "networkPolicy": {
                    "additionalEgress": [{"to": [{"podSelector": {}}], "ports": [{"port": 5432}, {"port": 8422}, {"port": 8100}]}]
                },
            },
        }
        with tempfile.TemporaryDirectory(prefix="runtime-helm-") as tmp:
            path = Path(tmp) / "values.json"
            path.write_text(json.dumps(values))
            print("Installing Helm migrations, API replicas and persistent gateway", flush=True)
            command(
                [
                    "helm",
                    "install",
                    "runtime-proof",
                    str(ROOT / "deploy/helm/agent-bom"),
                    "--kubeconfig",
                    str(args.kubeconfig),
                    "-n",
                    namespace,
                    "-f",
                    str(path),
                    "--wait",
                    "--timeout",
                    "8m",
                ]
            )
        pods = api_pods()
        assert len(pods) == 2
        reader, writer = [pod["metadata"]["name"] for pod in pods]
        report["api_pods_before"] = [pod["metadata"]["uid"] for pod in pods]
        source_files = [
            "gateway_server.py",
            "api/middleware.py",
            "api/routes/gateway_feed.py",
            "api/postgres_agent_identity.py",
            "api/agent_identity_store.py",
            "api/storage_schema.py",
        ]
        expected_sources = {name: hashlib.sha256((ROOT / "src/agent_bom" / name).read_bytes()).hexdigest() for name in source_files}
        assert probe(writer, "source", files=source_files) == expected_sources, "Image runtime sources differ from checkout"
        report["verified_image_sources"] = expected_sources
        report["container_images"] = [
            {"image": item["image"], "imageID": item["imageID"]} for item in pods[0]["status"]["containerStatuses"]
        ]
        gateway_before = json.loads(command([*kubectl, "get", "pods", "-l", "app.kubernetes.io/component=gateway", "-o", "json"]))["items"][
            0
        ]
        pvc_before = json.loads(command([*kubectl, "get", "pvc", "gateway-state", "-o", "json"]))["metadata"]["uid"]
        report["postgres_verification"] = command(
            [*kubectl, "logs", "-l", "app.kubernetes.io/component=postgres-verification", "--tail=1"]
        ).strip()
        identity = probe(writer, "seed")["identity_token"]
        redactions.append(identity)
        checkpoint = probe(writer, "read", host=pods[0]["status"]["podIP"])["cursor"]
        probe(writer, "call", count=205, identity_token=identity, transport_token=transport_key)
        first = probe(writer, "read", host=pods[0]["status"]["podIP"], cursor=checkpoint)
        assert len(first["events"]) == 205
        print("Restarting the serving API pod and the PVC-backed gateway", flush=True)
        command([*kubectl, "delete", "pod", reader, "--wait=true"])
        command([*kubectl, "rollout", "restart", "deployment/agent-bom-gateway"])
        for deployment in ["agent-bom-api", "agent-bom-gateway"]:
            command([*kubectl, "rollout", "status", "deployment/" + deployment, "--timeout=180s"])
        replacement = next(pod for pod in api_pods() if pod["metadata"]["name"] != writer)
        assert replacement["metadata"]["uid"] != pods[0]["metadata"]["uid"]
        probe(writer, "call", count=7, identity_token=identity, transport_token=transport_key)
        second = probe(writer, "read", host=replacement["status"]["podIP"], cursor=first["cursor"])
        events = first["events"] + second["events"]
        assert len(second["events"]) == 7
        assert [event["ingest_ordinal"] for event in events] == list(range(1, 213))
        assert len({event["event_id"] for event in events}) == 212
        assert all(event["profile_id"] == "acceptance-profile" and event["agent_id"] == "acceptance-agent" for event in events)
        assert not probe(writer, "read", host=replacement["status"]["podIP"], cursor=second["cursor"])["events"]
        probe(writer, "read", host=replacement["status"]["podIP"], cursor=second["cursor"], tenant="tenant-b", expected_status=400)
        gateway_after = json.loads(command([*kubectl, "get", "pods", "-l", "app.kubernetes.io/component=gateway", "-o", "json"]))["items"][
            0
        ]
        assert gateway_before["metadata"]["uid"] != gateway_after["metadata"]["uid"]
        assert json.loads(command([*kubectl, "get", "pvc", "gateway-state", "-o", "json"]))["metadata"]["uid"] == pvc_before
        report["gateway_restart"] = {
            "before_uid": gateway_before["metadata"]["uid"],
            "after_uid": gateway_after["metadata"]["uid"],
            "pvc_uid": pvc_before,
        }
        if args.ui_root:
            print("Verifying authenticated browser themes, mobile layout and live transport reconnect", flush=True)
            cookie = probe(writer, "cookie", role="admin")
            redactions.append(cookie["value"])
            report["browser"] = json.loads(
                command(
                    ["node", str(ROOT / "scripts/demo/runtime_browser_acceptance.mjs")],
                    data=json.dumps(
                        {
                            "uiRoot": str(args.ui_root.resolve()),
                            "kubeconfig": str(args.kubeconfig.resolve()),
                            "namespace": namespace,
                            "pod": replacement["metadata"]["name"],
                            "cookie": cookie,
                            "output": str(args.output.resolve().with_suffix("")),
                        }
                    ),
                )
            )
        report.update(
            {
                "events_verified": 212,
                "duplicates": 0,
                "missing_ordinals": 0,
                "replacement_api_uid": replacement["metadata"]["uid"],
                "status": "passed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        for selector in [
            "app.kubernetes.io/component=postgres-migration",
            "app.kubernetes.io/component=postgres-verification",
            "app.kubernetes.io/component=api",
            "app.kubernetes.io/component=gateway",
        ]:
            logs = subprocess.run(
                [*kubectl, "logs", "--all-containers=true", "--prefix=true", "--tail=30", "-l", selector, "--request-timeout=10s"],
                capture_output=True,
                text=True,
            ).stdout
            for credential in redactions:
                logs = logs.replace(credential, "[REDACTED]")
            print(logs, flush=True)
        raise
    finally:
        try:
            command(
                [
                    "helm",
                    "uninstall",
                    "runtime-proof",
                    "--kubeconfig",
                    str(args.kubeconfig),
                    "-n",
                    namespace,
                    "--ignore-not-found",
                    "--no-hooks",
                ]
            )
        finally:
            command([*kube, "delete", "namespace", namespace, "--wait=true", "--ignore-not-found", "--timeout=120s"])

    report["namespace_removed"] = True
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Helm restart and shared-cursor acceptance passed; namespace removed", flush=True)


if __name__ == "__main__":
    main()
