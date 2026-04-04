"""Tests for K8s deployment manifests and Helm chart structure."""

from __future__ import annotations

from pathlib import Path

import yaml

DEPLOY_DIR = Path(__file__).parent.parent / "deploy"
K8S_DIR = DEPLOY_DIR / "k8s"
HELM_DIR = DEPLOY_DIR / "helm" / "agent-bom"


# ─── K8s manifest validation ────────────────────────────────────────────────


def test_k8s_yamls_are_valid():
    """All YAML files in deploy/k8s/ parse as valid YAML."""
    yaml_files = list(K8S_DIR.glob("*.yaml"))
    assert len(yaml_files) >= 5, f"Expected at least 5 K8s manifests, found {len(yaml_files)}"
    for f in yaml_files:
        docs = list(yaml.safe_load_all(f.read_text()))
        assert len(docs) > 0, f"{f.name} produced no YAML documents"


def test_rbac_has_required_kinds():
    """RBAC manifest contains ServiceAccount + ClusterRole + ClusterRoleBinding."""
    docs = list(yaml.safe_load_all((K8S_DIR / "rbac.yaml").read_text()))
    kinds = {doc["kind"] for doc in docs if doc}
    assert "ServiceAccount" in kinds
    assert "ClusterRole" in kinds
    assert "ClusterRoleBinding" in kinds


def test_rbac_permissions():
    """ClusterRole has pod and namespace read permissions."""
    docs = list(yaml.safe_load_all((K8S_DIR / "rbac.yaml").read_text()))
    cluster_role = next(d for d in docs if d and d["kind"] == "ClusterRole")
    rules = cluster_role["rules"]
    resources = set()
    for rule in rules:
        resources.update(rule.get("resources", []))
    assert "pods" in resources
    assert "namespaces" in resources


def test_cronjob_valid_schedule():
    """CronJob has a valid cron schedule."""
    doc = yaml.safe_load((K8S_DIR / "cronjob.yaml").read_text())
    assert doc["kind"] == "CronJob"
    schedule = doc["spec"]["schedule"]
    # Basic cron format validation: 5 fields
    parts = schedule.split()
    assert len(parts) == 5, f"Invalid cron schedule: {schedule}"


def test_cronjob_uses_scanner_image():
    """CronJob references the agent-bom scanner image."""
    doc = yaml.safe_load((K8S_DIR / "cronjob.yaml").read_text())
    containers = doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"]
    assert any("agent-bom" in c["image"] for c in containers)


def test_daemonset_has_liveness_probe():
    """DaemonSet has a liveness probe configured."""
    doc = yaml.safe_load((K8S_DIR / "daemonset.yaml").read_text())
    assert doc["kind"] == "DaemonSet"
    containers = doc["spec"]["template"]["spec"]["containers"]
    monitor = containers[0]
    assert "livenessProbe" in monitor


def test_sidecar_has_two_containers():
    """Sidecar example has both MCP server and proxy containers."""
    doc = yaml.safe_load((K8S_DIR / "sidecar-example.yaml").read_text())
    containers = doc["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 2
    names = {c["name"] for c in containers}
    assert "mcp-server" in names
    assert "agent-bom-proxy" in names


def test_sidecar_has_prometheus_annotations():
    """Sidecar example has Prometheus scrape annotations."""
    doc = yaml.safe_load((K8S_DIR / "sidecar-example.yaml").read_text())
    annotations = doc["spec"]["template"]["metadata"]["annotations"]
    assert annotations["prometheus.io/scrape"] == "true"
    assert annotations["prometheus.io/port"] == "8422"


def test_namespace_manifest():
    """Namespace manifest creates agent-bom namespace."""
    doc = yaml.safe_load((K8S_DIR / "namespace.yaml").read_text())
    assert doc["kind"] == "Namespace"
    assert doc["metadata"]["name"] == "agent-bom"


# ─── Helm chart validation ──────────────────────────────────────────────────


def test_helm_chart_yaml_fields():
    """Chart.yaml has required fields."""
    doc = yaml.safe_load((HELM_DIR / "Chart.yaml").read_text())
    assert doc["apiVersion"] == "v2"
    assert doc["name"] == "agent-bom"
    assert "version" in doc
    assert "appVersion" in doc


def test_helm_values_yaml_keys():
    """values.yaml has expected top-level keys."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    expected_keys = {
        "image",
        "runtimeImage",
        "scanner",
        "monitor",
        "rbac",
        "serviceAccount",
        "resources",
        "podSecurityContext",
        "securityContext",
        "livenessProbe",
        "readinessProbe",
        "startupProbe",
        "networkPolicy",
    }
    assert expected_keys.issubset(set(doc.keys()))


def test_helm_templates_exist():
    """Helm templates directory has required files."""
    templates_dir = HELM_DIR / "templates"
    expected = {
        "_helpers.tpl",
        "serviceaccount.yaml",
        "rbac.yaml",
        "cronjob.yaml",
        "daemonset.yaml",
        "service.yaml",
        "servicemonitor.yaml",
    }
    actual = {f.name for f in templates_dir.iterdir() if f.is_file()}
    assert expected.issubset(actual), f"Missing templates: {expected - actual}"


def test_helm_scanner_defaults():
    """Scanner defaults are reasonable."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    scanner = doc["scanner"]
    assert scanner["enabled"] is True
    assert scanner["allNamespaces"] is True
    assert "schedule" in scanner


def test_helm_monitor_disabled_by_default():
    """Monitor is disabled by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    assert doc["monitor"]["enabled"] is False


def test_helm_monitor_defaults_include_service_and_servicemonitor():
    """Monitor values expose operator-visible service and ServiceMonitor toggles."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    assert doc["monitor"]["service"]["enabled"] is True
    assert doc["monitor"]["serviceMonitor"]["enabled"] is False


def test_helm_monitor_probes_are_defined():
    """Monitor readiness and startup probes are configurable in values."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    assert doc["readinessProbe"]["httpGet"]["path"] == "/status"
    assert doc["startupProbe"]["httpGet"]["path"] == "/status"
