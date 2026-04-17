"""Tests for K8s deployment manifests and Helm chart structure."""

from __future__ import annotations

from pathlib import Path

import yaml

DEPLOY_DIR = Path(__file__).parent.parent / "deploy"
K8S_DIR = DEPLOY_DIR / "k8s"
HELM_DIR = DEPLOY_DIR / "helm" / "agent-bom"
ENDPOINTS_DIR = DEPLOY_DIR / "endpoints"


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


def test_sidecar_example_pins_runtime_image():
    """Static sidecar example should not rely on :latest for the runtime image."""
    doc = yaml.safe_load((K8S_DIR / "sidecar-example.yaml").read_text())
    containers = doc["spec"]["template"]["spec"]["containers"]
    proxy = next(container for container in containers if container["name"] == "agent-bom-proxy")
    assert proxy["image"].startswith("agentbom/agent-bom-runtime:")
    assert not proxy["image"].endswith(":latest")


def test_proxy_sidecar_pilot_uses_runtime_proxy_policy_fields():
    """Pilot sidecar policy example should use the proxy's real local policy DSL."""
    docs = list(yaml.safe_load_all((K8S_DIR / "proxy-sidecar-pilot.yaml").read_text()))
    config_map = next(doc for doc in docs if doc and doc["kind"] == "ConfigMap")
    policy = yaml.safe_load(config_map["data"]["policy.json"])
    rules = policy["rules"]
    assert any(rule.get("deny_tool_classes") for rule in rules)
    assert any(rule.get("block_secret_paths") for rule in rules)
    assert any(rule.get("block_unknown_egress") for rule in rules)
    assert any(rule.get("rate_limit") == 60 for rule in rules)


def test_proxy_sidecar_pilot_bootstraps_restricted_namespace():
    """Pilot sidecar manifest should include the namespace with PSA restricted labels."""
    docs = list(yaml.safe_load_all((K8S_DIR / "proxy-sidecar-pilot.yaml").read_text()))
    namespace = next(doc for doc in docs if doc and doc["kind"] == "Namespace")
    labels = namespace["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
    assert labels["pod-security.kubernetes.io/audit"] == "restricted"
    assert labels["pod-security.kubernetes.io/warn"] == "restricted"


def test_endpoint_fleet_templates_exist():
    """Endpoint fleet pilot templates should ship for macOS and Linux."""
    expected = {
        "agent-bom-fleet-sync.sh",
        "agent-bom-fleet-sync.service",
        "agent-bom-fleet-sync.timer",
        "com.agentbom.fleet-sync.plist",
    }
    actual = {path.name for path in ENDPOINTS_DIR.iterdir() if path.is_file()}
    assert expected.issubset(actual)


def test_namespace_manifest():
    """Namespace manifest creates agent-bom namespace."""
    doc = yaml.safe_load((K8S_DIR / "namespace.yaml").read_text())
    assert doc["kind"] == "Namespace"
    assert doc["metadata"]["name"] == "agent-bom"


def test_namespace_manifest_sets_psa_restricted():
    """Namespace manifest should enforce restricted Pod Security Admission."""
    doc = yaml.safe_load((K8S_DIR / "namespace.yaml").read_text())
    labels = doc["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
    assert labels["pod-security.kubernetes.io/audit"] == "restricted"
    assert labels["pod-security.kubernetes.io/warn"] == "restricted"


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
        "pdb",
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
        "pdb.yaml",
        "ingress.yaml",
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
    assert doc["monitor"]["ingress"]["enabled"] is False


def test_helm_monitor_probes_are_defined():
    """Monitor readiness and startup probes are configurable in values."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    assert doc["readinessProbe"]["httpGet"]["path"] == "/status"
    assert doc["startupProbe"]["httpGet"]["path"] == "/status"


def test_helm_network_policy_defaults_are_explicit():
    """Network policy defaults should be explicit, not allow-all."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    policy = doc["networkPolicy"]
    assert policy["enabled"] is True
    assert policy["allowDns"] is True
    assert policy["allowWeb"] is True
    assert policy["webPorts"] == [80, 443]
    assert policy["additionalEgress"] == []


def test_helm_pdb_defaults_are_defined():
    """PDB values are explicit and disabled by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    pdb = doc["pdb"]
    assert pdb["enabled"] is False
    assert pdb["minAvailable"] == 1
    assert pdb["maxUnavailable"] is None


def test_helm_monitor_ingress_defaults_are_defined():
    """Ingress values are explicit and disabled by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    ingress = doc["monitor"]["ingress"]
    assert ingress["enabled"] is False
    assert ingress["hosts"][0]["paths"][0]["path"] == "/"
    assert ingress["hosts"][0]["paths"][0]["pathType"] == "Prefix"


def test_pilot_values_restrict_ingress():
    """Focused EKS pilot values should not leave ingress wide open."""
    pilot = yaml.safe_load((HELM_DIR / "examples" / "eks-mcp-pilot-values.yaml").read_text())
    policy = pilot["networkPolicy"]
    assert policy["enabled"] is True
    assert policy["restrictIngress"] is True
    assert len(policy["ingress"]) >= 2
