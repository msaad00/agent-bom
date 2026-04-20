"""Tests for K8s deployment manifests and Helm chart structure."""

from __future__ import annotations

from pathlib import Path

import yaml

DEPLOY_DIR = Path(__file__).parent.parent / "deploy"
K8S_DIR = DEPLOY_DIR / "k8s"
HELM_DIR = DEPLOY_DIR / "helm" / "agent-bom"
ENDPOINTS_DIR = DEPLOY_DIR / "endpoints"
LOADTEST_DIR = DEPLOY_DIR / "loadtest"
OPS_DIR = DEPLOY_DIR / "ops"


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


def test_loadtest_harness_assets_exist():
    """Self-hosted operator load-test assets should ship with the repo."""
    expected = {
        "README.md",
        "k6-control-plane-api.js",
        "k6-proxy-audit.js",
    }
    actual = {path.name for path in LOADTEST_DIR.iterdir() if path.is_file()}
    assert expected.issubset(actual)


def test_restore_backup_script_exists():
    """Operators should get a concrete restore path with the packaged backup job."""
    script = OPS_DIR / "restore-postgres-backup.sh"
    assert script.exists()
    body = script.read_text()
    assert "aws s3 cp" in body
    assert "pg_restore" in body


def test_loadtest_scripts_target_real_endpoints():
    """k6 scripts should exercise the real shipped API and proxy paths."""
    control_plane = (LOADTEST_DIR / "k6-control-plane-api.js").read_text()
    proxy_audit = (LOADTEST_DIR / "k6-proxy-audit.js").read_text()
    assert "/health" in control_plane
    assert "/v1/fleet" in control_plane
    assert "/v1/fleet/stats" in control_plane
    assert "/v1/proxy/audit" in proxy_audit


def test_chart_packages_grafana_dashboard_asset():
    """The Helm chart should package the shipped Grafana dashboard JSON."""
    dashboard = HELM_DIR / "files" / "grafana-agent-bom.json"
    assert dashboard.exists()
    payload = yaml.safe_load(dashboard.read_text())
    assert payload["title"] == "agent-bom — AI Supply Chain Security"


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
        "uiImage",
        "runtimeImage",
        "scanner",
        "monitor",
        "controlPlane",
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
        "topologySpread",
    }
    assert expected_keys.issubset(set(doc.keys()))


def test_helm_templates_exist():
    """Helm templates directory has required files."""
    templates_dir = HELM_DIR / "templates"
    expected = {
        "_helpers.tpl",
        "controlplane-api-deployment.yaml",
        "controlplane-api-hpa.yaml",
        "controlplane-api-service.yaml",
        "controlplane-backup-cronjob.yaml",
        "controlplane-externalsecret.yaml",
        "controlplane-grafana-dashboard.yaml",
        "controlplane-ingress.yaml",
        "controlplane-istio-authorizationpolicy.yaml",
        "controlplane-istio-peerauthentication.yaml",
        "controlplane-kyverno-policy.yaml",
        "controlplane-pdb.yaml",
        "controlplane-priorityclass.yaml",
        "controlplane-prometheusrule.yaml",
        "controlplane-ui-deployment.yaml",
        "controlplane-ui-hpa.yaml",
        "controlplane-ui-service.yaml",
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


def test_helm_control_plane_autoscaling_defaults():
    """Control plane ships explicit HPA defaults without enabling autoscaling by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    api = doc["controlPlane"]["api"]["autoscaling"]
    ui = doc["controlPlane"]["ui"]["autoscaling"]
    assert api["enabled"] is False
    assert api["minReplicas"] == 2
    assert api["maxReplicas"] == 6
    assert api["targetCPUUtilizationPercentage"] == 70
    assert api["behavior"] == {}
    assert ui["enabled"] is False
    assert ui["minReplicas"] == 2
    assert ui["maxReplicas"] == 4
    assert ui["behavior"] == {}


def test_helm_topology_spread_defaults():
    """Topology spread knobs are explicit for production operators."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    spread = doc["topologySpread"]
    assert spread["enabled"] is False
    assert spread["zone"]["enabled"] is True
    assert spread["node"]["enabled"] is True


def test_helm_control_plane_priority_and_anti_affinity_defaults():
    """Control-plane HA knobs are explicit and opt-in by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    anti_affinity = doc["controlPlane"]["podAntiAffinity"]
    priority_class = doc["controlPlane"]["priorityClass"]
    assert anti_affinity["enabled"] is False
    assert anti_affinity["topologyKey"] == "kubernetes.io/hostname"
    assert priority_class["create"] is False
    assert priority_class["name"] == ""


def test_helm_external_secrets_defaults():
    """External secrets support is packaged but disabled by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    ext = doc["controlPlane"]["externalSecrets"]
    assert ext["enabled"] is False
    assert ext["secretStoreRef"]["kind"] == "ClusterSecretStore"
    assert ext["target"]["name"] == "agent-bom-control-plane"
    assert ext["secrets"] == []


def test_helm_control_plane_observability_defaults():
    """PrometheusRule and Grafana dashboard packaging is explicit and opt-in."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    observability = doc["controlPlane"]["observability"]
    assert observability["grafanaDashboard"]["enabled"] is False
    assert observability["grafanaDashboard"]["folder"] == "agent-bom"
    assert observability["prometheusRule"]["enabled"] is False
    assert observability["prometheusRule"]["rules"]["apiErrorRate"]["enabled"] is True
    assert observability["prometheusRule"]["rules"]["proxyAuditBacklog"]["backlogBytesThreshold"] == 10485760


def test_helm_control_plane_mesh_and_policy_defaults():
    """Service-mesh and policy-controller packaging should be explicit and opt-in."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    mesh = doc["controlPlane"]["serviceMesh"]
    policy = doc["controlPlane"]["policyController"]
    assert mesh["enabled"] is False
    assert mesh["provider"] == "istio"
    assert mesh["istio"]["peerAuthentication"]["enabled"] is True
    assert mesh["istio"]["peerAuthentication"]["mode"] == "STRICT"
    assert mesh["istio"]["authorizationPolicy"]["enabled"] is True
    assert mesh["istio"]["authorizationPolicy"]["allowSameNamespace"] is True
    assert mesh["istio"]["authorizationPolicy"]["allowedNamespaces"] == []
    assert policy["enabled"] is False
    assert policy["provider"] == "kyverno"
    assert policy["kyverno"]["validationFailureAction"] == "Audit"
    assert policy["kyverno"]["requireControlPlanePodHardening"] is True


def test_helm_control_plane_backup_defaults():
    """Postgres backup packaging is explicit and disabled by default."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    backup = doc["controlPlane"]["backup"]
    assert backup["enabled"] is False
    assert backup["schedule"] == "0 3 * * *"
    assert backup["destination"]["prefix"] == "agent-bom/postgres"
    assert backup["destination"]["bucketRegion"] == ""
    assert backup["destination"]["encryption"]["enabled"] is True
    assert backup["destination"]["encryption"]["mode"] == "AES256"
    assert backup["image"]["dumpRepository"] == "postgres"
    assert backup["image"]["uploadRepository"] == "amazon/aws-cli"
    assert backup["serviceAccount"]["create"] is True
    assert backup["serviceAccount"]["annotations"] == {}


def test_helm_gateway_service_account_defaults():
    """Gateway service account knobs stay explicit for IRSA-style rollout."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    sa = doc["gateway"]["serviceAccount"]
    assert sa["create"] is True
    assert sa["name"] == ""
    assert sa["annotations"] == {}


def test_helm_scanner_service_account_defaults():
    """Scanner service account knobs stay explicit for IRSA-style rollout."""
    doc = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
    sa = doc["scanner"]["serviceAccount"]
    assert sa["create"] is True
    assert sa["name"] == ""
    assert sa["annotations"] == {}


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
    assert policy["restrictIngress"] is True
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


def test_production_values_enable_operator_defaults():
    """Production example should turn on the packaged operator defaults."""
    production = yaml.safe_load((HELM_DIR / "examples" / "eks-production-values.yaml").read_text())
    assert production["controlPlane"]["api"]["autoscaling"]["enabled"] is True
    assert production["controlPlane"]["ui"]["autoscaling"]["enabled"] is True
    assert production["controlPlane"]["api"]["autoscaling"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"] == 300
    assert production["controlPlane"]["ui"]["autoscaling"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"] == 300
    assert production["controlPlane"]["externalSecrets"]["enabled"] is True
    assert production["controlPlane"]["observability"]["grafanaDashboard"]["enabled"] is True
    assert production["controlPlane"]["observability"]["prometheusRule"]["enabled"] is True
    assert production["controlPlane"]["backup"]["enabled"] is True
    assert production["controlPlane"]["backup"]["destination"]["bucket"] == "agent-bom-prod-backups"
    assert production["controlPlane"]["backup"]["destination"]["bucketRegion"] == "REPLACE_ME_BUCKET_REGION"
    assert production["controlPlane"]["backup"]["destination"]["encryption"]["enabled"] is True
    assert production["controlPlane"]["backup"]["destination"]["encryption"]["mode"] == "aws:kms"
    assert production["controlPlane"]["backup"]["destination"]["encryption"]["kmsKeyId"] == "alias/agent-bom-backups"
    secrets = production["controlPlane"]["externalSecrets"]["secrets"]
    assert {secret["target"]["name"] for secret in secrets} == {
        "agent-bom-control-plane-auth",
        "agent-bom-control-plane-db",
    }
    assert next(secret for secret in secrets if secret["target"]["name"] == "agent-bom-control-plane-db")["refreshInterval"] == "1h"
    assert next(secret for secret in secrets if secret["target"]["name"] == "agent-bom-control-plane-auth")["refreshInterval"] == "5m"
    env_from = production["controlPlane"]["api"]["envFrom"]
    assert env_from == [
        {"secretRef": {"name": "agent-bom-control-plane-db"}},
        {"secretRef": {"name": "agent-bom-control-plane-auth"}},
    ]
    env = {entry["name"]: entry["value"] for entry in production["controlPlane"]["api"]["env"]}
    assert env["AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT"] == "1"
    assert env["AGENT_BOM_POSTGRES_POOL_MIN_SIZE"] == "5"
    assert env["AGENT_BOM_POSTGRES_POOL_MAX_SIZE"] == "20"
    assert env["AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS"] == "5"
    assert env["AGENT_BOM_POSTGRES_STATEMENT_TIMEOUT_MS"] == "15000"
    assert production["controlPlane"]["podAntiAffinity"]["enabled"] is True
    assert production["controlPlane"]["priorityClass"]["create"] is True
    assert production["topologySpread"]["enabled"] is True
    assert production["networkPolicy"]["restrictIngress"] is True
    assert "cert-manager.io/cluster-issuer" in production["controlPlane"]["ingress"]["annotations"]


def test_mesh_example_enables_istio_and_kyverno_hardening():
    """Mesh example should wire the chart's Istio and Kyverno packaging coherently."""
    values = yaml.safe_load((HELM_DIR / "examples" / "eks-istio-kyverno-values.yaml").read_text())
    mesh = values["controlPlane"]["serviceMesh"]
    policy = values["controlPlane"]["policyController"]
    assert values["controlPlane"]["enabled"] is True
    assert mesh["enabled"] is True
    assert mesh["provider"] == "istio"
    assert mesh["istio"]["peerAuthentication"]["mode"] == "STRICT"
    assert set(mesh["istio"]["authorizationPolicy"]["allowedNamespaces"]) == {"ingress-nginx", "istio-system"}
    assert policy["enabled"] is True
    assert policy["provider"] == "kyverno"
    assert policy["kyverno"]["validationFailureAction"] == "Enforce"
    ingress_rule = values["networkPolicy"]["ingress"][1]
    ports = {port["port"] for port in ingress_rule["ports"]}
    assert ports == {3000, 8422}


def test_pilot_and_production_values_narrow_ingress_to_controller_pods_and_ports():
    """Focused values should narrow ingress traffic to controller pods on UI/API ports."""
    for name in ("eks-mcp-pilot-values.yaml", "eks-production-values.yaml"):
        values = yaml.safe_load((HELM_DIR / "examples" / name).read_text())
        ingress_rule = values["networkPolicy"]["ingress"][1]
        source = ingress_rule["from"][0]
        ports = {port["port"] for port in ingress_rule["ports"]}
        assert source["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == "ingress-nginx"
        assert source["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "controller"
        assert ports == {3000, 8422}
