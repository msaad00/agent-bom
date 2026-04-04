"""Tests for the Helm chart IaC security scanner (iac/helm.py)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from agent_bom.iac import scan_iac_directory
from agent_bom.iac.helm import scan_chart_yaml, scan_values_yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a file inside tmp_path and return the path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return p


def _rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# scan_chart_yaml — HELM-001 (deprecated apiVersion)
# ---------------------------------------------------------------------------


class TestChartYamlApiVersion:
    def test_v1_api_version_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v1
            name: my-chart
            version: 1.0.0
            appVersion: "1.2.3"
        """,
        )
        findings = scan_chart_yaml(p)
        assert "HELM-001" in _rule_ids(findings)

    def test_v2_api_version_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v2
            name: my-chart
            version: 1.0.0
            appVersion: "1.2.3"
        """,
        )
        findings = scan_chart_yaml(p)
        assert "HELM-001" not in _rule_ids(findings)

    def test_helm001_finding_has_correct_fields(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v1
            name: my-chart
            version: 1.0.0
            appVersion: "1.2.3"
        """,
        )
        findings = scan_chart_yaml(p)
        helm001 = [f for f in findings if f.rule_id == "HELM-001"][0]
        assert helm001.severity == "high"
        assert helm001.category == "helm"
        assert helm001.line_number >= 1


# ---------------------------------------------------------------------------
# scan_chart_yaml — HELM-002 (missing appVersion)
# ---------------------------------------------------------------------------


class TestChartYamlAppVersion:
    def test_missing_app_version_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v2
            name: my-chart
            version: 1.0.0
        """,
        )
        findings = scan_chart_yaml(p)
        assert "HELM-002" in _rule_ids(findings)

    def test_present_app_version_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v2
            name: my-chart
            version: 1.0.0
            appVersion: "2.3.4"
        """,
        )
        findings = scan_chart_yaml(p)
        assert "HELM-002" not in _rule_ids(findings)

    def test_helm002_finding_has_correct_fields(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v2
            name: my-chart
            version: 1.0.0
        """,
        )
        findings = scan_chart_yaml(p)
        helm002 = [f for f in findings if f.rule_id == "HELM-002"][0]
        assert helm002.severity == "low"
        assert helm002.category == "helm"


# ---------------------------------------------------------------------------
# scan_chart_yaml — non-YAML / unreadable input
# ---------------------------------------------------------------------------


class TestChartYamlEdgeCases:
    def test_non_yaml_returns_empty(self, tmp_path):
        p = _write(tmp_path, "Chart.yaml", "this: is: not: valid: yaml: :: :")
        findings = scan_chart_yaml(p)
        # Non-YAML must not raise; empty list or findings without crash
        assert isinstance(findings, list)

    def test_nonexistent_file_returns_empty(self, tmp_path):
        findings = scan_chart_yaml(tmp_path / "does_not_exist.yaml")
        assert findings == []

    def test_clean_chart_produces_no_findings(self, tmp_path):
        p = _write(
            tmp_path,
            "Chart.yaml",
            """\
            apiVersion: v2
            name: my-chart
            version: 1.0.0
            appVersion: "3.0.0"
        """,
        )
        findings = scan_chart_yaml(p)
        assert findings == []


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-003 (hardcoded secrets)
# ---------------------------------------------------------------------------


class TestValuesYamlSecrets:
    def test_hardcoded_password_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            db:
              password: super-secret-value
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" in _rule_ids(findings)

    def test_empty_password_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            db:
              password: ""
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" not in _rule_ids(findings)

    def test_changeme_placeholder_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            db:
              password: changeme
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" not in _rule_ids(findings)

    def test_your_prefix_placeholder_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            api:
              token: your-api-token-here
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" not in _rule_ids(findings)

    def test_hardcoded_token_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            api:
              token: ghp_realtoken1234567890
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" in _rule_ids(findings)

    def test_jinja_template_variable_not_flagged(self, tmp_path):
        """{{ .Values.* }} template references must NOT trigger HELM-003 — they
        are resolved at deploy time and are not hardcoded secrets."""
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            app:
              apiKey: "{{ .Values.global.apiKey }}"
              password: "{{ .Values.db.password }}"
              token: "{{ .Values.auth.token | default '' }}"
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-003" not in _rule_ids(findings), "Jinja/Helm template variables should not be flagged as hardcoded secrets"

    def test_helm003_finding_has_critical_severity(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            db:
              password: actually-a-real-password
        """,
        )
        findings = scan_values_yaml(p)
        helm003 = [f for f in findings if f.rule_id == "HELM-003"][0]
        assert helm003.severity == "critical"
        assert helm003.category == "helm"


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-004 (latest image tag)
# ---------------------------------------------------------------------------


class TestValuesYamlImageTag:
    def test_latest_tag_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            image:
              repository: nginx
              tag: latest
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-004" in _rule_ids(findings)

    def test_pinned_tag_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            image:
              repository: nginx
              tag: "1.25.3"
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-004" not in _rule_ids(findings)

    def test_helm004_finding_has_medium_severity(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            image:
              repository: nginx
              tag: latest
        """,
        )
        findings = scan_values_yaml(p)
        helm004 = [f for f in findings if f.rule_id == "HELM-004"][0]
        assert helm004.severity == "medium"


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-005 (NodePort)
# ---------------------------------------------------------------------------


class TestValuesYamlServiceType:
    def test_nodeport_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            service:
              type: NodePort
              port: 80
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-005" in _rule_ids(findings)

    def test_clusterip_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            service:
              type: ClusterIP
              port: 80
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-005" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-006 (networkPolicy.enabled: false)
# ---------------------------------------------------------------------------


class TestValuesYamlNetworkPolicy:
    def test_network_policy_disabled_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            networkPolicy:
              enabled: false
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-006" in _rule_ids(findings)

    def test_network_policy_enabled_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            networkPolicy:
              enabled: true
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-006" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-007 (rbac.create / serviceAccount.create false)
# ---------------------------------------------------------------------------


class TestValuesYamlRbac:
    def test_rbac_create_false_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            rbac:
              create: false
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-007" in _rule_ids(findings)

    def test_rbac_create_true_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            rbac:
              create: true
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-007" not in _rule_ids(findings)

    def test_service_account_create_false_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            serviceAccount:
              create: false
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-007" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-008 (Ingress without TLS)
# ---------------------------------------------------------------------------


class TestValuesYamlIngressTLS:
    def test_ingress_without_tls_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            ingress:
              enabled: true
              hosts:
                - host: example.com
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-008" in _rule_ids(findings)

    def test_ingress_with_tls_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            ingress:
              enabled: true
              tls:
                - secretName: tls-secret
                  hosts:
                    - example.com
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-008" not in _rule_ids(findings)

    def test_ingress_disabled_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            ingress:
              enabled: false
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-008" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-009 (externalTrafficPolicy: Cluster)
# ---------------------------------------------------------------------------


class TestValuesYamlExternalTrafficPolicy:
    def test_cluster_policy_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            service:
              type: LoadBalancer
              externalTrafficPolicy: Cluster
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-009" in _rule_ids(findings)

    def test_local_policy_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            service:
              type: LoadBalancer
              externalTrafficPolicy: Local
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-009" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-010 (PVC without storageClassName)
# ---------------------------------------------------------------------------


class TestValuesYamlPersistence:
    def test_no_storage_class_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            persistence:
              enabled: true
              size: 10Gi
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-010" in _rule_ids(findings)

    def test_with_storage_class_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            persistence:
              enabled: true
              storageClassName: gp3
              size: 10Gi
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-010" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-011 (resources without memory limits)
# ---------------------------------------------------------------------------


class TestValuesYamlMemoryLimits:
    def test_no_memory_limit_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            resources:
              requests:
                cpu: 100m
                memory: 128Mi
              limits:
                cpu: 500m
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-011" in _rule_ids(findings)

    def test_with_memory_limit_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            resources:
              requests:
                cpu: 100m
                memory: 128Mi
              limits:
                cpu: 500m
                memory: 256Mi
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-011" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-012 (missing podSecurityContext)
# ---------------------------------------------------------------------------


class TestValuesYamlPodSecurityContext:
    def test_no_pod_security_context_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicaCount: 3
            image:
              repository: nginx
              tag: "1.25"
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-012" in _rule_ids(findings)

    def test_with_pod_security_context_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            podSecurityContext:
              runAsNonRoot: true
              fsGroup: 1000
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-012" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-013 (default admin password)
# ---------------------------------------------------------------------------


class TestValuesYamlAdminPassword:
    def test_admin_password_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            adminPassword: supersecret123
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-013" in _rule_ids(findings)

    def test_admin_password_placeholder_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            adminPassword: changeme
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-013" not in _rule_ids(findings)

    def test_helm013_finding_has_critical_severity(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            adminPassword: realpassword123
        """,
        )
        findings = scan_values_yaml(p)
        helm013 = [f for f in findings if f.rule_id == "HELM-013"][0]
        assert helm013.severity == "critical"


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-014 (missing livenessProbe)
# ---------------------------------------------------------------------------


class TestValuesYamlLivenessProbe:
    def test_no_liveness_probe_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicaCount: 2
            image:
              repository: nginx
              tag: "1.25"
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-014" in _rule_ids(findings)

    def test_with_liveness_probe_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            livenessProbe:
              httpGet:
                path: /healthz
                port: http
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-014" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_values_yaml — HELM-015 (replicas set to 1)
# ---------------------------------------------------------------------------


class TestValuesYamlReplicas:
    def test_single_replica_flagged(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicaCount: 1
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-015" in _rule_ids(findings)

    def test_multiple_replicas_ok(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicaCount: 3
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-015" not in _rule_ids(findings)

    def test_replicas_key_also_works(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicas: 1
        """,
        )
        findings = scan_values_yaml(p)
        assert "HELM-015" in _rule_ids(findings)

    def test_helm015_finding_has_low_severity(self, tmp_path):
        p = _write(
            tmp_path,
            "values.yaml",
            """\
            replicaCount: 1
        """,
        )
        findings = scan_values_yaml(p)
        helm015 = [f for f in findings if f.rule_id == "HELM-015"][0]
        assert helm015.severity == "low"


# ---------------------------------------------------------------------------
# scan_iac_directory — end-to-end integration
# ---------------------------------------------------------------------------


class TestScanIacDirectoryHelm:
    def _make_helm_chart(self, tmp_path: Path) -> Path:
        """Create a minimal Helm chart directory with intentional misconfigurations."""
        chart_dir = tmp_path / "mychart"
        chart_dir.mkdir()
        templates_dir = chart_dir / "templates"
        templates_dir.mkdir()

        # Chart.yaml: v1 apiVersion (HELM-001) + no appVersion (HELM-002)
        (chart_dir / "Chart.yaml").write_text(
            textwrap.dedent("""\
            apiVersion: v1
            name: mychart
            version: 0.1.0
        """)
        )

        # values.yaml: hardcoded password (HELM-003) + latest tag (HELM-004)
        (chart_dir / "values.yaml").write_text(
            textwrap.dedent("""\
            image:
              repository: myapp
              tag: latest
            db:
              password: realpassword123
            service:
              type: ClusterIP
              port: 80
        """)
        )

        # A template file (not scanned by Helm scanner, but present in dir)
        (templates_dir / "deployment.yaml").write_text(
            textwrap.dedent("""\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: mychart
            spec:
              replicas: 1
              template:
                spec:
                  containers:
                  - name: app
                    image: myapp:latest
        """)
        )

        return chart_dir

    def test_helm_findings_present_in_directory_scan(self, tmp_path):
        chart_dir = self._make_helm_chart(tmp_path)
        findings = scan_iac_directory(chart_dir)
        rule_ids = _rule_ids(findings)
        assert "HELM-001" in rule_ids, f"Expected HELM-001 in {rule_ids}"
        assert "HELM-002" in rule_ids, f"Expected HELM-002 in {rule_ids}"
        assert "HELM-003" in rule_ids, f"Expected HELM-003 in {rule_ids}"
        assert "HELM-004" in rule_ids, f"Expected HELM-004 in {rule_ids}"

    def test_values_env_file_also_scanned(self, tmp_path):
        """values-prod.yaml should also be picked up by the scanner."""
        chart_dir = tmp_path / "chart"
        chart_dir.mkdir()
        (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: x\nversion: 1.0.0\nappVersion: '1.0'\n")
        (chart_dir / "values-prod.yaml").write_text(
            textwrap.dedent("""\
            image:
              tag: latest
        """)
        )
        findings = scan_iac_directory(chart_dir)
        assert "HELM-004" in _rule_ids(findings)

    def test_directory_scan_returns_list(self, tmp_path):
        findings = scan_iac_directory(tmp_path)
        assert isinstance(findings, list)


class TestAgentBomHelmChartDefaults:
    def test_repo_values_file_meets_repo_helm_security_baseline(self):
        values_path = Path("deploy/helm/agent-bom/values.yaml")
        findings = scan_values_yaml(values_path)
        rule_ids = _rule_ids(findings)

        assert "HELM-006" not in rule_ids
        assert "HELM-012" not in rule_ids
        assert "HELM-014" not in rule_ids

    def test_repo_templates_wire_security_contexts_and_network_policy(self):
        cronjob = Path("deploy/helm/agent-bom/templates/cronjob.yaml").read_text()
        daemonset = Path("deploy/helm/agent-bom/templates/daemonset.yaml").read_text()
        network_policy = Path("deploy/helm/agent-bom/templates/networkpolicy.yaml").read_text()
        service = Path("deploy/helm/agent-bom/templates/service.yaml").read_text()
        service_monitor = Path("deploy/helm/agent-bom/templates/servicemonitor.yaml").read_text()

        assert "securityContext:" in cronjob
        assert ".Values.podSecurityContext" in cronjob
        assert ".Values.securityContext" in cronjob

        assert "securityContext:" in daemonset
        assert ".Values.podSecurityContext" in daemonset
        assert ".Values.securityContext" in daemonset
        assert "readinessProbe:" in daemonset
        assert "startupProbe:" in daemonset

        assert "kind: NetworkPolicy" in network_policy
        assert ".Values.networkPolicy.enabled" in network_policy

        assert "kind: Service" in service
        assert ".Values.monitor.service.enabled" in service
        assert "kind: ServiceMonitor" in service_monitor
        assert ".Values.monitor.serviceMonitor.enabled" in service_monitor
