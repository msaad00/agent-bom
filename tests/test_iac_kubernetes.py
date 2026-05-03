"""Tests for Kubernetes manifest misconfiguration scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac.kubernetes import scan_k8s_manifest


@pytest.fixture()
def tmp_k8s(tmp_path: Path):
    """Helper to create a temporary K8s YAML file."""

    def _write(content: str, name: str = "pod.yaml") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    return _write


# ── Minimal compliant pod (baseline) ─────────────────────────────────────────

_COMPLIANT_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: compliant
  namespace: production
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
"""


class TestK8sPrivileged:
    """K8S-001: privileged: true."""

    def test_privileged_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        privileged: true
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "512Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s001 = [f for f in findings if f.rule_id == "K8S-001"]
        assert len(k8s001) == 1
        assert k8s001[0].severity == "critical"

    def test_privileged_false_ok(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s001 = [f for f in findings if f.rule_id == "K8S-001"]
        assert len(k8s001) == 0


class TestK8sHostNetwork:
    """K8S-002: hostNetwork: true."""

    def test_host_network(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  hostNetwork: true
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s002 = [f for f in findings if f.rule_id == "K8S-002"]
        assert len(k8s002) == 1


class TestK8sHostPIDIPC:
    """K8S-003: hostPID or hostIPC."""

    def test_host_pid(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  hostPID: true
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s003 = [f for f in findings if f.rule_id == "K8S-003"]
        assert len(k8s003) >= 1

    def test_host_ipc(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  hostIPC: true
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s003 = [f for f in findings if f.rule_id == "K8S-003"]
        assert len(k8s003) >= 1


class TestK8sResourceLimits:
    """K8S-004: No resource limits."""

    def test_no_limits(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s004 = [f for f in findings if f.rule_id == "K8S-004"]
        assert len(k8s004) >= 1

    def test_with_limits_ok(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s004 = [f for f in findings if f.rule_id == "K8S-004"]
        assert len(k8s004) == 0


class TestK8sRunAsRoot:
    """K8S-005: runAsUser: 0 or runAsNonRoot: false."""

    def test_run_as_user_0(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        runAsUser: 0
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s005 = [f for f in findings if f.rule_id == "K8S-005"]
        assert len(k8s005) >= 1

    def test_run_as_nonroot_false(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        runAsNonRoot: false
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s005 = [f for f in findings if f.rule_id == "K8S-005"]
        assert len(k8s005) >= 1


class TestK8sReadOnlyFS:
    """K8S-006: Missing readOnlyRootFilesystem."""

    def test_no_readonly(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s006 = [f for f in findings if f.rule_id == "K8S-006"]
        assert len(k8s006) >= 1

    def test_readonly_set(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s006 = [f for f in findings if f.rule_id == "K8S-006"]
        assert len(k8s006) == 0


class TestK8sSecretInEnv:
    """K8S-007: Secrets in plain env values."""

    def test_secret_in_env_value(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      env:
        - name: DB_PASSWORD
          value: "supersecretpassword123"
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s007 = [f for f in findings if f.rule_id == "K8S-007"]
        assert len(k8s007) >= 1
        assert k8s007[0].severity == "critical"

    def test_secret_ref_ok(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s007 = [f for f in findings if f.rule_id == "K8S-007"]
        assert len(k8s007) == 0


class TestK8sDefaultNamespace:
    """K8S-008: Using default namespace."""

    def test_default_namespace(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: default
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s008 = [f for f in findings if f.rule_id == "K8S-008"]
        assert len(k8s008) >= 1

    def test_named_namespace_ok(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s008 = [f for f in findings if f.rule_id == "K8S-008"]
        assert len(k8s008) == 0


class TestK8sPrivilegeEscalation:
    """K8S-009: allowPrivilegeEscalation: true."""

    def test_allow_escalation(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s009 = [f for f in findings if f.rule_id == "K8S-009"]
        assert len(k8s009) >= 1


class TestK8sServiceAccountToken:
    """K8S-010: automountServiceAccountToken not false."""

    def test_token_mounted(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s010 = [f for f in findings if f.rule_id == "K8S-010"]
        assert len(k8s010) >= 1

    def test_token_disabled_ok(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s010 = [f for f in findings if f.rule_id == "K8S-010"]
        assert len(k8s010) == 0


class TestK8sDeployment:
    """Scanner handles Deployment kind (not just Pod)."""

    def test_deployment(self, tmp_k8s):
        content = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            privileged: true
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s001 = [f for f in findings if f.rule_id == "K8S-001"]
        assert len(k8s001) >= 1


class TestK8sMultiDoc:
    """Scanner handles multi-document YAML."""

    def test_multi_doc(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        privileged: true
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:2.0
      securityContext:
        privileged: true
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s001 = [f for f in findings if f.rule_id == "K8S-001"]
        # Should detect privileged in both documents
        assert len(k8s001) >= 2


class TestK8sLivenessProbe:
    """K8S-022: Container without liveness probe."""

    def test_no_liveness_probe(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s022 = [f for f in findings if f.rule_id == "K8S-022"]
        assert len(k8s022) >= 1

    def test_with_liveness_probe(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s022 = [f for f in findings if f.rule_id == "K8S-022"]
        assert len(k8s022) == 0


class TestK8sReadinessProbe:
    """K8S-023: Container without readiness probe."""

    def test_no_readiness_probe(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s023 = [f for f in findings if f.rule_id == "K8S-023"]
        assert len(k8s023) >= 1

    def test_with_readiness_probe(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      readinessProbe:
        tcpSocket:
          port: 8080
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s023 = [f for f in findings if f.rule_id == "K8S-023"]
        assert len(k8s023) == 0


class TestK8sServiceAccountAutoMount:
    """K8S-024: ServiceAccount with automountServiceAccountToken: true."""

    def test_sa_automount_true(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: prod
automountServiceAccountToken: true
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s024 = [f for f in findings if f.rule_id == "K8S-024"]
        assert len(k8s024) == 1
        assert k8s024[0].severity == "medium"

    def test_sa_automount_false_ok(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: prod
automountServiceAccountToken: false
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s024 = [f for f in findings if f.rule_id == "K8S-024"]
        assert len(k8s024) == 0


class TestK8sClusterRoleBinding:
    """K8S-025: ClusterRoleBinding with cluster-admin role."""

    def test_cluster_admin_binding(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: dev-user
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s025 = [f for f in findings if f.rule_id == "K8S-025"]
        assert len(k8s025) == 1
        assert k8s025[0].severity == "critical"

    def test_non_admin_binding_ok(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: view-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: User
    name: dev-user
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s025 = [f for f in findings if f.rule_id == "K8S-025"]
        assert len(k8s025) == 0


class TestK8sHostPort:
    """K8S-026: Pod with hostPort specified."""

    def test_host_port_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      ports:
        - containerPort: 8080
          hostPort: 8080
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s026 = [f for f in findings if f.rule_id == "K8S-026"]
        assert len(k8s026) >= 1


class TestK8sDockerSocket:
    """K8S-027: Container with writable /var/run/docker.sock mount."""

    def test_docker_sock_writable(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s027 = [f for f in findings if f.rule_id == "K8S-027"]
        assert len(k8s027) >= 1
        assert k8s027[0].severity == "critical"

    def test_docker_sock_readonly_ok(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
          readOnly: true
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s027 = [f for f in findings if f.rule_id == "K8S-027"]
        assert len(k8s027) == 0


class TestK8sNetworkPolicyEgress:
    """K8S-028: NetworkPolicy missing egress rules."""

    def test_no_egress(self, tmp_k8s):
        content = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s028 = [f for f in findings if f.rule_id == "K8S-028"]
        assert len(k8s028) >= 1

    def test_with_egress_ok(self, tmp_k8s):
        content = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  egress:
    - to:
        - podSelector: {}
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s028 = [f for f in findings if f.rule_id == "K8S-028"]
        assert len(k8s028) == 0


class TestK8sUntrustedRegistry:
    """K8S-029: Container image from untrusted registry."""

    def test_untrusted_registry(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: evil-registry.io/malicious:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s029 = [f for f in findings if f.rule_id == "K8S-029"]
        assert len(k8s029) >= 1
        assert k8s029[0].severity == "high"

    def test_trusted_registry_ok(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: gcr.io/my-project/myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s029 = [f for f in findings if f.rule_id == "K8S-029"]
        assert len(k8s029) == 0

    def test_docker_hub_library_ok(self, tmp_k8s):
        """Docker Hub library images (no registry prefix) are trusted."""
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s029 = [f for f in findings if f.rule_id == "K8S-029"]
        assert len(k8s029) == 0


class TestK8sPodAntiAffinity:
    """K8S-030: Deployment without PodAntiAffinity."""

    def test_no_anti_affinity(self, tmp_k8s):
        content = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s030 = [f for f in findings if f.rule_id == "K8S-030"]
        assert len(k8s030) >= 1

    def test_with_anti_affinity_ok(self, tmp_k8s):
        content = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deploy
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: kubernetes.io/hostname
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s030 = [f for f in findings if f.rule_id == "K8S-030"]
        assert len(k8s030) == 0


class TestK8sSeccompProfile:
    """K8S-031: Missing seccompProfile."""

    def test_no_seccomp(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s031 = [f for f in findings if f.rule_id == "K8S-031"]
        assert len(k8s031) >= 1

    def test_with_pod_seccomp_ok(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s031 = [f for f in findings if f.rule_id == "K8S-031"]
        assert len(k8s031) == 0


class TestK8sNetAdmin:
    """K8S-032: Container with NET_ADMIN capability."""

    def test_net_admin(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
        capabilities:
          add:
            - NET_ADMIN
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s032 = [f for f in findings if f.rule_id == "K8S-032"]
        assert len(k8s032) >= 1
        assert k8s032[0].severity == "high"


class TestK8sShareProcessNamespace:
    """K8S-033: Pod with shareProcessNamespace: true."""

    def test_share_process_namespace(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: prod
spec:
  shareProcessNamespace: true
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s033 = [f for f in findings if f.rule_id == "K8S-033"]
        assert len(k8s033) >= 1
        assert k8s033[0].severity == "medium"

    def test_no_share_process_namespace_ok(self, tmp_k8s):
        findings = scan_k8s_manifest(tmp_k8s(_COMPLIANT_POD))
        k8s033 = [f for f in findings if f.rule_id == "K8S-033"]
        assert len(k8s033) == 0


class TestK8sPodDisruptionBudget:
    """K8S-021: Missing PodDisruptionBudget for Deployments."""

    def test_deployment_without_pdb(self, tmp_k8s):
        content = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: "256Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s021 = [f for f in findings if f.rule_id == "K8S-021"]
        assert len(k8s021) >= 1

    def test_deployment_with_pdb_ok(self, tmp_k8s):
        content = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: prod
spec:
  replicas: 3
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: "256Mi"
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-app-pdb
  namespace: prod
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: web-app
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s021 = [f for f in findings if f.rule_id == "K8S-021"]
        assert len(k8s021) == 0


class TestK8sCompliance:
    """All findings have compliance tags."""

    def test_compliance_tags(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        privileged: true
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        for f in findings:
            assert len(f.compliance) > 0, f"Finding {f.rule_id} has no compliance tags"
            assert f.category == "kubernetes"


class TestK8sGpuPrivilegeEscape:
    """K8S-034: GPU container with privileged mode or allowPrivilegeEscalation."""

    def test_gpu_privileged_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: gpu-workload
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: trainer
      image: nvcr.io/nvidia/pytorch:23.10-py3
      securityContext:
        privileged: true
        readOnlyRootFilesystem: false
      resources:
        limits:
          nvidia.com/gpu: "1"
          cpu: "4"
          memory: "16Gi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s034 = [f for f in findings if f.rule_id == "K8S-034"]
        assert len(k8s034) == 1
        assert k8s034[0].severity == "critical"
        assert "T1611" in k8s034[0].attack_techniques

    def test_gpu_allow_privilege_escalation_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: gpu-workload
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: trainer
      image: nvcr.io/nvidia/cuda:12.3
      securityContext:
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: false
      resources:
        limits:
          nvidia.com/gpu: "2"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s034 = [f for f in findings if f.rule_id == "K8S-034"]
        assert len(k8s034) == 1
        assert k8s034[0].severity == "critical"

    def test_gpu_without_privilege_not_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: gpu-workload
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: trainer
      image: nvcr.io/nvidia/cuda:12.3
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
      resources:
        limits:
          nvidia.com/gpu: "1"
          cpu: "4"
          memory: "16Gi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s034 = [f for f in findings if f.rule_id == "K8S-034"]
        assert len(k8s034) == 0

    def test_non_gpu_privileged_does_not_trigger_k8s034(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: priv-app
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: "1"
          memory: "512Mi"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s034 = [f for f in findings if f.rule_id == "K8S-034"]
        assert len(k8s034) == 0

    def test_amd_gpu_privileged_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: amd-gpu-workload
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: rocm-trainer
      image: rocm/pytorch:latest
      securityContext:
        privileged: true
        readOnlyRootFilesystem: false
      resources:
        limits:
          amd.com/gpu: "1"
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s034 = [f for f in findings if f.rule_id == "K8S-034"]
        assert len(k8s034) == 1
        assert k8s034[0].severity == "critical"


class TestK8sNvidiaDeviceExposure:
    """K8S-035: hostPath volume mounting /dev/nvidia or /proc/driver/nvidia."""

    def test_dev_nvidia_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: gpu-direct
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: nvcr.io/nvidia/cuda:12.3
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "1Gi"
      volumeMounts:
        - name: nvidia-dev
          mountPath: /dev/nvidia0
  volumes:
    - name: nvidia-dev
      hostPath:
        path: /dev/nvidia0
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s035 = [f for f in findings if f.rule_id == "K8S-035"]
        assert len(k8s035) == 1
        assert k8s035[0].severity == "critical"
        assert "T1611" in k8s035[0].attack_techniques

    def test_proc_driver_nvidia_flagged(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: gpu-direct
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: nvcr.io/nvidia/cuda:12.3
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "1Gi"
  volumes:
    - name: nv-proc
      hostPath:
        path: /proc/driver/nvidia
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s035 = [f for f in findings if f.rule_id == "K8S-035"]
        assert len(k8s035) == 1
        assert k8s035[0].severity == "critical"

    def test_non_nvidia_hostpath_not_flagged_by_035(self, tmp_k8s):
        content = """\
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: prod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: "1Gi"
  volumes:
    - name: data
      hostPath:
        path: /var/data
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s035 = [f for f in findings if f.rule_id == "K8S-035"]
        assert len(k8s035) == 0


class TestK8sNvidiaDevicePluginRBAC:
    """K8S-036: nvidia-device-plugin ClusterRole with mutation verbs."""

    def test_mutation_verbs_flagged(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nvidia-device-plugin
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch", "update", "patch"]
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s036 = [f for f in findings if f.rule_id == "K8S-036"]
        assert len(k8s036) == 1
        assert k8s036[0].severity == "high"
        assert "update" in k8s036[0].message or "patch" in k8s036[0].message

    def test_read_only_verbs_not_flagged(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nvidia-device-plugin
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s036 = [f for f in findings if f.rule_id == "K8S-036"]
        assert len(k8s036) == 0

    def test_non_device_plugin_role_not_flagged(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-app-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "delete", "update"]
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s036 = [f for f in findings if f.rule_id == "K8S-036"]
        assert len(k8s036) == 0

    def test_delete_verb_flagged(self, tmp_k8s):
        content = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nvidia-device-plugin-manager
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "delete"]
"""
        findings = scan_k8s_manifest(tmp_k8s(content))
        k8s036 = [f for f in findings if f.rule_id == "K8S-036"]
        assert len(k8s036) == 1
