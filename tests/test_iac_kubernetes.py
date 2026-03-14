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
