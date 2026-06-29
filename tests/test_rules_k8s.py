import pytest
from vigil.rules.k8s import K8sSecurityRule, K8sPrivilegeEscalationRule, K8sCapabilitiesRule, K8sHostPathVolumeRule
from vigil.rules.base import Severity

rule = K8sSecurityRule()

_K8S_PRIVILEGED = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
"""

_K8S_HOST_NET = """\
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
"""

_K8S_HOST_PID = """\
apiVersion: v1
kind: Pod
spec:
  hostPID: true
"""

_K8S_HOST_IPC = """\
apiVersion: v1
kind: Pod
spec:
  hostIPC: true
"""

_K8S_CLEAN = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: python:3.12-slim
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
"""

_NOT_K8S = """\
services:
  api:
    image: python:3.12-slim
"""


def test_privileged_true_flagged_critical(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_PRIVILEGED)
    findings = rule.check(f)
    assert any(fi.severity == Severity.CRITICAL for fi in findings)
    assert any("privileged" in fi.message for fi in findings)


def test_host_network_flagged_high(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_HOST_NET)
    findings = rule.check(f)
    assert any(fi.severity == Severity.HIGH for fi in findings)
    assert any("hostNetwork" in fi.message for fi in findings)


def test_host_pid_flagged_high(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_HOST_PID)
    findings = rule.check(f)
    assert any("hostPID" in fi.message for fi in findings)


def test_host_ipc_flagged(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_HOST_IPC)
    findings = rule.check(f)
    assert any("hostIPC" in fi.message for fi in findings)


def test_clean_k8s_manifest_no_findings(tmp_path):
    f = tmp_path / "deploy.yaml"
    f.write_text(_K8S_CLEAN)
    findings = rule.check(f)
    assert findings == []


def test_finding_has_line_number(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_PRIVILEGED)
    findings = rule.check(f)
    assert all(fi.line is not None and fi.line > 0 for fi in findings)


def test_applies_to_k8s_yaml(tmp_path):
    f = tmp_path / "pod.yaml"
    f.write_text(_K8S_PRIVILEGED)
    assert rule.applies_to(f) is True


def test_does_not_apply_to_docker_compose(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_NOT_K8S)
    assert rule.applies_to(f) is False


def test_does_not_apply_to_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("print('hello')")
    assert rule.applies_to(f) is False


# ── VGL-K002 — allowPrivilegeEscalation ──────────────────────────────────────

_K8S_PRIV_ESC = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: true
"""

_K8S_PRIV_ESC_FALSE = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
"""


class TestK8sPrivilegeEscalationRule:
    rule = K8sPrivilegeEscalationRule()

    def test_detects_allow_priv_esc_true(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_PRIV_ESC)
        assert self.rule.check(f)

    def test_ignores_allow_priv_esc_false(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_PRIV_ESC_FALSE)
        assert not self.rule.check(f)

    def test_ignores_clean_manifest(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text(_K8S_CLEAN)
        assert not self.rule.check(f)

    def test_finding_is_critical(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_PRIV_ESC)
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_PRIV_ESC)
        assert self.rule.check(f)[0].rule_id == "VGL-K002"

    def test_fix_mentions_false(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_PRIV_ESC)
        assert "false" in self.rule.check(f)[0].fix

    def test_does_not_apply_to_non_k8s(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_NOT_K8S)
        assert not self.rule.applies_to(f)


# ── VGL-K003 — Dangerous capabilities ────────────────────────────────────────

_K8S_CAP_ALL = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          add:
          - ALL
"""

_K8S_CAP_ALL_INLINE = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          add: [ALL]
"""

_K8S_CAP_SYS_ADMIN = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          add:
          - SYS_ADMIN
"""

_K8S_CAP_DROP_ALL = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          drop:
          - ALL
          add:
          - NET_BIND_SERVICE
"""


class TestK8sCapabilitiesRule:
    rule = K8sCapabilitiesRule()

    def test_detects_cap_all_list(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_ALL)
        assert self.rule.check(f)

    def test_detects_cap_all_inline(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_ALL_INLINE)
        assert self.rule.check(f)

    def test_all_finding_is_critical(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_ALL)
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_detects_sys_admin(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_SYS_ADMIN)
        assert self.rule.check(f)

    def test_sys_admin_finding_is_high(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_SYS_ADMIN)
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_ignores_drop_all_add_minimal(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_DROP_ALL)
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_CAP_ALL)
        assert self.rule.check(f)[0].rule_id == "VGL-K003"

    def test_does_not_apply_to_non_k8s(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_NOT_K8S)
        assert not self.rule.applies_to(f)


# ── VGL-K004 — hostPath volumes ───────────────────────────────────────────────

_K8S_HOSTPATH_DOCKER_SOCK = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: ci
      volumeMounts:
        - name: docker-socket
          mountPath: /var/run/docker.sock
  volumes:
    - name: docker-socket
      hostPath:
        path: /var/run/docker.sock
        type: Socket
"""

_K8S_HOSTPATH_ETC = """\
apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: etc
      hostPath:
        path: /etc
"""

_K8S_SAFE_PVC = """\
apiVersion: v1
kind: Pod
spec:
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: my-pvc
"""


class TestK8sHostPathVolumeRule:
    rule = K8sHostPathVolumeRule()

    def test_detects_docker_sock_as_critical(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_HOSTPATH_DOCKER_SOCK)
        findings = self.rule.check(f)
        assert findings
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_etc_as_high(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_HOSTPATH_ETC)
        findings = self.rule.check(f)
        assert findings
        assert findings[0].severity == Severity.HIGH

    def test_ignores_pvc(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_SAFE_PVC)
        assert not self.rule.check(f)

    def test_ignores_clean_manifest(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text(_K8S_CLEAN)
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_HOSTPATH_ETC)
        assert self.rule.check(f)[0].rule_id == "VGL-K004"

    def test_fix_mentions_pvc(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_K8S_HOSTPATH_ETC)
        assert "PersistentVolumeClaim" in self.rule.check(f)[0].fix

    def test_does_not_apply_to_non_k8s(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_NOT_K8S)
        assert not self.rule.applies_to(f)
