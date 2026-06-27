import pytest
from vigil.rules.k8s import K8sSecurityRule
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
