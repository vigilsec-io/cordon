"""
VGL-K001  CRITICAL/HIGH  Kubernetes pod/container host namespace sharing (privileged, hostNetwork, hostPID, hostIPC)
VGL-K002  CRITICAL       allowPrivilegeEscalation: true — container can gain elevated privileges
VGL-K003  HIGH           Dangerous Linux capabilities added (ALL, SYS_ADMIN, SYS_PTRACE, NET_RAW, etc.)
VGL-K004  CRITICAL/HIGH  Sensitive host path mounted via hostPath volume
"""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_PRIV_PAT = re.compile(r"^\s+privileged\s*:\s*true\b", re.IGNORECASE)
_HOST_NET_PAT = re.compile(r"^\s+hostNetwork\s*:\s*true\b", re.IGNORECASE)
_HOST_PID_PAT = re.compile(r"^\s+hostPID\s*:\s*true\b", re.IGNORECASE)
_HOST_IPC_PAT = re.compile(r"^\s+hostIPC\s*:\s*true\b", re.IGNORECASE)
_API_VER_PAT = re.compile(r"^apiVersion\s*:", re.IGNORECASE)


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix not in (".yml", ".yaml"):
        return False
    try:
        return bool(_API_VER_PAT.search(path.read_text(errors="replace")))
    except OSError:
        return False


class K8sSecurityRule(Rule):
    id = "VGL-K001"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        return _is_k8s_manifest(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for i, line in enumerate(lines, 1):
            if _PRIV_PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message="privileged: true — container has full host kernel access",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Set 'privileged: false' or remove the field (false is the default).",
                ))
            elif _HOST_NET_PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    message="hostNetwork: true — pod shares the host network namespace",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Remove hostNetwork or set to false; use a Service/Ingress instead.",
                ))
            elif _HOST_PID_PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    message="hostPID: true — pod can see all host processes",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Remove hostPID or set to false.",
                ))
            elif _HOST_IPC_PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    message="hostIPC: true — pod shares host IPC namespace",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Remove hostIPC or set to false.",
                ))
        return findings


class K8sPrivilegeEscalationRule(Rule):
    """VGL-K002 — allowPrivilegeEscalation: true lets processes gain privileges via setuid binaries."""

    id = "VGL-K002"
    name = "allowPrivilegeEscalation enabled in Kubernetes securityContext"
    severity = Severity.CRITICAL

    _PAT = re.compile(r"^\s+allowPrivilegeEscalation\s*:\s*true\b", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return _is_k8s_manifest(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="allowPrivilegeEscalation: true — container processes can gain more privileges than their parent via setuid/setgid binaries",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Set allowPrivilegeEscalation: false in the container's securityContext. This is the recommended default and is required by most Pod Security Standards.",
                ))
        return findings


_ADD_SEC = re.compile(r"^\s+add\s*:", re.IGNORECASE)
_DROP_SEC = re.compile(r"^\s+drop\s*:", re.IGNORECASE)


def _in_add_section(lines: list[str], idx: int) -> bool:
    """Scan back up to 6 lines from idx (0-based) to find the nearest add: or drop: header."""
    for j in range(idx - 1, max(idx - 7, -1), -1):
        if _ADD_SEC.search(lines[j]):
            return True
        if _DROP_SEC.search(lines[j]):
            return False
    return True  # no section header found — assume add (conservative)


class K8sCapabilitiesRule(Rule):
    """VGL-K003 — Overly broad Linux capabilities added to a container."""

    id = "VGL-K003"
    name = "Dangerous Linux capabilities added in Kubernetes securityContext"
    severity = Severity.HIGH

    # List-style: - ALL  (check context to distinguish add vs drop)
    _ALL_LIST = re.compile(r"^\s+-\s+ALL\b")
    # Inline add: [ALL] — already scoped to add: by regex
    _ALL_INLINE = re.compile(r"add\s*:\s*\[.*\bALL\b", re.IGNORECASE)
    _DANGEROUS_LIST = re.compile(
        r"^\s+-\s+(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|SYS_BOOT|NET_RAW|NET_ADMIN|DAC_OVERRIDE|DAC_READ_SEARCH)\b"
    )
    _DANGEROUS_INLINE = re.compile(
        r"add\s*:\s*\[.*\b(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE|NET_RAW|NET_ADMIN|DAC_OVERRIDE)\b",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return _is_k8s_manifest(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._ALL_LIST.search(line):
                # drop: [ALL] is the recommended pattern — only flag if under add:
                if not _in_add_section(lines, i - 1):
                    continue
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message="capabilities.add: [ALL] — grants every Linux capability; equivalent to privileged mode",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Drop ALL and add only the specific capabilities required: capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}",
                ))
            elif self._ALL_INLINE.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message="capabilities.add: [ALL] — grants every Linux capability; equivalent to privileged mode",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Drop ALL and add only the specific capabilities required: capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}",
                ))
            elif self._DANGEROUS_LIST.search(line) and _in_add_section(lines, i - 1):
                cap = self._DANGEROUS_LIST.search(line).group(0).split()[-1]
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Dangerous capability added: {cap} — allows significant host privilege escalation",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix=f"Remove {cap} from capabilities.add. Drop ALL capabilities and add only the minimum required: capabilities: {{drop: [ALL], add: [<minimal-cap>]}}",
                ))
            elif self._DANGEROUS_INLINE.search(line):
                cap = self._DANGEROUS_INLINE.search(line).group(0).split()[-1].rstrip("]")
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Dangerous capability added: {cap} — allows significant host privilege escalation",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix=f"Remove {cap} from capabilities.add. Drop ALL capabilities and add only the minimum required: capabilities: {{drop: [ALL], add: [<minimal-cap>]}}",
                ))
        return findings


class K8sHostPathVolumeRule(Rule):
    """VGL-K004 — Sensitive host paths mounted via hostPath into a pod."""

    id = "VGL-K004"
    name = "Sensitive hostPath volume in Kubernetes manifest"
    severity = Severity.HIGH

    _HOSTPATH = re.compile(r"^\s+hostPath\s*:", re.IGNORECASE)
    _SENSITIVE = re.compile(
        r"^\s+path\s*:\s*(/var/run/docker\.sock|/etc|/proc|/sys|/root|/home|/var/run)\b"
    )
    _DOCKER_SOCK = re.compile(r"/var/run/docker\.sock")

    def applies_to(self, path: Path) -> bool:
        return _is_k8s_manifest(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if not self._HOSTPATH.search(line):
                continue
            # Check the next 4 lines for the path: value
            for j in range(i, min(i + 5, len(lines))):
                m = self._SENSITIVE.search(lines[j])
                if m:
                    mounted = m.group(1)
                    sev = Severity.CRITICAL if self._DOCKER_SOCK.search(lines[j]) else Severity.HIGH
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=sev,
                        message=f"hostPath volume mounts '{mounted}' — exposes sensitive host filesystem to the pod",
                        file_path=path,
                        line=j + 1,
                        snippet=lines[j].strip(),
                        fix="Remove the hostPath volume. Use ConfigMap for configuration, PersistentVolumeClaim for data, or emptyDir for scratch space. Mounting sensitive host paths allows container escape and data exfiltration.",
                    ))
                    break
        return findings
