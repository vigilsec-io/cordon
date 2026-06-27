"""VGL-K001 — Kubernetes manifest security misconfigurations."""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_PRIV_PAT = re.compile(r"^\s+privileged\s*:\s*true\b", re.IGNORECASE)
_HOST_NET_PAT = re.compile(r"^\s+hostNetwork\s*:\s*true\b", re.IGNORECASE)
_HOST_PID_PAT = re.compile(r"^\s+hostPID\s*:\s*true\b", re.IGNORECASE)
_HOST_IPC_PAT = re.compile(r"^\s+hostIPC\s*:\s*true\b", re.IGNORECASE)
_API_VER_PAT = re.compile(r"^apiVersion\s*:", re.IGNORECASE)


class K8sSecurityRule(Rule):
    id = "VGL-K001"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        if path.suffix not in (".yml", ".yaml"):
            return False
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return False
        return bool(_API_VER_PAT.search(text))

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
