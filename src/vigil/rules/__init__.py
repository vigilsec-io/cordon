from .base import Finding, Rule, Severity, SEVERITY_ORDER
from .secrets import (
    AwsAccessKeyRule,
    HardcodedPasswordRule,
    HardcodedApiKeyRule,
    HardcodedTokenRule,
    EvalInjectionRule,
    ShellTrueRule,
    OsSystemRule,
)
from .docker import DockerPortExposureRule
from .dockerfile import DockerfileRootUserRule, DockerfileLatestTagRule
from .deps import PipAuditRule, NpmAuditRule

DEFAULT_RULES: list[Rule] = [
    # Secrets / injection — applies to all text file types
    AwsAccessKeyRule(),
    HardcodedPasswordRule(),
    HardcodedApiKeyRule(),
    HardcodedTokenRule(),
    EvalInjectionRule(),
    ShellTrueRule(),
    OsSystemRule(),
    # Docker IaC — the rule no existing tool catches
    DockerPortExposureRule(),
    # Dockerfile hardening
    DockerfileRootUserRule(),
    DockerfileLatestTagRule(),
    # Dependency CVE scanning
    PipAuditRule(),
    NpmAuditRule(),
]

__all__ = [
    "Finding", "Rule", "Severity", "SEVERITY_ORDER", "DEFAULT_RULES",
    "AwsAccessKeyRule", "HardcodedPasswordRule", "HardcodedApiKeyRule",
    "HardcodedTokenRule", "EvalInjectionRule", "ShellTrueRule", "OsSystemRule",
    "DockerPortExposureRule",
    "DockerfileRootUserRule", "DockerfileLatestTagRule",
    "PipAuditRule", "NpmAuditRule",
]
