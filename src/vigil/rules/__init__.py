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
from .docker import DockerPortExposureRule, DockerComposeEnvSecretRule
from .dockerfile import DockerfileEnvSecretRule, DockerfileRootUserRule, DockerfileLatestTagRule
from .nginx import NginxSecurityHeadersRule
from .trivy import TrivyIacScanRule
from .deps import PipAuditRule, NpmAuditRule
from .k8s import K8sSecurityRule
from .iam import IamWildcardRule

DEFAULT_RULES: list[Rule] = [
    # Secrets / injection — applies to all text file types
    AwsAccessKeyRule(),
    HardcodedPasswordRule(),
    HardcodedApiKeyRule(),
    HardcodedTokenRule(),
    EvalInjectionRule(),
    ShellTrueRule(),
    OsSystemRule(),
    # Docker IaC
    DockerPortExposureRule(),
    DockerComposeEnvSecretRule(),
    # Dockerfile hardening
    DockerfileEnvSecretRule(),
    DockerfileRootUserRule(),
    DockerfileLatestTagRule(),
    # nginx security
    NginxSecurityHeadersRule(),
    # Trivy IaC deep scan
    TrivyIacScanRule(),
    # Dependency CVE scanning
    PipAuditRule(),
    NpmAuditRule(),
    # Kubernetes manifest security
    K8sSecurityRule(),
    # IAM policy wildcards
    IamWildcardRule(),
]

__all__ = [
    "Finding", "Rule", "Severity", "SEVERITY_ORDER", "DEFAULT_RULES",
    "AwsAccessKeyRule", "HardcodedPasswordRule", "HardcodedApiKeyRule",
    "HardcodedTokenRule", "EvalInjectionRule", "ShellTrueRule", "OsSystemRule",
    "DockerPortExposureRule", "DockerComposeEnvSecretRule",
    "DockerfileEnvSecretRule", "DockerfileRootUserRule", "DockerfileLatestTagRule",
    "NginxSecurityHeadersRule",
    "TrivyIacScanRule",
    "PipAuditRule", "NpmAuditRule",
    "K8sSecurityRule",
    "IamWildcardRule",
]
