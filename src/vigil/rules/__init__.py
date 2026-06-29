from .base import Finding, Rule, Severity, SEVERITY_ORDER
from .secrets import (
    AwsAccessKeyRule,
    HardcodedPasswordRule,
    HardcodedApiKeyRule,
    HardcodedTokenRule,
    EvalInjectionRule,
    ShellTrueRule,
    OsSystemRule,
    JwtSecretRule,
    PemPrivateKeyRule,
    CredentialUrlRule,
    StripeLiveKeyRule,
    SlackTokenRule,
    GenericProviderKeyRule,
    InsecureConfigDefaultRule,
)
from .docker import DockerPortExposureRule, DockerComposeEnvSecretRule
from .dockerfile import DockerfileEnvSecretRule, DockerfileRootUserRule, DockerfileLatestTagRule
from .nginx import NginxSecurityHeadersRule
from .trivy import TrivyIacScanRule
from .deps import PipAuditRule, NpmAuditRule
from .k8s import K8sSecurityRule
from .iam import IamWildcardRule
from .agency import LlmShellExecRule, AutoApprovalBypassRule, UnboundedAgentLoopRule, LlmOutputFileWriteRule
from .mcp_security import McpToolPoisoningRule, McpDynamicDescriptionRule, McpShellToolRule
from .prompt_injection import (
    UserInputInSystemPromptRule,
    RawRequestAsLlmContentRule,
    TemplateInjectionInPromptRule,
    UnsanitizedToolOutputRule,
)
from .shell import ShellSecretInjectionRule
from .web import SsrfRule, SqlInjectionFstringRule, SqlOrmRawRule, CorsWildcardRule, SslVerifyDisabledRule
from .crypto import WeakRandomnessRule
from .packages import PackageAuditRule
from .terraform import TerraformHardcodedSecretRule, TerraformPublicAccessRule, TerraformEncryptionDisabledRule
from .github_actions import GhActionsSecretInRunRule, GhActionsExcessivePermissionsRule, GhActionsUnpinnedActionRule
from .xss import XssRule
from .auth import JwtAlgorithmNoneRule, JwtVerifyDisabledRule, WeakSecretKeyRule, DebugModeEnabledRule
from .rls import RlsDisabledRule, MissingTenantFilterRule
from .logging_secrets import LoggingSecretsRule

DEFAULT_RULES: list[Rule] = [
    # Secrets — hardcoded credentials
    AwsAccessKeyRule(),
    HardcodedPasswordRule(),
    HardcodedApiKeyRule(),
    HardcodedTokenRule(),
    JwtSecretRule(),
    PemPrivateKeyRule(),
    CredentialUrlRule(),
    StripeLiveKeyRule(),
    SlackTokenRule(),
    GenericProviderKeyRule(),
    # Code injection
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
    # Excessive agency — AI agents without human oversight
    LlmShellExecRule(),
    AutoApprovalBypassRule(),
    UnboundedAgentLoopRule(),
    LlmOutputFileWriteRule(),
    # MCP server security
    McpToolPoisoningRule(),
    McpDynamicDescriptionRule(),
    McpShellToolRule(),
    # Prompt injection in AI-calling code
    UserInputInSystemPromptRule(),
    RawRequestAsLlmContentRule(),
    TemplateInjectionInPromptRule(),
    UnsanitizedToolOutputRule(),
    # Shell script secret leakage
    ShellSecretInjectionRule(),
    # Web security — SSRF, SQL injection, CORS, SSL
    SsrfRule(),
    SqlInjectionFstringRule(),
    SqlOrmRawRule(),
    CorsWildcardRule(),
    SslVerifyDisabledRule(),
    # Cryptographic weaknesses
    WeakRandomnessRule(),
    # Package audit — CVE, hallucination, staleness, supply chain
    PackageAuditRule(),
    # Terraform IaC security
    TerraformHardcodedSecretRule(),
    TerraformPublicAccessRule(),
    TerraformEncryptionDisabledRule(),
    # GitHub Actions security
    GhActionsSecretInRunRule(),
    GhActionsExcessivePermissionsRule(),
    GhActionsUnpinnedActionRule(),
    # Cross-Site Scripting
    XssRule(),
    # Broken authentication
    JwtAlgorithmNoneRule(),
    JwtVerifyDisabledRule(),
    WeakSecretKeyRule(),
    DebugModeEnabledRule(),
    # Row-Level Security / data isolation
    RlsDisabledRule(),
    MissingTenantFilterRule(),
    # Sensitive data in logs
    LoggingSecretsRule(),
]

__all__ = [
    "Finding", "Rule", "Severity", "SEVERITY_ORDER", "DEFAULT_RULES",
    "AwsAccessKeyRule", "HardcodedPasswordRule", "HardcodedApiKeyRule",
    "HardcodedTokenRule", "EvalInjectionRule", "ShellTrueRule", "OsSystemRule",
    "JwtSecretRule", "PemPrivateKeyRule", "CredentialUrlRule",
    "StripeLiveKeyRule", "SlackTokenRule", "GenericProviderKeyRule",
    "DockerPortExposureRule", "DockerComposeEnvSecretRule",
    "DockerfileEnvSecretRule", "DockerfileRootUserRule", "DockerfileLatestTagRule",
    "NginxSecurityHeadersRule",
    "TrivyIacScanRule",
    "PipAuditRule", "NpmAuditRule",
    "K8sSecurityRule",
    "IamWildcardRule",
    "LlmShellExecRule", "AutoApprovalBypassRule", "UnboundedAgentLoopRule", "LlmOutputFileWriteRule",
    "McpToolPoisoningRule", "McpDynamicDescriptionRule", "McpShellToolRule",
    "UserInputInSystemPromptRule", "RawRequestAsLlmContentRule",
    "TemplateInjectionInPromptRule", "UnsanitizedToolOutputRule",
]
