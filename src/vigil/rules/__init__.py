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
from .docker import (
    DockerPortExposureRule, DockerComposeEnvSecretRule,
    DockerPrivilegedRule, DockerHostNetworkRule,
    DockerSocketMountRule, DockerDangerousVolumeRule,
)
from .dockerfile import (
    DockerfileEnvSecretRule, DockerfileRootUserRule, DockerfileLatestTagRule,
    DockerfileCurlBashRule, DockerfileInsecureFetchRule,
    DockerfileAddLocalRule, DockerfileWildcardCopyRule, DockerfileChmod777Rule,
)
from .nginx import NginxSecurityHeadersRule
from .trivy import TrivyIacScanRule
from .deps import PipAuditRule, NpmAuditRule
from .k8s import K8sSecurityRule, K8sPrivilegeEscalationRule, K8sCapabilitiesRule, K8sHostPathVolumeRule
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
from .terraform import (
    TerraformHardcodedSecretRule, TerraformPublicAccessRule, TerraformEncryptionDisabledRule,
    TerraformImdsv1Rule, TerraformStateEncryptionRule,
    TerraformDeletionProtectionRule, TerraformLoggingDisabledRule,
)
from .github_actions import GhActionsSecretInRunRule, GhActionsExcessivePermissionsRule, GhActionsUnpinnedActionRule
from .gha import (
    GhaPwnRequestRule, GhaScriptInjectionRule, GhaSecretsInRunRule,
    GhaMissingPermissionsRule, GhaCachePoisoningRule,
    GhaSelfHostedOnPrRule, GhaWorkflowRunNoRefRule,
)
from .xss import XssRule
from .auth import JwtAlgorithmNoneRule, JwtVerifyDisabledRule, WeakSecretKeyRule, DebugModeEnabledRule
from .rls import RlsDisabledRule, MissingTenantFilterRule
from .logging_secrets import LoggingSecretsRule, ErrorLeakRule, SilentAuthExceptionRule, CrlfLogInjectionRule
from .deserialization import (
    PickleDeserializeRule, YamlLoadRule, MarshalDeserializeRule,
    PathTraversalRule, SstiRule,
)
from .js_security import ProcessEnvFallbackRule, JsEvalNewFunctionRule
from .swift import SwiftHardcodedSecretRule, SwiftPlainHttpRule, SwiftUserDefaultsSecretRule, SwiftSslBypassRule

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
    InsecureConfigDefaultRule(),
    # Code injection
    EvalInjectionRule(),
    ShellTrueRule(),
    OsSystemRule(),
    # Docker IaC
    DockerPortExposureRule(),
    DockerComposeEnvSecretRule(),
    DockerPrivilegedRule(),
    DockerHostNetworkRule(),
    DockerSocketMountRule(),
    DockerDangerousVolumeRule(),
    # Dockerfile hardening
    DockerfileEnvSecretRule(),
    DockerfileRootUserRule(),
    DockerfileLatestTagRule(),
    DockerfileCurlBashRule(),
    DockerfileInsecureFetchRule(),
    DockerfileAddLocalRule(),
    DockerfileWildcardCopyRule(),
    DockerfileChmod777Rule(),
    # nginx security
    NginxSecurityHeadersRule(),
    # Trivy IaC deep scan
    TrivyIacScanRule(),
    # Dependency CVE scanning
    PipAuditRule(),
    NpmAuditRule(),
    # Kubernetes manifest security
    K8sSecurityRule(),
    K8sPrivilegeEscalationRule(),
    K8sCapabilitiesRule(),
    K8sHostPathVolumeRule(),
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
    TerraformImdsv1Rule(),
    TerraformStateEncryptionRule(),
    TerraformDeletionProtectionRule(),
    TerraformLoggingDisabledRule(),
    # GitHub Actions security (legacy GH001-003)
    GhActionsSecretInRunRule(),
    GhActionsExcessivePermissionsRule(),
    GhActionsUnpinnedActionRule(),
    # GitHub Actions security — advanced (GHA001-008)
    GhaPwnRequestRule(),
    GhaScriptInjectionRule(),
    GhaSecretsInRunRule(),
    GhaMissingPermissionsRule(),
    GhaCachePoisoningRule(),
    GhaSelfHostedOnPrRule(),
    GhaWorkflowRunNoRefRule(),
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
    ErrorLeakRule(),
    SilentAuthExceptionRule(),
    CrlfLogInjectionRule(),
    # Insecure deserialization, path traversal, SSTI
    PickleDeserializeRule(),
    YamlLoadRule(),
    MarshalDeserializeRule(),
    PathTraversalRule(),
    SstiRule(),
    # JS/TS specific
    ProcessEnvFallbackRule(),
    JsEvalNewFunctionRule(),
    # Swift / iOS security
    SwiftHardcodedSecretRule(),
    SwiftPlainHttpRule(),
    SwiftUserDefaultsSecretRule(),
    SwiftSslBypassRule(),
]

__all__ = [
    "Finding", "Rule", "Severity", "SEVERITY_ORDER", "DEFAULT_RULES",
    "AwsAccessKeyRule", "HardcodedPasswordRule", "HardcodedApiKeyRule",
    "HardcodedTokenRule", "EvalInjectionRule", "ShellTrueRule", "OsSystemRule",
    "JwtSecretRule", "PemPrivateKeyRule", "CredentialUrlRule",
    "StripeLiveKeyRule", "SlackTokenRule", "GenericProviderKeyRule", "InsecureConfigDefaultRule",
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
