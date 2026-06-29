"""
VGL-SW001  CRITICAL  Hardcoded secret in Swift string literal
VGL-SW002  HIGH      HTTP (non-TLS) URL in Swift networking code
VGL-SW003  HIGH      Sensitive value written to UserDefaults (unencrypted on-device storage)
VGL-SW004  CRITICAL  SSL certificate validation bypassed in URLSession delegate
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SWIFT = {".swift"}

# Security-sensitive Swift variable / property names
_SECRET_NAME = re.compile(
    r"\b(?:apiKey|api_key|apiSecret|api_secret|accessToken|access_token|"
    r"refreshToken|refresh_token|authToken|auth_token|bearerToken|bearer_token|"
    r"clientSecret|client_secret|jwtSecret|jwt_secret|signingKey|signing_key|"
    r"encryptionKey|encryption_key|privateKey|private_key|"
    r"password|passwd|pwd|secret|credential|token)\b",
    re.IGNORECASE,
)


# ── VGL-SW001 — Hardcoded secret string literal ───────────────────────────────

class SwiftHardcodedSecretRule(Rule):
    id = "VGL-SW001"
    name = "Hardcoded secret in Swift string literal"
    severity = Severity.CRITICAL

    # let/var <secret-name>[: Type] = "value-with-6+-chars"
    _PAT = re.compile(
        r'(?:let|var)\s+\w*(?:key|token|secret|password|passwd|pwd|api|auth|'
        r'credential|jwt|bearer|signing|encryption|private)\w*'
        r'\s*(?::\s*String\s*)?=\s*"[^"]{6,}"',
        re.IGNORECASE,
    )
    # Also catch: static let / private let
    _STATIC = re.compile(
        r'(?:static|private|internal|public|fileprivate)\s+(?:let|var)\s+'
        r'\w*(?:key|token|secret|password|api|auth|credential)\w*\s*'
        r'(?::\s*String\s*)?=\s*"[^"]{6,}"',
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _SWIFT

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if "vigil: ignore" in line:
                continue
            if self._PAT.search(line) or self._STATIC.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Hardcoded secret in Swift source — value visible in compiled binary and git history",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Store secrets in the iOS Keychain (KeychainHelper) or load from a "
                        "remote config endpoint at runtime. Never hardcode credentials in source — "
                        "they are extractable from the .ipa binary with standard tools (strings, otool)."
                    ),
                ))
        return findings


# ── VGL-SW002 — Plain HTTP URL ────────────────────────────────────────────────

class SwiftPlainHttpRule(Rule):
    id = "VGL-SW002"
    name = "Plain HTTP URL in Swift networking code"
    severity = Severity.HIGH

    # "http://<something>" that is not localhost/127.0.0.1 — in a Swift file
    _PAT = re.compile(
        r'"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^"]{4,}"',
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _SWIFT

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if "vigil: ignore" in line:
                continue
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Plain HTTP URL — traffic is unencrypted and interceptable via network proxy",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        'Change to "https://". '
                        "iOS App Transport Security (ATS) blocks plain HTTP by default — "
                        "using http:// requires an NSAllowsArbitraryLoads exception in Info.plist, "
                        "which Apple flags during App Store review."
                    ),
                ))
        return findings


# ── VGL-SW003 — Sensitive value in UserDefaults ───────────────────────────────

class SwiftUserDefaultsSecretRule(Rule):
    id = "VGL-SW003"
    name = "Sensitive value written to UserDefaults (unencrypted)"
    severity = Severity.HIGH

    # UserDefaults.standard.set(...) or defaults.set(...)
    _SET_CALL = re.compile(
        r"""UserDefaults\b.*\.\s*(?:set|setValue|setObject)\s*\(|"""
        r"""defaults\s*\.\s*(?:set|setValue|setObject)\s*\(""",
        re.IGNORECASE,
    )
    # forKey: "sensitive-name" or just a sensitive variable being set
    _SENSITIVE_KEY = re.compile(
        r'forKey\s*:\s*"[^"]*(?:token|key|secret|password|auth|credential|jwt|api)[^"]*"'
        r'|(?:set|setValue|setObject)\s*\(\s*\w*(?:token|key|secret|password|auth|credential)\w*',
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _SWIFT

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if "vigil: ignore" in line:
                continue
            if self._SET_CALL.search(line) and self._SENSITIVE_KEY.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Sensitive value stored in UserDefaults — plaintext, readable in iTunes backups and on jailbroken devices",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use the iOS Keychain instead: SecItemAdd / SecItemCopyMatching, "
                        "or a wrapper like KeychainAccess. "
                        "UserDefaults is stored as a plaintext plist in the app's Library/Preferences "
                        "directory — visible in device backups and on rooted devices."
                    ),
                ))
        return findings


# ── VGL-SW004 — SSL certificate validation bypass ─────────────────────────────

class SwiftSslBypassRule(Rule):
    id = "VGL-SW004"
    name = "SSL certificate validation bypassed in URLSession delegate"
    severity = Severity.CRITICAL

    # completionHandler(.useCredential, URLCredential(trust:...)) without SecTrustEvaluate
    _BYPASS = re.compile(
        r"""completionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(""",
        re.IGNORECASE,
    )
    # SecTrustResultType.proceed without evaluation, or evaluateWithError always succeeding
    _TRUST_PROCEED = re.compile(
        r"""SecTrustEvaluate\s*\([^)]+,\s*nil\)|"""
        r"""\.proceed\b|"""
        r"""forceAllowHTTPSCertificate""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _SWIFT

    # Safe evaluation calls — presence within the method window means the dev is validating
    _SAFE_EVAL = re.compile(r"SecTrustEvaluateWithError|SecTrustEvaluate\s*\(", re.IGNORECASE)
    _WINDOW = 20  # lines to check around the bypass line

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []

        # Only scan files that have URLSession authentication challenge handling
        if "URLAuthenticationChallenge" not in content and "didReceive challenge" not in content:
            return []

        lines = content.splitlines()
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if "vigil: ignore" in line:
                continue
            if self._BYPASS.search(line) or self._TRUST_PROCEED.search(line):
                # Check a window of surrounding lines for a proper trust evaluation call
                lo = max(0, i - 1 - self._WINDOW)
                hi = min(len(lines), i + self._WINDOW)
                window = "\n".join(lines[lo:hi])
                if self._SAFE_EVAL.search(window):
                    continue  # validation present — not a bypass
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="SSL certificate validation bypassed — all HTTPS connections accepted including invalid/self-signed certs",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Evaluate the server trust before calling completionHandler(.useCredential, ...): "
                        "use SecTrustEvaluateWithError(serverTrust, &error) and only proceed if it returns true. "
                        "Bypassing certificate validation enables man-in-the-middle attacks against all "
                        "HTTPS connections in the app."
                    ),
                ))
        return findings
