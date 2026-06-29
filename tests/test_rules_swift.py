"""Tests for Swift / iOS security rules: VGL-SW001–SW004."""
import pytest
from vigil.rules.swift import (
    SwiftHardcodedSecretRule,
    SwiftPlainHttpRule,
    SwiftUserDefaultsSecretRule,
    SwiftSslBypassRule,
)


@pytest.fixture
def sw(tmp_path):
    def _make(content):
        f = tmp_path / "App.swift"
        f.write_text(content)
        return f
    return _make


# ── VGL-SW001 — Hardcoded secret ─────────────────────────────────────────────

class TestSwiftHardcodedSecretRule:
    rule = SwiftHardcodedSecretRule()

    def test_detects_let_apikey(self, sw):
        f = sw('let apiKey = "sk-live-abc1234567890"\n')
        assert self.rule.check(f)

    def test_detects_let_password(self, sw):
        f = sw('let password = "supersecret123"\n')
        assert self.rule.check(f)

    def test_detects_var_token(self, sw):
        f = sw('var token = "Bearer eyJhbGciOiJIUzI1NiJ9"\n')
        assert self.rule.check(f)

    def test_detects_static_let_secret(self, sw):
        f = sw('static let clientSecret = "a1b2c3d4e5f6g7h8"\n')
        assert self.rule.check(f)

    def test_detects_private_let_api_key(self, sw):
        f = sw('private let apiSecret = "my-api-secret-value"\n')
        assert self.rule.check(f)

    def test_detects_typed_declaration(self, sw):
        f = sw('let authToken: String = "hardcoded-auth-token-here"\n')
        assert self.rule.check(f)

    def test_ignores_short_value(self, sw):
        f = sw('let key = "abc"\n')
        assert not self.rule.check(f)

    def test_ignores_non_secret_name(self, sw):
        f = sw('let title = "Welcome to the app"\n')
        assert not self.rule.check(f)

    def test_ignores_empty_string(self, sw):
        f = sw('let apiKey = ""\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, sw):
        f = sw('// let apiKey = "hardcoded-key-example"\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, sw):
        f = sw('let apiKey = "sk-live-abc123"  // vigil: ignore\n')
        assert not self.rule.check(f)

    def test_does_not_apply_to_non_swift(self, tmp_path):
        f = tmp_path / "config.py"
        assert not self.rule.applies_to(f)

    def test_finding_has_correct_rule_id(self, sw):
        f = sw('let apiKey = "sk-live-abc1234"\n')
        assert self.rule.check(f)[0].rule_id == "VGL-SW001"

    def test_fix_mentions_keychain(self, sw):
        f = sw('let password = "mysecretpass"\n')
        assert "Keychain" in self.rule.check(f)[0].fix


# ── VGL-SW002 — Plain HTTP URL ────────────────────────────────────────────────

class TestSwiftPlainHttpRule:
    rule = SwiftPlainHttpRule()

    def test_detects_http_url_in_url_string(self, sw):
        f = sw('let url = URL(string: "http://api.example.com/v1")\n')
        assert self.rule.check(f)

    def test_detects_http_in_urlrequest(self, sw):
        f = sw('var request = URLRequest(url: URL(string: "http://backend.myapp.com")!)\n')
        assert self.rule.check(f)

    def test_detects_http_in_string_literal(self, sw):
        f = sw('let baseURL = "http://api.myserver.com"\n')
        assert self.rule.check(f)

    def test_ignores_https(self, sw):
        f = sw('let url = URL(string: "https://api.example.com/v1")\n')
        assert not self.rule.check(f)

    def test_ignores_localhost_http(self, sw):
        f = sw('let url = URL(string: "http://localhost:8080")\n')
        assert not self.rule.check(f)

    def test_ignores_127_http(self, sw):
        f = sw('let url = URL(string: "http://127.0.0.1:3000")\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, sw):
        f = sw('// let url = URL(string: "http://old-api.example.com")\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, sw):
        f = sw('let url = URL(string: "http://api.example.com")  // vigil: ignore\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, sw):
        f = sw('URL(string: "http://api.example.com")\n')
        assert self.rule.check(f)[0].rule_id == "VGL-SW002"


# ── VGL-SW003 — UserDefaults secret ──────────────────────────────────────────

class TestSwiftUserDefaultsSecretRule:
    rule = SwiftUserDefaultsSecretRule()

    def test_detects_set_token_with_key(self, sw):
        f = sw('UserDefaults.standard.set(token, forKey: "auth_token")\n')
        assert self.rule.check(f)

    def test_detects_set_password_with_key(self, sw):
        f = sw('UserDefaults.standard.set(password, forKey: "user_password")\n')
        assert self.rule.check(f)

    def test_detects_setValue_with_secret_key(self, sw):
        f = sw('UserDefaults.standard.setValue(apiKey, forKey: "api_key")\n')
        assert self.rule.check(f)

    def test_detects_defaults_set_token(self, sw):
        f = sw('defaults.set(authToken, forKey: "token")\n')
        assert self.rule.check(f)

    def test_detects_set_credential(self, sw):
        f = sw('UserDefaults.standard.set(credential, forKey: "stored_credential")\n')
        assert self.rule.check(f)

    def test_ignores_non_sensitive_key(self, sw):
        f = sw('UserDefaults.standard.set(true, forKey: "hasSeenOnboarding")\n')
        assert not self.rule.check(f)

    def test_ignores_non_sensitive_value_and_key(self, sw):
        f = sw('UserDefaults.standard.set(username, forKey: "username")\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, sw):
        f = sw('// UserDefaults.standard.set(token, forKey: "auth_token")\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, sw):
        f = sw('UserDefaults.standard.set(token, forKey: "token")  // vigil: ignore\n')
        assert not self.rule.check(f)

    def test_finding_mentions_keychain(self, sw):
        f = sw('UserDefaults.standard.set(token, forKey: "auth_token")\n')
        assert "Keychain" in self.rule.check(f)[0].fix

    def test_finding_has_correct_rule_id(self, sw):
        f = sw('UserDefaults.standard.set(token, forKey: "auth_token")\n')
        assert self.rule.check(f)[0].rule_id == "VGL-SW003"


# ── VGL-SW004 — SSL bypass ────────────────────────────────────────────────────

_SSL_BYPASS_DELEGATE = """\
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
"""

_SAFE_DELEGATE = """\
class SafeDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
"""


class TestSwiftSslBypassRule:
    rule = SwiftSslBypassRule()

    def test_detects_unchecked_use_credential(self, sw):
        f = sw(_SSL_BYPASS_DELEGATE)
        assert self.rule.check(f)

    def test_ignores_safe_delegate_with_evaluation(self, sw):
        f = sw(_SAFE_DELEGATE)
        assert not self.rule.check(f)

    def test_ignores_file_without_challenge_handling(self, sw):
        f = sw('let session = URLSession.shared\nsession.dataTask(with: url).resume()\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, sw):
        challenge_ctx = "// URLAuthenticationChallenge example\n"
        f = sw(challenge_ctx + '// completionHandler(.useCredential, URLCredential(trust: serverTrust))\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, sw):
        content = (
            "// didReceive challenge: URLAuthenticationChallenge\n"
            "completionHandler(.useCredential, URLCredential(trust: serverTrust))  // vigil: ignore\n"
        )
        f = sw(content)
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, sw):
        f = sw(_SSL_BYPASS_DELEGATE)
        assert self.rule.check(f)[0].rule_id == "VGL-SW004"

    def test_finding_is_critical(self, sw):
        from vigil.rules.base import Severity
        f = sw(_SSL_BYPASS_DELEGATE)
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_mentions_mitm(self, sw):
        f = sw(_SSL_BYPASS_DELEGATE)
        assert "man-in-the-middle" in self.rule.check(f)[0].fix
