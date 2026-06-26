from pathlib import Path
import pytest
from vigil.rules.nginx import NginxSecurityHeadersRule
from vigil.rules.base import Severity

rule = NginxSecurityHeadersRule()

_SAFE = """\
server {
    listen 443 ssl;
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;

    location / { proxy_pass http://127.0.0.1:8000; }
}
"""

_UNSAFE = """\
server {
    listen 443 ssl;
    ssl_protocols TLSv1.1 TLSv1.2;
    location / { proxy_pass http://127.0.0.1:8000; }
}
"""


def test_safe_nginx_no_findings(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text(_SAFE)
    findings = rule.check(f)
    assert findings == []


def test_missing_x_frame_options_flagged_as_high(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text(_UNSAFE)
    findings = rule.check(f)
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    messages = " ".join(f.message for f in findings)
    assert "X-Frame-Options" in messages


def test_missing_server_tokens_flagged_as_medium(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text(_UNSAFE)
    findings = rule.check(f)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert any("server_tokens" in f.message for f in medium)


def test_old_tls_version_flagged(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text(_UNSAFE)
    findings = rule.check(f)
    tls_findings = [f for f in findings if "TLS" in f.message or "tls" in f.message.lower()]
    assert len(tls_findings) == 1
    assert tls_findings[0].severity == Severity.HIGH


def test_only_new_tls_is_clean(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text(_SAFE)
    findings = rule.check(f)
    assert not any("TLS" in fi.message for fi in findings)


def test_applies_to_nginx_conf(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_sites_available(tmp_path):
    d = tmp_path / "sites-available"
    d.mkdir()
    f = d / "myapp"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_nginx_extension(tmp_path):
    f = tmp_path / "myapp.nginx"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_does_not_apply_to_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("")
    assert rule.applies_to(f) is False
