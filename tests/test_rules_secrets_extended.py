import pytest
from vigil.rules.secrets import (
    JwtSecretRule, PemPrivateKeyRule, CredentialUrlRule,
    StripeLiveKeyRule, SlackTokenRule, GenericProviderKeyRule,
)
from vigil.rules.base import Severity

jwt = JwtSecretRule()
pem = PemPrivateKeyRule()
db_url = CredentialUrlRule()
stripe = StripeLiveKeyRule()
slack = SlackTokenRule()
generic = GenericProviderKeyRule()


def _f(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return f


# VGL-S005 JWT secret
def test_jwt_secret_flagged(tmp_path):
    f = _f(tmp_path, "config.py", 'jwt_secret = "supersecretvalue123"')  # vigil: ignore
    assert any(fi.rule_id == "VGL-S005" for fi in jwt.check(f))

def test_jwt_empty_value_not_flagged(tmp_path):
    f = _f(tmp_path, "config.py", 'jwt_secret = ""')
    assert jwt.check(f) == []

def test_jwt_env_var_not_flagged(tmp_path):
    f = _f(tmp_path, "config.py", 'jwt_secret = os.environ["JWT_SECRET"]')
    assert jwt.check(f) == []


# VGL-S006 PEM key
def test_pem_private_key_flagged(tmp_path):
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo..."  # vigil: ignore
    f = _f(tmp_path, "key.py", content)
    assert any(fi.rule_id == "VGL-S006" for fi in pem.check(f))

def test_pem_openssh_flagged(tmp_path):
    f = _f(tmp_path, "deploy.sh", "-----BEGIN OPENSSH PRIVATE KEY-----")  # vigil: ignore
    assert pem.check(f) != []

def test_pem_public_key_not_flagged(tmp_path):
    f = _f(tmp_path, "key.py", "-----BEGIN PUBLIC KEY-----")
    assert pem.check(f) == []


# VGL-S007 DB URL
def test_postgres_url_with_creds_flagged(tmp_path):
    f = _f(tmp_path, "settings.py", 'DB_URL = "postgres://admin:secret123@localhost:5432/db"')  # vigil: ignore
    assert any(fi.rule_id == "VGL-S007" for fi in db_url.check(f))

def test_mysql_url_flagged(tmp_path):
    f = _f(tmp_path, "config.py", 'DSN = "mysql://root:pass@db.host/mydb"')  # vigil: ignore
    assert db_url.check(f) != []

def test_db_url_no_password_not_flagged(tmp_path):
    f = _f(tmp_path, "config.py", 'DB = "postgres://localhost:5432/mydb"')
    assert db_url.check(f) == []


# VGL-S008 Stripe live key
def test_stripe_live_key_flagged(tmp_path):
    f = _f(tmp_path, "payments.py", 'STRIPE_KEY = "sk_live_" + "abcdefghijklmnopqrstuvwx"')  # vigil: ignore
    assert any(fi.rule_id == "VGL-S008" for fi in stripe.check(f))

def test_stripe_test_key_not_flagged(tmp_path):
    f = _f(tmp_path, "payments.py", 'STRIPE_KEY = "sk_test_" + "abcdefghijklmnopqrstuvwx"')
    assert stripe.check(f) == []


# VGL-S009 Slack token
def test_slack_bot_token_flagged(tmp_path):
    tok = "xoxb-" + "12345678901-12345678901-abcdefghijklmnopqrstuvwx"  # vigil: ignore
    f = _f(tmp_path, "slack.py", f'TOKEN = "{tok}"')
    assert any(fi.rule_id == "VGL-S009" for fi in slack.check(f))


# VGL-S010 Generic provider keys
def test_openai_key_flagged(tmp_path):
    f = _f(tmp_path, "ai.py", 'OPENAI_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz1234"')  # vigil: ignore
    assert any(fi.rule_id == "VGL-S010" for fi in generic.check(f))

def test_github_pat_flagged(tmp_path):
    tok = "ghp_" + "a" * 36  # vigil: ignore
    f = _f(tmp_path, "ci.py", f'GH_TOKEN = "{tok}"')
    assert generic.check(f) != []

def test_google_api_key_flagged(tmp_path):
    tok = "AIzaSy" + "B" * 33  # vigil: ignore
    f = _f(tmp_path, "maps.py", f'KEY = "{tok}"')
    assert generic.check(f) != []
