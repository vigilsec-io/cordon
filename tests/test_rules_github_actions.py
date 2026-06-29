"""Tests for GitHub Actions security rules: VGL-GH001, VGL-GH002, VGL-GH003."""
import pytest
from vigil.rules.github_actions import (
    GhActionsSecretInRunRule,
    GhActionsExcessivePermissionsRule,
    GhActionsUnpinnedActionRule,
)

_GH_HEADER = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"


@pytest.fixture
def wf_file(tmp_path):
    """Creates a .github/workflows/ YAML file."""
    wdir = tmp_path / ".github" / "workflows"
    wdir.mkdir(parents=True)
    def _make(content):
        f = wdir / "test.yml"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def plain_yml(tmp_path):
    """Creates a plain YAML file without GH Actions markers — should be ignored."""
    def _make(content):
        f = tmp_path / "config.yml"
        f.write_text(content)
        return f
    return _make


# ── VGL-GH001 — Secret in run step ────────────────────────────────────────────

class TestGhActionsSecretInRunRule:
    rule = GhActionsSecretInRunRule()

    def test_detects_secret_in_run_step(self, wf_file):
        f = wf_file(_GH_HEADER + '      - run: echo ${{ secrets.API_KEY }}\n')
        assert self.rule.check(f)

    def test_detects_secret_in_curl(self, wf_file):
        f = wf_file(_GH_HEADER + '        curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" https://api.example.com\n')
        assert self.rule.check(f)

    def test_detects_echo_with_secret(self, wf_file):
        f = wf_file(_GH_HEADER + '        echo "key=${{ secrets.DEPLOY_KEY }}"\n')
        assert self.rule.check(f)

    def test_ignores_secret_in_env_block(self, wf_file):
        # env: block is safe — sets the env var without printing
        f = wf_file(_GH_HEADER + '      env:\n        MY_KEY: ${{ secrets.API_KEY }}\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, wf_file):
        f = wf_file(_GH_HEADER + '      # run: echo ${{ secrets.API_KEY }}\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, wf_file):
        f = wf_file(_GH_HEADER + '      - run: echo ${{ secrets.API_KEY }}  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_ignores_non_gh_actions_yml(self, plain_yml):
        f = plain_yml('run: echo ${{ secrets.API_KEY }}\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, wf_file):
        f = wf_file(_GH_HEADER + '      - run: echo ${{ secrets.API_KEY }}\n')
        assert self.rule.check(f)[0].rule_id == "VGL-GH001"


# ── VGL-GH002 — Excessive permissions ─────────────────────────────────────────

class TestGhActionsExcessivePermissionsRule:
    rule = GhActionsExcessivePermissionsRule()

    def test_detects_write_all(self, wf_file):
        f = wf_file("on:\n  push:\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert self.rule.check(f)

    def test_detects_contents_write(self, wf_file):
        f = wf_file("on:\n  push:\npermissions:\n  contents: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert self.rule.check(f)

    def test_detects_packages_write(self, wf_file):
        f = wf_file("on:\n  push:\npermissions:\n  packages: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert self.rule.check(f)

    def test_detects_id_token_write(self, wf_file):
        f = wf_file("on:\n  push:\npermissions:\n  id-token: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert self.rule.check(f)

    def test_ignores_read_all(self, wf_file):
        f = wf_file("on:\n  push:\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert not self.rule.check(f)

    def test_ignores_contents_read(self, wf_file):
        f = wf_file("on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert not self.rule.check(f)

    def test_ignores_comment(self, wf_file):
        f = wf_file("on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      # permissions: write-all\n")
        assert not self.rule.check(f)

    def test_ignores_non_gh_actions_yml(self, plain_yml):
        f = plain_yml("permissions: write-all\n")
        assert not self.rule.check(f)


# ── VGL-GH003 — Unpinned action ───────────────────────────────────────────────

class TestGhActionsUnpinnedActionRule:
    rule = GhActionsUnpinnedActionRule()

    def test_detects_major_version_tag(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@v4\n')
        assert self.rule.check(f)

    def test_detects_semver_tag(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/setup-python@v5.1.0\n')
        assert self.rule.check(f)

    def test_detects_main_branch(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: owner/action@main\n')
        assert self.rule.check(f)

    def test_detects_master_branch(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: owner/action@master\n')
        assert self.rule.check(f)

    def test_detects_latest(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: owner/action@latest\n')
        assert self.rule.check(f)

    def test_ignores_pinned_sha_short(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n')
        assert not self.rule.check(f)

    def test_ignores_pinned_sha_7char(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@a81bbbf\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, wf_file):
        f = wf_file(_GH_HEADER + '      # - uses: actions/checkout@v4\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@v4  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_ignores_non_gh_actions_yml(self, plain_yml):
        f = plain_yml('uses: actions/checkout@v4\n')
        assert not self.rule.check(f)

    def test_finding_message_includes_ref(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@v4\n')
        findings = self.rule.check(f)
        assert "v4" in findings[0].message

    def test_finding_has_correct_rule_id(self, wf_file):
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@v4\n')
        assert self.rule.check(f)[0].rule_id == "VGL-GH003"

    def test_floating_branch_is_critical(self, wf_file):
        from vigil.rules.base import Severity
        f = wf_file(_GH_HEADER + '      - uses: owner/action@main\n')
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_version_tag_is_high(self, wf_file):
        from vigil.rules.base import Severity
        f = wf_file(_GH_HEADER + '      - uses: actions/checkout@v4\n')
        assert self.rule.check(f)[0].severity == Severity.HIGH
