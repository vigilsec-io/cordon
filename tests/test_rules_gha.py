"""Tests for GitHub Actions advanced security rules: VGL-GHA001-002, GHA004-008."""
import pytest
from vigil.rules.gha import (
    GhaPwnRequestRule, GhaScriptInjectionRule, GhaSecretsInRunRule,
    GhaMissingPermissionsRule, GhaCachePoisoningRule,
    GhaSelfHostedOnPrRule, GhaWorkflowRunNoRefRule,
)
from vigil.rules.base import Severity


@pytest.fixture
def wf(tmp_path):
    """Creates a .github/workflows/ YAML file."""
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    def _make(content, name="ci.yml"):
        f = d / name
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def plain_yml(tmp_path):
    def _make(content):
        f = tmp_path / "config.yml"
        f.write_text(content)
        return f
    return _make


# ── VGL-GHA001 — Pwn Request ──────────────────────────────────────────────────

class TestGhaPwnRequestRule:
    rule = GhaPwnRequestRule()

    _PPT_CHECKOUT_SHA = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    _PPT_CHECKOUT_REF = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"""
    _PPT_HEAD_REF = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
"""
    _SAFE_PPT = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    _PR_ONLY = """\
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""

    def test_detects_ppt_with_head_sha(self, wf):
        assert self.rule.check(wf(self._PPT_CHECKOUT_SHA))

    def test_detects_ppt_with_head_ref(self, wf):
        assert self.rule.check(wf(self._PPT_CHECKOUT_REF))

    def test_detects_ppt_with_github_head_ref(self, wf):
        assert self.rule.check(wf(self._PPT_HEAD_REF))

    def test_ignores_ppt_without_fork_ref(self, wf):
        assert not self.rule.check(wf(self._SAFE_PPT))

    def test_ignores_pr_trigger_with_head_sha(self, wf):
        # pull_request (not _target) is safer — no production secrets
        assert not self.rule.check(wf(self._PR_ONLY))

    def test_finding_is_critical(self, wf):
        f = self.rule.check(wf(self._PPT_CHECKOUT_SHA))
        assert f[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, wf):
        f = self.rule.check(wf(self._PPT_CHECKOUT_SHA))
        assert f[0].rule_id == "VGL-GHA001"

    def test_fix_mentions_two_workflow(self, wf):
        f = self.rule.check(wf(self._PPT_CHECKOUT_SHA))
        assert "workflow" in f[0].fix.lower()

    def test_ignores_vigil_ignore(self, wf):
        content = self._PPT_CHECKOUT_SHA.replace(
            "ref: ${{ github.event.pull_request.head.sha }}",
            "ref: ${{ github.event.pull_request.head.sha }}  # vigil: ignore",
        )
        assert not self.rule.check(wf(content))

    def test_does_not_apply_to_non_yml(self, tmp_path):
        f = tmp_path / "workflow.py"
        assert not self.rule.applies_to(f)


# ── VGL-GHA002 — Script injection ────────────────────────────────────────────

_PR_HEADER = "on:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
_RUN_BLOCK = "      - name: step\n        run: |\n"


class TestGhaScriptInjectionRule:
    rule = GhaScriptInjectionRule()

    def test_detects_pr_title_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.title }}"\n')
        assert self.rule.check(f)

    def test_detects_pr_body_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.body }}"\n')
        assert self.rule.check(f)

    def test_detects_head_ref_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          git checkout ${{ github.head_ref }}\n')
        assert self.rule.check(f)

    def test_detects_comment_body_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.comment.body }}"\n')
        assert self.rule.check(f)

    def test_detects_actor_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "User: ${{ github.actor }}"\n')
        assert self.rule.check(f)

    def test_ignores_pr_title_in_env_block(self, wf):
        f = wf(_PR_HEADER + "      - name: step\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n")
        assert not self.rule.check(f)

    def test_ignores_safe_context_in_run(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.sha }}"\n')
        assert not self.rule.check(f)

    def test_finding_is_critical(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.title }}"\n')
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.title }}"\n')
        assert self.rule.check(f)[0].rule_id == "VGL-GHA002"

    def test_fix_mentions_env_var(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.title }}"\n')
        assert "env" in self.rule.check(f)[0].fix.lower()

    def test_ignores_comment_line(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          # echo "${{ github.event.pull_request.title }}"\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          echo "${{ github.event.pull_request.title }}"  # vigil: ignore\n')
        assert not self.rule.check(f)


# ── VGL-GHA004 — Secrets in run: step ────────────────────────────────────────

class TestGhaSecretsInRunRule:
    rule = GhaSecretsInRunRule()

    def test_detects_secret_in_run_pipe(self, wf):
        f = wf(_PR_HEADER + _RUN_BLOCK + '          curl -H "Auth: ${{ secrets.API_TOKEN }}"\n')
        assert self.rule.check(f)

    def test_detects_secret_on_run_line(self, wf):
        f = wf(_PR_HEADER + "      - run: echo ${{ secrets.MY_SECRET }}\n")
        assert self.rule.check(f)

    def test_ignores_secret_in_env_block(self, wf):
        f = wf(_PR_HEADER + "      - env:\n          TOKEN: ${{ secrets.API_TOKEN }}\n        run: echo $TOKEN\n")
        assert not self.rule.check(f)

    def test_ignores_secret_under_with(self, wf):
        f = wf(_PR_HEADER + "      - uses: some/action@v1\n        with:\n          token: ${{ secrets.GITHUB_TOKEN }}\n")
        assert not self.rule.check(f)

    def test_finding_is_high(self, wf):
        f = wf(_PR_HEADER + "      - run: echo ${{ secrets.MY_SECRET }}\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, wf):
        f = wf(_PR_HEADER + "      - run: echo ${{ secrets.MY_SECRET }}\n")
        assert self.rule.check(f)[0].rule_id == "VGL-GHA004"

    def test_fix_mentions_env(self, wf):
        f = wf(_PR_HEADER + "      - run: echo ${{ secrets.MY_SECRET }}\n")
        assert "env" in self.rule.check(f)[0].fix.lower()

    def test_ignores_vigil_ignore(self, wf):
        f = wf(_PR_HEADER + "      - run: echo ${{ secrets.MY_SECRET }}  # vigil: ignore\n")
        assert not self.rule.check(f)


# ── VGL-GHA005 — Missing permissions block ────────────────────────────────────

_WF_NO_PERMS = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
_WF_WITH_PERMS = "on:\n  push:\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n"


class TestGhaMissingPermissionsRule:
    rule = GhaMissingPermissionsRule()

    def test_detects_missing_permissions(self, wf):
        assert self.rule.check(wf(_WF_NO_PERMS))

    def test_ignores_workflow_with_permissions(self, wf):
        assert not self.rule.check(wf(_WF_WITH_PERMS))

    def test_ignores_job_level_permissions(self, wf):
        content = "on:\n  push:\njobs:\n  build:\n    permissions: read-all\n    runs-on: ubuntu-latest\n"
        assert not self.rule.check(wf(content))

    def test_finding_is_medium(self, wf):
        assert self.rule.check(wf(_WF_NO_PERMS))[0].severity == Severity.MEDIUM

    def test_finding_has_correct_rule_id(self, wf):
        assert self.rule.check(wf(_WF_NO_PERMS))[0].rule_id == "VGL-GHA005"

    def test_fix_mentions_read_all(self, wf):
        f = self.rule.check(wf(_WF_NO_PERMS))
        assert "read-all" in f[0].fix

    def test_does_not_apply_to_non_yml(self, tmp_path):
        f = tmp_path / "ci.sh"
        assert not self.rule.applies_to(f)

    def test_ignores_non_gha_yaml(self, plain_yml):
        f = plain_yml("services:\n  web:\n    image: nginx\n")
        assert not self.rule.check(f)


# ── VGL-GHA006 — Cache poisoning ─────────────────────────────────────────────

_CACHE_PR = """\
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: node-${{ hashFiles('**/package-lock.json') }}
"""
_CACHE_PUSH = """\
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
"""


class TestGhaCachePoisoningRule:
    rule = GhaCachePoisoningRule()

    def test_detects_cache_in_pr_workflow(self, wf):
        assert self.rule.check(wf(_CACHE_PR))

    def test_detects_cache_restore_in_ppt(self, wf):
        content = _CACHE_PR.replace("pull_request:", "pull_request_target:").replace("actions/cache@v4", "actions/cache/restore@v4")
        assert self.rule.check(wf(content))

    def test_ignores_cache_in_push_workflow(self, wf):
        assert not self.rule.check(wf(_CACHE_PUSH))

    def test_finding_is_high(self, wf):
        assert self.rule.check(wf(_CACHE_PR))[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, wf):
        assert self.rule.check(wf(_CACHE_PR))[0].rule_id == "VGL-GHA006"

    def test_fix_mentions_guard(self, wf):
        f = self.rule.check(wf(_CACHE_PR))
        assert "github.repository" in f[0].fix

    def test_ignores_vigil_ignore(self, wf):
        content = _CACHE_PR.replace("uses: actions/cache@v4", "uses: actions/cache@v4  # vigil: ignore")
        assert not self.rule.check(wf(content))


# ── VGL-GHA007 — Self-hosted on PR ───────────────────────────────────────────

_SELF_HOSTED_PR = """\
on:
  pull_request:
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
"""
_SELF_HOSTED_PUSH = """\
on:
  push:
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
"""
_SELF_HOSTED_LIST = """\
on:
  pull_request:
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo hi
"""


class TestGhaSelfHostedOnPrRule:
    rule = GhaSelfHostedOnPrRule()

    def test_detects_self_hosted_in_pr_workflow(self, wf):
        assert self.rule.check(wf(_SELF_HOSTED_PR))

    def test_detects_self_hosted_list_in_pr_workflow(self, wf):
        assert self.rule.check(wf(_SELF_HOSTED_LIST))

    def test_detects_self_hosted_in_ppt(self, wf):
        content = _SELF_HOSTED_PR.replace("pull_request:", "pull_request_target:")
        assert self.rule.check(wf(content))

    def test_ignores_self_hosted_in_push_workflow(self, wf):
        assert not self.rule.check(wf(_SELF_HOSTED_PUSH))

    def test_ignores_github_hosted_in_pr_workflow(self, wf):
        content = _SELF_HOSTED_PR.replace("self-hosted", "ubuntu-latest")
        assert not self.rule.check(wf(content))

    def test_finding_is_high(self, wf):
        assert self.rule.check(wf(_SELF_HOSTED_PR))[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, wf):
        assert self.rule.check(wf(_SELF_HOSTED_PR))[0].rule_id == "VGL-GHA007"

    def test_fix_mentions_ephemeral(self, wf):
        f = self.rule.check(wf(_SELF_HOSTED_PR))
        assert "ephemeral" in f[0].fix.lower()

    def test_ignores_vigil_ignore(self, wf):
        content = _SELF_HOSTED_PR.replace("runs-on: self-hosted", "runs-on: self-hosted  # vigil: ignore")
        assert not self.rule.check(wf(content))


# ── VGL-GHA008 — workflow_run no ref check ───────────────────────────────────

_WR_NO_REF = """\
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
"""
_WR_WITH_BRANCH = """\
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    if: github.event.workflow_run.head_branch == 'main'
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
"""
_WR_WITH_REPO = """\
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    if: github.event.workflow_run.head_repository.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
"""


class TestGhaWorkflowRunNoRefRule:
    rule = GhaWorkflowRunNoRefRule()

    def test_detects_workflow_run_without_ref_check(self, wf):
        assert self.rule.check(wf(_WR_NO_REF))

    def test_ignores_workflow_run_with_head_branch(self, wf):
        assert not self.rule.check(wf(_WR_WITH_BRANCH))

    def test_ignores_workflow_run_with_head_repository(self, wf):
        assert not self.rule.check(wf(_WR_WITH_REPO))

    def test_ignores_non_workflow_run_trigger(self, wf):
        content = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        assert not self.rule.check(wf(content))

    def test_finding_is_high(self, wf):
        assert self.rule.check(wf(_WR_NO_REF))[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, wf):
        assert self.rule.check(wf(_WR_NO_REF))[0].rule_id == "VGL-GHA008"

    def test_fix_mentions_head_branch(self, wf):
        f = self.rule.check(wf(_WR_NO_REF))
        assert "head_branch" in f[0].fix

    def test_does_not_apply_to_non_yml(self, tmp_path):
        f = tmp_path / "workflow.py"
        assert not self.rule.applies_to(f)
