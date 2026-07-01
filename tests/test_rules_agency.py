import pytest
from vigil.rules.agency import (
    LlmShellExecRule, AutoApprovalBypassRule,
    UnboundedAgentLoopRule, LlmOutputFileWriteRule,
)
from vigil.rules.base import Severity

shell_rule = LlmShellExecRule()
approve_rule = AutoApprovalBypassRule()
loop_rule = UnboundedAgentLoopRule()
write_rule = LlmOutputFileWriteRule()


def _f(tmp_path, content, name="agent.py"):
    f = tmp_path / name
    f.write_text(content)
    return f


# VGL-A001: LLM shell exec
def test_llm_output_to_subprocess_flagged(tmp_path):
    f = _f(tmp_path, "subprocess.run(response.content.split())")
    assert any(fi.rule_id == "VGL-A001" for fi in shell_rule.check(f))

def test_os_system_with_completion_flagged(tmp_path):
    f = _f(tmp_path, "os.system(completion.text)")
    assert shell_rule.check(f) != []

def test_safe_subprocess_not_flagged(tmp_path):
    f = _f(tmp_path, 'subprocess.run(["ls", "-la"], shell=False)')
    assert shell_rule.check(f) == []

def test_does_not_apply_to_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("key: value")
    assert shell_rule.applies_to(f) is False


# VGL-A002: Auto-approval bypass
def test_auto_approve_true_flagged(tmp_path):
    f = _f(tmp_path, "auto_approve = True")
    assert any(fi.rule_id == "VGL-A002" for fi in approve_rule.check(f))

def test_skip_confirmation_flagged(tmp_path):
    f = _f(tmp_path, "skip_confirmation = True")
    assert approve_rule.check(f) != []

def test_approve_false_not_flagged(tmp_path):
    f = _f(tmp_path, "auto_approve = False")
    assert approve_rule.check(f) == []

def test_commented_out_not_flagged(tmp_path):
    # Rule must skip Python comment lines — commented-out code is not live
    f = _f(tmp_path, "# auto_approve = True  (removed this)")
    assert approve_rule.check(f) == []


# VGL-A003: Unbounded agentic loop
def test_while_true_with_llm_flagged(tmp_path):
    code = "import anthropic\n\nwhile True:\n    client.messages.create()"
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-A003" for fi in loop_rule.check(f))

def test_while_true_with_max_iter_not_flagged(tmp_path):
    code = "import anthropic\nmax_iterations = 10\nwhile True:\n    pass"
    f = _f(tmp_path, code)
    assert loop_rule.check(f) == []

def test_while_true_without_llm_not_flagged(tmp_path):
    f = _f(tmp_path, "while True:\n    time.sleep(1)")
    assert loop_rule.check(f) == []


# VGL-A004: LLM output to file write
def test_write_text_with_llm_output_flagged(tmp_path):
    f = _f(tmp_path, "path.write_text(response.content)")
    assert any(fi.rule_id == "VGL-A004" for fi in write_rule.check(f))

def test_write_with_completion_content_flagged(tmp_path):
    f = _f(tmp_path, "f.write(completion.content)")
    assert write_rule.check(f) != []

def test_write_static_string_not_flagged(tmp_path):
    f = _f(tmp_path, 'path.write_text("hello world")')
    assert write_rule.check(f) == []


def test_vgla002_does_not_match_rule_source_file():
    """VGL-A002 must not fire on its own source file (pattern strings are not live code)."""
    from pathlib import Path
    import vigil.rules.agency as agency_mod
    source = Path(agency_mod.__file__)
    assert approve_rule.check(source) == []

def test_vgla002_pattern_in_string_literal_not_flagged(tmp_path):
    """Pattern inside a string literal (e.g. test fixture arg) must not trigger VGL-A002."""
    f = _f(tmp_path, '_f(tmp_path, "auto_approve = True")')
    assert approve_rule.check(f) == []

def test_vgla001_pattern_in_string_literal_not_flagged(tmp_path):
    """Pattern inside a string literal must not trigger VGL-A001."""
    f = _f(tmp_path, '_f(tmp_path, "subprocess.run(response.content.split())")')
    assert shell_rule.check(f) == []

def test_vgla004_pattern_in_string_literal_not_flagged(tmp_path):
    """Pattern inside a string literal must not trigger VGL-A004."""
    f = _f(tmp_path, '_f(tmp_path, "path.write_text(response.content)")')
    assert write_rule.check(f) == []


# vigil: ignore inline suppression
def test_engine_inline_ignore_suppresses_finding(tmp_path):
    """Lines with '# vigil: ignore' must not produce findings."""
    from vigil.engine import Engine
    from vigil.rules.agency import AutoApprovalBypassRule
    engine = Engine(rules=[AutoApprovalBypassRule()])
    f = tmp_path / "agent.py"
    f.write_text("auto_approve = True  # vigil: ignore")
    findings = engine.scan(f)
    assert findings == []
