import pytest
from vigil.rules.prompt_injection import (
    UserInputInSystemPromptRule,
    RawRequestAsLlmContentRule,
    TemplateInjectionInPromptRule,
    UnsanitizedToolOutputRule,
)
from vigil.rules.base import Severity

sys_rule = UserInputInSystemPromptRule()
req_rule = RawRequestAsLlmContentRule()
tmpl_rule = TemplateInjectionInPromptRule()
tool_rule = UnsanitizedToolOutputRule()


def _f(tmp_path, content, name="app.py"):
    f = tmp_path / name
    f.write_text(content)
    return f


# VGL-PI001: user input in system prompt
def test_user_input_in_system_prompt_flagged(tmp_path):
    code = (
        "import anthropic\n"
        'system = f"You are a helpful assistant. Context: {user_input}"'  # vigil: ignore
    )
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-PI001" for fi in sys_rule.check(f))

def test_request_body_in_system_flagged(tmp_path):
    code = (
        "from anthropic import Anthropic\n"
        'system = f"Instructions: {request.body}"'  # vigil: ignore
    )
    f = _f(tmp_path, code)
    assert sys_rule.check(f) != []

def test_static_system_prompt_not_flagged(tmp_path):
    code = (
        "import anthropic\n"
        'system = "You are a helpful coding assistant."'
    )
    f = _f(tmp_path, code)
    assert sys_rule.check(f) == []

def test_no_llm_signal_not_flagged(tmp_path):
    code = 'system = f"Hello {user_input}"'  # vigil: ignore
    f = _f(tmp_path, code)
    assert sys_rule.check(f) == []


# VGL-PI002: raw request as LLM content
def test_request_body_as_content_flagged(tmp_path):
    code = (
        "import openai\n"
        '"content": request.body'  # vigil: ignore
    )
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-PI002" for fi in req_rule.check(f))

def test_request_json_as_content_flagged(tmp_path):
    code = (
        "from anthropic import Anthropic\n"
        '"content": request.json'  # vigil: ignore
    )
    f = _f(tmp_path, code)
    assert req_rule.check(f) != []

def test_static_content_not_flagged(tmp_path):
    code = (
        "import openai\n"
        '"content": "Tell me a joke"'
    )
    f = _f(tmp_path, code)
    assert req_rule.check(f) == []


# VGL-PI003: template injection in system prompt
def test_format_in_system_prompt_flagged(tmp_path):
    code = (
        "import anthropic\n"
        'system_prompt = "You help with {task}".format(task=user_task)'  # vigil: ignore
    )
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-PI003" for fi in tmpl_rule.check(f))

def test_clean_system_prompt_not_flagged(tmp_path):
    code = (
        "import anthropic\n"
        'system_prompt = "You are a helpful assistant."'
    )
    f = _f(tmp_path, code)
    assert tmpl_rule.check(f) == []


# VGL-PI004: unsanitized tool output
def test_tool_output_appended_flagged(tmp_path):
    code = (
        "import openai\n"
        'messages.append({"role": "tool", "content": result})'
    )
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-PI004" for fi in tool_rule.check(f))

def test_sanitized_tool_output_not_flagged(tmp_path):
    code = (
        "import openai\n"
        "content = sanitize(result)\n"
        'messages.append({"role": "tool", "content": content})'
    )
    f = _f(tmp_path, code)
    assert tool_rule.check(f) == []

def test_does_not_apply_to_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("key: value")
    assert sys_rule.applies_to(f) is False
