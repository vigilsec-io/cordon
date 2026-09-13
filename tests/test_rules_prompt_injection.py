import pytest
from valca.rules.prompt_injection import (
    UserInputInSystemPromptRule,
    RawRequestAsLlmContentRule,
    TemplateInjectionInPromptRule,
    UnsanitizedToolOutputRule,
    HttpRequestDataInPromptRule,
    LlmOutputToExecRule,
    WebhookPayloadToAgentRule,
    DbContentInPromptRule,
    UserInputToVectorStoreRule,
)
from valca.rules.base import Severity

sys_rule = UserInputInSystemPromptRule()
req_rule = RawRequestAsLlmContentRule()
tmpl_rule = TemplateInjectionInPromptRule()
tool_rule = UnsanitizedToolOutputRule()
http_rule = HttpRequestDataInPromptRule()
exec_rule = LlmOutputToExecRule()
webhook_rule = WebhookPayloadToAgentRule()
db_rule = DbContentInPromptRule()
vectorstore_rule = UserInputToVectorStoreRule()


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


# VGL-PI005: HTTP request data interpolated into AI prompt
def test_request_data_near_llm_call_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def handler(request):\n"
        '    prompt = f"Summarize this feedback: {request.json()[\'feedback\']}"\n'
        '    client.messages.create(messages=[{"role": "user", "content": prompt}])\n'
    )
    f = _f(tmp_path, code)
    findings = http_rule.check(f)
    assert any(fi.rule_id == "VGL-PI005" for fi in findings)
    assert findings[0].severity == Severity.CRITICAL

def test_request_data_via_variable_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        'user_input = request.POST.get("query")\n'
        'response = client.complete(f"Answer: {user_input}")\n'
    )
    f = _f(tmp_path, code)
    assert http_rule.check(f) != []

def test_request_data_far_from_llm_call_not_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "feedback = request.json()['feedback']\n"
        + "\n".join(f"do_something_unrelated_{i}()" for i in range(20))
        + "\nclient.messages.create(messages=[])\n"
    )
    f = _f(tmp_path, code)
    assert http_rule.check(f) == []

def test_no_llm_signal_not_flagged_pi005(tmp_path):
    code = "prompt = f\"Feedback: {request.json()['feedback']}\"\n"
    f = _f(tmp_path, code)
    assert http_rule.check(f) == []


# VGL-PI006: AI output piped to subprocess/exec/eval
def test_llm_output_to_subprocess_flagged(tmp_path):
    code = (
        "import anthropic, subprocess\n"
        "client = anthropic.Anthropic()\n"
        "response = client.messages.create(messages=[])\n"
        "result = response.content[0].text\n"
        "subprocess.run(result, shell=True)\n"
    )
    f = _f(tmp_path, code)
    findings = exec_rule.check(f)
    assert any(fi.rule_id == "VGL-PI006" for fi in findings)
    assert findings[0].severity == Severity.CRITICAL

def test_llm_output_to_eval_direct_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "response = client.messages.create(messages=[])\n"
        "eval(response.content[0].text)\n"
    )
    f = _f(tmp_path, code)
    assert exec_rule.check(f) != []

def test_eval_unrelated_to_llm_not_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "config = load_config()\n"
        "eval(config['expression'])\n"
    )
    f = _f(tmp_path, code)
    assert exec_rule.check(f) == []

def test_llm_output_parsed_as_json_not_flagged(tmp_path):
    code = (
        "import anthropic, json\n"
        "client = anthropic.Anthropic()\n"
        "response = client.messages.create(messages=[])\n"
        "result = json.loads(response.content[0].text)\n"
        "validate_schema(result)\n"
    )
    f = _f(tmp_path, code)
    assert exec_rule.check(f) == []


# VGL-PI007: webhook payload passed directly to AI agent
def test_webhook_payload_to_agent_flagged(tmp_path):
    code = (
        "from myagents import Agent\n"
        "async def github_webhook(payload: dict):\n"
        '    agent = Agent(task=payload["pull_request"]["title"])\n'
        "    result = await agent.run()\n"
    )
    f = _f(tmp_path, code)
    findings = webhook_rule.check(f)
    assert any(fi.rule_id == "VGL-PI007" for fi in findings)
    assert findings[0].severity == Severity.HIGH

def test_webhook_payload_extracted_field_not_near_agent_not_flagged(tmp_path):
    code = (
        "from myagents import Agent\n"
        "async def github_webhook(payload: dict):\n"
        '    title = payload["pull_request"]["title"]\n'
        "    log_event(title)\n"
    )
    f = _f(tmp_path, code)
    assert webhook_rule.check(f) == []


# VGL-PI008: second-order injection via DB-sourced content
def test_db_content_in_prompt_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def summarize(doc_id):\n"
        "    doc = db.query(Document).filter_by(id=doc_id).first()\n"
        '    prompt = f"Summarize this document: {doc.content}"\n'
        '    client.messages.create(messages=[{"role": "user", "content": prompt}])\n'
    )
    f = _f(tmp_path, code)
    findings = db_rule.check(f)
    assert any(fi.rule_id == "VGL-PI008" for fi in findings)
    assert findings[0].severity == Severity.HIGH

def test_raw_sql_row_in_prompt_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        'rows = db.execute("SELECT bio FROM users WHERE id = ?", [user_id])\n'
        '    task = f"Analyze this user bio: {rows[0][\'bio\']}"\n'
        "client.complete(task)\n"
    )
    f = _f(tmp_path, code)
    assert db_rule.check(f) != []

def test_fstring_plain_variable_not_flagged(tmp_path):
    # No attribute/index access — VGL-PI001's territory, not PI008.
    code = (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "doc = db.query(Document).first()\n"
        'prompt = f"Summarize: {some_plain_var}"\n'
        "client.messages.create(messages=[])\n"
    )
    f = _f(tmp_path, code)
    assert db_rule.check(f) == []

def test_db_field_no_llm_call_not_flagged(tmp_path):
    code = (
        "import anthropic\n"
        "doc = db.query(Document).filter_by(id=1).first()\n"
        'label = f"Document: {doc.content}"\n'
        "print(label)\n"
    )
    f = _f(tmp_path, code)
    assert db_rule.check(f) == []


# VGL-PI009: user input flowing into vector store write
def test_user_message_to_chromadb_flagged(tmp_path):
    code = (
        "import chromadb\n"
        'collection = chromadb.Client().get_collection("notes")\n'
        "def handler(request):\n"
        '    user_message = request.json()["message"]\n'
        "    collection.add(documents=[user_message])\n"
    )
    f = _f(tmp_path, code)
    findings = vectorstore_rule.check(f)
    assert any(fi.rule_id == "VGL-PI009" for fi in findings)
    assert findings[0].severity == Severity.HIGH

def test_form_data_to_pinecone_upsert_flagged(tmp_path):
    code = (
        "import pinecone\n"
        'user_bio = form.cleaned_data["bio"]\n'
        "index.upsert(vectors=[(id, embed(user_bio), {\"text\": user_bio})])\n"
    )
    f = _f(tmp_path, code)
    assert vectorstore_rule.check(f) != []

def test_static_content_to_vectorstore_not_flagged(tmp_path):
    code = (
        "import chromadb\n"
        'collection = chromadb.Client().get_collection("notes")\n'
        'static_doc = "This is a hardcoded internal document"\n'
        "collection.add(documents=[static_doc])\n"
    )
    f = _f(tmp_path, code)
    assert vectorstore_rule.check(f) == []

def test_no_vectorstore_import_not_flagged(tmp_path):
    code = (
        'user_message = request.json()["message"]\n'
        "collection.add(documents=[user_message])\n"
    )
    f = _f(tmp_path, code)
    assert vectorstore_rule.check(f) == []
