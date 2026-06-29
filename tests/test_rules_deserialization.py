"""Tests for deserialization, path traversal, and SSTI rules: VGL-DESER001–003, VGL-PATH001, VGL-SSTI001."""
import pytest
from vigil.rules.deserialization import (
    PickleDeserializeRule, YamlLoadRule, MarshalDeserializeRule,
    PathTraversalRule, SstiRule,
)
from vigil.rules.base import Severity


@pytest.fixture
def py(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make


# ── VGL-DESER001 — pickle ─────────────────────────────────────────────────────

class TestPickleDeserializeRule:
    rule = PickleDeserializeRule()

    def test_detects_pickle_loads(self, py):
        f = py("import pickle\ndata = pickle.loads(user_data)\n")
        assert self.rule.check(f)

    def test_detects_pickle_load(self, py):
        f = py("import pickle\nobj = pickle.load(file_handle)\n")
        assert self.rule.check(f)

    def test_finding_is_critical(self, py):
        f = py("obj = pickle.loads(data)\n")
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, py):
        f = py("obj = pickle.loads(data)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DESER001"

    def test_fix_mentions_json(self, py):
        f = py("obj = pickle.loads(data)\n")
        assert "JSON" in self.rule.check(f)[0].fix

    def test_ignores_comment(self, py):
        f = py("# obj = pickle.loads(data)\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py):
        f = py("obj = pickle.loads(data)  # vigil: ignore\n")
        assert not self.rule.check(f)

    def test_does_not_apply_to_js(self, tmp_path):
        f = tmp_path / "app.js"
        assert not self.rule.applies_to(f)


# ── VGL-DESER002 — yaml.load ─────────────────────────────────────────────────

class TestYamlLoadRule:
    rule = YamlLoadRule()

    def test_detects_yaml_load_no_loader(self, py):
        f = py("import yaml\ndata = yaml.load(stream)\n")
        assert self.rule.check(f)

    def test_detects_yaml_full_loader(self, py):
        f = py("data = yaml.load(stream, Loader=yaml.FullLoader)\n")
        assert self.rule.check(f)

    def test_detects_yaml_unsafe_loader(self, py):
        f = py("data = yaml.load(stream, Loader=yaml.UnsafeLoader)\n")
        assert self.rule.check(f)

    def test_ignores_safe_load(self, py):
        f = py("data = yaml.safe_load(stream)\n")
        assert not self.rule.check(f)

    def test_ignores_yaml_safe_loader(self, py):
        f = py("data = yaml.load(stream, Loader=yaml.SafeLoader)\n")
        assert not self.rule.check(f)

    def test_finding_is_high(self, py):
        f = py("data = yaml.load(stream)\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, py):
        f = py("data = yaml.load(stream)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DESER002"

    def test_fix_mentions_safe_load(self, py):
        f = py("data = yaml.load(stream)\n")
        assert "safe_load" in self.rule.check(f)[0].fix

    def test_ignores_comment(self, py):
        f = py("# data = yaml.load(stream)\n")
        assert not self.rule.check(f)


# ── VGL-DESER003 — marshal.loads ─────────────────────────────────────────────

class TestMarshalDeserializeRule:
    rule = MarshalDeserializeRule()

    def test_detects_marshal_loads(self, py):
        f = py("import marshal\nobj = marshal.loads(user_bytes)\n")
        assert self.rule.check(f)

    def test_detects_marshal_load(self, py):
        f = py("obj = marshal.load(file_obj)\n")
        assert self.rule.check(f)

    def test_finding_is_high(self, py):
        f = py("obj = marshal.loads(data)\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, py):
        f = py("obj = marshal.loads(data)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DESER003"

    def test_ignores_comment(self, py):
        f = py("# obj = marshal.loads(data)\n")
        assert not self.rule.check(f)

    def test_does_not_apply_to_non_py(self, tmp_path):
        f = tmp_path / "main.go"
        assert not self.rule.applies_to(f)


# ── VGL-PATH001 — path traversal ─────────────────────────────────────────────

class TestPathTraversalRule:
    rule = PathTraversalRule()

    def test_detects_open_with_filename(self, py):
        f = py("content = open(filename).read()\n")
        assert self.rule.check(f)

    def test_detects_open_with_request_args(self, py):
        f = py("f = open(request.args.get('file'))\n")
        assert self.rule.check(f)

    def test_detects_os_path_join_with_user_input(self, py):
        f = py("path = os.path.join(base_dir, filename)\n")
        assert self.rule.check(f)

    def test_detects_pathlib_with_user_input(self, py):
        f = py("p = Path(filename)\n")
        assert self.rule.check(f)

    def test_ignores_open_with_literal(self, py):
        f = py("f = open('config.json')\n")
        assert not self.rule.check(f)

    def test_ignores_os_path_join_two_literals(self, py):
        f = py("path = os.path.join('/app', 'static', 'style.css')\n")
        assert not self.rule.check(f)

    def test_finding_is_high(self, py):
        f = py("f = open(filename)\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, py):
        f = py("f = open(filename)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-PATH001"

    def test_fix_mentions_resolve(self, py):
        f = py("f = open(filename)\n")
        assert "resolve" in self.rule.check(f)[0].fix

    def test_ignores_comment(self, py):
        f = py("# f = open(filename)\n")
        assert not self.rule.check(f)


# ── VGL-SSTI001 — SSTI ───────────────────────────────────────────────────────

class TestSstiRule:
    rule = SstiRule()

    def test_detects_render_template_string_user_content(self, py):
        f = py("return render_template_string(user_content)\n")
        assert self.rule.check(f)

    def test_detects_render_template_string_request_data(self, py):
        f = py("return render_template_string(request.args.get('tmpl'))\n")
        assert self.rule.check(f)

    def test_detects_jinja2_template(self, py):
        f = py("tmpl = jinja2.Template(user_template)\n")
        assert self.rule.check(f)

    def test_detects_template_with_user_string(self, py):
        f = py("t = Template(template_str)\n")
        assert self.rule.check(f)

    def test_ignores_safe_render_template(self, py):
        f = py("return render_template('index.html', name=user_name)\n")
        assert not self.rule.check(f)

    def test_finding_is_critical(self, py):
        f = py("render_template_string(user_content)\n")
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, py):
        f = py("render_template_string(user_content)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-SSTI001"

    def test_fix_mentions_render_template(self, py):
        f = py("render_template_string(user_content)\n")
        assert "render_template" in self.rule.check(f)[0].fix

    def test_ignores_comment(self, py):
        f = py("# render_template_string(user_input)\n")
        assert not self.rule.check(f)

    def test_does_not_apply_to_non_py(self, tmp_path):
        f = tmp_path / "app.js"
        assert not self.rule.applies_to(f)
