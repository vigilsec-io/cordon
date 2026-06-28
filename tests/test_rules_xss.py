"""Tests for XSS rule: VGL-XSS001."""
import pytest
from vigil.rules.xss import XssRule


@pytest.fixture
def js_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.js"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def tsx_file(tmp_path):
    def _make(content):
        f = tmp_path / "Component.tsx"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def vue_file(tmp_path):
    def _make(content):
        f = tmp_path / "App.vue"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def html_file(tmp_path):
    def _make(content):
        f = tmp_path / "index.html"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "views.py"
        f.write_text(content)
        return f
    return _make


class TestXssRule:
    rule = XssRule()

    # ── innerHTML ────────────────────────────────────────────────────────────
    def test_detects_inner_html_assignment(self, js_file):
        f = js_file("el.innerHTML = userInput;\n")
        assert self.rule.check(f)

    def test_detects_outer_html_assignment(self, js_file):
        f = js_file("el.outerHTML = data;\n")
        assert self.rule.check(f)

    def test_ignores_inner_html_read(self, js_file):
        f = js_file("const content = el.innerHTML;\n")
        assert not self.rule.check(f)

    def test_ignores_inner_html_comparison(self, js_file):
        f = js_file("if (el.innerHTML === '') { ... }\n")
        assert not self.rule.check(f)

    # ── dangerouslySetInnerHTML ──────────────────────────────────────────────
    def test_detects_dangerous_set_inner_html(self, tsx_file):
        f = tsx_file('<div dangerouslySetInnerHTML={{ __html: userHtml }} />\n')
        assert self.rule.check(f)

    # ── v-html ───────────────────────────────────────────────────────────────
    def test_detects_v_html(self, vue_file):
        f = vue_file('<div v-html="rawHtml"></div>\n')
        assert self.rule.check(f)

    # ── document.write ───────────────────────────────────────────────────────
    def test_detects_document_write(self, js_file):
        f = js_file("document.write('<script>' + data + '</script>');\n")
        assert self.rule.check(f)

    # ── Jinja2 | safe ────────────────────────────────────────────────────────
    def test_detects_jinja_safe_filter(self, html_file):
        f = html_file("{{ user_bio | safe }}\n")
        assert self.rule.check(f)

    def test_detects_autoescape_false(self, html_file):
        f = html_file("{% autoescape false %}\n{{ content }}\n{% endautoescape %}\n")
        assert self.rule.check(f)

    # ── Python Markup() ──────────────────────────────────────────────────────
    def test_detects_markup_call(self, py_file):
        f = py_file("return Markup(request.args.get('html'))\n")
        assert self.rule.check(f)

    # ── Ignores ──────────────────────────────────────────────────────────────
    def test_ignores_comment_js(self, js_file):
        f = js_file("// el.innerHTML = userInput; — don't do this\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, js_file):
        f = js_file("el.innerHTML = safeHtml;  // vigil: ignore\n")
        assert not self.rule.check(f)

    def test_ignores_non_code_file(self, tmp_path):
        f = tmp_path / "notes.md"
        f.write_text("el.innerHTML = userInput;\n")
        assert not self.rule.applies_to(f)

    def test_finding_has_correct_rule_id(self, js_file):
        f = js_file("el.innerHTML = data;\n")
        assert self.rule.check(f)[0].rule_id == "VGL-XSS001"
