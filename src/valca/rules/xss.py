"""
VGL-XSS001  HIGH  Cross-Site Scripting — unsafe HTML injection (CWE-79)
             AI models consistently suggest innerHTML, dangerouslySetInnerHTML,
             and Jinja2 |safe without escaping user-controlled data.
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_JS_EXTS  = {".js", ".ts", ".jsx", ".tsx", ".vue"}
_TPL_EXTS = {".html", ".jinja", ".jinja2", ".j2", ".htm"}
_PY_EXTS  = {".py"}
_ALL_EXTS = _JS_EXTS | _TPL_EXTS | _PY_EXTS


class XssRule(Rule):
    id = "VGL-XSS001"
    name = "Cross-Site Scripting — unsafe HTML injection (CWE-79)"
    severity = Severity.HIGH

    # JS/TS/Vue: innerHTML / outerHTML assignment (not comparison)
    _INNER_HTML = re.compile(
        r"""\.(?:inner|outer)HTML\s*=[^=]""",
        re.IGNORECASE,
    )
    # React: dangerouslySetInnerHTML prop
    _DANGEROUS = re.compile(r"""dangerouslySetInnerHTML""")
    # Angular: [innerHTML]= binding
    _NG_INNER = re.compile(r"""\[innerHTML\]\s*=""", re.IGNORECASE)
    # Vue: v-html directive
    _V_HTML = re.compile(r"""\bv-html\s*=""", re.IGNORECASE)
    # document.write() — always dangerous with dynamic content
    _DOC_WRITE = re.compile(r"""document\s*\.\s*write\s*\(""", re.IGNORECASE)

    # Jinja2 / template: {{ ... | safe }} or {% autoescape false %}
    _JINJA_SAFE = re.compile(r"""\|\s*safe\b""", re.IGNORECASE)
    _AUTOESCAPE_OFF = re.compile(r"""\{%-?\s*autoescape\s+false\s*-?%\}""", re.IGNORECASE)

    # Python: Markup(user_input) — wraps content as safe HTML
    _MARKUP = re.compile(r"""\bMarkup\s*\(""")

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _ALL_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []

        ext = path.suffix
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*", "<!--", "{#")):
                continue
            if "vigil: ignore" in line:
                continue

            match = None
            msg = ""
            fix = ""

            if ext in _JS_EXTS:
                if self._INNER_HTML.search(line):
                    match = True
                    msg = "innerHTML/outerHTML assignment — unsanitized HTML injected into DOM"
                    fix = (
                        "Use textContent instead of innerHTML for plain text. "
                        "If HTML is required, sanitize with DOMPurify.sanitize(html) first. "
                        "Never assign user-controlled data directly to innerHTML."
                    )
                elif self._DANGEROUS.search(line):
                    match = True
                    msg = "dangerouslySetInnerHTML — React bypasses all XSS protection"
                    fix = (
                        "Sanitize with DOMPurify.sanitize(html) before passing to "
                        "dangerouslySetInnerHTML={{ __html: sanitized }}. "
                        "Prefer rendering data as React children (text nodes) instead."
                    )
                elif self._V_HTML.search(line):
                    match = True
                    msg = "v-html directive renders raw HTML — XSS if value contains user input"
                    fix = (
                        "Sanitize with DOMPurify before using v-html, or use {{ value }} "
                        "(double-brace renders as text, not HTML). "
                        "Avoid v-html entirely if the value ever comes from user input."
                    )
                elif self._NG_INNER.search(line):
                    match = True
                    msg = "[innerHTML] binding renders raw HTML — XSS if value is user-controlled"
                    fix = (
                        "Use Angular's DomSanitizer.bypassSecurityTrustHtml() only after "
                        "manual sanitization, or switch to {{ value }} text binding."
                    )
                elif self._DOC_WRITE.search(line):
                    match = True
                    msg = "document.write() injects raw HTML — blocks parser and enables XSS"
                    fix = (
                        "Replace document.write() with DOM manipulation: "
                        "document.createElement() + textContent or appendChild(). "
                        "document.write() after page load also wipes the entire document."
                    )

            elif ext in _TPL_EXTS:
                if self._JINJA_SAFE.search(line):
                    match = True
                    msg = "Jinja2 |safe filter disables HTML escaping — XSS if variable contains user input"
                    fix = (
                        "Remove |safe and let Jinja2 auto-escape (enabled by default in Flask/Django). "
                        "Only use |safe for trusted, static HTML you control — never on user-supplied data. "
                        "If you must render HTML from users, sanitize server-side with bleach.clean()."
                    )
                elif self._AUTOESCAPE_OFF.search(line):
                    match = True
                    msg = "{% autoescape false %} disables HTML escaping for the entire block"
                    fix = (
                        "Remove autoescape false — Jinja2 auto-escaping is your primary XSS defense. "
                        "Mark individual trusted strings with Markup() on the Python side instead."
                    )

            elif ext in _PY_EXTS:
                if self._MARKUP.search(line):
                    match = True
                    msg = "Markup() wraps content as safe HTML — XSS if called with user-controlled input"
                    fix = (
                        "Only call Markup() on string literals you fully control. "
                        "For user input, use flask.escape() or markupsafe.escape() first: "
                        "Markup('<b>') + escape(user_input) + Markup('</b>'). "
                        "Never: Markup(request.args.get('html'))."
                    )

            if match:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=msg,
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=fix,
                ))

        return findings
