"""
VGL-DESER001  CRITICAL  pickle.loads / pickle.load called with non-literal data (arbitrary code execution)
VGL-DESER002  HIGH      yaml.load() without Loader=yaml.SafeLoader (arbitrary code execution)
VGL-DESER003  HIGH      marshal.loads() with untrusted data
VGL-PATH001   HIGH      Path traversal — user input passed to open() or os.path.join without validation
VGL-SSTI001   CRITICAL  Server-Side Template Injection — user input rendered as a Jinja2 template
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_PY = {".py"}
_CODE = {".py", ".js", ".ts", ".rb", ".go", ".java", ".php"}


def _check_lines(path: Path, patterns: list, rule_id: str, severity: Severity,
                 message: str, fix: str, exts: set[str]) -> list[Finding]:
    if path.suffix not in exts:
        return []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except (OSError, PermissionError):
        return []
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*")):
            continue
        if "vigil: ignore" in line:
            continue
        for pat in patterns:
            if pat.search(line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=fix,
                ))
                break
    return findings


# ── VGL-DESER001 — pickle ─────────────────────────────────────────────────────

class PickleDeserializeRule(Rule):
    """pickle.loads(data) executes arbitrary Python code — never use on untrusted input."""

    id = "VGL-DESER001"
    name = "Insecure deserialization — pickle.loads / pickle.load"
    severity = Severity.CRITICAL

    # pickle.loads(anything) — even with a variable is dangerous
    # pickle.load(file_from_user) — loading from a user-supplied file handle
    _PAT = re.compile(r"\bpickle\s*\.\s*(?:loads?)\s*\(", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _PY

    def check(self, path: Path) -> list[Finding]:
        return _check_lines(
            path, [self._PAT], self.id, self.severity,
            "pickle.loads() deserializes arbitrary Python objects — executes code on unpickling",
            "Never deserialize pickle data from untrusted sources. "
            "Use JSON (json.loads), MessagePack, or Protocol Buffers for cross-system data exchange. "
            "If pickle is required for trusted internal data, sign it with hmac.new(secret, data, 'sha256') "
            "and verify the signature before deserializing.",
            _PY,
        )


# ── VGL-DESER002 — yaml.load without SafeLoader ──────────────────────────────

class YamlLoadRule(Rule):
    """yaml.load() with the default Loader executes Python constructors (!!python/object/apply).
    yaml.safe_load() or Loader=yaml.SafeLoader are the safe alternatives."""

    id = "VGL-DESER002"
    name = "Insecure YAML deserialization — yaml.load() without SafeLoader"
    severity = Severity.HIGH

    # yaml.load(data) or yaml.load(data, Loader=yaml.FullLoader / UnsafeLoader)
    # Safe: yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)
    _UNSAFE = re.compile(
        r"""\byaml\s*\.\s*load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)""",
        re.IGNORECASE,
    )
    # Also catch explicit unsafe loaders
    _EXPLICIT_UNSAFE = re.compile(
        r"""\byaml\s*\.\s*load\s*\(.*Loader\s*=\s*yaml\.(?:UnsafeLoader|FullLoader|Loader)\b""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _PY

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            # Skip yaml.safe_load() — that's the correct call
            if re.search(r"\byaml\s*\.\s*safe_load\s*\(", line):
                continue
            if self._EXPLICIT_UNSAFE.search(line) or self._UNSAFE.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="yaml.load() without SafeLoader — YAML !!python/object tags execute arbitrary Python constructors",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix="Replace yaml.load(data) with yaml.safe_load(data). "
                       "SafeLoader only deserializes standard YAML types and rejects Python-specific tags. "
                       "yaml.full_load() and yaml.unsafe_load() also allow code execution — avoid them.",
                ))
        return findings


# ── VGL-DESER003 — marshal.loads ─────────────────────────────────────────────

class MarshalDeserializeRule(Rule):
    """marshal is Python's internal bytecode format — never expose it to external input.
    marshal.loads() on attacker-controlled data can crash the interpreter or execute code."""

    id = "VGL-DESER003"
    name = "Insecure deserialization — marshal.loads with untrusted data"
    severity = Severity.HIGH

    _PAT = re.compile(r"\bmarshal\s*\.\s*loads?\s*\(", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _PY

    def check(self, path: Path) -> list[Finding]:
        return _check_lines(
            path, [self._PAT], self.id, self.severity,
            "marshal.loads() — Python internal format not designed for untrusted input; can crash or execute code",
            "marshal is not a secure serialization format. Use json.loads() for data exchange. "
            "marshal is only safe for Python's own .pyc files generated by the same Python version.",
            _PY,
        )


# ── VGL-PATH001 — Path traversal ─────────────────────────────────────────────

class PathTraversalRule(Rule):
    """Path traversal allows an attacker to read or write files outside the intended directory
    by injecting '../' sequences into filenames supplied by user input."""

    id = "VGL-PATH001"
    name = "Path traversal — user input passed to file open or path join without validation"
    severity = Severity.HIGH

    # open(request.*), open(user_*), open(filename) where filename could be user-supplied
    _OPEN_USER = re.compile(
        r"""\bopen\s*\(\s*(?:request\.|user_|filename|filepath|path|file_path|"""
        r"""upload_|input_|f_name|fname|file_name)\w*""",
        re.IGNORECASE,
    )
    # os.path.join(basedir, user_input) — the key is the second arg looks user-controlled
    _JOIN_USER = re.compile(
        r"""os\.path\.join\s*\([^,]+,\s*(?:request\.|user_|filename|filepath|"""
        r"""path|file_path|upload_|input_)\w*""",
        re.IGNORECASE,
    )
    # Path(user_input) — pathlib
    _PATHLIB = re.compile(
        r"""\bPath\s*\(\s*(?:request\.|user_|filename|filepath|input_)\w*""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE

    def check(self, path: Path) -> list[Finding]:
        return _check_lines(
            path, [self._OPEN_USER, self._JOIN_USER, self._PATHLIB],
            self.id, self.severity,
            "Path traversal risk — user-controlled value passed to file open or path construction",
            "Validate the resolved path stays within the intended directory: "
            "safe = Path(BASE_DIR, filename).resolve(); "
            "if not safe.is_relative_to(BASE_DIR): raise ValueError('path traversal'). "
            "Also strip leading slashes and '../' from user input before constructing paths.",
            _CODE,
        )


# ── VGL-SSTI001 — Server-Side Template Injection ─────────────────────────────

class SstiRule(Rule):
    """SSTI allows an attacker to inject template expressions that execute on the server.
    Rendering user-provided content as a Jinja2 template gives full RCE."""

    id = "VGL-SSTI001"
    name = "Server-Side Template Injection — user input rendered as Jinja2 template"
    severity = Severity.CRITICAL

    # Flask render_template_string(user_content)
    _FLASK = re.compile(
        r"""\brender_template_string\s*\(\s*(?:request\.|user_|template_|content|"""
        r"""body|text|html|message|input_)\w*""",
        re.IGNORECASE,
    )
    # jinja2.Template(user_input).render()  or  Environment().from_string(user_input)
    _JINJA = re.compile(
        r"""jinja2\s*\.\s*(?:Template|Environment)\s*\(|"""
        r"""env(?:ironment)?\s*\.\s*from_string\s*\(\s*(?:request\.|user_)\w*""",
        re.IGNORECASE,
    )
    # Template(user_string) where Template is imported from jinja2
    _TEMPLATE_CALL = re.compile(
        r"""\bTemplate\s*\(\s*(?:request\.|user_|template_str|content|body|text)\w*""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _PY

    def check(self, path: Path) -> list[Finding]:
        return _check_lines(
            path, [self._FLASK, self._JINJA, self._TEMPLATE_CALL],
            self.id, self.severity,
            "SSTI — user input passed to Jinja2 template renderer; attacker can execute arbitrary code",
            "Never render user-supplied content as a template. "
            "If you need dynamic content, pass user input as template variables, not as the template itself: "
            "render_template('page.html', name=user_input). "
            "Use render_template() with a fixed template path — never render_template_string(user_content).",
            _PY,
        )
