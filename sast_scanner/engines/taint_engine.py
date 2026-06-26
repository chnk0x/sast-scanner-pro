"""Basic intra-procedural taint analysis engine for Python."""
import ast
import re
from pathlib import Path
from typing import List, Set, Dict

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


TAINT_SOURCES = {
    "request.args.get", "request.form.get", "request.json.get", "request.values.get",
    "request.headers.get", "request.cookies.get", "request.files.get", "request.get_json",
    "request.args", "request.form", "request.json", "request.values", "request.data",
    "input", "raw_input", "sys.argv",
}

SINKS = {
    "os.system": "Command Injection",
    "subprocess.call": "Command Injection",
    "subprocess.run": "Command Injection",
    "subprocess.Popen": "Command Injection",
    "subprocess.check_output": "Command Injection",
    "eval": "Arbitrary Code Execution",
    "exec": "Arbitrary Code Execution",
    "compile": "Arbitrary Code Execution",
    "cursor.execute": "SQL Injection",
    "db.session.execute": "SQL Injection",
    "requests.get": "SSRF",
    "requests.post": "SSRF",
    "urllib.request.urlopen": "SSRF",
    "send_from_directory": "Path Traversal",
    "open": "Path Traversal",
    "pickle.loads": "Insecure Deserialization",
    "yaml.load": "Insecure Deserialization",
    "json.loads": "Unsafe Deserialization",
    "redirect": "Open Redirect",
}

SANITIZERS = {
    "escape", "html.escape", "bleach.clean", "shlex.quote", "sqlite3.paramstyle",
    "re.escape", "urllib.parse.quote", "markupsafe.escape", "flask.escape",
}


class TaintVisitor(ast.NodeVisitor):
    """Tracks taint within a single function scope."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.tainted_vars: Dict[str, Set[str]] = {}
        self.findings: List[Finding] = []
        self.current_function = None

    def _get_line(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 1)
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    def _resolve_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            return self._resolve_name(node.value)
        return ""

    def _is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.FormattedValue):
            return self._is_tainted(node.value)
        name = self._resolve_name(node)
        if name in TAINT_SOURCES:
            return True
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return True
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted(v) for v in node.values)
        if isinstance(node, ast.Call):
            func_name = self._resolve_name(node.func)
            if func_name in SANITIZERS:
                return False
            return func_name in TAINT_SOURCES or any(self._is_tainted(a) for a in node.args)
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        return False

    def _is_sanitized(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func_name = self._resolve_name(node.func)
            if func_name in SANITIZERS:
                return True
            return self._is_sanitized(node.func)
        return False

    def _add_finding(self, sink_name: str, node: ast.Call):
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        snippet = self._get_line(node)
        self.findings.append(Finding(
            rule_id="TAINT-001",
            rule_name=f"Taint-based {sink_name}",
            description=f"User-controlled input reaches a dangerous {sink_name} sink.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=self.file_path,
            line_number=line,
            column=col,
            snippet=snippet[:200],
            remediation="Validate, sanitize, or parameterize the user input before passing it to the sink. Use allow-lists and parameterized APIs.",
            cwe_id="CWE-78" if "Command" in sink_name else "CWE-89" if "SQL" in sink_name else "CWE-918" if "SSRF" in sink_name else "CWE-94",
            owasp_category="A03:2021 – Injection",
            engine="taint",
            tags=["taint", "data-flow", "injection"],
        ))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_tainted = self.tainted_vars.copy()
        self.current_function = node.name
        # Mark parameters as potentially tainted if they are named like user input
        for arg in node.args.args:
            if arg.arg.lower() in {"user_input", "cmd", "url", "data", "host", "q", "filename", "target", "password"}:
                self.tainted_vars[arg.arg] = {arg.arg}

        for stmt in node.body:
            self.visit(stmt)

        self.tainted_vars = old_tainted
        self.current_function = None

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if self._is_tainted(node.value) and not self._is_sanitized(node.value):
                    self.tainted_vars[target.id] = self._taint_sources(node.value)
                elif target.id in self.tainted_vars:
                    del self.tainted_vars[target.id]
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_name(node.func)
        if func_name in SINKS:
            if any(self._is_tainted(a) for a in node.args):
                self._add_finding(SINKS[func_name], node)
        self.generic_visit(node)

    def _taint_sources(self, node: ast.AST) -> Set[str]:
        sources = set()
        if isinstance(node, ast.FormattedValue):
            sources.update(self._taint_sources(node.value))
            return sources
        name = self._resolve_name(node)
        if name in TAINT_SOURCES:
            sources.add(name)
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            sources.update(self.tainted_vars[node.id])
        if isinstance(node, ast.BinOp):
            sources.update(self._taint_sources(node.left))
            sources.update(self._taint_sources(node.right))
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                sources.update(self._taint_sources(v))
        if isinstance(node, ast.Call):
            if name in TAINT_SOURCES:
                sources.add(name)
            for a in node.args:
                sources.update(self._taint_sources(a))
        return sources


class TaintEngine(BaseEngine):
    """Basic taint/data-flow analysis engine for Python."""

    name = "taint"

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        if file_path.suffix != ".py":
            return []
        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return []
        visitor = TaintVisitor(str(file_path), content)
        visitor.visit(tree)
        return visitor.findings
