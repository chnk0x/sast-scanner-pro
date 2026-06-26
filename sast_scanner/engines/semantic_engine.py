"""AST-based semantic analysis engine for Python."""
import ast
import re
from pathlib import Path
from typing import List

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


class PythonSemanticVisitor(ast.NodeVisitor):
    """Walks Python AST to detect dangerous patterns."""

    DANGEROUS_CALLS = {
        "exec": ("Arbitrary Code Execution", Severity.CRITICAL, "CWE-94", "A03:2021 – Injection",
                 "Avoid exec. Use safer parsing or dedicated expression evaluators with allow-lists."),
        "eval": ("Unsafe eval() Usage", Severity.CRITICAL, "CWE-94", "A03:2021 – Injection",
                 "Avoid eval on untrusted input. Use ast.literal_eval for literals or safer parsers."),
        "os.system": ("Command Injection", Severity.CRITICAL, "CWE-78", "A03:2021 – Injection",
                      "Use subprocess.run with a list of arguments and validated input."),
        "subprocess.call": ("Command Injection", Severity.CRITICAL, "CWE-78", "A03:2021 – Injection",
                            "Use subprocess.run with shell=False and pass arguments as a list."),
        "subprocess.Popen": ("Command Injection", Severity.CRITICAL, "CWE-78", "A03:2021 – Injection",
                             "Avoid shell=True. Pass arguments as a list and validate input."),
        "subprocess.run": ("Command Injection", Severity.CRITICAL, "CWE-78", "A03:2021 – Injection",
                           "Avoid shell=True. Pass arguments as a list and validate input."),
        "pickle.loads": ("Insecure Deserialization", Severity.CRITICAL, "CWE-502", "A08:2021 – Software and Data Integrity Failures",
                         "Never unpickle untrusted data. Use JSON or signed serialization."),
        "yaml.load": ("Insecure Deserialization", Severity.HIGH, "CWE-502", "A08:2021 – Software and Data Integrity Failures",
                      "Use yaml.safe_load or a restricted loader for untrusted YAML."),
        "compile": ("Dynamic Code Compilation", Severity.MEDIUM, "CWE-94", "A03:2021 – Injection",
                    "Avoid compiling untrusted source code. Validate input thoroughly."),
        "input": ("Unsafe Python 2 input()", Severity.CRITICAL, "CWE-94", "A03:2021 – Injection",
                  "Use raw_input equivalent and never pass input to eval/exec."),
    }

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings: List[Finding] = []

    def _make_finding(self, name: str, node: ast.AST, severity: Severity, cwe: str, owasp: str, remediation: str, tags=None):
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        snippet = self.source_lines[line - 1].strip() if 1 <= line <= len(self.source_lines) else ""
        self.findings.append(Finding(
            rule_id="PY-SEM-001",
            rule_name=name,
            description=f"Semantic analysis detected {name}.",
            severity=severity,
            confidence=Confidence.HIGH,
            file_path=self.file_path,
            line_number=line,
            column=col,
            snippet=snippet[:200],
            remediation=remediation,
            cwe_id=cwe,
            owasp_category=owasp,
            engine="semantic",
            tags=tags or ["semantic"],
        ))

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_name(node.func)
        if func_name and func_name in self.DANGEROUS_CALLS:
            name, severity, cwe, owasp, remediation = self.DANGEROUS_CALLS[func_name]
            # Check if shell=True is passed to subprocess
            if func_name in ("subprocess.call", "subprocess.Popen", "subprocess.run"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._make_finding(
                            f"{func_name} with shell=True", node, Severity.CRITICAL, "CWE-78", "A03:2021 – Injection",
                            "Never use shell=True with user-controlled input. Pass command as a list of arguments.",
                            tags=["command", "subprocess", "shell"]
                        )
                        break
                else:
                    self._make_finding(name, node, severity, cwe, owasp, remediation, tags=["command", "subprocess"])
            else:
                self._make_finding(name, node, severity, cwe, owasp, remediation)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Detect dangerous default arguments (mutable defaults are not security, but unsafe raw input is)
        self.generic_visit(node)

    def _resolve_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""


class SemanticEngine(BaseEngine):
    """AST-based semantic engine for Python and JavaScript-style parsing."""

    name = "semantic"

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content, filename=str(file_path))
                visitor = PythonSemanticVisitor(str(file_path), content)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass
        return findings
