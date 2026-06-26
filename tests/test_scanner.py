"""Unit tests for SAST scanner engines."""
import unittest
from pathlib import Path

from sast_scanner.engines.regex_engine import RegexEngine
from sast_scanner.engines.semantic_engine import SemanticEngine
from sast_scanner.engines.secret_engine import SecretEngine
from sast_scanner.utils.file_utils import FileWalker


class TestEngines(unittest.TestCase):
    sample = Path(__file__).parent / "samples" / "vulnerable.py"

    def _read(self):
        with open(self.sample, "r", encoding="utf-8") as f:
            content = f.read()
        return content, content.splitlines()

    def test_regex_engine(self):
        content, lines = self._read()
        engine = RegexEngine()
        findings = engine.analyze(self.sample, content, lines)
        self.assertTrue(any(f.rule_name == "Hardcoded Secret / API Key" for f in findings))
        self.assertTrue(any(f.rule_name == "Command Injection Vector" for f in findings))
        self.assertTrue(any(f.rule_name == "SQL Injection Vector" for f in findings))
        self.assertTrue(any(f.rule_name == "Insecure Deserialization" for f in findings))

    def test_semantic_engine(self):
        content, lines = self._read()
        engine = SemanticEngine()
        findings = engine.analyze(self.sample, content, lines)
        rule_names = {f.rule_name for f in findings}
        self.assertIn("Arbitrary Code Execution", rule_names)
        self.assertIn("subprocess.run with shell=True", rule_names)
        self.assertIn("Insecure Deserialization", rule_names)

    def test_secret_engine(self):
        content, lines = self._read()
        engine = SecretEngine()
        findings = engine.analyze(self.sample, content, lines)
        self.assertTrue(any("Hardcoded Secret" in f.rule_name for f in findings))

    def test_file_walker(self):
        walker = FileWalker(str(self.sample.parent))
        files = list(walker.iter_files())
        self.assertTrue(any(f.name == "vulnerable.py" for f in files))

    def test_js_scan(self):
        js_sample = self.sample.parent / "vulnerable.js"
        with open(js_sample, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        engine = RegexEngine()
        findings = engine.analyze(js_sample, content, lines)
        rule_names = {f.rule_name for f in findings}
        self.assertIn("Command Injection Vector", rule_names)
        self.assertIn("Cross-Site Scripting (XSS) Sink", rule_names)
        self.assertIn("Insecure CORS / Network Binding", rule_names)

    def test_taint_engine(self):
        code = '''
def login():
    username = request.form.get("username")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    db.session.execute(query)
'''
        from sast_scanner.engines.taint_engine import TaintEngine
        engine = TaintEngine()
        findings = engine.analyze(Path("test.py"), code, code.splitlines())
        self.assertTrue(any("SQL Injection" in f.rule_name for f in findings))

    def test_sca_engine(self):
        from sast_scanner.engines.sca_engine import SCAEngine
        engine = SCAEngine()
        content = "Jinja2==3.1.2\nFlask==2.3.3\n"
        findings = engine.analyze(Path("requirements.txt"), content, content.splitlines())
        self.assertTrue(any("Jinja2" in f.rule_name for f in findings))

    def test_iac_engine(self):
        from sast_scanner.engines.iac_engine import IACEngine
        engine = IACEngine()
        content = "runAsUser: 0\nprivileged: true\n"
        findings = engine.analyze(Path("k8s/deployment.yaml"), content, content.splitlines())
        self.assertTrue(any("Container Running as Root" in f.rule_name for f in findings))


if __name__ == "__main__":
    unittest.main()
