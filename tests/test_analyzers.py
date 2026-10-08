from __future__ import annotations

import unittest

from repo_dast_audit_mcp.analyzers import analyze_python_ast, analyze_secret_text


class AnalyzerTests(unittest.TestCase):
    def test_ast_rules_and_parse_failure_are_explicit(self) -> None:
        result = analyze_python_ast("a.py", "eval('x')\nsubprocess.run('x', shell=True)\npickle.loads(b'x')\nyaml.load('x')")
        self.assertEqual(result.status, "findings")
        self.assertEqual({item["rule"] for item in result.findings}, {"PY001", "PY002", "PY003", "PY004"})
        self.assertEqual(analyze_python_ast("bad.py", "def :").status, "partial")

    def test_secret_values_and_pem_body_never_appear(self) -> None:
        secret = "super-secret-value"
        pem_body = "PRIVATE-BODY"
        result = analyze_secret_text(".env", f"API_TOKEN={secret}\n-----BEGIN PRIVATE KEY-----\n{pem_body}\n")
        rendered = str(result.as_dict())
        self.assertEqual(result.status, "findings")
        self.assertNotIn(secret, rendered)
        self.assertNotIn(pem_body, rendered)
        self.assertIn("[REDACTED]", rendered)


if __name__ == "__main__":
    unittest.main()
