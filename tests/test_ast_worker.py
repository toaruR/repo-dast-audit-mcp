import time
import unittest
from repo_dast_audit_mcp.ast_worker import analyze_isolated_python

class IsolatedAstTests(unittest.TestCase):
    def test_real_subprocess_detects_without_evaluating_source(self):
        result=analyze_isolated_python("app.py","eval('never executed')\n")
        self.assertEqual(result.status,"findings")
        self.assertEqual(result.findings[0]["rule"],"PY001")
    def test_tiny_deadline_stops_worker(self):
        started=time.monotonic()
        result=analyze_isolated_python("app.py","x=1\n"*5000,max_ms=1)
        self.assertEqual(result.reason,"AST_TIMEOUT")
        self.assertLess(time.monotonic()-started,3)
    def test_syntax_error_is_uncertainty(self):
        self.assertEqual(analyze_isolated_python("app.py","def :").reason,"AST_PARSE_ERROR")
