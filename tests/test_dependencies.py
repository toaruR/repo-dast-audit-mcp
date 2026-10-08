from __future__ import annotations

import unittest

from repo_dast_audit_mcp.dependencies import Package, parse_package_lock, parse_requirements, query_osv


class DependencyTests(unittest.TestCase):
    def test_exact_pins_and_unsupported_forms_are_explicit(self) -> None:
        result, packages = parse_requirements("requirements.txt", "safe==1.2\nunsafe>=2\n-e .\n")
        self.assertEqual(packages, (Package("PyPI", "safe", "1.2"),))
        self.assertEqual(result.status, "partial")
        lock, npm = parse_package_lock("package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}')
        self.assertEqual(lock.status, "clean")
        self.assertEqual(npm, (Package("npm", "a", "1.0.0"),))

    def test_osv_default_is_disabled_and_no_package_is_not_clean(self) -> None:
        self.assertEqual(query_osv((), enabled=False).status, "skipped")
        self.assertEqual(query_osv((), enabled=True).status, "skipped")


if __name__ == "__main__":
    unittest.main()
