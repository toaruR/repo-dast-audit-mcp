from __future__ import annotations

import unittest

from repository_vulnerability_report_mcp.schemas import (
    JSON_SCHEMA_DRAFT_2020_12,
    InvalidToolArguments,
    TOOL_DEFINITIONS,
    validate_tool_arguments,
)


class SchemaTests(unittest.TestCase):
    def test_only_three_strict_draft_2020_12_tool_schemas_are_public(self) -> None:
        self.assertEqual([tool["name"] for tool in TOOL_DEFINITIONS], ["scan_repository", "get_scan", "cancel_scan"])
        for tool in TOOL_DEFINITIONS:
            self.assertEqual(tool["inputSchema"]["$schema"], JSON_SCHEMA_DRAFT_2020_12)
            self.assertFalse(tool["inputSchema"]["additionalProperties"])

    def test_arguments_reject_unknown_properties_and_bad_uuid(self) -> None:
        validate_tool_arguments("scan_repository", {"root": "C:/repo"})
        with self.assertRaises(InvalidToolArguments):
            validate_tool_arguments("scan_repository", {"root": "C:/repo", "cache_dir": "C:/bad"})
        with self.assertRaises(InvalidToolArguments):
            validate_tool_arguments("get_scan", {"scan_id": "not-a-uuid"})

