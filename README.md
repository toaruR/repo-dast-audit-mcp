# repo-dast-audit-mcp

> **Status: prototype.** This project is an experimental prototype. Interfaces, storage layout, and audit behavior may change without notice; it is not intended for production use.

Bounded MCP server that inventories tracked Git files and writes canonical JSON and Markdown reports to server-owned storage. Static scans are read-only; an opt-in browser audit tests registered local web-service fixtures.

## Local launch

Create or verify the project virtual environment with the exact bundled CPython runtime:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-python.ps1 -Create -PythonPath /path/to/codex-primary-runtime/dependencies/python/python.exe
```

Start the newline-delimited JSON-RPC stdio server with that environment:

```powershell
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.server
```

The server writes protocol responses only to stdout. Its scan records and `report.json` / `report.md` files are kept outside the repository under `%LOCALAPPDATA%\repo-dast-audit-mcp`.

## Project-local MCP registration

Add this entry to this project's `.mcp.json` when registering it with an MCP-capable client:

```json
{
  "mcpServers": {
    "repo-dast-audit": {
      "type": "stdio",
      "command": "/path/to/project/.venv/Scripts/python.exe",
      "args": ["-m", "repo_dast_audit_mcp.server"],
      "env": {"PYTHONUTF8": "1"}
    }
  }
}
```

Project-local registration makes the definition available to clients that load this project. It does not inject the server into an already-running chat; restart or reconnect the client and confirm its MCP-server discovery flow.

## Browser security audit

The optional Docker/Chromium runtime adds nine MCP tools for browser observations, LLM-authored test proposals, controlled verification, evidence, and recovery. It currently verifies authorization isolation, reflected XSS, and registered business invariants against isolated test data.

See [setup, project profiles, client workflow, limits, and verification](docs/web-security-audit.md). The default setup registers synthetic vulnerable/patched reference apps; register a project-specific profile to test your own service. Daybreak approval is not a server startup requirement.
