# Repository Vulnerability Report MCP

Read-only, bounded MCP server that inventories tracked Git files and writes canonical JSON and Markdown reports to server-owned storage.

## Local launch

Create or verify the project virtual environment with the exact bundled CPython runtime:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-python.ps1 -Create -PythonPath /path/to/codex-primary-runtime/dependencies/python/python.exe
```

Start the newline-delimited JSON-RPC stdio server with that environment:

```powershell
.\.venv\Scripts\python.exe -m repository_vulnerability_report_mcp.server
```

The server writes protocol responses only to stdout. Its scan records and `report.json` / `report.md` files are kept outside the repository under `%LOCALAPPDATA%\repository-vulnerability-report-mcp`.

## Project-local MCP registration

Add this entry to this project's `.mcp.json` when registering it with an MCP-capable client:

```json
{
  "mcpServers": {
    "repository-vulnerability-report": {
      "type": "stdio",
      "command": "/path/to/project/.venv/Scripts/python.exe",
      "args": ["-m", "repository_vulnerability_report_mcp.server"],
      "env": {"PYTHONUTF8": "1"}
    }
  }
}
```

Project-local registration makes the definition available to clients that load this project. It does not inject the server into an already-running chat; restart or reconnect the client and confirm its MCP-server discovery flow.
