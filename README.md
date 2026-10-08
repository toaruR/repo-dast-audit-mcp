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

## MCP registration

Register per audited project rather than globally. Browser audit profiles are bound to a target repository root through `REPO_DAST_PROFILES`, so one global entry cannot select the right registry, and enabling `REPO_DAST_AUDIT` globally would expose container-launching tools in unrelated sessions.

| Scope | Registration |
| --- | --- |
| Global (optional) | Static scan only; omit `REPO_DAST_AUDIT`. `scan_repository` takes any repository through its `root` argument. |
| Audited project's `.mcp.json` | Enable browser auditing with `REPO_DAST_AUDIT=1` and that project's `REPO_DAST_PROFILES`. |

When both scopes use the same server key, Claude Code gives the project-scoped entry precedence, so browser auditing is enabled only inside that project. Verify the active definition with `/mcp`. In either scope, `command` must be the absolute path to this repository's `.venv` Python.

Static-scan entry (global or project):

```json
{
  "mcpServers": {
    "repo-dast-audit": {
      "type": "stdio",
      "command": "/path/to/repo-dast-audit-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "repo_dast_audit_mcp.server"],
      "env": {"PYTHONUTF8": "1"}
    }
  }
}
```

For the browser-audit entry, see [docs/web-security-audit.md](docs/web-security-audit.md).

Registration does not inject the server into an already-running chat; restart or reconnect the client and confirm its MCP-server discovery flow.

## Browser security audit

The optional Docker/Chromium runtime adds nine MCP tools for browser observations, LLM-authored test proposals, controlled verification, evidence, and recovery. It currently verifies authorization isolation, reflected XSS, and registered business invariants against isolated test data.

See [setup, project profiles, client workflow, limits, and verification](docs/web-security-audit.md). The default setup registers synthetic vulnerable/patched reference apps; register a project-specific profile to test your own service. Daybreak approval is not a server startup requirement.

## License

MIT. See [LICENSE](LICENSE).

The browser-audit setup downloads Playwright Core, the official Playwright Docker image, and its seccomp profile (Apache-2.0) at setup time; they are not redistributed here. Keep their notices if you distribute a built worker image.
