# repo-dast-audit-mcp

[English](README.md) | [日本語](readme.ja.md)

> **Status: prototype.** This project is an experimental prototype. Interfaces, storage layout, and audit behavior may change without notice; it is not intended for production use.

An MCP server for browser-based dynamic security audits of local web applications. An LLM client reads code and browser observations, proposes test cases, and asks the server to verify them against operator-registered rules in isolated Docker/Chromium environments. Results include reproducible steps, evidence hashes, and JSON/Markdown reports.

Read-only static repository scans are also available. Browser auditing is explicitly enabled per audited project.

## Browser security audit

The browser workflow exposes nine MCP tools for observations, source inspection, test proposals, verification, evidence retrieval, and cleanup. The server does not call an LLM API itself; the connected MCP client authors the proposals.

### What it verifies

| Check | Verification |
| --- | --- |
| Authorization isolation | Compare an owner's normal resource read with the same read by an unauthorized actor. |
| Reflected XSS | Compare normal input with a registered nonce probe and observe execution in Chromium. |
| Business invariants | Compare normal input with a test mutation against registered numeric constraints, such as a minimum price. |

Each verification runs twice in fresh target and browser environments. Matching results produce `confirmed` or `rejected`; inconsistent or insufficient evidence produces `inconclusive`. Proposals without a registered oracle remain `candidate`.

The default setup registers `fixture_vulnerable` and `fixture_patched`: synthetic reference applications for these three checks. **Their findings are demonstration results, not vulnerabilities in your repository.** To audit your own service, register a project-specific profile as described below.

### Quick start: reference applications

Requirements: CPython 3.12, Docker running Linux containers, and Node.js/npm. Run these commands from this MCP server's repository root.

1. Create or verify the local Python environment using the bundled-runtime helper. The helper requires its configured bundled CPython 3.12 runtime to be installed.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-python.ps1 -Create
```

2. Install the pinned Playwright Core package and provision the browser runtime and reference profiles.

```powershell
npm install --prefix .web-audit-runtime/node-runtime --ignore-scripts --save-exact playwright-core@1.62.1

$browserCore = (Resolve-Path .web-audit-runtime/node-runtime/node_modules/playwright-core).Path
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root (Get-Location).Path --playwright-core $browserCore
```

Setup downloads the pinned official Playwright Docker image and seccomp profile, builds a dedicated worker image, and writes generated files under the Git-ignored `.web-audit-runtime/` directory. Provisioning is an operator action, not an MCP tool.

3. Enable browser auditing and launch the stdio server, or configure your MCP client using the registration below.

```powershell
$env:REPO_DAST_AUDIT = '1'
$env:REPO_DAST_PROFILES = (Resolve-Path .web-audit-runtime/profiles.json).Path
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.server
```

The server uses newline-delimited JSON-RPC over stdio and writes protocol responses only to stdout. Reports and audit records are stored outside the repository under `%LOCALAPPDATA%\repo-dast-audit-mcp`.

### Register the MCP server for an audited project

Browser profiles are bound to a target repository root. Put the browser-enabled entry in the audited project's `.mcp.json`, using absolute paths for both the server's Python environment and that project's profile registry:

```json
{
  "mcpServers": {
    "repo-dast-audit": {
      "type": "stdio",
      "command": "/path/to/repo-dast-audit-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "repo_dast_audit_mcp.server"],
      "env": {
        "PYTHONUTF8": "1",
        "REPO_DAST_AUDIT": "1",
        "REPO_DAST_PROFILES": "/path/to/audited-project/.web-audit-runtime/profiles.json"
      }
    }
  }
}
```

For the reference-app quick start, use the registry generated in this MCP server's repository. For your own service, use the registry generated for its repository by the next step.

Restart or reconnect the client after registration and confirm that `tools/list` exposes the nine browser tools alongside the three static-scan tools. Registration does not add tools to an already-running chat automatically. Keep browser-enabled registration project-scoped; an optional global entry should omit `REPO_DAST_AUDIT` and expose only static scans.

### Audit your own service

Prepare an operator-owned JSON profile defining the service's startup command, container image when needed, port, test accounts, resource ownership and permissions, controls, request templates, mutable fields, and verification oracles. Profiles are not generated or changed by the LLM or page content.

From the MCP server's repository, provision a registry for the target project using the Playwright Core path from the quick start:

```powershell
.\.venv\Scripts\python.exe -m repo_dast_audit_mcp.web_audit.setup --root /path/to/audited-project --runtime-dir /path/to/audited-project/.web-audit-runtime --playwright-core $browserCore --project-profile /path/to/operator-profile.json
```

The service must run from a read-only snapshot of tracked Git files and isolated test data. Untracked files, virtual environments, and secret files are not automatically copied. Prepare any required dependencies in the container image; the audit does not install them or connect to external databases or production services. Custom images must be registered by immutable image ID.

See the [profile example and setup details](docs/web-security-audit.md#実プロジェクトの登録) before registering a real service.

### Client workflow

| Tool | Purpose |
| --- | --- |
| `start_web_audit` | Snapshot a registered repository/profile and start an asynchronous audit. |
| `get_web_audit` | Read state, revision, observations, cases, budgets, and report information. |
| `web_action` | Observe as a registered actor, navigate relative paths, interact through opaque handles, or replay a registered request. |
| `get_web_source` | Read redacted snapshot source and the public profile. |
| `propose_web_case` | Register a test proposal grounded in observations and source. |
| `verify_web_case` | Check baseline and attack behavior twice in fresh environments. |
| `get_web_artifact` | Retrieve evidence with hashes and JSON/Markdown reports. |
| `cancel_web_audit` | Request cancellation and cleanup. |
| `finish_web_audit` | Request normal completion and inspect the result after cleanup. |

1. Start an audit with the registered root and profile, then poll `get_web_audit` for readiness and the current revision.
2. Observe the service with `web_action`. Read the public profile through its observation `source_ref`, then inspect relevant snapshot code with `get_web_source`.
3. Propose a case using observed behavior and a registered oracle, and run `verify_web_case`.
4. Retrieve the verdict and evidence, finish the audit, and confirm cleanup before collecting the final report.

Mutating operations use the current revision and a UUID `client_action_id`; actor-specific actions also require `actor_id`. Reusing an action ID with identical input returns its existing receipt, while changed input is rejected. If a write response is lost, inspect audit state before deciding how to retry.

### Isolation, evidence, and limits

The target has no external network access. Chromium communicates through a fixed loopback proxy within the target's network namespace. Target and worker containers run as non-root with dropped capabilities, no-new-privileges, read-only root filesystems, and no host bind mounts or Docker socket access. Navigation and requests are restricted to the registered scope; there is no MCP tool for arbitrary script evaluation.

Reports include verified findings, reproduction steps, coverage, and evidence hashes calculated after credential redaction. Interrupted audits are recovered on restart; uncertain operations are recorded as `outcome_unknown`. If cleanup cannot be confirmed, the server refuses new audits.

Current verification covers the three registered checks above and single-request cases. Stored XSS, CSRF, multi-step oracles, arbitrary business logic, external services, screenshots, automatic profile generation, and static-scan snapshot linkage are not supported. Findings do not identify a root-cause source line, and the audit does not establish whole-service safety or an LLM's detection rate.

See [the detailed browser-audit guide](docs/web-security-audit.md) for profile contracts, budgets, recovery behavior, and verification commands.

## Static repository scans

The server also inventories tracked Git files and writes canonical JSON and Markdown reports through `scan_repository`, `get_scan`, and `cancel_scan`. Static scans are read-only and require neither Docker nor Playwright.

For static-only registration, use the same `command` and `args` as above with only `PYTHONUTF8=1` in `env`; omit `REPO_DAST_AUDIT` and `REPO_DAST_PROFILES`. `scan_repository` selects the target repository through its `root` argument.

## License

MIT. See [LICENSE](LICENSE).

The browser-audit setup downloads Playwright Core, the official Playwright Docker image, and its seccomp profile (Apache-2.0) at setup time; they are not redistributed here. Keep their notices if you distribute a built worker image.
