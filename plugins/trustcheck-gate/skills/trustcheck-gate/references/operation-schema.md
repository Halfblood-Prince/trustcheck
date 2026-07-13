# Trustcheck Gate Adapter Operation Schema

Run the adapter with a JSON request file or stdin:

```bash
python plugins/trustcheck-gate/skills/trustcheck-gate/scripts/trustcheck_agent_adapter.py request.json --pretty
```

Trustcheck must be installed separately. The adapter resolves `trustcheck` on
`PATH` first, then falls back to `python -m trustcheck` when the running Python
environment can import Trustcheck. Adapter `0.1.x` supports Trustcheck
`>=2.2,<3.0`; incompatible or missing installations return `classification:
"scan_failed"` and `policy_permits_install: false`.

The adapter accepts Trustcheck report schema `1.11.0` for security decisions.
Newer, older, missing, or malformed report schemas fail closed with
`policy_permits_install: false`.

Versioned schemas live under `plugins/trustcheck-gate/schemas/`:

- `adapter-request-0.1.json`
- `adapter-result-0.1.json`
- `accepted-trustcheck-report-1.11.0.json`

Common fields:

```json
{
  "operation": "check_package",
  "workspace": ".",
  "policy": "default",
  "analysis_depth": "standard",
  "with_osv": true,
  "timeout_seconds": 120,
  "max_output_bytes": 500000
}
```

Allowed `operation` values:

- `check_package`: Check one PyPI package before installation. Fields: `package`, optional `version`, optional `with_osv`, optional `source_release_provenance`.
- `verify_release`: Verify one package release against repository/provenance expectations. Fields: `package`, optional `version`, optional `expected_repository`, optional `release_tag`.
- `check_requirements`: Scan one dependency file. Field: `path`.
- `scan_project`: Discover and scan supported dependency files in the workspace. Optional fields: `path`, `max_files`.
- `plan_remediation`: Produce a remediation plan without editing files. Fields: `path`, optional `max_fix_attempts`.
- `compare_versions`: Compare current and proposed package versions. Fields: `package`, `current_version`, `proposed_version`.
- `generate_report`: Produce a Trustcheck report as adapter output. Fields: `target_type` (`package` or `requirements`), `format`, plus `package`/`version` or `path`.
- `explain_findings`: Convert an existing Trustcheck JSON payload into structured explanations. Fields: `report` or `report_path`.

Allowed values:

- `policy`: `default` or `strict`
- `analysis_depth`: `fast`, `standard`, or `full`
- `artifact_scope`: `target`, `sdist`, or `all`
- `format`: `json`, `markdown`, `sarif`, `cyclonedx-json`, `cyclonedx-1.7-json`, `spdx-json`, `spdx-3-json`, or `openvex`

Request validation and quotas:

- Requests larger than 100,000 bytes are rejected before parsing.
- Unknown operations, unexpected fields, and unsupported mutating fields are rejected.
- `timeout_seconds` is capped at 600 seconds.
- `max_output_bytes` must be between 10,000 and 5,000,000 bytes.
- `scan_project` scans at most 5 dependency files and uses one total deadline.
- Batch package lists are not accepted; package operations check one package per request.
- Paths must be non-empty, shorter than 4,096 characters, free of control characters, and resolve inside the workspace.
- Repository URLs must be HTTPS, credential-free, query-free, fragment-free, unambiguous, and on the default HTTPS port.

Security decision fields:

```json
{
  "classification": "passed",
  "execution_status": "completed",
  "report_status": "valid",
  "security_status": "passed",
  "policy_permits_install": true,
  "report_schema_version": "1.11.0"
}
```

`policy_permits_install` is true only when Trustcheck completed, emitted valid
supported JSON, every package report includes explicit `policy.passed: true`,
no scan failure was reported, and no blocking finding was present. Empty
stdout, malformed JSON, JSON arrays, `{}`, unsupported schema versions, missing
policy state, nonzero Trustcheck exits, timeouts, output-limit breaches, and
non-JSON report generation all block installation.

Status values:

- `execution_status`: `completed`, `timed_out`, `output_limit_exceeded`,
  `failed_to_start`, or `terminated`
- `report_status`: `valid`, `malformed`, `incompatible`, `missing`, or
  `invalid_schema`
- `security_status`: `passed`, `findings`, `blocked`, `unknown`, or
  `scan_failed`

Safety constraints:

- The adapter invokes the installed `trustcheck` executable or `python -m trustcheck`
  with fixed argv lists and `shell=False`.
- When `workspace` is omitted, the current working directory is used. Supplied
  workspaces must resolve to existing directories.
- `analysis_depth: full` requires `advanced_analysis: true`.
- Paths must resolve inside the selected workspace.
- Trustcheck runs with a minimal environment allowlist. Private index, proxy,
  token, and plugin configuration variables are not forwarded by default.
- Stdout and stderr are captured with independent byte limits while the process
  runs. Timeout or output-limit breaches terminate the Trustcheck process tree.
- Diagnostics redact URL credentials, bearer tokens, sensitive query parameters,
  private-index credentials, authentication headers, and sensitive env values.
- Custom index URLs, Trustcheck plugin loading, dynamic analysis, package installation, remediation application, and pull request creation are not exposed.
- Output is returned through the adapter response. Do not use unrestricted output paths.
