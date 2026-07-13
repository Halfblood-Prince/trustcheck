# Trustcheck Gate Adapter Operation Schema

Run the adapter with a JSON request file or stdin:

```bash
python plugins/trustcheck-gate/skills/trustcheck-gate/scripts/trustcheck_agent_adapter.py request.json --pretty
```

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

Safety constraints:

- The adapter invokes `python -m trustcheck` with fixed argv lists and `shell=False`.
- `analysis_depth: full` requires `advanced_analysis: true`.
- Paths must resolve inside the selected workspace.
- Custom index URLs, Trustcheck plugin loading, dynamic analysis, package installation, remediation application, and pull request creation are not exposed.
- Output is returned through the adapter response. Do not use unrestricted output paths.
