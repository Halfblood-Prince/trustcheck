# Compatibility

`trustcheck` is intended for CI and policy automation, so compatibility is treated as a product feature.

## Stable interfaces

The following interfaces are supported across compatible releases:

- `inspect_package(...)` returning a `TrustReport`
- `TrustReport.to_dict()` returning the machine-readable report envelope
- top-level JSON fields `schema_version` and `report`
- currently documented report field names
- the `include_dependencies` and `include_transitive_dependencies` keywords on `inspect_package(...)`
- the `inspect_artifacts` keyword on `inspect_package(...)`
- the machine-readable `report.diagnostics` block
- the machine-readable `report.policy` evaluation block
- the meaning of `schema_version`, `JSON_SCHEMA_ID`, and `get_json_schema()`

The current machine-readable report schema is `1.12.0`
(`urn:trustcheck:report:1.12.0`). Schema identifiers are immutable: a report
with a given `schema_version` must continue to validate against the exact JSON
Schema document advertised by the matching `JSON_SCHEMA_ID`.

## Best-effort fields

These fields are useful, but may vary with upstream data or wording changes:

- free-form text such as `summary`, `risk_flags[*].message`, `risk_flags[*].why`, and remediation text
- upstream-derived metadata such as ownership details, vulnerability summaries, and publisher `raw` payloads

## Expandable areas

Backward-compatible releases may add fields in places designed to grow:

- the `report` object
- `ownership` and ownership role data
- publisher `raw` payloads
- per-file artifact inspection findings
- lists that reflect PyPI or provenance evidence sources

## Breaking changes

The following changes require a compatibility break:

- removing or renaming stable fields
- changing the meaning or type of a stable field
- changing CLI JSON output so it no longer validates against the published schema for the same `schema_version`

When a breaking JSON or Python API change is necessary, `trustcheck` will:

- increment the package major version
- publish a new schema major version
- record the change in the [changelog](../changelog.md)

## Supported public API

`trustcheck` exposes a small supported public API for programmatic use:

- `trustcheck.inspect_package`
- `trustcheck.TrustReport`
- `trustcheck.TrustReport.to_dict()`
- `trustcheck.JSON_SCHEMA_VERSION`
- `trustcheck.JSON_SCHEMA_ID`
- `trustcheck.get_json_schema()`

Everything else under `trustcheck.*` should be treated as internal implementation detail and may change between minor releases.

## GitHub Action Artifacts

The TrustCheck Package Scanner Action asks the CLI for JSON internally so step
outputs can remain structured, then uploads one report artifact in the selected
format. The default format is text, so the derived default artifact path is
`trustcheck-report.txt`.

The switch from always uploading a JSON report artifact to format-specific
artifact paths is a documented minor-version behavior change. Workflows that
parse the artifact as JSON should set either:

```yaml
with:
  format: json
```

or an explicit JSON path:

```yaml
with:
  report-path: trustcheck-report.json
```

The `policy-passed`, `recommendation`, and `report-path` outputs remain the
stable compatibility surface for downstream workflow steps.
