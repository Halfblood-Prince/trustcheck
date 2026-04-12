# Compatibility

`trustcheck` is intended for CI and policy automation, so compatibility is treated as a product feature.

## Stable interfaces

The following interfaces are supported across compatible releases:

- `inspect_package(...)` returning a `TrustReport`
- `TrustReport.to_dict()` returning the machine-readable report envelope
- top-level JSON fields `schema_version` and `report`
- currently documented report field names
- the machine-readable `report.diagnostics` block
- the machine-readable `report.policy` evaluation block
- the meaning of `schema_version`, `JSON_SCHEMA_ID`, and `get_json_schema()`

## Best-effort fields

These fields are useful, but may vary with upstream data or wording changes:

- free-form text such as `summary`, `risk_flags[*].message`, `risk_flags[*].why`, and remediation text
- upstream-derived metadata such as ownership details, vulnerability summaries, and publisher `raw` payloads

## Expandable areas

Backward-compatible releases may add fields in places designed to grow:

- the `report` object
- `ownership` and ownership role data
- publisher `raw` payloads
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
