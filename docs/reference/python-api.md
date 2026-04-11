# Python API

`trustcheck` exposes a small supported public API for programmatic use.

## Supported symbols

- `trustcheck.inspect_package`
- `trustcheck.TrustReport`
- `trustcheck.TrustReport.to_dict()`
- `trustcheck.JSON_SCHEMA_VERSION`
- `trustcheck.JSON_SCHEMA_ID`
- `trustcheck.get_json_schema()`

Everything else under `trustcheck.*` should be treated as internal implementation detail and may change between minor releases.

## Example

```python
from trustcheck import JSON_SCHEMA_VERSION, TrustReport, get_json_schema, inspect_package

report = inspect_package("sampleproject", version="4.0.0")
payload = report.to_dict()
assert payload["schema_version"] == JSON_SCHEMA_VERSION

schema = get_json_schema()
assert schema["$id"]
```

## `inspect_package`

Use `inspect_package(project, version=None, expected_repository=None, client=None, progress_callback=None)` to collect evidence and build a `TrustReport`.

In most applications, you only need to provide:

- `project`
- optionally `version`
- optionally `expected_repository`

## `TrustReport`

`TrustReport` is the main result object. It includes:

- package identity and summary
- repository signals
- vulnerabilities
- per-file provenance data
- coverage summary
- publisher trust summary
- provenance consistency
- release drift
- policy evaluation
- diagnostics

Use `report.to_dict()` when you need the stable JSON envelope.
