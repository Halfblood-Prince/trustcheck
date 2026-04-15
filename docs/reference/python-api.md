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

report = inspect_package("sampleproject", version="4.0.0", include_dependencies=True)
payload = report.to_dict()
assert payload["schema_version"] == JSON_SCHEMA_VERSION

schema = get_json_schema()
assert schema["$id"]
```

## Common patterns

### Inspect a package inside a Python program

```python
from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0")

print(report.recommendation)
print(report.coverage.status)
```

### Inspect direct dependencies too

```python
from trustcheck import inspect_package

report = inspect_package(
    "sampleproject",
    version="4.0.0",
    include_dependencies=True,
)

print(report.dependency_summary.total_inspected)
print(report.dependency_summary.highest_risk_recommendation)
for dependency in report.dependencies:
    print(dependency.project, dependency.version, dependency.recommendation)
```

### Inspect the full dependency tree

```python
from trustcheck import inspect_package

report = inspect_package(
    "sampleproject",
    version="4.0.0",
    include_transitive_dependencies=True,
)

print(report.dependency_summary.max_depth)
for dependency in report.dependencies:
    print(dependency.project, dependency.depth)
```

### Require a repository match before continuing

```python
from trustcheck import inspect_package

report = inspect_package(
    "sampleproject",
    version="4.0.0",
    expected_repository="https://github.com/pypa/sampleproject",
)

if report.recommendation in {"review-required", "high-risk"}:
    raise SystemExit("package trust review required")
```

### Convert the result to JSON-ready data

```python
import json

from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0", include_dependencies=True)
payload = report.to_dict()

print(json.dumps(payload, indent=2))
```

## `inspect_package`

Use `inspect_package(project, version=None, expected_repository=None, client=None, progress_callback=None, include_dependencies=False, include_transitive_dependencies=False)` to collect evidence and build a `TrustReport`.

In most applications, you only need to provide:

- `project`
- optionally `version`
- optionally `expected_repository`
- optionally `include_dependencies=True` when you want direct dependency inspection
- optionally `include_transitive_dependencies=True` when you want recursive dependency inspection

### Progress callback example

When you want to surface progress in a script or UI, pass a callback that receives `(filename, index, total)`:

```python
from trustcheck import inspect_package


def on_progress(filename: str, index: int, total: int) -> None:
    print(f"[{index}/{total}] verifying {filename}")


report = inspect_package(
    "sampleproject",
    version="4.0.0",
    progress_callback=on_progress,
)
```

## `TrustReport`

`TrustReport` is the main result object. It includes:

- package identity and summary
- declared dependency metadata
- repository signals
- vulnerabilities
- per-file provenance data
- coverage summary
- publisher trust summary
- provenance consistency
- release drift
- dependency inspection results and aggregate dependency summary
- policy evaluation
- diagnostics

Use `report.to_dict()` when you need the stable JSON envelope.

### Accessing report fields

```python
from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0")

for flag in report.risk_flags:
    print(flag.severity, flag.code, flag.message)

for file in report.files:
    print(file.filename, file.verified, file.error)

for dependency in report.dependencies:
    print(dependency.project, dependency.depth, dependency.recommendation, dependency.error)
```
