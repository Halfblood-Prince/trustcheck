# Python API

`trustcheck` exposes a small supported public API for programmatic use.

## Supported symbols

- `trustcheck.inspect_package`
- `trustcheck.PipResolver`
- `trustcheck.TargetEnvironment`
- `trustcheck.Resolution`
- `trustcheck.ResolvedDistribution`
- `trustcheck.ResolutionError`
- `trustcheck.discover_installed_distributions`
- `trustcheck.TrustReport`
- `trustcheck.TrustReport.to_dict()`
- `trustcheck.JSON_SCHEMA_VERSION`
- `trustcheck.JSON_SCHEMA_ID`
- `trustcheck.get_json_schema()`

Everything else under `trustcheck.*` should be treated as internal implementation detail and may change between minor releases.

## Dependency resolution

Use `PipResolver` to obtain the exact package set selected by pip without
installing it:

```python
from trustcheck import PipResolver, TargetEnvironment

resolution = PipResolver().resolve_requirements_file(
    "requirements.txt",
    constraints=["constraints.txt"],
    target=TargetEnvironment(
        python_version="3.12",
        platforms=("manylinux_2_28_x86_64",),
        implementation="cp",
        abis=("cp312",),
    ),
)

print(resolution.versions)
```

The resolver invokes pip with `--dry-run --ignore-installed --report -`.
Cross-target resolution adds `--only-binary :all:` because source builds cannot
be performed correctly for a foreign target.

Pip may still invoke build-backend metadata hooks for source, local, editable,
or VCS requirements. Dry-run resolution is therefore not a sandbox.

## Installed distributions

```python
from trustcheck import discover_installed_distributions

active = discover_installed_distributions()
other = discover_installed_distributions(
    [".venv/lib/python3.12/site-packages"]
)
```

Discovery uses `importlib.metadata` and reads PEP 610 `direct_url.json` when it
is available.

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

Use `inspect_package(project, version=None, expected_repository=None, client=None, progress_callback=None, include_dependencies=False, include_transitive_dependencies=False, include_osv=False, inspect_artifacts=False, osv_client=None, locked_versions=None, resolver=None, target_environment=None, complete_locked_versions=False, expected_artifacts=())` to collect evidence and build a `TrustReport`.

In most applications, you only need to provide:

- `project`
- optionally `version`
- optionally `expected_repository`
- optionally `include_dependencies=True` when you want direct dependency inspection
- optionally `include_transitive_dependencies=True` when you want recursive dependency inspection
- optionally `include_osv=True` to query OSV for the exact selected versions
- optionally `inspect_artifacts=True` to statically inspect downloaded wheels and sdists
- optionally `locked_versions={"dependency-name": "1.2.3"}` to retain resolved direct and transitive versions
- optionally `target_environment=TargetEnvironment(...)` for resolver target controls
- optionally `expected_artifacts=(ArtifactReference(...),)` to require locked
  filenames, URLs, sizes, and hashes

When dependency inspection is requested without `locked_versions`,
`inspect_package` resolves the root package and dependency set through
`PipResolver`.

`PipResolver(indexes=IndexConfiguration(...))` supports primary and extra
PEP 503/691 indexes, keyring provider selection, source attribution, and
dependency-confusion detection. Cross-index collisions raise
`ResolutionError` unless `allow_dependency_confusion=True`.

`load_lockfile(path, extras=(), groups=(), environment=None)` returns a
`LockfileResolution` containing exact `LockedPackage` entries and retained
`ArtifactReference` records for PEP 751, Pipfile, uv, Poetry, and PDM locks.
`SimpleRepositoryClient` is the public PEP 503/691 parser and authenticated
index client.

Artifact inspection reads archive contents only. It does not import or execute
the inspected package.

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
