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
- `trustcheck.ExportPackage`
- `trustcheck.SourceLocation`
- `trustcheck.render_export`
- `trustcheck.package_purl`
- `trustcheck.OUTPUT_FORMATS`
- `trustcheck.INDUSTRY_OUTPUT_FORMATS`
- `trustcheck.OsvClient`
- `trustcheck.OsvProvider`
- `trustcheck.CisaKevClient`
- `trustcheck.EpssClient`
- `trustcheck.VulnerabilityIntelligenceClient`
- `trustcheck.VulnerabilitySuppression`
- `trustcheck.HeuristicFinding`
- `trustcheck.MaliciousPackageAssessment`
- `trustcheck.NativeBinaryInspection`
- `trustcheck.DEFAULT_TRUSTED_PROJECTS`
- `trustcheck.analyze_python_source`
- `trustcheck.inspect_native_binary`
- `trustcheck.heuristic_score`
- `trustcheck.ContentAddressedCache`
- `trustcheck.AdvisorySnapshotStore`
- `trustcheck.ADVISORY_SNAPSHOT_SCHEMA`
- `trustcheck.PluginManager`
- `trustcheck.PluginDescriptor`
- `trustcheck.PluginError`
- `trustcheck.AdvisorySourcePlugin`
- `trustcheck.IndexPlugin`
- `trustcheck.ArtifactAnalyzerPlugin`
- `trustcheck.PolicyRulePlugin`
- `trustcheck.RendererPlugin`
- `trustcheck.PLUGIN_API_VERSION`
- `trustcheck.PLUGIN_GROUPS`

Everything else under `trustcheck.*` should be treated as internal implementation detail and may change between minor releases.

## Vulnerability intelligence

```python
from trustcheck import (
    CisaKevClient,
    EpssClient,
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
    inspect_package,
)

intelligence = VulnerabilityIntelligenceClient(
    providers=(
        OsvProvider("OSV", OsvClient()),
        OsvProvider(
            "Private OSV",
            OsvClient(base_url="https://advisories.example.com"),
        ),
    ),
    kev_client=CisaKevClient(),
    epss_client=EpssClient(),
)
report = inspect_package(
    "jinja2",
    version="2.10.0",
    vulnerability_client=intelligence,
)
```

Configured providers are queried concurrently. Results merge by identifiers
and aliases, then receive normalized CVSS, CWE, withdrawal, fix-version, KEV,
and EPSS fields.

`VulnerabilityIntelligenceClient.prefetch()` performs bounded multi-package
OSV batch queries. An `AdvisorySnapshotStore` can be supplied for reusable
offline records, and `flush_snapshots()` atomically writes configured output.
Snapshot schema 2 includes source URLs, generation and expiration timestamps,
and a canonical record digest. Configure `max_age`, `sigstore_identity`, and
optionally `sigstore_issuer` when loading. Set `sign_output=True` when writing
with ambient Sigstore identity; unsigned compatibility requires the explicit
`allow_unsigned=True` setting.

## Plugin API

`PluginManager` discovers entry points only when explicitly enabled. It routes
advisory sources, index clients, artifact analyzers, policy rules, and
renderers through the public protocol types listed above. Plugin API version
`1` requires deterministic return values, thread-safe plugin instances, and
declared Trustcheck model or primitive result types. When the resource-bounded
worker is enabled, plugin IPC is versioned JSON bytes; the parent reconstructs
trusted models and rejects unknown fields or arbitrary custom result objects.
Trusted plugin loading also requires a signed statement bound to the installed
distribution version, RECORD digest, canonical installed-content digest,
dependencies, capabilities, configuration schema hash, and an external trust
root: either a trusted key fingerprint or an installed-content digest allowlist.

See [Performance and extensibility](performance-extensibility.md) for entry
point group names and registration examples.

## Industry exports

```python
from trustcheck import (
    ExportPackage,
    SourceLocation,
    inspect_package,
    render_export,
)

report = inspect_package("sampleproject", version="4.0.0")
sarif = render_export(
    "sarif",
    [
        ExportPackage(
            report=report,
            source=SourceLocation("requirements.txt", 12),
        )
    ],
    source_name="requirements.txt",
)
```

`render_export` accepts `sarif`, `cyclonedx-json`, `cyclonedx-xml`,
`cyclonedx-1.7-json`, `cyclonedx-1.7-xml`, `spdx-json`, `spdx-3-json`,
`openvex`, or `markdown`. `ExportPackage.artifacts` can carry lockfile
`ArtifactReference` records so multi-algorithm hashes are retained.

## Malicious-package heuristics

```python
from trustcheck import inspect_package

report = inspect_package(
    "internal-sdkk",
    inspect_artifacts=True,
    trusted_projects=("internal-sdk",),
    dependency_confusion_indexes=(
        "https://pypi.org/simple",
        "https://packages.example/simple",
    ),
)

print(report.malicious_package.score)
for finding in report.malicious_package.findings:
    print(finding.code, finding.confidence, finding.location)
```

Metadata, name, index, ownership, repository, and cadence checks run without
artifact inspection. `inspect_artifacts=True` additionally parses bounded
Python source with `ast` and inspects PE, ELF, and Mach-O structure. Findings
are heuristic review indicators, not proof that a package is malicious.

## Dependency resolution

Use `PipResolver` to obtain the exact package set selected by pip without
installing it:

```python
from trustcheck import PipResolver, TargetEnvironment

resolution = PipResolver(sandbox_mode="auto").resolve_requirements_file(
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
It starts pip through the supported subprocess CLI, `python -m pip`, using the
configured `python_executable`; it does not import unsupported `pip._internal`
modules.
Cross-target resolution adds `--only-binary :all:` because source builds cannot
be performed correctly for a foreign target. `sandbox_mode` accepts `off`,
`warn`, `auto`, `container`, `bubblewrap`, and `strict`; the default is `auto`.
The selected mode and any fallback warnings are available
as `resolution.sandbox_mode` and `resolution.sandbox_warnings`.

`container` discovers Docker or Podman. `bubblewrap` requires Linux and
`bwrap`. `auto` prefers Bubblewrap, then a container, then strict wheel-only
resolution. Strict mode rejects requirement forms that can directly execute
source metadata hooks, tells pip to use isolated configuration and wheels
only, and loads a temporary `sitecustomize.py` audit guard through a minimal
`PYTHONPATH` so transitive backend or VCS commands fail closed. Container and
Bubblewrap execution stages only resolver inputs and referenced local
dependencies instead of mounting the project workspace. `container_image`
overrides the built-in image and must contain a full `@sha256:` digest.

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

Use `inspect_package(project, version=None, expected_repository=None, client=None,
progress_callback=None, include_dependencies=False,
include_transitive_dependencies=False, include_osv=False,
inspect_artifacts=False, dynamic_analysis=False, dynamic_analysis_image=None,
dynamic_analysis_python="3.12", osv_client=None, vulnerability_client=None,
locked_versions=None, resolver=None, target_environment=None,
complete_locked_versions=False, expected_artifacts=())` to collect evidence and
build a `TrustReport`.

In most applications, you only need to provide:

- `project`
- optionally `version`
- optionally `expected_repository`
- optionally `include_dependencies=True` when you want direct dependency inspection
- optionally `include_transitive_dependencies=True` when you want recursive dependency inspection
- optionally `include_osv=True` to query OSV for the exact selected versions
- optionally `vulnerability_client=VulnerabilityIntelligenceClient(...)` to
  merge multiple advisory and enrichment providers
- optionally `inspect_artifacts=True` to statically inspect downloaded wheels and sdists
- optionally `dynamic_analysis=True` to run bounded install analysis in a
  digest-pinned analyzer image; set `dynamic_analysis_python="3.13"` for a
  configured profile or `dynamic_analysis_image="image@sha256:..."` for an
  explicit analyzer image. Profiles without a recorded digest-pinned analyzer
  image fail as unsupported rather than falling back to a generic Python image.
- optionally `trusted_projects=("internal-sdk",)` to extend the typosquatting
  reference set
- optionally `dependency_confusion_indexes=(...)` to attach a resolver-observed
  cross-index collision to the package assessment
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
the inspected package. Native signature fields report embedded signature
presence, not cryptographic validity.

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
- remediation summary

Use `report.to_dict()` when you need the stable JSON envelope.

### Accessing report fields

```python
from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0")

for flag in report.risk_flags:
    print(flag.severity, flag.code, flag.message)

for file in report.files:
    print(file.filename, file.verified, file.error)
    for provenance in file.slsa_provenance:
        print(
            provenance.source_repository,
            provenance.source_commit,
            provenance.builder_id,
        )

for dependency in report.dependencies:
    print(dependency.project, dependency.depth, dependency.recommendation, dependency.error)
```

The public deep-provenance surface includes `SlsaProvenance`,
`ProvenanceMaterial`, `ProvenanceIssue`, `analyze_slsa_provenance(...)`, and
publisher-organization allowlist helpers. Normal package inspection populates
these models only after the SLSA statement, signature, subject filename, and
artifact digest have verified.

## Remediation API

The public remediation surface includes:

- `plan_remediation(...)`
- `prepare_remediation(...)`
- `apply_prepared_remediation(...)`
- `create_pull_request(...)`
- `RemediationPlan`, `RemediationUpgrade`, `BlockedFix`, `FilePatch`,
  `SemanticEdit`, `RemediationValidation`, and `PullRequestResult`
- `REMEDIATION_SCHEMA_VERSION` and `REMEDIATION_SCHEMA_ID`

`plan_remediation` accepts a baseline `Resolution`, exact-version reports,
root requirements, and resolver/scanner callbacks. This keeps network and
policy configuration under application control. Only plans with status
`validated` can be passed to `prepare_remediation`; prepared changes expose
exact file bytes and patches and support context-manager cleanup.

Most callers should use the CLI because it supplies the same index, target
matrix, advisory providers, and policy to every resolution and rescan.
