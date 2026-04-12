<p align="center">
  <img src="https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/main/docs/assets/images/logo.png" width="300">
</p>

# trustcheck

[![CI](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Source Build](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml)
[![PyPI](https://img.shields.io/pypi/v/trustcheck.svg)](https://pypi.org/project/trustcheck/)
[![Python 3.12 | 3.13 | 3.14](https://img.shields.io/badge/ci-python%203.12-blue.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/trustcheck?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/trustcheck)

`trustcheck` is a Python package and CLI for evaluating the trust posture of PyPI releases before they are installed, promoted, or approved.

It combines PyPI metadata, vulnerability records, provenance availability, cryptographic attestation verification, Trusted Publisher identity hints, and repository matching into a single operator-friendly report.

## What it checks

For a selected package version, `trustcheck` can:

- fetch project and release metadata from PyPI
- inspect declared repository URLs from project metadata
- retrieve provenance envelopes for each release artifact
- verify attestations against the downloaded artifact digest
- extract Trusted Publisher identity details such as repository and workflow
- compare expected repository input against declared and attested repository signals
- flag publisher repository and workflow drift against the previous release
- surface PyPI vulnerability records for the selected version
- emit a concise human-readable report or structured JSON

## Installation

```bash
pip install trustcheck
```

Requirements:

- Python `>=3.10`
- Network access to PyPI

CI runs a supported-version matrix and should stay aligned with the package's advertised Python support.

## Quick start

Inspect the latest release:

```bash
trustcheck inspect requests
```

Inspect a specific version:

```bash
trustcheck inspect sampleproject --version 4.0.0
```

Require the release to match an expected source repository:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject
```

Show detailed per-file evidence:

```bash
trustcheck inspect sampleproject --version 4.0.0 --verbose
```

Emit JSON for another tool:

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

## Supported Public API

`trustcheck` has a small supported Python API for programmatic use:

- `trustcheck.inspect_package`
- `trustcheck.TrustReport`
- `trustcheck.TrustReport.to_dict()`
- `trustcheck.JSON_SCHEMA_VERSION`
- `trustcheck.JSON_SCHEMA_ID`
- `trustcheck.get_json_schema()`

Everything else under `trustcheck.*` should be treated as internal implementation detail and may change between minor releases.

Quick example:

```python
from trustcheck import JSON_SCHEMA_VERSION, TrustReport, get_json_schema, inspect_package

report = inspect_package("sampleproject", version="4.0.0")
payload = report.to_dict()
assert payload["schema_version"] == JSON_SCHEMA_VERSION

schema = get_json_schema()
```

## CLI reference

Primary command:

```bash
trustcheck inspect <project>
```

Supported flags:

- `--version`: inspect a specific release instead of the latest project version
- `--expected-repo`: require repository evidence to match an expected GitHub or GitLab repository
- `--format text|json`: choose human-readable text or machine-readable JSON
- `--verbose`: include per-file provenance, digest, publisher, and note fields in text output
- `--strict`: apply the built-in strict policy
- `--policy default|strict|internal-metadata`: evaluate a built-in policy profile
- `--policy-file PATH`: load policy settings from a JSON file
- `--config-file PATH`: load network settings from a JSON config file
- `--require-verified-provenance none|all`: override provenance enforcement
- `--allow-metadata-only` / `--disallow-metadata-only`: override metadata-only handling
- `--require-expected-repo-match`: require expected repository evidence
- `--fail-on-vulnerability ignore|any`: override vulnerability blocking
- `--fail-on-risk-severity none|medium|high`: fail on advisory risk flags at or above a severity
- `--timeout FLOAT`: set request timeout in seconds
- `--retries INT`: set transient retry count
- `--backoff FLOAT`: set retry backoff factor
- `--cache-dir PATH`: persist cached PyPI responses for repeated runs
- `--offline`: use cached responses only
- `--debug`: emit structured debug logs and print tracebacks for operational failures
- `--log-format text|json`: choose debug log format for `--debug`

## Output model

The default text output is optimized for operators. It starts with a concise summary and then expands into evidence and risk details.

It includes:

- recommendation tier
- package URL and package summary
- verification coverage summary
- publisher trust depth
- network/request diagnostics
- "why this result" explanations
- declared repository URLs
- ownership and vulnerability data when PyPI exposes them
- per-risk remediation guidance

With `--verbose`, the report also shows per-file provenance, digest, attestation, publisher, and error details.

Recommendation tiers:

- `verified`: every discovered release artifact verified successfully
- `metadata-only`: no cryptographically verified artifact set, but no risk flags elevated the result
- `review-required`: medium-severity issues require manual review
- `high-risk`: high-severity issues were detected

## Exit codes

`trustcheck` is designed to fit into automation as well as interactive review.

- `0`: success
- `1`: upstream PyPI/network failure
- `2`: command usage error
- `3`: invalid or unexpected response / processing failure
- `4`: strict policy failure triggered by `--strict`

`--strict` is intentionally conservative:

- if no release files are discovered, it fails
- if any discovered file is not fully verified, it fails

## JSON contract

`trustcheck inspect --format json` is the stable machine-readable interface.

Top-level shape:

```json
{
  "schema_version": "1.2.0",
  "report": {
    "project": "demo",
    "version": "1.2.3",
    "summary": "Demo package",
    "package_url": "https://pypi.org/project/demo/1.2.3/",
    "diagnostics": {
      "timeout": 10.0,
      "max_retries": 2,
      "backoff_factor": 0.25,
      "offline": false,
      "cache_dir": null,
      "request_count": 3,
      "retry_count": 1,
      "cache_hit_count": 0,
      "request_failures": [],
      "artifact_failures": []
    },
    "policy": {
      "profile": "default",
      "passed": true,
      "enforced": false,
      "fail_on_severity": "none",
      "require_verified_provenance": "none",
      "require_expected_repository_match": false,
      "allow_metadata_only": true,
      "vulnerability_mode": "ignore",
      "violations": []
    },
    "declared_repository_urls": ["https://github.com/example/demo"],
    "repository_urls": ["https://github.com/example/demo"],
    "expected_repository": "https://github.com/example/demo",
    "ownership": {
      "organization": "example-org",
      "roles": []
    },
    "vulnerabilities": [],
    "files": [],
    "coverage": {
      "total_files": 0,
      "files_with_provenance": 0,
      "verified_files": 0,
      "status": "none"
    },
    "publisher_trust": {
      "depth_score": 0,
      "depth_label": "none",
      "verified_publishers": [],
      "unique_verified_repositories": [],
      "unique_verified_workflows": []
    },
    "provenance_consistency": {
      "has_sdist": false,
      "has_wheel": false,
      "sdist_wheel_consistent": null,
      "consistent_repositories": [],
      "consistent_workflows": []
    },
    "release_drift": {
      "compared_to_version": null,
      "publisher_repository_drift": null,
      "publisher_workflow_drift": null,
      "previous_repositories": [],
      "previous_workflows": []
    },
    "risk_flags": [],
    "recommendation": "verified"
  }
}
```

Contract rules:

- `schema_version` is semantic and version-controls the JSON shape
- `JSON_SCHEMA_ID` identifies the exact JSON Schema document for a given `schema_version`
- patch releases keep the same JSON contract for a given schema version
- new fields may be added within expandable objects in a backward-compatible way
- breaking JSON changes require a new major `schema_version`
- text output is presentation-oriented and is not a compatibility contract

You can retrieve the published JSON Schema directly from Python:

```python
from trustcheck import get_json_schema

schema = get_json_schema()
```

## Compatibility Policy

`trustcheck` is intended for CI and policy automation, so compatibility is treated as a product feature.

Stable contract:

- `inspect_package(...)` returning a `TrustReport`
- `TrustReport.to_dict()` returning the machine-readable report envelope
- top-level JSON fields `schema_version` and `report`
- currently documented report field names
- the machine-readable `report.diagnostics` block
- the machine-readable `report.policy` evaluation block
- the meaning of `schema_version`, `JSON_SCHEMA_ID`, and `get_json_schema()`

Best-effort fields:

- free-form text such as `summary`, `risk_flags[*].message`, `risk_flags[*].why`, and remediation text
- upstream-derived metadata such as ownership details, vulnerability summaries, and publisher `raw` payloads

Expandable areas:

- new fields may be added to the `report` object in a backward-compatible release
- `ownership`, ownership roles, and publisher `raw` data may gain extra keys without a schema-version bump
- list contents may grow when PyPI or provenance sources expose more evidence

Breaking changes:

- removing or renaming stable fields
- changing the meaning or type of a stable field
- changing CLI JSON output so it no longer validates against the published schema for the same `schema_version`

When a breaking JSON or Python API change is necessary, `trustcheck` will:

- increment the package major version
- publish a new schema major version
- record the change in [`CHANGELOG.md`](CHANGELOG.md)

## Policy Evaluation

`inspect_package(...)` collects evidence and produces the advisory report. CLI enforcement is then handled by a separate policy layer.

Built-in policies:

- `default`: advisory only; never fails the command by itself
- `strict`: requires verified provenance for every artifact, disallows metadata-only outcomes, and blocks on known vulnerabilities or high-severity risk flags
- `internal-metadata`: permissive profile for internal review flows where metadata-only results are acceptable

Policy settings currently support:

- requiring verified provenance for all artifacts
- allowing or disallowing metadata-only results
- requiring an expected repository match
- blocking on any known vulnerability
- failing on advisory risk flags at `medium` or `high`

Example JSON policy file:

```json
{
  "profile": "team-policy",
  "require_verified_provenance": "all",
  "allow_metadata_only": false,
  "require_expected_repository_match": true,
  "vulnerability_mode": "any",
  "fail_on_severity": "high"
}
```

Example usage:

```bash
trustcheck inspect sampleproject \
  --expected-repo https://github.com/pypa/sampleproject \
  --policy-file policy.json
```

## Network Controls And Diagnostics

`trustcheck` distinguishes package risk from upstream instability. The report includes a machine-readable `diagnostics` block so automation can see whether a failure came from policy, verification, or PyPI/network behavior.

Diagnostics currently include:

- request failures encountered, with deterministic `code` and `subcode`
- retry counts and total request counts
- cache hit counts
- artifact-level provenance or verification failures
- effective network settings such as timeout, retry count, backoff, offline mode, and cache directory

Common upstream subcodes include:

- `http_not_found`
- `http_transient`
- `network_timeout`
- `network_dns_temporary`
- `network_dns_failure`
- `network_tls`
- `network_connection_refused`
- `json_malformed`
- `project_shape_invalid`
- `provenance_shape_invalid`
- `offline_cache_miss`

Network settings can come from three places:

- CLI flags such as `--timeout`, `--retries`, `--backoff`, `--cache-dir`, and `--offline`
- environment variables `TRUSTCHECK_TIMEOUT`, `TRUSTCHECK_RETRIES`, `TRUSTCHECK_BACKOFF`, `TRUSTCHECK_CACHE_DIR`, and `TRUSTCHECK_OFFLINE`
- `--config-file`, using a JSON object with a `network` section

Example config file:

```json
{
  "network": {
    "timeout": 5.0,
    "retries": 4,
    "backoff_factor": 0.5,
    "cache_dir": ".cache/trustcheck",
    "offline": false
  }
}
```

Example repeated-CI usage with a persistent cache:

```bash
trustcheck inspect sampleproject \
  --cache-dir .cache/trustcheck \
  --format json
```

Example offline reuse of cached results:

```bash
trustcheck inspect sampleproject \
  --cache-dir .cache/trustcheck \
  --offline \
  --format json
```

## Repository matching rules

Repository matching is intentionally strict.

`trustcheck` currently normalizes and matches canonical repository roots for supported forges:

- GitHub
- GitLab

It accepts canonical repository URLs and equivalent git-style remotes, and rejects non-repository pages such as profile, organization, documentation, or archive URLs. Invalid `--expected-repo` values are reported explicitly as a risk condition rather than being matched loosely.

## Trust and verification model

`trustcheck` does not treat project metadata alone as proof of origin.

The strongest result comes from verified provenance bound to the exact artifact digest that was downloaded. Repository URLs and publisher identity hints are useful context, but they are not equivalent to a cryptographically verified attestation.

That distinction is reflected in the report:

- metadata can support an explanation
- verified provenance can support a trust decision
- missing or unverifiable provenance drives risk flags and strict-policy failures

## Common automation patterns

Fail a build if a pinned release is not fully verified:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

Record JSON as a CI artifact:

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json > trustcheck-report.json
```

Review a release against an expected repository during package admission:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject \
  --strict
```

## Quality and release process

The repository includes:

- CI for lint, type checks, cross-platform test matrices, coverage enforcement, and build smoke tests
- dependency auditing and secret scanning in CI
- CodeQL analysis for the Python codebase
- release publishing from immutable tagged commits
- annotated tag enforcement for releases
- GitHub Release creation with generated notes
- release artifact checksum generation
- SBOM generation for release artifacts
- PyPI Trusted Publishing with artifact attestations
- opt-in live integration tests against real PyPI packages
- contract snapshot tests that detect accidental JSON-schema drift

Live integration tests are excluded from the default test run and can be enabled with:

```bash
TRUSTCHECK_RUN_LIVE=1 python -m pytest -q tests/test_integration_live.py
```

## Limitations

- PyPI metadata quality varies by project
- some projects do not publish provenance at all
- repository matching currently supports canonical GitHub and GitLab URLs only
- provenance verification may depend on local environment support required by underlying tooling
- text output is intentionally concise and may omit low-level detail unless `--verbose` is used

## Development

Run the local test suite:

```bash
python -m pytest -q tests
```

Run tests with coverage:

```bash
python -m pytest --cov=trustcheck --cov-report=term-missing tests
```

Run lint:

```bash
ruff check src tests
```

Run type checks:

```bash
mypy src
```

## License

[Trustcheck Personal Use License](LICENSE)


## Documentation

Documentation: https://Halfblood-Prince.github.io/trustcheck/
