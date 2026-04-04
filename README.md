# trustcheck

[![CI](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/trustcheck.svg)](https://pypi.org/project/trustcheck/)
[![Python 3.12](https://img.shields.io/badge/ci-python%203.12-blue.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/trustcheck?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/trustcheck)

`trustcheck` is a Python package and CLI for evaluating the trust posture of PyPI releases before they are installed, promoted, or approved.

It combines PyPI metadata, vulnerability records, provenance availability, cryptographic attestation verification, Trusted Publisher identity hints, and repository matching into a single operator-friendly report.

## Why use it

`pip install` answers whether a package can be installed.

`trustcheck` helps answer whether a release should be trusted.

It is designed for maintainers, platform teams, security reviewers, CI pipelines, and anyone who wants a fast local check for questions like:

- Does this release publish provenance on PyPI?
- Do the attestations verify for the exact artifact digest I would consume?
- Does the publisher identity line up with the repository I expect?
- Are sdist and wheel provenance signals consistent?
- Did the verified publisher repository or workflow drift from the previous release?
- Does PyPI already report known vulnerabilities for this version?

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

CI currently runs on Python 3.12, and package classifiers only advertise versions covered by CI.

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
- `--strict`: return a failing exit code if every discovered artifact is not cryptographically verified
- `--debug`: print tracebacks for operational failures

## Output model

The default text output is optimized for operators. It starts with a concise summary and then expands into evidence and risk details.

It includes:

- recommendation tier
- package URL and package summary
- verification coverage summary
- publisher trust depth
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
  "schema_version": "1",
  "report": {
    "project": "demo",
    "version": "1.2.3",
    "summary": "Demo package",
    "package_url": "https://pypi.org/project/demo/1.2.3/",
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

- `schema_version` version-controls the JSON shape
- patch releases keep the same JSON contract for a given schema version
- new fields may be added within `report` in a backward-compatible way
- breaking JSON changes require a new `schema_version`
- text output is presentation-oriented and is not a compatibility contract

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

- CI for tests, lint, type checks, and build smoke tests
- release publishing from immutable tagged commits
- annotated tag enforcement for releases
- GitHub Release creation with generated notes
- release artifact checksum generation
- opt-in live integration tests against real PyPI packages

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

Run lint:

```bash
ruff check src tests
```

Run type checks:

```bash
mypy src
```

## License

BSD 3-Clause License
