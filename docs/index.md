# trustcheck

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
- inspect declared runtime dependencies and summarize the worst-risk dependency in the set
- emit a concise human-readable report or structured JSON

## Install

```bash
pip install trustcheck
```

## First command

```bash
trustcheck inspect sampleproject --version 4.0.0
```

## Common use cases

Check the latest release:

```bash
trustcheck inspect requests
```

Require a specific upstream repository:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject
```

Emit JSON for automation:

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

Inspect the package and its direct dependencies:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

Inspect the full dependency tree:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-transitive-deps
```

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

## Use from Python

`trustcheck` can also be imported directly into Python programs:

```python
from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0", include_dependencies=True)
print(report.recommendation)
print(report.to_dict()["report"]["coverage"]["status"])
print(report.dependency_summary.highest_risk_recommendation)
```

<script
  src="https://context7.com/widget.js"
  data-library="/halfblood-prince/trustcheck">
</script>

## Docs map

- Start with [Installation](getting-started/installation.md) and [Quickstart](getting-started/quickstart.md)
- Use [CLI Overview](cli/index.md) for command and flag reference
- Use [JSON contract](reference/json-contract.md) for integrations
- Use [Python API](reference/python-api.md) for programmatic use
- Use [Compatibility](reference/compatibility.md) for API and JSON stability guarantees
- Use [Trust model and repository matching](reference/trust-model.md) for verification semantics and diagnostics
- Use [CI integration](guides/ci-integration.md) to wire `trustcheck` into GitHub Actions
- Use [Development and release process](guides/development.md) for local workflows and release controls
