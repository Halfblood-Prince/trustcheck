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

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

<div id="context7-chatbot"></div>

## Docs map

- Start with [Installation](getting-started/installation.md) and [Quickstart](getting-started/quickstart.md)
- Use [CLI Overview](cli/index.md) for command and flag reference
- Use [JSON contract](reference/json-contract.md) for integrations
- Use [Python API](reference/python-api.md) for programmatic use
- Use [CI integration](guides/ci-integration.md) to wire `trustcheck` into GitHub Actions
