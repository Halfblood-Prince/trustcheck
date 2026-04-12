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
- verify published provenance against artifact digests
- surface Trusted Publisher repository and workflow identity hints
- compare expected repository input against declared and attested signals
- flag publisher drift, missing verification, and known vulnerabilities
- emit concise text output or structured JSON for automation

## Installation

```bash
pip install trustcheck
```

Requirements:

- Python `>=3.10`
- Network access to PyPI

## Quick start

Inspect the latest release:

```bash
trustcheck inspect requests
```

Inspect a specific version:

```bash
trustcheck inspect sampleproject --version 4.0.0
```

Require a release to match an expected repository:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject
```

Emit JSON for another tool:

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

## Documentation

Full documentation: https://halfblood-prince.github.io/trustcheck/

- Getting started: [Installation](docs/getting-started/installation.md) and [Quickstart](docs/getting-started/quickstart.md)
- CLI usage: [CLI overview](docs/cli/index.md), [Policies](docs/cli/policies.md), and [Config and offline mode](docs/cli/configuration.md)
- Integrations: [JSON contract](docs/reference/json-contract.md), [Python API](docs/reference/python-api.md), and [Compatibility](docs/reference/compatibility.md)
- Trust model: [Verification model and repository matching](docs/reference/trust-model.md)
- Automation: [CI integration](docs/guides/ci-integration.md)
- Project details: [Development and release process](docs/guides/development.md) and [Changelog](CHANGELOG.md)

## License

[Trustcheck Personal Use License](LICENSE)
