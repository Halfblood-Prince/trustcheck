<p align="center">
  <img src="https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/main/docs/assets/images/logo.png" width="300">
</p>

# trustcheck

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![CI](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Source Build](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml)
[![CodeQL](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml)
[![pip-audit](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=pip-audit)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Bandit](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml)
[![Semgrep](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml)
[![Ruff](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=ruff)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![mypy](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=mypy)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Halfblood-Prince/trustcheck/branch/main/graph/badge.svg)](https://codecov.io/gh/Halfblood-Prince/trustcheck)
[![PyPI](https://img.shields.io/pypi/v/trustcheck.svg)](https://pypi.org/project/trustcheck/)
[![Python 3.10 | 3.11 | 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/trustcheck?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/trustcheck)
[![Marketplace](https://img.shields.io/badge/Marketplace-TrustCheck%20Python%20Package%20Scanner-blue?logo=github&logoColor=white)](https://github.com/marketplace/actions/trustcheck-python-package-scanner)

`trustcheck` is a Python package and CLI for evaluating the trust posture of PyPI releases before they are installed, promoted, or approved.

It combines PyPI metadata, vulnerability records, provenance availability, cryptographic attestation verification, Trusted Publisher identity hints, and repository matching into a single operator-friendly report.

Packages that publish no provenance are treated as needing review rather than as automatic high-risk findings, while invalid provenance, partial coverage, repository mismatches, and known vulnerabilities remain stronger negative signals.

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

Show only known vulnerabilities for a release:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cve
```

Enrich vulnerability intelligence with OSV and GitHub Advisory Database data:

```bash
trustcheck inspect jinja2 --version 2.10.0 --with-osv --cve
```

Inspect a package and its direct dependencies:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

Inspect the full transitive dependency tree:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-transitive-deps
```

Inspect every package listed in a requirements-style file:

```bash
trustcheck scan requirements.txt
```

Inspect dependencies declared in a TOML project file:

```bash
trustcheck scan pyproject.toml
```

Inspect exact direct and transitive versions from a supported lockfile:

```bash
trustcheck scan uv.lock --with-transitive-deps
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

Emit combined JSON for a requirements-style, TOML, or lockfile scan:

```bash
trustcheck scan requirements.txt --format json
```

Emit only vulnerability records as JSON:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cve --format json
```

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

Use it from Python:

```python
from trustcheck import inspect_package

report = inspect_package("sampleproject", version="4.0.0", include_dependencies=True)
print(report.recommendation)
```

## Documentation

Full documentation: https://halfblood-prince.github.io/trustcheck/

- Getting started: [Installation](https://halfblood-prince.github.io/trustcheck/getting-started/installation/) and [Quickstart](https://halfblood-prince.github.io/trustcheck/getting-started/quickstart/)
- CLI usage: [CLI overview](https://halfblood-prince.github.io/trustcheck/cli/), [Policies](https://halfblood-prince.github.io/trustcheck/cli/policies/), and [Config and offline mode](https://halfblood-prince.github.io/trustcheck/cli/configuration/)
- Integrations: [JSON contract](https://halfblood-prince.github.io/trustcheck/reference/json-contract/), [Python API](https://halfblood-prince.github.io/trustcheck/reference/python-api/), and [Compatibility](https://halfblood-prince.github.io/trustcheck/reference/compatibility/)
- Trust model: [Verification model and repository matching](https://halfblood-prince.github.io/trustcheck/reference/trust-model/)
- Automation: [CI integration](https://halfblood-prince.github.io/trustcheck/guides/ci-integration/)
- Project details: [Development and release process](https://halfblood-prince.github.io/trustcheck/guides/development/) and [Changelog](https://halfblood-prince.github.io/trustcheck/changelog/)

## License

[Trustcheck Personal Use License](LICENSE)
