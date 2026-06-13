<p align="center">
  <img src="https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/main/docs/assets/images/logo.png" width="300">
</p>

# trustcheck [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

[![CI](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Source Build](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml)
[![CodeQL](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml)
[![pip-audit](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=pip-audit)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Bandit](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml)
[![Semgrep](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml)
[![Windows Defender](https://img.shields.io/github/check-runs/Halfblood-Prince/trustcheck/main?nameFilter=Windows%20Defender&label=Windows%20Defender&logo=windows11)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
[![ClamAV](https://img.shields.io/github/check-runs/Halfblood-Prince/trustcheck/main?nameFilter=ClamAV&label=ClamAV&logo=linux)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
[![Ruff](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=ruff)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![mypy](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=mypy)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/coverage-badge/coverage.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/trustcheck.svg)](https://pypi.org/project/trustcheck/)
[![Python 3.11 | 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/trustcheck?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/trustcheck)
[![TrustCheck Package Scanner](https://img.shields.io/badge/GitHub%20Action-TrustCheck%20Package%20Scanner-blue?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/trustcheck-package-scanner)

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
- scan requirements files, project TOML, `pylock.toml`, `Pipfile.lock`,
  pip-tools output, and `uv.lock`, `poetry.lock`, or `pdm.lock`
- resolve complete dependency sets with pip installation reports, including
  constraints, nested requirements, extras, dependency groups, editable
  requirements, and VCS references
- audit the active Python environment or arbitrary `site-packages` directories
- resolve against PEP 503/691 private indexes with optional keyring credentials
- block dependency-confusion collisions across public and private indexes
- preserve and verify lockfile artifact hashes before trusting downloaded bytes
- optionally inspect wheel and sdist contents without importing or executing package code
- emit concise text output or structured JSON for automation

Every push also builds standalone Windows and Linux executables. The Windows
artifact is scanned with Microsoft Defender's `MpCmdRun.exe`; the Linux
artifact is scanned with ClamAV. Clean binaries, checksums, and scanner reports
are retained as workflow artifacts by
[Binary Security](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml).

## Installation

Install from PyPI:

```bash
pip install trustcheck
```

Install the optional Python keyring provider when private-index credentials are
stored in an in-process keyring backend:

```bash
pip install "trustcheck[keyring]"
```

Or install the Snap Store package:

```bash
sudo snap install trustcheck
```

The Snap command is `trustcheck`. If the shell reports `command not found`
immediately after installation, start a new login session or add Snap's
command directory to the current shell:

```bash
export PATH="/snap/bin:$PATH"
trustcheck --version
```

You can always bypass shell PATH lookup with:

```bash
snap run trustcheck inspect requests
```

PyPI installation requirements:

- Python `>=3.11`
- Network access to PyPI

Machine-readable reports currently use JSON schema `1.5.0`. Package and report
schema versions are independent so documentation-only package releases do not
force contract churn.

## TrustCheck Package Scanner

Use the TrustCheck Package Scanner action to scan a checked-in dependency file
before merge:

```yaml
steps:
  - uses: actions/checkout@v6
  - uses: Halfblood-Prince/trustcheck@v1
    with:
      target: requirements.txt
      policy: strict
```

The action installs and runs `trustcheck`, uploads `trustcheck-report.json` as
a workflow artifact, and fails the job with the CLI's exit code when policy
evaluation fails. `target` also accepts a PyPI package name, `pyproject.toml`,
`pylock.toml`, `Pipfile.lock`, `uv.lock`, `poetry.lock`, or `pdm.lock`.
Each stable release publishes an immutable full version tag and updates the
compatible major action tag used above.

See the [CI integration guide](https://halfblood-prince.github.io/trustcheck/guides/ci-integration/)
for custom policies, OSV, dependency traversal, outputs, and report naming.

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

Resolution uses `pip install --dry-run --report` and includes transitive
packages selected by pip:

```bash
trustcheck scan requirements.txt \
  --constraint constraints.txt \
  --python-version 3.12 \
  --platform manylinux_2_28_x86_64 \
  --implementation cp \
  --abi cp312
```

Resolver note: pip may invoke build-backend metadata hooks for source, local,
editable, or VCS requirements even in dry-run mode. Do not resolve an
untrusted source requirement outside an appropriate sandbox. Cross-target
resolution is wheel-only.

Inspect dependencies declared in a TOML project file:

```bash
trustcheck scan pyproject.toml
```

Select project extras and dependency groups:

```bash
trustcheck scan pyproject.toml --extra security --group test
```

Inspect exact direct and transitive versions from a supported lockfile:

```bash
trustcheck scan pylock.toml --with-transitive-deps
trustcheck scan Pipfile.lock
```

Hash-pinned pip-tools output is detected automatically. Every retained
lockfile hash is emitted in combined JSON and checked against the downloaded
artifact. This integrity check does not require `--inspect-artifacts`.

Resolve and audit from a private PEP 503/691 index:

```bash
trustcheck scan requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --keyring-provider subprocess
```

Adding a public fallback is deliberately guarded:

```bash
trustcheck scan requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --extra-index-url https://pypi.org/simple
```

If the same normalized project name exists on both indexes, the scan stops
with a dependency-confusion error. `--allow-dependency-confusion` is available
for a source collision that has been independently reviewed; the finding
remains in combined JSON.

Audit the active environment:

```bash
trustcheck environment
```

Audit one or more explicit `site-packages` directories:

```bash
trustcheck environment --path .venv/lib/python3.12/site-packages
```

Statically inspect wheel and sdist contents:

```bash
trustcheck inspect sampleproject --version 4.0.0 --inspect-artifacts --verbose
```

Artifact inspection validates wheel `RECORD` hashes, lists console scripts,
detects native extensions and unusual files, and compares wheel and sdist
metadata. It reads archive bytes only and never imports the inspected package.

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
- Project details: [Changelog](https://halfblood-prince.github.io/trustcheck/changelog/)

Project support:

- Bugs and feature requests: [GitHub Issues](https://github.com/Halfblood-Prince/trustcheck/issues)
- Sensitive security reports: [GitHub private vulnerability reporting](https://github.com/Halfblood-Prince/trustcheck/security/advisories/new)
- Security policy: [SECURITY.md](https://github.com/Halfblood-Prince/trustcheck/security/policy)

## License

[Trustcheck Personal Use License](LICENSE)
