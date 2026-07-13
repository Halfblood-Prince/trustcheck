<p align="center">
  <img src="https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/main/docs/assets/images/logo.png" width="260" alt="trustcheck logo">
</p>

# trustcheck [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

[![CI](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Source Build](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/source-build.yml)
[![CodeQL](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml/badge.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/codeql.yml)
[![pip-audit](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=pip-audit)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Bandit](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/bandit.yml)
[![Semgrep](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/semgrep.yml)
[![Adversarial fuzzing](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/fuzz.yml)
[![Windows Defender](https://img.shields.io/github/check-runs/Halfblood-Prince/trustcheck/main?nameFilter=Windows%20Defender&label=Windows%20Defender&logo=windows11)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
[![ClamAV](https://img.shields.io/github/check-runs/Halfblood-Prince/trustcheck/main?nameFilter=ClamAV&label=ClamAV&logo=linux)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
[![Ruff](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=ruff)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![mypy](https://img.shields.io/github/actions/workflow/status/Halfblood-Prince/trustcheck/ci.yml?branch=main&label=mypy)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/coverage-badge/coverage.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/trustcheck.svg)](https://pypi.org/project/trustcheck/)
[![Python 3.11 | 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/ci.yml)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/trustcheck?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/trustcheck)
[![TrustCheck Package Scanner](https://img.shields.io/badge/GitHub%20Action-TrustCheck%20Package%20Scanner-blue?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/trustcheck-package-scanner)

[![Get it from the Snap Store](https://snapcraft.io/en/dark/install.svg)](https://snapcraft.io/trustcheck)
<a href="https://pypi.org/project/trustcheck/"><img src="https://raw.githubusercontent.com/Halfblood-Prince/trustcheck/coverage-badge/PyPI.png" alt="Get it from PyPI" height="55"></a>

`trustcheck` is a Python package and CLI for deciding whether a PyPI release,
dependency file, or dependency update is safe enough to install, merge, or
promote.

It combines vulnerability intelligence, PyPI provenance, cryptographic
attestation verification, Trusted Publisher identity, repository matching,
artifact hashes, private-index origin checks, and package-risk heuristics into
one operator-friendly report.

Standalone Windows and Linux executables are scanned by
[Binary Security](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
with Microsoft Defender and ClamAV.

## Why trustcheck

- Verifies PyPI provenance and artifact digests instead of trusting metadata alone.
- Scans packages, requirements files, `pyproject.toml`, supported lockfiles,
  installed environments, and dependency update pull requests.
- Closes the check-to-install gap with `trustcheck install`, which installs only
  already-verified artifacts from a temporary local wheelhouse.
- Blocks trust regressions with manifests, repository expectations, publisher
  policies, private-index protections, and CI-ready exit codes.
- Emits text, JSON, SARIF, CycloneDX, SPDX, OpenVEX, and Markdown for humans,
  release gates, code scanning, SBOMs, and downstream automation.
- Benchmarked against `pip-audit` with matching recall and faster warm p50 in
  the published fixed-input comparison.

<!-- trustcheck-benchmark:start -->
## Latest benchmark

Generated `2026-07-04T12:38:12.871592+00:00` on Python `3.14.6` with
`pip-audit 2.10.1`. Corpus `2026.06` contains 133 entries; this fixed-input
`--no-deps` comparison covers 112 comparable package entries.

| Tool | Cold p50 | Warm p50 | Warm p95 | Peak RSS | Requests p50 | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| trustcheck scan --fast | 16.00 s | 14.20 s | 14.44 s | 78.0 MiB | unknown | 1 |
| pip-audit | 36.69 s | 38.51 s | 39.82 s | 75.6 MiB | unknown | 1 |

Alias-aware agreement: `1.0` across `105` compared packages and `263` matched
advisories.
Resolver exact match: `True` (trustcheck `22`, pip-audit `22`).
<!-- trustcheck-benchmark:end -->

## Installation

```bash
pip install trustcheck
```

Optional private-index keyring support:

```bash
pip install "trustcheck[keyring]"
```

Snap package:

```bash
sudo snap install trustcheck
```

If the shell reports `command not found` immediately after Snap installation,
start a new login session or update the current shell:

```bash
export PATH="/snap/bin:$PATH"
trustcheck --version
```

You can always bypass shell PATH lookup with:

```bash
snap run trustcheck inspect requests
```

Machine-readable reports currently use JSON schema `1.11.0`. Package and
report schema versions are independent.

## Quick start

```bash
trustcheck inspect requests
trustcheck scan -f requirements.txt --standard
trustcheck install -r requirements.txt --policy strict
```

Review a dependency update:

```bash
trustcheck diff requirements-old.lock requirements-new.lock
```

Run it in GitHub Actions:

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: Halfblood-Prince/trustcheck@v2
    with:
      target: requirements.txt
      policy: strict
```

## Command map

| Command | Use it to |
| --- | --- |
| `trustcheck inspect` | assess one PyPI release |
| `trustcheck scan` | audit a dependency file or package |
| `trustcheck install` | verify before installing |
| `trustcheck diff` | review dependency update PRs |
| `trustcheck manifest` | lock approved trust evidence |
| `trustcheck impact` | prioritize vulnerable packages by observed usage |

## Documentation

Full docs: <https://halfblood-prince.github.io/trustcheck/docs/>

- [Installation](https://halfblood-prince.github.io/trustcheck/docs/getting-started/installation/)
- [Quickstart](https://halfblood-prince.github.io/trustcheck/docs/getting-started/quickstart/)
- [CLI overview](https://halfblood-prince.github.io/trustcheck/docs/cli/)
- [CI integration](https://halfblood-prince.github.io/trustcheck/docs/guides/ci-integration/)
- [Trust model](https://halfblood-prince.github.io/trustcheck/docs/reference/trust-model/)
- [Benchmarks](https://halfblood-prince.github.io/trustcheck/docs/reference/benchmarks/)

## License

[Trustcheck Personal Use License](LICENSE)
