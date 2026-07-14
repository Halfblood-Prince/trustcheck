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

`trustcheck` is a Python CLI and library for deciding whether a PyPI package,
dependency file, or dependency update has enough trust evidence to install,
merge, or promote.

It combines vulnerability intelligence, PyPI provenance, Sigstore
attestations, Trusted Publisher identity, repository matching, artifact hashes,
private-index origin checks, static artifact inspection, and policy evaluation
into one report. JSON reports currently use JSON schema `1.12.0`; package and
report schema versions are independent.

Standalone Windows and Linux executables are scanned by
[Binary Security](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml)
with Microsoft Defender and ClamAV.

<!-- trustcheck-benchmark:start -->
## Latest benchmark

The full fixed-input `pip-audit 2.10.1` comparison, corpus details, signed
truth-corpus gates, and benchmark caveats live in the
[Benchmarks](https://halfblood-prince.github.io/trustcheck/docs/reference/benchmarks/)
reference. README benchmark markers are kept so maintainers can publish a
reviewed table from `benchmarks/results/latest.json` when appropriate.
<!-- trustcheck-benchmark:end -->

## Installation

```bash
pip install trustcheck
```

Private-index keyring support is optional:

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

## Three Commands

Inspect one release and its provenance:

```bash
trustcheck inspect sampleproject --version 4.0.0 --expected-repo https://github.com/pypa/sampleproject
```

Scan a dependency file in CI:

```bash
trustcheck scan -f requirements.txt --policy strict --format json
```

Verify before installing:

```bash
trustcheck install -r requirements.txt --policy strict
```

## Security Model

Trustcheck is evidence-producing, not a proof of safety. It can block policy
failures, malformed artifacts, dependency-confusion risks, missing or changed
provenance, vulnerable releases, and suspicious static signals. It cannot prove
that a package is benign, and missing upstream data may make a result
inconclusive.

Dynamic installation analysis and third-party Trustcheck plugins are opt-in and
experimental.

## GitHub Action

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: Halfblood-Prince/trustcheck@v3
    with:
      target: requirements.txt
      policy: strict
```

Use `@v3` for compatible updates. For immutable release gates, pin the Action
and supporting actions to a full commit SHA such as
`Halfblood-Prince/trustcheck@<full-release-commit-sha>`.

## Documentation

Full docs: <https://halfblood-prince.github.io/trustcheck/docs/>

- [Installation](https://halfblood-prince.github.io/trustcheck/docs/getting-started/installation/)
- [Quickstart](https://halfblood-prince.github.io/trustcheck/docs/getting-started/quickstart/)
- [CLI overview](https://halfblood-prince.github.io/trustcheck/docs/cli/)
- [CI integration](https://halfblood-prince.github.io/trustcheck/docs/guides/ci-integration/)
- [Trust model](https://halfblood-prince.github.io/trustcheck/docs/reference/trust-model/)
- [Limitations and data flows](https://halfblood-prince.github.io/trustcheck/docs/reference/limitations-data-flows/)
- [Benchmarks](https://halfblood-prince.github.io/trustcheck/docs/reference/benchmarks/)

## Support

- Bugs and feature requests: <https://github.com/Halfblood-Prince/trustcheck/issues>
- Sensitive security reports: <https://github.com/Halfblood-Prince/trustcheck/security/advisories/new>
- Security policy: <https://github.com/Halfblood-Prince/trustcheck/security/policy>

## License

[Trustcheck Personal Use License](LICENSE)
