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

`trustcheck` is a Python package and CLI for evaluating the trust posture of PyPI releases before they are installed, promoted, or approved.

It combines PyPI metadata, vulnerability records, provenance availability, cryptographic attestation verification, Trusted Publisher identity hints, and repository matching into a single operator-friendly report.

Packages that publish no provenance are treated as needing review rather than as automatic high-risk findings, while invalid provenance, partial coverage, repository mismatches, and known vulnerabilities remain stronger negative signals.

## Choose your workflow

| Command | Use it to |
| --- | --- |
| `scan` | audit a project |
| `inspect` | assess one package release |
| `install` | verify before installing |
| `diff` | review a dependency PR |
| `manifest` | lock approved trust evidence |
| `impact` | prioritize by observed usage |

## What it checks

For a selected package version, `trustcheck` can:

- fetch project and release metadata from PyPI
- verify published provenance against artifact digests
- interpret SLSA v1 build definitions, builders, source materials, commits,
  workflows, and resolved build dependencies
- detect mutable workflow references, unpinned build actions, and
  source-to-artifact inconsistencies
- surface Trusted Publisher repository and workflow identity hints
- compare signer, repository, workflow, builder, build type, and source commit
  evidence across release history
- verify source/release parity so declared repositories, release tags,
  artifacts, and attestations agree on one source commit
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
- verify and install dependencies in one gate with a temporary local wheelhouse
  and reproducible lock, report, and attestation evidence
- prioritize vulnerable packages by observed first-party imports, dependency
  reachability, test-only usage, development-only usage, and unresolved dynamic
  imports
- plan, dry-run, apply, or publish the smallest validated secure dependency
  upgrade set without silently widening declared constraints
- review dependency update pull requests by comparing only changed lockfile
  packages, trust metadata, artifacts, index origins, licenses, and manifest
  expectations
- batch OSV queries, bound concurrent target work, and store responses by
  verified SHA-256 content digest
- consume offline advisory snapshots, resume interrupted scans, and load
  explicitly enabled advisory, index, artifact, policy, or renderer plugins
- optionally inspect wheel and sdist contents without importing or executing package code
- score typosquatting, dependency-confusion, package-history, source-code, and
  native-binary heuristic indicators without claiming a malware verdict
- emit text, JSON, SARIF 2.1.0, CycloneDX 1.6 JSON/XML, SPDX 2.3 JSON,
  OpenVEX 0.2.0, or Markdown
- emit a concise decision report for release gates and pull request checks

Check local prerequisites before relying on resolver isolation, private indexes,
or provenance verification:

```bash
trustcheck doctor
```

Every push also builds standalone Windows and Linux executables. The Windows
artifact is scanned with Microsoft Defender's `MpCmdRun.exe`; the Linux
artifact is scanned with ClamAV. Clean binaries, checksums, and scanner reports
are retained as workflow artifacts by
[Binary Security](https://github.com/Halfblood-Prince/trustcheck/actions/workflows/binary-security.yml).

<!-- trustcheck-benchmark:start -->
## Latest benchmark

Generated `2026-07-04T12:38:12.871592+00:00` on Python `3.14.6` with `pip-audit 2.10.1`. Corpus `2026.06` contains 133 entries; this fixed-input `--no-deps` comparison covers 112 comparable package entries.

| Tool | Cold p50 | Warm p50 | Warm p95 | Peak RSS | Requests p50 | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| trustcheck scan --fast | 16.00 s | 14.20 s | 14.44 s | 78.0 MiB | unknown | 1 |
| pip-audit | 36.69 s | 38.51 s | 39.82 s | 75.6 MiB | unknown | 1 |

Alias-aware agreement: `1.0` across `105` compared packages and `263` matched advisories.
Resolver exact match: `True` (trustcheck `22`, pip-audit `22`).
<!-- trustcheck-benchmark:end -->

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

Project defaults can live in `.trustcheck.toml` or under `[tool.trustcheck]` in
`pyproject.toml`. CLI flags override environment variables, which override
project configuration. See the [configuration guide](https://halfblood-prince.github.io/trustcheck/cli/configuration/).

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

Machine-readable reports currently use JSON schema `1.11.0`. Package and report
schema versions are independent so documentation-only package releases do not
force contract churn.

## Pre-commit and monorepos

Trustcheck publishes a first-party hook for changed dependency files:

```yaml
repos:
  - repo: https://github.com/Halfblood-Prince/trustcheck
    rev: v2
    hooks:
      - id: trustcheck
```

The hook runs `--fast --no-deps --with-osv`, preserves lockfile artifact hashes,
deduplicates filenames, and merges failures across every changed dependency file.
For monorepos, `trustcheck-workspace . --format sarif` discovers supported files,
aggregates repository-relative results, and accepts `--baseline` plus
`--policy-overrides` for per-project policies.

Use a trust manifest to approve the current dependency identities and block
future trust regressions even when an upgrade is vulnerability-free:

```bash
trustcheck manifest init -f requirements.lock --output trustcheck.manifest.json
trustcheck manifest verify -f requirements.lock --manifest trustcheck.manifest.json
trustcheck manifest update -f requirements.lock --manifest trustcheck.manifest.json
```

The manifest records source repository and owner, verified Trusted Publisher
identity and workflow, SLSA builder and build type, provenance and attestation
coverage, package index origin, malicious-package score ceiling, native-binary
allowance, dynamic-execution allowance, and expiring package exceptions.

Review dependency update pull requests with a trust diff that inspects only
packages whose resolved version or source changed:

```bash
trustcheck diff requirements-old.lock requirements-new.lock
trustcheck diff --base origin/main --head HEAD --github-pr --format markdown
trustcheck diff --base origin/main --head HEAD --github-pr --comment
```

The diff highlights new direct and transitive packages, vulnerability and
malicious-package signals, provenance loss, repository or Trusted Publisher
changes, wheel or sdist native-binary changes, license and private-index origin
changes, and trust-manifest violations when `--manifest` is provided. Use
`--format sarif` to upload findings to code scanning.

## TrustCheck Package Scanner

Use the TrustCheck Package Scanner action to scan a checked-in dependency file
before merge:

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: Halfblood-Prince/trustcheck@v2
    with:
      target: requirements.txt
      policy: strict
```

For a protected release gate, pin both actions to commit SHAs. GitHub treats a
full commit SHA as the only immutable Action reference:

```yaml
steps:
  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
  - uses: Halfblood-Prince/trustcheck@<full-release-commit-sha>
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

Produce SARIF for GitHub code scanning without repeating the audit:

```yaml
- uses: Halfblood-Prince/trustcheck@v2
  id: trustcheck
  with:
    target: requirements.txt
    format: sarif

- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: ${{ steps.trustcheck.outputs.report-path }}
```

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
trustcheck scan sampleproject --version 4.0.0 --fast
```

Scan profiles make the analysis depth explicit. `--fast` (the default) performs
dependency resolution and advisory lookup only. `--standard` adds provenance,
while `--full` adds static archives, native binaries, release history, and
malicious-package heuristics. Artifact breadth defaults to the best compatible
wheel for the requested target, with an sdist fallback.

```bash
trustcheck scan -f requirements.txt --standard
trustcheck scan sampleproject --version 4.0.0 --full --workers 8
trustcheck scan sampleproject --full --artifact-scope all --strict
```

Use `--artifact-scope sdist` for source review or `--artifact-scope all` for a
strict whole-release review. Release and promotion policies should scan every
published artifact, including wheels for other operating systems and
architectures:

```bash
trustcheck scan -f requirements.lock --full --artifact-scope all --strict
```

Verify and install the exact resolved dependency graph in one workflow:

```bash
trustcheck install -r requirements.txt --policy strict
trustcheck install -r requirements.txt --lock trustcheck.lock
trustcheck install requests==2.32.5 --require-provenance
```

`trustcheck install` resolves the complete graph, verifies the selected
artifacts, materializes a temporary verified wheelhouse, and invokes pip with
`--no-index --find-links` plus hash-pinned exact requirements. Nothing is
installed if policy, provenance, advisory, hash, artifact, or private-index
origin checks fail. Each run writes `trustcheck.lock`,
`trustcheck-install-report.json`, and `trustcheck-install-attestation.json`.

Prioritize vulnerable packages by observed application usage:

```bash
trustcheck impact -f requirements.lock --source .
trustcheck impact -f requirements.lock --source src --source services/api --format json
```

`trustcheck impact` combines the resolved dependency graph with a conservative
static import graph from first-party source, console-script metadata, pytest
plugins, and common framework imports. Findings are classified as directly
used, transitively reachable, test-only, development-only, not observed in
project source, or unknown due to dynamic loading. It never claims a dependency
is not exploitable; no first-party usage means only that static analysis did
not observe it, and dynamic imports, plugins, and runtime configuration still
require manual review.

Enrich vulnerability intelligence with OSV and GitHub Advisory Database data:

```bash
trustcheck scan jinja2 --version 2.10.0 --with-osv
```

Merge OSV, Ecosyste.ms, a private OSV-compatible service, CISA KEV, and FIRST
EPSS intelligence:

```bash
trustcheck scan jinja2 \
  --version 2.10.0 \
  --with-osv \
  --with-ecosystems \
  --osv-url https://advisories.example.com \
  --with-kev \
  --with-epss
```

Gate only critical, known-exploited, or fixable vulnerabilities:

```bash
trustcheck scan -f pylock.toml --fail-on-vulnerability kev
```

Require verified publishers to belong to an approved organization:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --trusted-publisher-organization github:pypa
```

Custom policy files can suppress a specific advisory temporarily, but every
suppression must name an owner, justification, and ISO expiration date.

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
trustcheck inspect -f requirements.txt
```

Resolution uses `pip install --dry-run --report` and includes transitive
packages selected by pip:

```bash
trustcheck scan -f requirements.txt \
  --constraint constraints.txt \
  --python-version 3.12 \
  --platform manylinux_2_28_x86_64 \
  --implementation cp \
  --abi cp312
```

Pip may invoke build-backend metadata hooks even in dry-run mode. Trustcheck
can isolate that resolver invocation:

```bash
trustcheck scan -f requirements.txt --sandbox auto
```

`--sandbox auto` is the default. It prefers Bubblewrap on Linux, then Docker or
Podman, and falls back to strict wheel-only resolution when no runtime is
available. The full mode set is:

- `warn`: explicitly preserve host pip behavior and emit an execution-risk warning
- `off`: preserve pip behavior without the warning
- `container`: run pip as an unprivileged process in a read-only Docker/Podman
  container with dropped capabilities and only staged resolver inputs mounted
- `bubblewrap`: run pip in low-privilege Linux namespaces with a read-only
  staged input tree, read-only system paths, and a cleared environment
- `strict`: reject editable, VCS, local non-wheel, direct non-wheel, and source
  archive inputs, ignore user pip configuration, and require wheels for every
  resolved package; child-process creation is denied so unexpected transitive
  source hooks and VCS commands fail closed

Container and Bubblewrap modes retain network access for package-index
resolution. Requirements, nested includes, constraints, dependency-group
files, and referenced local dependencies are copied to a temporary input tree;
the project workspace is not mounted. Container images must be pinned by a
full SHA-256 digest when supplied with `--sandbox-image`. Cross-target
resolution is always wheel-only.

Inspect dependencies declared in a TOML project file:

```bash
trustcheck inspect -f pyproject.toml
```

Plan the smallest constraint-compatible secure upgrade set:

```bash
trustcheck scan -f requirements.txt \
  --with-osv \
  --plan-fixes \
  --remediation-output reports/trustcheck-remediation.json
```

Generate and validate the exact patch without changing dependency files:

```bash
trustcheck scan -f pyproject.toml --with-osv --fix --dry-run
```

Apply the same transaction only after re-resolution, a clean virtualenv
install, `pip check`, configured validation commands, and a complete rescan:

```bash
trustcheck scan -f uv.lock --with-osv --fix
```

Configured fix validation commands live under `[tool.trustcheck.fix]`:

```toml
[tool.trustcheck.fix]
test_commands = ["pytest -q", "python -m compileall src"]
```

Successful fix runs write a review patch such as `trustcheck-fix.patch` and
record the exact path in the remediation output.

Secure versions excluded by a declared range remain blocked unless
`--allow-constraint-changes` is passed. Editable, local-path, direct-archive,
and VCS dependencies are reported as requiring human remediation.

Select project extras and dependency groups:

```bash
trustcheck scan -f pyproject.toml --extra security --group test
```

Inspect exact direct and transitive versions from a supported lockfile:

```bash
trustcheck inspect -f pylock.toml --with-transitive-deps
trustcheck scan -f Pipfile.lock
```

Run a bounded, resumable scan and publish an advisory snapshot:

```bash
trustcheck scan -f requirements.txt \
  --with-osv \
  --workers 8 \
  --resume-state .trustcheck/scan-state.json \
  --write-advisory-snapshot .trustcheck/advisories.json \
  --sign-advisory-snapshot
```

Signed snapshots include source URLs, generation and expiration times, and a
SHA-256 digest of canonical advisory records. Reading one requires the trusted
Sigstore certificate identity and accepts snapshots for at most seven days by
default; adjust that bound with `--max-advisory-age HOURS`.

Enable an installed, signed plugin explicitly:

```bash
trustcheck scan -f requirements.txt --plugin policy:company-policy
```

Every plugin must be explicitly allowlisted. Trustcheck verifies its signed
`trustcheck-plugin.json` name, kind, entry point, and API version before using a
spawned resource-bounded worker. Optional signer fingerprints live under
`_trustcheck.trusted_signers` in plugin config. Each call is reported in
`diagnostics.plugin_executions` with status, duration, and isolation state.

Hash-pinned pip-tools output is detected automatically. Every retained
lockfile hash is emitted in combined JSON and checked against the downloaded
artifact. This integrity check does not require `--inspect-artifacts`.

Resolve and audit from a private PEP 503/691 index:

```bash
trustcheck scan -f requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --keyring-provider subprocess
```

Adding a public fallback is deliberately guarded:

```bash
trustcheck scan -f requirements.txt \
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
parses Python source with `ast`, detects suspicious capability combinations,
and compares wheel and sdist metadata. PE, ELF, and Mach-O files are inspected
for imported libraries, embedded signature presence, entropy, and embedded
payload signatures. It reads archive bytes only and never imports the
inspected package.

For behavior evidence, `--dynamic-analysis` is available as an explicit opt-in.
It executes downloaded artifacts in a disposable Docker container with no
network, a non-root user, dropped capabilities, and strict CPU, memory, process,
and wall-clock limits. The dynamic-analysis image is digest-pinned by default,
and mutable image tags are rejected. It is never enabled by default.

Name, index, ownership, repository, and release-cadence heuristics run during
normal inspection. Add organization-specific reference names with repeatable
`--trusted-project`:

```bash
trustcheck inspect -f requirements.txt \
  --trusted-project internal-sdk \
  --trusted-project internal-auth
```

Every malicious-package finding is explicitly labeled as a heuristic indicator
for review, not proof that a package is malicious.

Require a release to match an expected repository:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject
```

Require source/release provenance parity for a package release:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --source-release-provenance \
  --release-tag v4.0.0
```

Emit JSON for another tool:

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

Emit only the gate decision fields:

```bash
trustcheck scan -f requirements.txt --summary
```

Emit combined JSON for a requirements-style, TOML, or lockfile scan:

```bash
trustcheck scan -f requirements.txt --format json
```

Write SARIF, SBOM, VEX, or Markdown output directly to a file:

```bash
trustcheck scan -f requirements.txt \
  --format sarif \
  --output-file reports/trustcheck.sarif

trustcheck scan -f pylock.toml \
  --format cyclonedx-json \
  --output-file reports/trustcheck.cdx.json
```

Supported industry formats are `sarif`, `cyclonedx-json`, `cyclonedx-xml`,
`spdx-json`, `openvex`, and `markdown`. SBOM exports retain package purls,
vulnerabilities, provenance coverage, artifact hashes, recommendations, and
policy violations.

Emit only vulnerability records as JSON:

```bash
trustcheck scan sampleproject --version 4.0.0 --format json
```

Fail CI when full verification is missing:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

Starter policy bundles include `startup`, `regulated`,
`enterprise-private-index`, `release-gate`, and `open-source-maintainer`:

```bash
trustcheck scan -f requirements.txt --policy release-gate
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
- Performance and extensibility: [Batching, caching, snapshots, resume state, and plugins](https://halfblood-prince.github.io/trustcheck/reference/performance-extensibility/)
- Benchmarks: [Reproducible comparison with pip-audit](https://halfblood-prince.github.io/trustcheck/reference/benchmarks/)
- Project details: [Changelog](https://halfblood-prince.github.io/trustcheck/changelog/)

Project support:

- Bugs and feature requests: [GitHub Issues](https://github.com/Halfblood-Prince/trustcheck/issues)
- Sensitive security reports: [GitHub private vulnerability reporting](https://github.com/Halfblood-Prince/trustcheck/security/advisories/new)
- Security policy: [SECURITY.md](https://github.com/Halfblood-Prince/trustcheck/security/policy)

## License

[Trustcheck Personal Use License](LICENSE)
