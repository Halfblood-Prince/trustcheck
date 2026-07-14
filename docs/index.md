# trustcheck

`trustcheck` is a Python package and CLI for evaluating the trust posture of PyPI releases before they are installed, promoted, or approved.

It combines PyPI metadata, vulnerability records, provenance availability, cryptographic attestation verification, Trusted Publisher identity hints, and repository matching into a single operator-friendly report.

## What it checks

For a selected package version, `trustcheck` can:

- fetch project and release metadata from PyPI
- inspect declared repository URLs from project metadata
- retrieve provenance envelopes for each release artifact
- verify attestations against the downloaded artifact digest
- interpret SLSA v1 builder, build type, source commit, workflow, and material
  evidence
- detect mutable workflow references, unpinned build actions, and
  source-to-artifact inconsistencies
- extract Trusted Publisher identity details such as repository and workflow
- compare expected repository input against declared and attested repository signals
- compare signer, repository, workflow, builder, build type, and source commit
  evidence against the previous release
- merge PyPI, OSV, custom OSV-compatible, and Ecosyste.ms advisory intelligence
- normalize CVSS, CWE, aliases, fix versions, and withdrawn status
- enrich CVEs with optional CISA KEV and FIRST EPSS intelligence
- inspect declared runtime dependencies and summarize the worst-risk dependency in the set
- scan requirements files, project TOML, PEP 751 `pylock.toml`,
  `Pipfile.lock`, and `uv.lock`, `poetry.lock`, or `pdm.lock`
- export SARIF 2.1.0, CycloneDX 1.6 or 1.7 JSON/XML, SPDX 2.3 or
  SPDX 3 JSON, OpenVEX 0.2.0, Markdown, or native JSON
- statically inspect wheel and sdist contents without importing package code
- score typosquatting and package-history anomalies, and inspect Python ASTs
  plus PE, ELF, and Mach-O binaries for suspicious capabilities
- calculate, validate, dry-run, and transactionally apply minimal secure
  dependency upgrades
- verify and install dependencies in one gate with a temporary local wheelhouse
  and reproducible lock, report, and attestation evidence
- prioritize vulnerable packages by observed first-party imports, dependency
  reachability, test-only usage, development-only usage, and unresolved dynamic
  imports
- batch advisory queries, bound concurrent scans, checkpoint interrupted work,
  and use SHA-256 content-addressed offline caches
- extend advisory, index, artifact, policy, and rendering behavior through
  explicitly enabled experimental entry-point plugins
- emit a concise human-readable report or structured JSON

## Install

```bash
pip install trustcheck
```

## First command

```bash
trustcheck inspect sampleproject --version 4.0.0
```

Or add the reusable TrustCheck Package Scanner action:

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: Halfblood-Prince/trustcheck@v2
    with:
      target: requirements.txt
      policy: strict
```

The action asks the CLI for JSON internally, uploads the selected report
artifact, and propagates the CLI policy exit code. The default artifact is
`trustcheck-report.txt`; set `format: json` when an integration expects
`trustcheck-report.json`.

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

Scan every package listed in a requirements-style file for vulnerabilities:

```bash
trustcheck scan -f requirements.txt
```

Verify and install only the already-checked artifacts:

```bash
trustcheck install -r requirements.txt --policy strict
trustcheck install requests==2.32.5 --require-provenance
```

The install command resolves the full graph, verifies hashes, provenance,
advisories, artifact policy, and index origin, writes a lock/report/attestation
bundle, then invokes pip with `--no-index --find-links` against the temporary
verified wheelhouse. No package is installed if verification fails.

Prioritize vulnerability alerts by observed source usage:

```bash
trustcheck impact -f requirements.lock --source .
```

Impact triage combines vulnerable package reports with static first-party
imports and resolved dependency edges. It distinguishes directly used,
transitively reachable, test-only, development-only, not observed, and unknown
dynamic-loading cases, without claiming that an unobserved package is safe.

Scan dependencies declared in a TOML project file for vulnerabilities:

```bash
trustcheck scan -f pyproject.toml
```

Inspect exact versions from a supported lockfile:

```bash
trustcheck inspect -f uv.lock --with-transitive-deps
```

Plan or validate a safe dependency repair:

```bash
trustcheck scan -f requirements.txt --with-osv --plan-fixes
trustcheck scan -f uv.lock --with-osv --fix --dry-run
```

Inspect wheel and sdist contents:

```bash
trustcheck inspect sampleproject --version 4.0.0 --inspect-artifacts --verbose
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

Machine-readable reports currently use JSON schema `1.12.0`. The package release
and report schema are versioned independently.

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
- Use [Performance and extensibility](reference/performance-extensibility.md) for batching, caching, snapshots, resume state, and plugins
- Use [Limitations and data flows](reference/limitations-data-flows.md) for result meanings, privacy behavior, external services, retained data, and experimental feature limits
- Use [Benchmarks](reference/benchmarks.md) for the reproducible `pip-audit` comparison
- Use [Malicious-package detection](reference/malicious-package-detection.md) for heuristic scoring and calibration status
- Use [Trust model and repository matching](reference/trust-model.md) for verification semantics and diagnostics
- Use [CI integration](guides/ci-integration.md) to wire `trustcheck` into GitHub Actions

## Project support

- Bugs and feature requests: [GitHub Issues](https://github.com/Halfblood-Prince/trustcheck/issues)
- Sensitive security reports: [GitHub private vulnerability reporting](https://github.com/Halfblood-Prince/trustcheck/security/advisories/new)
- Security policy: [SECURITY.md](https://github.com/Halfblood-Prince/trustcheck/security/policy)
