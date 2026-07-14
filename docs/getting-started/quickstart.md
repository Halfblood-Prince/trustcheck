# Quickstart

## Run as a GitHub Action

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: Halfblood-Prince/trustcheck@v3
    with:
      target: requirements.txt
      policy: strict
```

This produces and uploads `trustcheck-report.txt`. The action fails when the
configured policy fails. Set `format: json` for a JSON artifact.

## Inspect the latest release

```bash
trustcheck inspect requests
```

## Inspect a specific version

```bash
trustcheck inspect sampleproject --version 4.0.0
```

## Show only known vulnerabilities

```bash
trustcheck scan sampleproject --version 4.0.0
```

## Merge and enrich vulnerability intelligence

```bash
trustcheck scan jinja2 \
  --version 2.10.0 \
  --with-osv \
  --with-ecosystems \
  --osv-url https://advisories.example.com \
  --with-kev \
  --with-epss
```

Configured OSV-compatible providers run concurrently. Records are merged by
advisory identifiers and aliases, then normalized with CVSS, CWE, fix-version,
withdrawal, KEV, and EPSS fields.

Block a selected vulnerability class:

```bash
trustcheck scan -f requirements.txt --fail-on-vulnerability critical
trustcheck scan -f requirements.txt --fail-on-vulnerability kev
trustcheck scan -f requirements.txt --fail-on-vulnerability fixable
```

## Require a known source repository

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --expected-repo https://github.com/pypa/sampleproject
```

## Show per-file evidence

```bash
trustcheck inspect sampleproject --version 4.0.0 --verbose
```

## Inspect direct dependencies too

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

## Inspect the full dependency tree

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-transitive-deps
```

## Scan a requirements-style file

```bash
trustcheck scan -f requirements.txt
```

Pip resolves the complete dependency set before trustcheck audits it. Nested
requirements, constraints, hashes, editable installs, and VCS references are
supported.

## Verify and install dependencies

```bash
trustcheck install -r requirements.txt --policy strict
trustcheck install -r requirements.txt --lock trustcheck.lock
trustcheck install requests==2.32.5 --require-provenance
```

`trustcheck install` closes the check-to-install gap: it resolves the complete
graph, verifies the selected wheels, fails before pip runs when policy fails,
and installs only from a temporary local wheelhouse with `--no-index` and
`--find-links`. Source distributions are rejected by default unless
`--allow-sdist` is passed. Each run writes `trustcheck.lock`,
`trustcheck-install-report.json`, and `trustcheck-install-attestation.json`.

## Prioritize vulnerable packages by source usage

```bash
trustcheck impact -f requirements.lock --source .
```

Impact triage answers which vulnerable packages are directly imported,
reachable through imported dependencies, test-only, development-only, not
observed in project source, or unknown because dynamic loading is present. It
never claims "not exploitable"; no first-party usage means only that static
analysis did not observe usage. Dynamic imports, plugins, and runtime
configuration still require manual review.

Resolve potentially untrusted input in Bubblewrap or Docker/Podman, with a
wheel-only fallback when neither runtime is available:

```bash
trustcheck scan -f requirements.txt --sandbox auto
```

`--sandbox auto` is the default. `--sandbox warn` remains an explicit
compatibility mode that preserves host pip behavior and warns that source
metadata hooks may execute. The GitHub Action defaults to `strict`, which
rejects editable, local non-wheel, VCS, direct non-wheel, and source-only
requirements.

```bash
trustcheck scan -f requirements.txt --constraint constraints.txt
```

## Scan a TOML dependency file

```bash
trustcheck scan -f pyproject.toml
```

Select extras and dependency groups:

```bash
trustcheck scan -f pyproject.toml --extra security --group test
```

## Inspect a supported lockfile

```bash
trustcheck inspect -f uv.lock --with-transitive-deps
```

Supported lockfiles are PEP 751 `pylock.toml` and named `pylock.<name>.toml`
files, `Pipfile.lock`, `uv.lock`, `poetry.lock`, and `pdm.lock`. Exact locked
versions, source indexes, artifact URLs, sizes, and hashes are retained during
inspection. Hash-pinned pip-tools output is recognized as a requirements input.

## Scan a private index

```bash
trustcheck scan -f requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --keyring-provider subprocess
```

Add `--extra-index-url` for each fallback index. Trustcheck stops by default
when the same normalized project name exists on multiple configured indexes,
which identifies a dependency-confusion opportunity.

## Audit an installed environment

```bash
trustcheck environment
```

Audit an explicit environment without activating it:

```bash
trustcheck environment --path .venv/lib/python3.12/site-packages
```

## Inspect artifact contents

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --inspect-artifacts \
  --verbose
```

Artifact inspection is opt-in. It reads wheel and sdist archives without
extracting them, importing modules, or executing package code. It validates
`RECORD`, parses bounded Python source with `ast`, and inspects PE, ELF, and
Mach-O structure, imports, signature-record presence, entropy, and embedded
payload signatures. Add repeatable `--trusted-project NAME` values for local
typosquatting references. Every malicious-package result is a heuristic review
indicator, not proof of malware.

When dependency inspection is enabled, the text report adds a dependency summary with the number of declared and inspected dependencies, the maximum traversal depth, and the highest-risk dependency recommendation observed in the set. `--with-deps` inspects only direct dependencies. `--with-transitive-deps` continues recursively through nested dependencies too.

## Emit machine-readable JSON

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

To emit combined JSON for every package in a requirements-style or TOML dependency file:

```bash
trustcheck scan -f requirements.txt --format json
```

## Write SARIF or an SBOM

```bash
trustcheck scan -f requirements.txt \
  --format sarif \
  --output-file reports/trustcheck.sarif

trustcheck scan -f pylock.toml \
  --format cyclonedx-json \
  --output-file reports/trustcheck.cdx.json
```

Other formats are `cyclonedx-xml`, `cyclonedx-1.7-json`,
`cyclonedx-1.7-xml`, `spdx-json`, `spdx-3-json`, `openvex`, and `markdown`.

To emit only the known vulnerability records in JSON:

```bash
trustcheck scan sampleproject --version 4.0.0 --format json
```

## Enforce a conservative gate

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

## What to look for

A strong result usually includes:

- verified provenance for all discovered release artifacts
- publisher identity details tied to a repository and workflow
- no high-severity risk flags
- no repository mismatch against your expected source

A weaker but still potentially acceptable result is `metadata-only`, which means `trustcheck` did not obtain a fully verified artifact set but also did not detect enough risk to escalate the release.

A `review-required` result can include packages that publish no provenance at all. That is weaker than a fully verified release, but it is intentionally distinct from stronger negative evidence such as failed verification or mismatched provenance.
