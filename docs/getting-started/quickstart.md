# Quickstart

## Run as a GitHub Action

```yaml
steps:
  - uses: actions/checkout@v6
  - uses: Halfblood-Prince/trustcheck@v1
    with:
      target: requirements.txt
      policy: strict
```

This produces and uploads `trustcheck-report.json`. The action fails when the
configured policy fails.

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
trustcheck inspect sampleproject --version 4.0.0 --cve
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
trustcheck scan requirements.txt
```

Pip resolves the complete dependency set before trustcheck audits it. Nested
requirements, constraints, hashes, editable installs, and VCS references are
supported.

```bash
trustcheck scan requirements.txt --constraint constraints.txt
```

## Scan a TOML dependency file

```bash
trustcheck scan pyproject.toml
```

Select extras and dependency groups:

```bash
trustcheck scan pyproject.toml --extra security --group test
```

## Scan a supported lockfile

```bash
trustcheck scan uv.lock --with-transitive-deps
```

Supported lockfiles are PEP 751 `pylock.toml` and named `pylock.<name>.toml`
files, `Pipfile.lock`, `uv.lock`, `poetry.lock`, and `pdm.lock`. Exact locked
versions, source indexes, artifact URLs, sizes, and hashes are retained during
inspection. Hash-pinned pip-tools output is recognized as a requirements input.

## Scan a private index

```bash
trustcheck scan requirements.txt \
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
extracting them, importing modules, or executing package code. Wheel inspection
validates `RECORD`, lists console scripts, and detects native extensions and
unexpected top-level files. Sdist inspection reports suspicious scripts,
oversized or unusual files, and metadata differences.

When dependency inspection is enabled, the text report adds a dependency summary with the number of declared and inspected dependencies, the maximum traversal depth, and the highest-risk dependency recommendation observed in the set. `--with-deps` inspects only direct dependencies. `--with-transitive-deps` continues recursively through nested dependencies too.

## Emit machine-readable JSON

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
```

To emit combined JSON for every package in a requirements-style or TOML dependency file:

```bash
trustcheck scan requirements.txt --format json
```

To emit only the known vulnerability records in JSON:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cve --format json
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
