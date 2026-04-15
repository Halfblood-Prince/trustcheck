# CI integration

A common pattern is to run `trustcheck` before promotion, deployment, or dependency approval.

## Basic GitHub Actions example

```yaml
name: Verify dependency trust

on:
  workflow_dispatch:
  pull_request:

jobs:
  trustcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install trustcheck
        run: python -m pip install --upgrade pip trustcheck

      - name: Inspect release
        run: |
          trustcheck inspect sampleproject \
            --version 4.0.0 \
            --expected-repo https://github.com/pypa/sampleproject \
            --strict
```

## Inspect the dependency set in CI

Use `--with-deps` when you want the gate to consider direct runtime dependencies in addition to the top-level package release.

```yaml
- name: Inspect release and direct dependencies
  run: |
    trustcheck inspect sampleproject \
      --version 4.0.0 \
      --with-deps \
      --strict
```

Use `--with-transitive-deps` when you want to walk the full dependency tree recursively:

```yaml
- name: Inspect release and full dependency tree
  run: |
    trustcheck inspect sampleproject \
      --version 4.0.0 \
      --with-transitive-deps \
      --strict
```

This is useful when a package itself verifies cleanly, but one of its dependencies is missing provenance, has known vulnerabilities, or otherwise escalates the overall review outcome.

## Capture JSON output

```yaml
- name: Write JSON report
  run: |
    trustcheck inspect sampleproject \
      --version 4.0.0 \
      --with-deps \
      --format json > trustcheck-report.json
```

## Use a cache directory

```yaml
- name: Inspect with cache
  run: |
    trustcheck inspect sampleproject \
      --version 4.0.0 \
      --cache-dir .trustcheck-cache
```

## When to use strict mode

Use `--strict` when you want a blocking control for release promotion. Use the default mode when you want advisory output first and plan to tune policy after observing real package behavior.
