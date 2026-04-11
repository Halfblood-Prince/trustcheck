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

## Capture JSON output

```yaml
- name: Write JSON report
  run: |
    trustcheck inspect sampleproject \
      --version 4.0.0 \
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
