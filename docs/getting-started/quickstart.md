# Quickstart

## Inspect the latest release

```bash
trustcheck inspect requests
```

## Inspect a specific version

```bash
trustcheck inspect sampleproject --version 4.0.0
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

## Inspect declared dependencies too

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

When dependency inspection is enabled, the text report adds a dependency summary with the number of declared and inspected dependencies, the maximum traversal depth, and the highest-risk dependency recommendation observed in the set.

## Emit machine-readable JSON

```bash
trustcheck inspect sampleproject --version 4.0.0 --format json
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
