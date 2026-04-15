# CLI overview

Primary command:

```bash
trustcheck inspect <project>
```

## Core flags

- `--version`: inspect a specific release instead of the latest project version
- `--expected-repo`: require repository evidence to match an expected GitHub or GitLab repository
- `--format text|json`: choose human-readable text or machine-readable JSON
- `--verbose`: include per-file provenance, digest, publisher, and note fields in text output
- `--with-deps`: recursively inspect declared runtime dependencies and summarize the highest-risk dependency
- `--strict`: apply the built-in strict policy
- `--policy default|strict|internal-metadata`: evaluate a built-in policy profile
- `--policy-file PATH`: load policy settings from a JSON file

## Policy override flags

- `--require-verified-provenance none|all`
- `--allow-metadata-only`
- `--disallow-metadata-only`
- `--require-expected-repo-match`
- `--fail-on-vulnerability ignore|any`
- `--fail-on-risk-severity none|medium|high`

## Network and diagnostics flags

- `--config-file PATH`: load network settings from a JSON config file
- `--timeout FLOAT`: set request timeout in seconds
- `--retries INT`: set transient retry count
- `--backoff FLOAT`: set retry backoff factor
- `--cache-dir PATH`: persist cached PyPI responses for repeated runs
- `--offline`: use cached responses only
- `--debug`: emit structured debug logs and print tracebacks for operational failures
- `--log-format text|json`: choose debug log format for `--debug`

## Examples

Inspect a package:

```bash
trustcheck inspect requests
```

Run with strict policy:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

Inspect the package and its dependency set:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

When `--with-deps` is enabled, `trustcheck` reads `requires_dist` metadata, resolves compatible dependency versions from PyPI, recursively inspects those releases, and adds a dependency summary to the report. The top-level result can be escalated if an inspected dependency is `review-required` or `high-risk`.

Use a custom policy file:

```bash
trustcheck inspect sampleproject --version 4.0.0 --policy-file ./policy.json
```

Use cached responses only:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cache-dir .trustcheck-cache --offline
```
