# CLI overview

Primary command:

```bash
trustcheck inspect <project>
```

Requirements file scan:

```bash
trustcheck scan <filename>
```

## Core flags

- `--version`: inspect a specific release instead of the latest project version
- `--expected-repo`: require repository evidence to match an expected GitHub or GitLab repository
- `--format text|json`: choose human-readable text or machine-readable JSON
- `--verbose`: include per-file provenance, digest, publisher, and note fields in text output
- `--cve`: show only the known vulnerability records reported for the selected release
- `--with-deps`: inspect direct runtime dependencies and summarize the highest-risk dependency
- `--with-transitive-deps`: inspect direct and transitive runtime dependencies recursively
- `--strict`: apply the built-in strict policy
- `--policy default|strict|internal-metadata`: evaluate a built-in policy profile
- `--policy-file PATH`: load policy settings from a JSON file
- `scan <filename>`: read a requirements-style file and run package inspection for each entry

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

Show only known vulnerability records:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cve
```

Run with strict policy:

```bash
trustcheck inspect sampleproject --version 4.0.0 --strict
```

Inspect the package and its direct dependency set:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-deps
```

Inspect the full transitive dependency tree:

```bash
trustcheck inspect sampleproject --version 4.0.0 --with-transitive-deps
```

Scan every package listed in a requirements-style file:

```bash
trustcheck scan requirements.txt
```

Scan a requirements-style file and emit JSON:

```bash
trustcheck scan requirements.txt --format json
```

When dependency inspection is enabled, `trustcheck` reads `requires_dist` metadata, resolves compatible dependency versions from PyPI, and adds a dependency summary to the report. `--with-deps` stops at the immediate dependencies of the inspected package. `--with-transitive-deps` continues recursively through nested dependencies. The top-level result can be escalated if an inspected dependency is `review-required` or `high-risk`.

When `scan` is used, `trustcheck` reads a requirements-style file, skips blank lines and comments, evaluates requirement markers for the current environment, and then inspects each listed package in sequence. Exact or compatible version specifiers are resolved to a concrete release before inspection when possible.

For top-level package analysis, a complete absence of published provenance is typically surfaced as `review-required`. Stronger negative evidence such as failed verification, inconsistent provenance, or known vulnerabilities still drives `high-risk` outcomes.

Use a custom policy file:

```bash
trustcheck inspect sampleproject --version 4.0.0 --policy-file ./policy.json
```

Use cached responses only:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cache-dir .trustcheck-cache --offline
```

When `--cve` is used, `trustcheck` still collects the same package metadata and evaluates policy settings, but the output is reduced to the vulnerability records only. In JSON mode, the output is a minimal object containing `project`, `version`, `package_url`, and `vulnerabilities`.
