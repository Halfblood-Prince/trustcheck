# CLI overview

Primary command:

```bash
trustcheck inspect <project>
```

Requirements file scan:

```bash
trustcheck scan <filename>
```

Installed environment scan:

```bash
trustcheck environment --path .venv/lib/python3.12/site-packages
```

Show the installed package and report schema versions:

```bash
trustcheck --version
```

## Core flags

- `--version`: inspect a specific release instead of the latest project version
- `--expected-repo`: require repository evidence to match an expected GitHub or GitLab repository
- `--format text|json`: choose human-readable text or machine-readable JSON
- `--verbose`: include per-file provenance, digest, publisher, and note fields in text output
- `--cve`: show only the known vulnerability records reported for the selected release
- `--with-osv`: enrich PyPI vulnerability records with OSV and GitHub Advisory Database data
- `--with-deps`: inspect direct runtime dependencies and summarize the highest-risk dependency
- `--with-transitive-deps`: inspect direct and transitive runtime dependencies recursively
- `--inspect-artifacts`: statically inspect downloaded wheels and sdists
- `--strict`: apply the built-in strict policy
- `--policy default|strict|internal-metadata`: evaluate a built-in policy profile
- `--policy-file PATH`: load policy settings from a JSON file
- `scan <filename>`: read a requirements, project TOML, or supported lockfile and inspect each entry
- `environment`: inspect exact distributions installed in the active
  interpreter, or in repeatable `--path` locations

## Resolver flags

- `--constraint FILE`: apply a pip constraints file; repeatable
- `--extra NAME`: select a project optional-dependency extra; repeatable
- `--group NAME`: select a standard or Poetry dependency group; repeatable
- `--python-version VERSION`: resolve for a target Python version
- `--platform TAG`: resolve for a target wheel platform; repeatable
- `--implementation TAG`: resolve for an interpreter implementation such as `cp`
- `--abi TAG`: resolve for a target wheel ABI; repeatable

## Package index flags

- `--index-url URL`: primary PEP 503/691 Simple Repository index
- `--extra-index-url URL`: additional index; repeatable
- `--keyring-provider auto|disabled|import|subprocess`: pip-compatible
  credential provider
- `--allow-dependency-confusion`: continue after a cross-index name collision
  that has been independently reviewed

`--extra-index-url` is secure by default: `trustcheck` checks every resolved
name independently on each configured index and stops when public and private
indexes both provide the name. Index credentials are redacted from errors and
JSON output.

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

Query OSV in addition to PyPI and show source, severity, fixes, and advisory links:

```bash
trustcheck inspect jinja2 --version 2.10.0 --with-osv --cve
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

Requirements scans are resolved as complete environments with pip's
installation-report interface. Nested `-r` requirements, nested `-c`
constraints, hashes, extras, editable requirements, direct URLs, and VCS
requirements use pip's own parsing and resolution behavior.

Apply an additional constraints file and resolve for a target:

```bash
trustcheck scan requirements.txt \
  --constraint constraints.txt \
  --python-version 3.12 \
  --platform manylinux_2_28_x86_64 \
  --implementation cp \
  --abi cp312
```

Cross-target resolution uses wheels only because pip cannot safely build source
distributions for a foreign interpreter or platform.

!!! warning

    Pip can invoke build-backend metadata hooks while resolving source,
    editable, local, or VCS requirements, including with `--dry-run`. Treat
    resolver inputs with the same caution as installation inputs and use an
    external sandbox for untrusted source projects.

Scan dependencies declared in a TOML project file:

```bash
trustcheck scan pyproject.toml
```

Select only particular extras and dependency groups:

```bash
trustcheck scan pyproject.toml --extra security --group test
```

Without `--extra` or `--group`, all statically declared extras and groups are
included for backward compatibility. Standard dependency-group
`include-group` entries are expanded with cycle detection.

Scan a standard PEP 751 lockfile or another supported lock:

```bash
trustcheck scan pylock.toml --with-transitive-deps
trustcheck scan Pipfile.lock
```

Supported lock inputs are `pylock.toml`, named `pylock.<name>.toml` files,
`Pipfile.lock`, `uv.lock`, `poetry.lock`, and `pdm.lock`. Hash-pinned pip-tools
requirements files are recognized automatically, including nested `-r`
includes.

PEP 751 `requires-python`, `environments`, package markers, extras, default
groups, selected `--extra`/`--group` values, index origins, archives, sdists,
wheels, directories, and immutable VCS revisions are validated. A versionless
source-tree entry is reported as unsupported instead of being silently
reinterpreted as a public-index package.

Every artifact hash retained from a lockfile is verified against downloaded
bytes, independently of provenance and `--inspect-artifacts`. A mismatch or
unsupported algorithm produces a high-severity `lockfile_hash_mismatch`.

Resolve through a private index with keyring authentication:

```bash
trustcheck scan requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --keyring-provider subprocess
```

The `import` provider requires `pip install "trustcheck[keyring]"`. As with
pip, `auto` does not query keyring while non-interactive resolution uses
`--no-input`; select `import` or `subprocess` explicitly when required.

Audit installed distributions:

```bash
trustcheck environment
trustcheck environment --path .venv/lib/python3.12/site-packages
```

Installed scans use `importlib.metadata` and retain exact installed versions.
PEP 610 `direct_url.json` metadata is recorded for editable, local, and VCS
installations in combined JSON output.

Scan a requirements-style file and emit JSON:

```bash
trustcheck scan requirements.txt --format json
```

Inspect artifact contents for a package:

```bash
trustcheck inspect sampleproject --version 4.0.0 --inspect-artifacts --verbose
```

`--inspect-artifacts` never imports or executes package code. For wheels it
validates every non-`RECORD` file against its secure `RECORD` hash and size,
lists console scripts, detects native extensions, and reports unexpected
top-level files. For sdists it reports suspicious scripts, oversized or unusual
files, and metadata differences. When combined with dependency inspection, the
same static checks are applied to inspected dependency artifacts.

When dependency inspection is enabled, `trustcheck` resolves the complete set
with pip first and uses the resulting exact version map while traversing
`requires_dist` metadata. `--with-deps` stops at immediate dependencies.
`--with-transitive-deps` continues recursively. The top-level result can be
escalated if an inspected dependency is `review-required` or `high-risk`.

When `scan` is used, `trustcheck` reads a requirements-style file, TOML project
file, or supported lockfile. Requirements inputs are delegated to pip so their
complete resolved set is audited. TOML project files support
`[project.dependencies]`, optional dependencies, standard
`[dependency-groups]`, Poetry dependencies, and Poetry groups. Lockfile scans
support PEP 751 `pylock.toml`, `Pipfile.lock`, `uv.lock`, `poetry.lock`, and
`pdm.lock`; pip-tools hashes are retained from requirements files. Exact
resolved versions, index origins, artifact candidates, and hashes are retained
for both direct and transitive inspection.

Package releases and the machine-readable report schema are versioned
independently. Artifact inspection is represented in report schema `1.5.0`.

For top-level package analysis, a complete absence of published provenance is typically surfaced as `review-required`. Stronger negative evidence such as failed verification, inconsistent provenance, or known vulnerabilities still drives `high-risk` outcomes.

Use a custom policy file:

```bash
trustcheck inspect sampleproject --version 4.0.0 --policy-file ./policy.json
```

Use cached responses only:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cache-dir .trustcheck-cache --offline
```

When `--cve` is used, `trustcheck` still collects the same package metadata and evaluates policy settings, but the output is reduced to the vulnerability records only. In JSON mode, the output is a minimal object containing `project`, `version`, `package_url`, and `vulnerabilities`. `--with-osv` is opt-in and queries the exact selected package version. Records sharing a CVE or other advisory alias are merged across PyPI and OSV.
