# CLI overview

Primary command:

```bash
trustcheck inspect <project>
```

Package vulnerability scan:

```bash
trustcheck scan <project>
```

Dependency-file inspection or vulnerability scan:

```bash
trustcheck inspect -f <filename>
trustcheck scan -f <filename>
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
- `--format FORMAT`: choose `text`, `json`, `sarif`, `cyclonedx-json`,
  `cyclonedx-xml`, `spdx-json`, `openvex`, or `markdown`
- `--output-file PATH`: write the rendered report to a file and suppress stdout
- `--verbose`: include per-file provenance, digest, publisher, and note fields in text output
- `--with-osv`: query the public OSV API
- `--osv-url URL`: query an additional OSV-compatible API; repeatable
- `--with-ecosystems`: query the Ecosyste.ms OSV-compatible API
- `--with-kev`: enrich CVEs from the CISA Known Exploited Vulnerabilities catalog
- `--with-epss`: enrich CVEs with FIRST EPSS probability and percentile scores
- `--with-deps`: inspect direct runtime dependencies and summarize the highest-risk dependency
- `--with-transitive-deps`: inspect direct and transitive runtime dependencies recursively
- `--inspect-artifacts`: statically inspect downloaded wheels and sdists
- `--dynamic-analysis`: execute downloaded artifacts in a disposable Docker
  container with no network, a non-root user, and strict CPU/RAM/time limits
- `scan --fast`: resolve dependencies and query advisories only (default)
- `scan --standard`: add provenance for artifacts in the selected scope
- `scan --full`: add static, native-binary, release-history, and heuristic analysis
- `scan --artifact-scope target|sdist|all`: inspect the best target-compatible
  install artifact (default), source distributions, or the complete release
- `--trusted-project NAME`: add a project to the typosquatting reference set;
  repeatable
- `--strict`: apply the built-in strict policy
- `--policy default|strict|internal-metadata`: evaluate a built-in policy profile
- `--policy-file PATH`: load policy settings from a JSON file
- `--trusted-publisher-organization [PROVIDER:]ORGANIZATION`: require verified
  publishers to belong to an approved organization; repeatable
- `inspect -f <filename>`: inspect every package in a requirements, project TOML, or supported lockfile without vulnerability checks
- `scan -f <filename>`: scan every package in a requirements, project TOML, or supported lockfile using the selected scan profile
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
- `--trusted-publisher-organization [PROVIDER:]ORGANIZATION`
- `--fail-on-vulnerability ignore|any|critical|kev|fixable`
- `--fail-on-risk-severity none|medium|high`

## Network and diagnostics flags

- `--config-file PATH`: load JSON, standalone TOML, or `[tool.trustcheck]`
  settings from `pyproject.toml`
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
trustcheck scan sampleproject --version 4.0.0 --fast
```

Add selected-artifact provenance without deep archive inspection:

```bash
trustcheck scan -f requirements.txt --standard
```

Run full analysis on the target-compatible install artifact:

```bash
trustcheck scan sampleproject --version 4.0.0 --full --workers 8
```

Review the complete release under strict policy:

```bash
trustcheck scan sampleproject --full --artifact-scope all --strict
```

Query OSV in addition to PyPI and show source, severity, fixes, and advisory links:

```bash
trustcheck scan jinja2 --version 2.10.0 --with-osv
```

Query all built-in advisory providers and enrich CVE aliases:

```bash
trustcheck scan jinja2 \
  --version 2.10.0 \
  --with-osv \
  --with-ecosystems \
  --with-kev \
  --with-epss
```

The OSV-compatible providers run concurrently and merge deterministically with
PyPI records. A provider or enrichment failure is an operational failure rather
than silently returning partial intelligence.

The config file can enable the same services and override enrichment endpoints:

```json
{
  "advisories": {
    "osv": true,
    "osv_urls": ["https://advisories.example.com"],
    "ecosystems": true,
    "kev": true,
    "kev_url": "https://www.cisa.gov/example/known_exploited.json",
    "epss": true,
    "epss_url": "https://api.first.org/data/v1/epss"
  }
}
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
trustcheck scan -f requirements.txt
```

Requirements scans are resolved as complete environments with pip's
installation-report interface. Nested `-r` requirements, nested `-c`
constraints, hashes, extras, editable requirements, direct URLs, and VCS
requirements use pip's own parsing and resolution behavior.

Apply an additional constraints file and resolve for a target:

```bash
trustcheck scan -f requirements.txt \
  --constraint constraints.txt \
  --python-version 3.12 \
  --platform manylinux_2_28_x86_64 \
  --implementation cp \
  --abi cp312
```

Cross-target resolution uses wheels only because pip cannot safely build source
distributions for a foreign interpreter or platform.

Pip can invoke build-backend metadata hooks while resolving source, editable,
local, or VCS requirements, including with `--dry-run`. Select an enforced
resolver policy for untrusted inputs:

```bash
trustcheck scan -f requirements.txt --sandbox auto
```

| Mode | Behavior |
| --- | --- |
| `warn` | Explicit compatibility mode. Run the host pip resolver and warn that metadata hooks may execute. |
| `off` | Run the host pip resolver without a warning. |
| `auto` | Default. Prefer Bubblewrap on Linux, then Docker/Podman; fall back to `strict`. |
| `container` | Run as UID/GID 65534 in a read-only Docker/Podman container with no capabilities, `no-new-privileges`, bounded PIDs, a temporary cache, and only staged resolver inputs mounted read-only. |
| `bubblewrap` | On Linux, unshare user, mount, IPC, UTS, cgroup, and PID namespaces; clear the environment; expose system paths and staged resolver inputs read-only. |
| `strict` | Reject editable, VCS, source-archive, local non-wheel, and direct non-wheel inputs; use isolated pip configuration, require wheels, and deny child-process creation so unexpected transitive source hooks fail closed. |

Container and Bubblewrap keep network access because dependency resolution must
reach configured indexes. They stage only requirement and constraint files,
dependency-group TOML, nested includes, and referenced local dependencies; the
project workspace, user home, and host pip cache are not mounted.
`strict` does not execute source metadata hooks; a source-only dependency fails
resolution unless the configured index provides a target-compatible wheel.
External keyring helpers are also unavailable in strict mode; use index URL
credentials or an authenticated index endpoint.

The container backend defaults to
`python:3.13-slim@sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f`.
Override it with `--sandbox-image IMAGE@sha256:DIGEST`; mutable tags are rejected.

Scan dependencies declared in a TOML project file:

```bash
trustcheck scan -f pyproject.toml
```

Plan secure dependency changes without invoking writers:

```bash
trustcheck scan -f requirements.txt \
  --with-osv \
  --plan-fixes \
  --remediation-output reports/remediation.json
```

Regenerate and validate the exact patch in an isolated project mirror:

```bash
trustcheck scan -f pyproject.toml --with-osv --fix --dry-run
```

Apply the validated bytes transactionally:

```bash
trustcheck scan -f uv.lock --with-osv --fix
```

`--allow-constraint-changes` permits only the minimum range change needed when
all secure releases are excluded. `--source-manifest` identifies the roots for
a generated lockfile. `--max-fix-attempts` bounds branch-and-bound resolution;
Trustcheck refuses application when the search cannot prove minimality.

`--create-pr` publishes the validated patch through fixed-argument `git` and
`gh` commands from a temporary worktree. Use `--pr-base`, `--pr-branch`,
`--pr-title`, and `--pr-ready` to control the pull request. Draft is the
default. See [Safe remediation](../reference/remediation.md).

Select only particular extras and dependency groups:

```bash
trustcheck scan -f pyproject.toml --extra security --group test
```

Without `--extra` or `--group`, all statically declared extras and groups are
included for backward compatibility. Standard dependency-group
`include-group` entries are expanded with cycle detection.

Scan or inspect a standard PEP 751 lockfile or another supported lock:

```bash
trustcheck inspect -f pylock.toml --with-transitive-deps
trustcheck scan -f Pipfile.lock
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
trustcheck scan -f requirements.txt \
  --index-url https://username@packages.example.com/simple \
  --keyring-provider subprocess
```

The `import` provider requires `pip install "trustcheck[keyring]"`. `auto`
tries the installed Python keyring and then the keyring CLI when available;
select `disabled`, `import`, or `subprocess` for deterministic behavior.

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
trustcheck scan -f requirements.txt --format json
```

Emit SARIF with stable fingerprints and dependency-manifest locations:

```bash
trustcheck scan -f requirements.txt \
  --format sarif \
  --output-file reports/trustcheck.sarif
```

Emit SBOM, VEX, or Markdown documents:

```bash
trustcheck scan -f pylock.toml --format cyclonedx-json \
  --output-file reports/trustcheck.cdx.json
trustcheck environment --format cyclonedx-xml \
  --output-file reports/environment.cdx.xml
trustcheck scan -f requirements.txt --format spdx-json \
  --output-file reports/trustcheck.spdx.json
trustcheck scan -f requirements.txt --format openvex \
  --output-file reports/trustcheck.openvex.json
trustcheck scan -f requirements.txt --format markdown \
  --output-file reports/trustcheck.md
```

See [Industry output formats](../reference/industry-formats.md) for versioned
standards, field mappings, and CI guidance.

Inspect artifact contents for a package:

```bash
trustcheck inspect sampleproject --version 4.0.0 --inspect-artifacts --verbose
```

`--inspect-artifacts` never imports or executes package code. For wheels it
validates every non-`RECORD` file against its secure `RECORD` hash and size,
lists console scripts, parses bounded Python source with `ast`, and reports
unexpected top-level files. For sdists it gives install and build-hook source
extra weight. PE, ELF, and Mach-O files are inspected for imports,
architecture, signature-record presence, entropy, and embedded payload
signatures. When combined with dependency inspection, the same static checks
are applied to inspected dependency artifacts.

`--dynamic-analysis` is the explicit exception: it executes the downloaded
artifact inside a disposable Docker container using `--network none`, a
non-root user, a read-only root filesystem, dropped capabilities, and bounded
CPU, memory, process, and wall-clock limits. It defaults to
`python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf`
and rejects mutable image tags. It is never enabled by default.

Typosquatting, dependency-confusion, ownership, repository, and release-cadence
heuristics run without `--inspect-artifacts`. Add local reference names with
repeatable `--trusted-project NAME`. Findings and scores are explicitly
heuristic indicators for review, not proof of malware.

When dependency inspection is enabled, `trustcheck` resolves the complete set
with pip first and uses the resulting exact version map while traversing
`requires_dist` metadata. `--with-deps` stops at immediate dependencies.
`--with-transitive-deps` continues recursively. The top-level result can be
escalated if an inspected dependency is `review-required` or `high-risk`.

When `-f` is used, `trustcheck` reads a requirements-style file, TOML project
file, or supported lockfile. `inspect -f` collects trust evidence without
vulnerability checks; `scan -f` checks only vulnerability records.
Requirements inputs are delegated to pip so their complete resolved set is
audited. TOML project files support
`[project.dependencies]`, optional dependencies, standard
`[dependency-groups]`, Poetry dependencies, and Poetry groups. Lockfile scans
support PEP 751 `pylock.toml`, `Pipfile.lock`, `uv.lock`, `poetry.lock`, and
`pdm.lock`; pip-tools hashes are retained from requirements files. Exact
resolved versions, index origins, artifact candidates, and hashes are retained
in machine-readable output.

Package releases and the machine-readable report schema are versioned
independently. Deep provenance analysis and malicious-package calibration are
represented in report schema `1.11.0`.

For top-level package analysis, a complete absence of published provenance is typically surfaced as `review-required`. Stronger negative evidence such as failed verification, inconsistent provenance, or known vulnerabilities still drives `high-risk` outcomes.

Use a custom policy file:

```bash
trustcheck inspect sampleproject --version 4.0.0 --policy-file ./policy.json
```

Use cached responses only:

```bash
trustcheck inspect sampleproject --version 4.0.0 --cache-dir .trustcheck-cache --offline
```

When `scan` is used without `-f`, `trustcheck` scans the named PyPI package for
vulnerabilities only. In JSON mode, the output is a minimal object containing
`project`, `version`, `package_url`, and `vulnerabilities`. Advisory providers
query the exact selected package version. Records sharing a CVE or another
alias are merged across providers.
