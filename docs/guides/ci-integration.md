# TrustCheck Package Scanner

TrustCheck Package Scanner is the repository's first-class composite GitHub
Action. Callers do not need to install Python packages or invoke the CLI
themselves.

## Minimal dependency gate

This complete step is under ten lines and fails the job when strict policy
evaluation fails:

```yaml
steps:
  - uses: actions/checkout@v6
  - uses: Halfblood-Prince/trustcheck@v1
    with:
      target: requirements.txt
      policy: strict
      sandbox: auto
```

`actions/checkout` is required for file targets. It is optional when `target`
is only a PyPI package name.

The action always asks the CLI for JSON, writes the result to
`trustcheck-report.json`, uploads it as a workflow artifact, and then exits
with the original CLI exit code. A policy failure therefore still uploads its
report before failing the job.

Stable releases publish an immutable action ref such as `v1.10.0` and update
the compatible major ref `v1`. Use `@v1` for compatible updates or pin the full
release tag when immutable workflow dependencies are required.

## Supported targets

The `target` input accepts:

- a PyPI package name, such as `sampleproject`
- `requirements.txt` or another requirements-style `.txt` file
- `pyproject.toml`
- PEP 751 `pylock.toml` or a named `pylock.<name>.toml` file
- `Pipfile.lock`
- `uv.lock`
- `poetry.lock`
- `pdm.lock`

File targets use `trustcheck scan`. Package names use `trustcheck inspect`.

## Package repository verification

`expected-repo` applies to package targets:

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: sampleproject
    expected-repo: https://github.com/pypa/sampleproject
    policy: strict
```

A single expected repository is not meaningful for a multi-package dependency
file, so the action rejects `expected-repo` when `target` is a file.

## Dependencies, vulnerability intelligence, and artifacts

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: uv.lock
    policy: strict
    with-osv: "true"
    with-ecosystems: "true"
    with-kev: "true"
    with-epss: "true"
    with-transitive-deps: "true"
    inspect-artifacts: "true"
    trusted-projects: |
      internal-sdk
      internal-auth
```

`with-deps` and `with-transitive-deps` are mutually exclusive, matching the
CLI. Artifact inspection remains static and never imports inspected packages.

## Custom policy file

Pass a repository-relative JSON policy path:

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: pyproject.toml
    policy: .github/trustcheck-policy.json
```

The file uses the same schema as CLI `--policy-file`.

## Remediation pull requests

Plan a repair and upload the machine-readable patch bundle:

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: requirements.txt
    with-osv: "true"
    remediation: plan
    remediation-path: reports/remediation.json
```

Create a validated draft pull request:

```yaml
permissions:
  contents: write
  pull-requests: write

steps:
  - uses: actions/checkout@v6
    with:
      fetch-depth: 0
  - uses: Halfblood-Prince/trustcheck@v1
    with:
      target: uv.lock
      with-osv: "true"
      remediation: fix
      create-pr: "true"
      pr-base: main
```

The action never changes workflow permissions. PR mode requires the caller to
grant `contents: write` and `pull-requests: write`, and requires an
authenticated `gh` CLI. Draft is the default; set `pr-ready: "true"` to request
review immediately.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `target` | required | Package name or supported dependency file. |
| `policy` | `default` | `default`, `strict`, or a custom JSON policy path. |
| `expected-repo` | empty | Expected repository for a package target. |
| `trusted-publisher-organizations` | empty | Whitespace- or newline-separated `[provider:]organization` publisher allowlist entries. |
| `with-osv` | `false` | Query OSV and GitHub advisory data. |
| `osv-urls` | empty | Whitespace- or newline-separated custom OSV-compatible API base URLs. |
| `with-ecosystems` | `false` | Query the Ecosyste.ms OSV-compatible advisory service. |
| `with-kev` | `false` | Enrich CVEs with the CISA KEV catalog. |
| `with-epss` | `false` | Enrich CVEs with FIRST EPSS scores and percentiles. |
| `with-deps` | `false` | Inspect direct runtime dependencies. |
| `with-transitive-deps` | `false` | Inspect the complete runtime dependency tree. |
| `inspect-artifacts` | `false` | Statically inspect wheel and sdist contents. |
| `index-url` | empty | Primary PEP 503/691 Simple Repository index. |
| `extra-index-urls` | empty | Whitespace- or newline-separated additional indexes. |
| `keyring-provider` | `auto` | `auto`, `disabled`, `import`, or `subprocess`. |
| `allow-dependency-confusion` | `false` | Continue after reporting a cross-index project-name collision. |
| `trusted-projects` | empty | Whitespace- or newline-separated names added to the typosquatting reference set. |
| `max-workers` | `8` | Bound concurrent target, advisory, and network work from 1 through 64. |
| `sandbox` | `warn` | Resolver isolation: `off`, `warn`, `auto`, `container`, `bubblewrap`, or `strict`. |
| `advisory-snapshots` | empty | Whitespace- or newline-separated advisory snapshot paths. |
| `write-advisory-snapshot` | empty | Write a merged versioned advisory snapshot. |
| `resume-state` | empty | Checkpoint path for resumable dependency-file scans. |
| `enable-plugins` | `false` | Enable installed Trustcheck entry-point plugins. |
| `plugins` | empty | Whitespace- or newline-separated `[kind:]name` plugin allowlist. |
| `plugin-config` | empty | JSON configuration path keyed by plugin name. |
| `remediation` | `none` | `none`, `plan`, or `fix` for dependency-file targets. |
| `dry-run` | `false` | Regenerate and validate the exact patch without applying it. |
| `allow-constraint-changes` | `false` | Permit minimum required declared-range changes. |
| `source-manifest` | empty | Source requirements or `pyproject.toml` for a generated lock. |
| `remediation-path` | `trustcheck-remediation.json` | Machine-readable patch bundle path. |
| `max-fix-attempts` | `256` | Bound for minimal secure resolution attempts. |
| `create-pr` | `false` | Publish a validated fix through `git` and `gh`. |
| `pr-base` | empty | Pull request base branch. |
| `pr-branch` | generated | Pull request head branch. |
| `pr-title` | generated | Pull request title. |
| `pr-ready` | `false` | Create a ready PR instead of a draft. |
| `format` | `text` | `text`, `json`, `sarif`, `cyclonedx-json`, `cyclonedx-xml`, `spdx-json`, `openvex`, or `markdown`. |
| `report-path` | derived | Report location; the default extension follows `format`. |
| `artifact-name` | `trustcheck-report` | Uploaded workflow artifact name. |
| `python-version` | `3.12` | Python version used by the action. |

Private-index credentials can be supplied through URL user information,
`.netrc`, or the configured keyring provider. Reports redact URL passwords.
With multiple indexes, a normalized name found on more than one index fails
closed unless `allow-dependency-confusion` is explicitly enabled.

## Outputs

| Output | Description |
| --- | --- |
| `recommendation` | Overall recommendation such as `verified`, `review-required`, or `high-risk`. |
| `policy-passed` | `true` only when policy passes and the scan has no operational failures. |
| `report-path` | Absolute path to the generated report. |
| `remediation-status` | `not-requested`, `planned`, `validated`, `applied`, `pull-request-created`, `blocked`, or `failed`. |
| `applied-fixes` | Number of dependency upgrades in the remediation. |
| `patch-path` | Absolute path to the remediation bundle. |
| `pr-branch` | Created remediation branch. |
| `pr-url` | Created pull request URL. |

Use outputs in later workflow steps:

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  id: trustcheck
  with:
    target: requirements.txt

- run: echo "Recommendation is $RECOMMENDATION"
  env:
    RECOMMENDATION: ${{ steps.trustcheck.outputs.recommendation }}
```

## Custom report names

Use distinct artifact names when invoking the action more than once in a job:

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: poetry.lock
    report-path: reports/trustcheck-poetry.json
    artifact-name: trustcheck-poetry
```

## Upload SARIF to code scanning

The action always audits once. It derives SARIF from the same canonical JSON
result used for the recommendation and policy outputs.

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  id: trustcheck
  with:
    target: requirements.txt
    format: sarif

- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: ${{ steps.trustcheck.outputs.report-path }}
```

SARIF findings use stable fingerprints and point to the dependency manifest
and declaration line when available.

## CLI fallback

The CLI remains available for other CI systems:

```bash
trustcheck scan -f requirements.txt --policy strict --format json
```

GitHub users should prefer the action because it handles installation, report
upload, outputs, and exit-code propagation consistently.
