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

## Dependencies, OSV, and artifacts

```yaml
- uses: Halfblood-Prince/trustcheck@v1
  with:
    target: uv.lock
    policy: strict
    with-osv: "true"
    with-transitive-deps: "true"
    inspect-artifacts: "true"
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

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `target` | required | Package name or supported dependency file. |
| `policy` | `default` | `default`, `strict`, or a custom JSON policy path. |
| `expected-repo` | empty | Expected repository for a package target. |
| `with-osv` | `false` | Query OSV and GitHub advisory data. |
| `with-deps` | `false` | Inspect direct runtime dependencies. |
| `with-transitive-deps` | `false` | Inspect the complete runtime dependency tree. |
| `inspect-artifacts` | `false` | Statically inspect wheel and sdist contents. |
| `format` | `text` | Action log format: `text` or `json`. SARIF is reserved for a later release. |
| `report-path` | `trustcheck-report.json` | JSON report location in the caller workspace. |
| `artifact-name` | `trustcheck-report` | Uploaded workflow artifact name. |
| `python-version` | `3.12` | Python version used by the action. |

## Outputs

| Output | Description |
| --- | --- |
| `recommendation` | Overall recommendation such as `verified`, `review-required`, or `high-risk`. |
| `policy-passed` | `true` only when policy passes and the scan has no operational failures. |
| `report-path` | Absolute path to the generated JSON report. |

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

## CLI fallback

The CLI remains available for other CI systems:

```bash
trustcheck scan requirements.txt --policy strict --format json
```

GitHub users should prefer the action because it handles installation, report
upload, outputs, and exit-code propagation consistently.
