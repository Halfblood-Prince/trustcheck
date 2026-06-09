# Development and release process

## Local development

Run the local test suite:

```bash
python -m pytest -q tests
```

Run tests with coverage:

```bash
python -m pytest --cov=trustcheck --cov-report=term-missing tests
```

Run lint:

```bash
ruff check src tests
```

Run type checks:

```bash
mypy src
```

Live integration tests are excluded from the default test run and can be enabled with:

```bash
TRUSTCHECK_RUN_LIVE=1 python -m pytest -q tests/test_integration_live.py
```

## Release and quality controls

The repository includes:

- CI for lint, type checks, cross-platform test matrices, coverage enforcement, and build smoke tests
- dependency auditing and secret scanning in CI
- CodeQL analysis for the Python codebase
- release publishing from immutable tagged commits
- annotated tag enforcement for releases
- stable `vMAJOR.MINOR.PATCH` release-tag validation
- automatic publication of the moving GitHub Action major tag, such as `v1`
- GitHub Release creation with generated notes
- strict Snapcraft packaging with build, lint, install, and CLI smoke tests
- parallel PyPI, GitHub Action, and Snap Store publication after release QA
- release artifact checksum generation
- SBOM generation for release artifacts
- PyPI Trusted Publishing with artifact attestations
- opt-in live integration tests against real PyPI packages
- contract snapshot tests that detect accidental JSON-schema drift

Release runs are triggered by pushing an annotated `vMAJOR.MINOR.PATCH` tag.
The workflow trigger accepts stable version-shaped tags, then validates the
annotated tag object and exact semantic-version shape before publishing.

GitHub Release creation and moving action-tag updates use the repository secret
`RELEASE_TOKEN` when present, falling back to `GITHUB_TOKEN`. Configure
`RELEASE_TOKEN` as a fine-grained personal access token with repository
Contents read/write permission when repository or organization policy blocks
release creation by the built-in Actions integration.

PyPI Trusted Publishing, GitHub Marketplace activation, Snap Store name
registration, and scoped Snap Store credentials require one-time repository
or account configuration. See the
[release publishing guide](release-publishing.md) for the exact setup and the
parts that GitHub requires to be completed in its web interface.
