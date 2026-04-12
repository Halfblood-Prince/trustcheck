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
- GitHub Release creation with generated notes
- release artifact checksum generation
- SBOM generation for release artifacts
- PyPI Trusted Publishing with artifact attestations
- opt-in live integration tests against real PyPI packages
- contract snapshot tests that detect accidental JSON-schema drift
