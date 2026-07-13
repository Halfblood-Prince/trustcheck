# Release Baseline

Baseline date: 2026-07-13

This page records the release-engineering state before the hardening roadmap
continues beyond milestone 7. Re-run the commands below from the
repository root before tagging a release candidate.

## Snapshot

| Item | Baseline |
| --- | --- |
| Package version | `2.2.3.post1.dev1` |
| Git commit | `5a86629cfdf951017384cd9a6c38ca84ccffecb3` |
| Supported Python | `>=3.11`; classifiers cover Python 3.11, 3.12, 3.13, and 3.14 |
| Test count | 809 tests collected |
| Test result | 803 passed, 6 skipped, 518 subtests passed |
| Combined coverage | 97.77% with branch measurement enabled |
| Branch coverage | 94.99% |
| Coverage gate | Below the configured 98% threshold |
| Ruff | Passed |
| mypy | Passed for `src` in strict mode |
| Bandit | Passed for `src`; 23 findings intentionally skipped by local `nosec` annotations |
| Build | Passed; built `trustcheck-2.2.3.post1.dev1.tar.gz` and `trustcheck-2.2.3.post1.dev1-py3-none-any.whl` |
| Documentation | `mkdocs build --strict` passed; MkDocs Material emitted its upstream MkDocs 2.0 compatibility warning |

## Commands

```bash
git rev-parse HEAD
python -c "import trustcheck; print(trustcheck.__version__)"
python -m pytest --collect-only -q
python -m pytest -q -rs
python -m pytest --cov=trustcheck --cov-branch --cov-report=term --cov-report=json:.tmp-baseline-coverage.json -q
ruff check .
python -m mypy src
python -m bandit -r src
python -m build
python -m mkdocs build --strict
```

## Skipped Tests

All skipped tests are live PyPI integration tests in `tests/test_integration_live.py`.
They are intentionally skipped unless `TRUSTCHECK_RUN_LIVE=1` is set:

| Test location | Reason |
| --- | --- |
| `tests/test_integration_live.py:18` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |
| `tests/test_integration_live.py:41` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |
| `tests/test_integration_live.py:54` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |
| `tests/test_integration_live.py:65` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |
| `tests/test_integration_live.py:81` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |
| `tests/test_integration_live.py:91` | Set `TRUSTCHECK_RUN_LIVE=1` to run live PyPI integration tests |

## Known Release Blockers

| Scope | Blocker | Required milestone |
| --- | --- | --- |
| Main package | Coverage is below the configured 98% gate. | Milestone 4 |
| Main package | CI and release workflow hardening is not complete. | Milestone 8 |
| Main package | Packaging and source-distribution hygiene review is not complete; the baseline build output showed generated test cache/tmp paths when present. | Milestone 9 |
| Main package | Final release validation is not complete. | Milestone 14 |
| AI installation gate | Marketplace-ready adapter coverage and artifact tests are still open. | Milestone 4 |
| AI installation gate | Marketplace packaging and reviewer documentation are still open. | Milestone 11 |
| Third-party plugins | Safe plugin IPC and installed-code identity binding are implemented; final release validation remains open. | Milestone 14 |

## Re-run Notes

The coverage command writes `.tmp-baseline-coverage.json`; it is a temporary
local artifact and does not need to be committed. Build outputs in `build/` and
`dist/` should be treated as generated artifacts unless a release process
explicitly stages them.
