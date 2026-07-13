# Release Pull Request Checklist

Use this template for release-candidate pull requests and final release pull
requests.

## Baseline

- [ ] `docs/development/release-baseline.md` is updated with the current version, commit, test count, coverage, build result, docs result, skipped tests, and known blockers.
- [ ] Every open hardening milestone is represented in `docs/development/hardening-tracker.md` or a linked GitHub issue.
- [ ] Release-blocking work is labeled with `release-blocker`.

## Quality Gates

- [ ] `python -m pytest -q -rs`
- [ ] `python -m pytest --cov=trustcheck --cov-branch --cov-report=term -q`
- [ ] `ruff check .`
- [ ] `python -m mypy src`
- [ ] `python -m bandit -r src`
- [ ] `python -m build`
- [ ] `python -m mkdocs build --strict`
- [ ] Coverage is at or above the configured 98% gate, or the release is explicitly blocked.
- [ ] Skipped tests are listed with reasons and any live-test deferrals are intentional.

## Security And Compatibility

- [ ] Experimental features remain labeled in CLI help and documentation.
- [ ] Dynamic installation analysis is still opt-in and documented as experimental.
- [ ] Third-party Trustcheck plugins are still opt-in and documented as experimental until milestones 5 and 6 close.
- [ ] The AI installation gate is still documented as experimental until milestone 14 closes.
- [ ] No release artifact depends on an editable source checkout.
- [ ] Report schema, plugin protocol, and compatibility changes are documented.

## Artifacts

- [ ] Wheel and sdist are built from the reviewed commit.
- [ ] Built artifacts are smoke-tested in a clean environment.
- [ ] AI plugin archives, if included, are extracted and tested from clean directories.
- [ ] Marketplace manifests, privacy/security docs, and support links are present when publishing an AI plugin.
- [ ] Changelog and user-facing documentation describe observable behavior changes.
