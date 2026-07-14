# Release Pull Request Checklist

Use this template for release-candidate pull requests and final release pull
requests.

## Release Inputs

- [ ] Current version, commit, test count, coverage, build result, docs result, skipped tests, and known blockers are recorded in the release pull request.
- [ ] Release-blocking work is linked in GitHub issues or pull request tasks.
- [ ] Release-blocking work is labeled with `release-blocker`.

## Quality Gates

- [ ] `python -m pytest -q -rs`
- [ ] `python -m pytest --cov=trustcheck --cov-branch --cov-report=term -q`
- [ ] `ruff check .`
- [ ] `python -m mypy src`
- [ ] `python -m bandit -r src scripts`
- [ ] `python -m build`
- [ ] `python scripts/validate_distribution_artifacts.py "dist/*.whl" "dist/*.tar.gz"`
- [ ] `python -m twine check dist/*`
- [ ] `check-wheel-contents dist/*.whl`
- [ ] `python -m mkdocs build --strict`
- [ ] Mutation and fuzz/property thresholds are green for the configured release groups.
- [ ] Coverage is at or above the configured 98% gate, or the release is explicitly blocked.
- [ ] Skipped tests are listed with reasons and any live-test deferrals are intentional.

## Security And Compatibility

- [ ] Experimental features remain labeled in CLI help and documentation.
- [ ] Dynamic installation analysis is still opt-in and documented as experimental.
- [ ] Third-party Trustcheck plugins are still opt-in and documented as experimental.
- [ ] No release artifact depends on an editable source checkout.
- [ ] Report schema, plugin protocol, and compatibility changes are documented.
- [ ] GitHub Action artifact compatibility is reviewed; JSON artifact consumers can migrate with `format: json` or an explicit JSON `report-path`.

## Artifacts

- [ ] Wheel and sdist are built from the reviewed commit.
- [ ] Wheel and sdist contents are validated for bytecode, caches, temporary files, local reports, secrets, unexpected binaries, and accidental plugin bundles.
- [ ] Built artifacts are smoke-tested in a clean environment.
- [ ] Wheel, sdist, pipx, Homebrew, standalone executable, container, Snap, Winget, and GitHub Action clean-install evidence is attached or linked.
- [ ] Adversarial core-package results are attached or linked, including malformed archives, archive bombs, invalid wheel `RECORD`, malicious plugin return object, modified signed plugin files, resolver timeout, subprocess spawning, and suspicious metadata.
- [ ] Changelog and user-facing documentation describe observable behavior changes.

## Release Operations

- [ ] Post-release monitoring owner and review window are recorded.
- [ ] Rollback criteria are reviewed for PyPI, GitHub release assets, Snap, container, Homebrew, Winget, and GitHub Action channels.
- [ ] Release-channel parity must use the exact tag and SHA, not latest release or default branch.
