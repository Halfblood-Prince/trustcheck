# Safe remediation

Trustcheck remediation is an extension of `scan`; package inspection and
installed-environment auditing remain read-only.

## Modes

```bash
trustcheck scan -f requirements.txt --with-osv --plan-fixes
trustcheck scan -f requirements.txt --with-osv --fix --dry-run
trustcheck scan -f requirements.txt --with-osv --fix
```

`--plan-fixes` resolves and rescans candidates but does not invoke lockfile
writers. `--fix --dry-run` runs writers, installs the result in a clean virtual
environment, runs configured validation commands, and emits the exact validated
patch without modifying dependency files. `--fix` performs the same validation,
checks the original SHA-256 digests again, uses same-directory staged files and
atomic replacement, and rolls back a partial write.

All active, non-withdrawn, non-suppressed advisories with known fixes and all
packages failing the selected Trustcheck policy are targeted. Editable, local,
direct-archive, and VCS dependencies are immutable because selecting a source
revision requires human review.

## Minimality and acceptance

The solver minimizes changed packages first, direct manifest edits second, and
secure versions third. Unchanged packages are pinned and relaxed in increasing
set size. `--max-fix-attempts` defaults to `256`; a search-limited candidate is
reported but never applied.

Every generated result must:

- reproduce the proven complete resolution
- remove every targeted advisory
- introduce no active vulnerability or policy violation
- preserve package index origins
- preserve and verify artifact hashes
- pass a second exact-version Trustcheck scan
- install the exact resolved graph in a clean virtual environment
- pass `pip check`
- pass every configured `[tool.trustcheck.fix]` command

Declared ranges are never widened silently. Exact pins can be upgraded;
otherwise an excluded secure release requires
`--allow-constraint-changes`.

Validation commands are optional and run from the staged project copy with the
clean virtual environment first on `PATH`. Commands are parsed without a shell;
`python` and `pip` are redirected to the clean environment.

```toml
[tool.trustcheck.fix]
test_commands = [
  "pytest -q",
  "python -m compileall src",
  "python -m mypy src",
]
```

## Writers

Requirements, `requirements.lock`, nested includes, constraints, PEP 621,
Poetry, PDM, and PEP 751 files use syntax-aware edits. TOML comments,
ordering, and unknown tool tables are retained.

Hash-pinned pip-tools output requires `pip-compile`. `uv.lock`,
`poetry.lock`, and `pdm.lock` require their respective installed commands.
Trustcheck never installs these tools automatically and never hand-edits their
implementation-specific lock formats.

Use `--source-manifest` when a lockfile does not unambiguously identify its
root requirements.

## Patch bundles

```bash
trustcheck scan -f pylock.toml \
  --source-manifest pyproject.toml \
  --fix --dry-run \
  --remediation-output reports/remediation.json
```

Patch bundles use schema `urn:trustcheck:remediation:1.3.0`. They contain
before/after dependency graphs, file digests, unified diffs, structured edits,
advisory IDs removed, lockfile hash validation, reproduction commands,
post-fix graph and report digests, clean-install and command results,
minimality evidence, validation results, and PR metadata.

Successful `--fix` and `--fix --dry-run` runs also write a review patch to
`trustcheck-fix.patch` beside the remediation source. If that path already
contains unrelated content, Trustcheck writes the next numbered patch path
instead and records it as `patch_path`.

Each upgrade includes compatibility confidence, a likely-breaking-change
warning for major upgrades, an available changelog or release link, and its
direct or transitive dependency cause. `minimal_secure_upgrade_proof` records
the search strategy, attempts, selected versions, advisory removal, policy
result, and resolution reproduction evidence.

## Pull requests

```bash
trustcheck scan -f uv.lock --with-osv --fix --create-pr \
  --pr-base main
```

PR creation requires a clean Git worktree and authenticated `git` and `gh`.
Trustcheck creates a temporary worktree, commits only validated dependency
files, pushes a dedicated branch, and opens a draft PR unless `--pr-ready` is
provided. The caller's current branch is not modified.
