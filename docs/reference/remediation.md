# Safe remediation

Trustcheck remediation is an extension of `scan`; package inspection and
installed-environment auditing remain read-only.

## Modes

```bash
trustcheck scan requirements.txt --with-osv --plan-fixes
trustcheck scan requirements.txt --with-osv --fix --dry-run
trustcheck scan requirements.txt --with-osv --fix
```

`--plan-fixes` resolves and rescans candidates but does not invoke lockfile
writers. `--fix --dry-run` runs writers in an isolated project copy and emits
the exact validated patch. `--fix` checks the original SHA-256 digests again,
uses same-directory staged files and atomic replacement, and rolls back a
partial write.

All active, non-withdrawn, non-suppressed advisories with known fixes are
targeted. Editable, local, direct-archive, and VCS dependencies are immutable
because selecting a source revision requires human review.

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

Declared ranges are never widened silently. Exact pins can be upgraded;
otherwise an excluded secure release requires
`--allow-constraint-changes`.

## Writers

Requirements, nested includes, constraints, PEP 621, Poetry, PDM, and PEP 751
files use syntax-aware edits. TOML comments, ordering, and unknown tool tables
are retained.

Hash-pinned pip-tools output requires `pip-compile`. `uv.lock`,
`poetry.lock`, and `pdm.lock` require their respective installed commands.
Trustcheck never installs these tools automatically and never hand-edits their
implementation-specific lock formats.

Use `--source-manifest` when a lockfile does not unambiguously identify its
root requirements.

## Patch bundles

```bash
trustcheck scan pylock.toml \
  --source-manifest pyproject.toml \
  --fix --dry-run \
  --remediation-output reports/remediation.json
```

Patch bundles use schema `urn:trustcheck:remediation:1.1.0`. They contain
before/after dependency graphs, file digests, unified diffs, structured edits,
advisory IDs removed, lockfile hash validation, reproduction commands,
post-fix graph and report digests, minimality evidence, validation results, and
PR metadata.

## Pull requests

```bash
trustcheck scan uv.lock --with-osv --fix --create-pr \
  --pr-base main
```

PR creation requires a clean Git worktree and authenticated `git` and `gh`.
Trustcheck creates a temporary worktree, commits only validated dependency
files, pushes a dedicated branch, and opens a draft PR unless `--pr-ready` is
provided. The caller's current branch is not modified.
