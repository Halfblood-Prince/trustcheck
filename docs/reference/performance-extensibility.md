# Performance and extensibility

## Bounded concurrency

`--max-workers N` bounds target scans, artifact downloads, provenance requests,
static archive checks, advisory providers, OSV advisory fetches, and enrichment
work. The default is `8`; accepted values are `1` through `64`.

```bash
trustcheck scan -f requirements.txt --with-osv --max-workers 8
```

Results remain in resolved-input order even when workers finish out of order.
Each target uses an isolated mutable PyPI client while sharing the persistent
content store, digest-keyed artifact cache, advisory cache, and bounded HTTP
connection pool. Concurrent requests for the same artifact digest are
coalesced into one download.

Artifact and provenance work is predominantly network and archive I/O. CUDA or
other GPU acceleration would add transfer and deployment overhead without
speeding up these operations, so Trustcheck uses bounded CPU threads instead.

The same setting is available as `TRUSTCHECK_MAX_WORKERS`,
`performance.max_workers` in the JSON config file, and the GitHub Action
`max-workers` input.

## Artifact scope

`scan` defaults to `--artifact-scope target`. Trustcheck ranks wheel tags for
the requested Python, ABI, implementation, and platform, inspects the best
compatible non-yanked wheel, and falls back to one sdist when no compatible
wheel exists. This avoids downloading artifacts the target cannot install.

Use `--artifact-scope sdist` for source-only review. Use
`--full --artifact-scope all` when reviewing every file published for a release.

## OSV batch queries

Multi-package scans use OSV `/v1/querybatch` in chunks of at most 1,000
queries. Trustcheck follows each query's pagination token, deduplicates
advisory IDs, and fetches every full advisory record once with bounded
concurrency. OSV-compatible providers without the batch endpoint fall back to
bounded individual queries.

## Content-addressed cache

`--cache-dir` stores response bodies by SHA-256 under
`objects/sha256/<prefix>/<digest>`. Request references live separately under
`refs/`. Reads verify both the object size and SHA-256 digest; corrupted or
missing objects fail closed with `cache_integrity_failed`.

This layout deduplicates identical responses and artifact bytes while keeping
request lookup deterministic. Legacy request-addressed cache files remain
readable during migration.

## Advisory snapshots

Use a versioned snapshot to make advisory results portable and available to
offline scans:

```bash
trustcheck scan -f requirements.txt \
  --with-osv \
  --write-advisory-snapshot .trustcheck/advisories.json

trustcheck scan -f requirements.txt \
  --offline \
  --cache-dir .trustcheck/cache \
  --advisory-snapshot .trustcheck/advisories.json
```

`--advisory-snapshot` is repeatable. Inputs merge deterministically and
deduplicate advisory identities. `--write-advisory-snapshot` writes the merged
set atomically using schema
`urn:trustcheck:advisory-snapshot:1.0.0`.

The snapshot covers vulnerability intelligence. Offline package metadata and
artifacts still require a populated content cache.

## Resumable scans

`scan` and `environment` accept `--resume-state PATH`:

```bash
trustcheck scan -f requirements.txt \
  --with-osv \
  --resume-state .trustcheck/scan-state.json
```

Every completed target is checkpointed atomically. A restarted scan restores
successful reports and retries failed targets. State is accepted only when its
fingerprint matches the source digest, resolved targets, policy, indexes,
advisory options, and enabled plugins. Stale or mismatched state fails closed.

## Plugins

Plugins are disabled by default because loading an entry point executes
installed Python code. Enable all installed Trustcheck plugins with
`--enable-plugins`, or allowlist specific plugins with repeatable
`--plugin [KIND:]NAME`.

```bash
trustcheck scan -f requirements.txt \
  --plugin advisory:company-osv \
  --plugin policy:company-policy \
  --plugin-config trustcheck-plugins.json
```

Supported entry-point groups:

| Kind | Entry-point group | Purpose |
| --- | --- | --- |
| Advisory | `trustcheck.advisory_sources` | Return normalized vulnerability records |
| Index | `trustcheck.indexes` | Route custom index schemes and repositories |
| Artifact | `trustcheck.artifact_analyzers` | Add heuristic artifact findings |
| Policy | `trustcheck.policy_rules` | Add enforced policy violations |
| Renderer | `trustcheck.renderers` | Add output formats |

Example registration:

```toml
[project.entry-points."trustcheck.policy_rules"]
company-policy = "company_trustcheck:CompanyPolicy"
```

Plugin objects declare a stable `name`. Configuration is a JSON object keyed
by that name. Plugin API version `1` uses the public protocols exported by
`trustcheck`. Plugins used in concurrent scans must be thread-safe and should
return deterministic results. Exceptions and contract violations fail the
scan rather than being silently ignored.

The GitHub Action exposes `enable-plugins`, `plugins`, and `plugin-config`.
The workflow must install plugin distributions before invoking the composite
action.
