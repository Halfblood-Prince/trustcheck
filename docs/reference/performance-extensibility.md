# Performance and extensibility

## Bounded concurrency

`--workers N` bounds target scans, artifact downloads, provenance requests,
static archive checks, advisory providers, OSV advisory fetches, and enrichment
work. The default is `8`; accepted values are `1` through `64`, or `-1` for all
available CPU cores.

```bash
trustcheck scan -f requirements.txt --with-osv --workers 8
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
`workers` input.

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
  --write-advisory-snapshot .trustcheck/advisories.json \
  --sign-advisory-snapshot

trustcheck scan -f requirements.txt \
  --offline \
  --cache-dir .trustcheck/cache \
  --advisory-snapshot .trustcheck/advisories.json \
  --advisory-snapshot-identity \
    https://github.com/example/project/.github/workflows/snapshot.yml@refs/heads/main \
  --advisory-snapshot-issuer https://token.actions.githubusercontent.com \
  --max-advisory-age 24
```

`--advisory-snapshot` is repeatable. Inputs merge deterministically and
deduplicate advisory identities. `--write-advisory-snapshot` writes the merged
set atomically using schema `urn:trustcheck:advisory-snapshot:2.0.0`.

Schema 2 records a source manifest with provider URLs and a bound SHA-256
digest of canonical advisory records, plus generation and expiration
timestamps. `--sign-advisory-snapshot`
creates a Sigstore bundle beside the JSON as `<snapshot>.sigstore.json` using
ambient OIDC identity. Loading verifies that bundle against
`--advisory-snapshot-identity` and optional `--advisory-snapshot-issuer` before
parsing records. `--max-advisory-age HOURS` defaults to 168 and can impose a
shorter lifetime than the signed snapshot. Legacy or unsigned snapshots are
accepted only with `--allow-unsigned-advisory-snapshot`.

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

!!! warning "Experimental"

    Third-party Trustcheck plugins remain explicitly opt-in. Keep plugin
    loading disabled unless the plugin distribution, installed-code digest,
    and publisher trust root are explicitly approved.

Plugins are disabled by default and require an explicit allowlist. Trusted
plugin execution requires a signed `trustcheck-plugin.json` statement that
binds the name, kind, entry point, API version, plugin protocol version,
distribution name and version, installed RECORD digest, canonical installed
content digest, declared dependencies, declared capabilities, resource
requirements, and configuration schema digest. Trustcheck verifies the
signature, installed files against wheel `RECORD`, and a configured external
trust root before importing code in a spawned, resource-bounded worker.
Self-signed plugin metadata alone is rejected. Execution status, timing, and
whether the resource-bounded worker was used are included in report
diagnostics.

Worker IPC uses plugin protocol version `1` over
`multiprocessing.Pipe.send_bytes()` and `recv_bytes()`. The parent and worker
exchange UTF-8 JSON bytes only; plugin-controlled Python objects are never
received with `Pipe.recv()` or unpickled in the parent process. Responses use
this envelope:

```json
{
  "plugin_protocol_version": "1",
  "request_id": "request-id",
  "ok": true,
  "result": {}
}
```

The parent validates the envelope, protocol version, request id, JSON shape,
message byte size, nested depth, list and mapping length, and string length.
The worker returns plain data, and the parent reconstructs only trusted
Trustcheck models: vulnerability records, artifact findings, policy
violations, index projects and files, dependency-confusion findings, byte
payloads, and plugin errors. Unknown fields and unsupported return types fail
closed. The packaged schemas are
`trustcheck/plugin_schemas/plugin-statement-1.json`,
`trustcheck/plugin_schemas/plugin-ipc-request-1.json` and
`trustcheck/plugin_schemas/plugin-ipc-response-1.json`.

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
`trustcheck`; resource-bounded workers reject arbitrary custom result objects.
The distribution includes `trustcheck-plugin.json`:

```json
{
  "schema": "urn:trustcheck:plugin-manifest:1",
  "manifest": {
    "schema": "urn:trustcheck:plugin-statement:1",
    "name": "company-policy",
    "kind": "policy",
    "entry_point": "company_trustcheck:CompanyPolicy",
    "api_version": "1",
    "distribution": "company-trustcheck-policy",
    "distribution_version": "1.2.3",
    "wheel_sha256": "64 lowercase hex characters",
    "record_sha256": "64 lowercase hex characters",
    "configuration_schema_sha256": "64 lowercase hex characters",
    "protocol_version": "1",
    "capabilities": ["evaluate"],
    "requires_network": false,
    "requires_filesystem": false,
    "requires_subprocess": false,
    "dependencies": []
  },
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "signature": "base64-rsa-pkcs1v15-sha256",
  "configuration_schema": {
    "type": "object",
    "additionalProperties": false
  }
}
```

The signature covers canonical compact JSON for `manifest` with sorted keys.
The statement file itself and `RECORD` are metadata and are excluded from the
canonical installed-content digest; every other recorded file must have a
matching sha256 `RECORD` entry. Modifying plugin code, dependencies, `RECORD`,
the declared configuration schema, or declared capabilities fails closed.

Configure one trust-policy mode in `_trustcheck`:

| Mode | Required trust root |
| --- | --- |
| `trusted-key` | `trusted_signers`: SHA-256 fingerprints of approved public keys |
| `allowlisted-digest` | `trusted_wheel_sha256`: canonical installed-content digests |
| `sigstore-identity` | `trusted_sigstore_identities`: identity and issuer pairs |
| `organization-policy` | Any configured organization-managed trust root |
| `disabled` | Disables signed-plugin enforcement only when `require_signed=false` |

Example plugin configuration:

```json
{
  "_trustcheck": {
    "allowlist": ["policy:company-policy"],
    "trust_policy_mode": "trusted-key",
    "trusted_signers": [
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ]
  },
  "company-policy": {}
}
```

Exceptions, timeouts, signature failures, trust-root failures, and contract
violations fail closed.

The GitHub Action exposes `enable-plugins`, `plugins`, and `plugin-config`.
The workflow must install plugin distributions before invoking the composite
action.
