# Config and offline mode

Trustcheck discovers reusable project settings and combines them with environment
variables and CLI flags.

## Config file shape

Configuration is discovered in this order:

1. an explicit `--config-file PATH`
2. `.trustcheck.toml` in the current directory
3. `[tool.trustcheck]` in `pyproject.toml`

Explicit files may be JSON, standalone TOML, or `pyproject.toml`. The existing
JSON shape remains supported. The `network`, `advisories`, and `performance`
fields, when present, must be objects or TOML tables.

Project-level TOML example:

```toml
[tool.trustcheck]
policy = "strict"
with_osv = true
with_kev = true
scan_profile = "standard"
artifact_scope = "target"
dynamic_analysis = false
dynamic_python = "3.12"

[tool.trustcheck.network]
timeout = 20.0
retries = 4
cache_dir = ".trustcheck-cache"
```

The equivalent standalone `.trustcheck.toml` omits the `tool.trustcheck`
prefix:

```toml
policy = "strict"
with_osv = true
with_kev = true
scan_profile = "standard"
artifact_scope = "target"
dynamic_analysis = false
dynamic_python = "3.12"

[network]
timeout = 20.0
retries = 4
cache_dir = ".trustcheck-cache"
```

Supported project-level settings are `policy`, `with_osv`, `with_kev`,
`scan_profile`, `artifact_scope`, `dynamic_analysis`, `dynamic_python`, and
`dynamic_image`. Existing provider, performance, and network settings use their
nested tables. `dynamic_image`, when set, must be pinned by a full sha256
digest.

JSON example:

```json
{
  "network": {
    "timeout": 20.0,
    "retries": 4,
    "backoff_factor": 0.5,
    "cache_dir": ".trustcheck-cache"
  },
  "advisories": {
    "osv": true,
    "osv_urls": ["https://advisories.example.com"],
    "ecosystems": true,
    "kev": true,
    "kev_url": "https://www.cisa.gov/example/known_exploited.json",
    "epss": true,
    "epss_url": "https://api.first.org/data/v1/epss"
  },
  "performance": {
    "max_workers": 8
  }
}
```

Advisory settings:

- `osv`: enable the public OSV provider
- `osv_urls`: additional OSV-compatible API base URLs
- `ecosystems`: enable the Ecosyste.ms OSV-compatible provider
- `kev`: enable CISA Known Exploited Vulnerabilities enrichment
- `kev_url`: override the KEV JSON feed URL
- `epss`: enable FIRST EPSS enrichment
- `epss_url`: override the EPSS API base URL

CLI provider flags are additive with config-file providers. Duplicate base URLs
are queried once.

## Environment variables

The CLI also recognizes these environment variables:

- `TRUSTCHECK_TIMEOUT`
- `TRUSTCHECK_RETRIES`
- `TRUSTCHECK_BACKOFF`
- `TRUSTCHECK_CACHE_DIR`
- `TRUSTCHECK_OFFLINE`
- `TRUSTCHECK_MAX_WORKERS`
- `TRUSTCHECK_POLICY`
- `TRUSTCHECK_WITH_OSV`
- `TRUSTCHECK_WITH_KEV`
- `TRUSTCHECK_SCAN_PROFILE`
- `TRUSTCHECK_ARTIFACT_SCOPE`
- `TRUSTCHECK_DYNAMIC_ANALYSIS`
- `TRUSTCHECK_DYNAMIC_PYTHON`
- `TRUSTCHECK_DYNAMIC_IMAGE`

## Precedence

All supported settings use this precedence:

1. CLI flags
2. environment variables
3. discovered or explicit project configuration
4. built-in defaults

## Offline mode

Use `--offline` when you want `trustcheck` to use cached responses only and avoid live network requests.

Example:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --cache-dir .trustcheck-cache \
  --offline
```

Offline mode is useful in hermetic CI or for repeated local analysis after an
initial cached run. PyPI responses use a SHA-256 content-addressed persistent
cache with integrity verification.

Use repeatable `--advisory-snapshot PATH` for portable advisory data and
`--write-advisory-snapshot PATH` to create or update a snapshot. KEV and EPSS
data included in normalized snapshot records remains available offline.
Missing package metadata or artifacts still fail closed.

`scan` and `environment` can checkpoint target reports with
`--resume-state PATH`. State is reused only when the source, resolved targets,
policy, providers, indexes, and plugins produce the same fingerprint.

See [Performance and extensibility](../reference/performance-extensibility.md)
for cache layout, batching, resume semantics, and plugin entry points.
