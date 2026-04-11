# Config and offline mode

You can provide network settings through a JSON config file and optionally combine that with environment variables or CLI flags.

## Config file shape

`--config-file` expects a JSON object. The `network` field, when present, must also be an object.

Example:

```json
{
  "network": {
    "timeout": 20.0,
    "retries": 4,
    "backoff_factor": 0.5,
    "cache_dir": ".trustcheck-cache"
  }
}
```

## Environment variables

The CLI also recognizes these environment variables:

- `TRUSTCHECK_TIMEOUT`
- `TRUSTCHECK_RETRIES`
- `TRUSTCHECK_BACKOFF`
- `TRUSTCHECK_CACHE_DIR`
- `TRUSTCHECK_OFFLINE`

## Precedence

The effective network configuration is resolved from:

1. CLI flags
2. environment variables
3. config file values
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

Offline mode is useful in hermetic CI or for repeated local analysis after an initial cached run.
