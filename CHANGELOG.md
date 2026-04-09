# Changelog

All notable changes to `trustcheck` will be documented in this file.

The project follows Semantic Versioning for the supported public API described in `README.md`.

## Unreleased

### Added

- Formalized the machine-readable report contract as schema version `1.0.0`.
- Added the public contract helpers `trustcheck.JSON_SCHEMA_VERSION`, `trustcheck.JSON_SCHEMA_ID`, and `trustcheck.get_json_schema()`.
- Added contract snapshot tests for the JSON schema and representative report payloads.
- Documented the supported public Python API and compatibility guarantees for automation users.
- Split evidence collection from policy evaluation with a dedicated policy layer.
- Added built-in policy profiles, CLI policy overrides, and JSON policy-file support.
- Extended the machine-readable report with a `policy` evaluation block and advanced the schema to `1.1.0`.
- Added configurable network timeout, retry, backoff, cache, and offline controls via CLI, environment variables, and JSON config.
- Added deterministic upstream error subcodes plus structured debug logging for request lifecycle events.
- Extended the machine-readable report with a `diagnostics` block and advanced the schema to `1.2.0`.
- Added repository security guidance in `SECURITY.md`.
- Added dependency audit, secret scanning, and CodeQL workflows for the package itself.
- Hardened release automation with explicit PyPI artifact attestations, build provenance attestation, SBOM generation, and published checksums.
