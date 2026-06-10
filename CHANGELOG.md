# Changelog

All notable changes to `trustcheck` will be documented in this file.

The project follows Semantic Versioning for the supported public API described in `README.md`.

## Unreleased

### Added

- Added a first-class reusable GitHub Action through `action.yml`.
- Added action inputs for package and dependency-file targets, built-in or custom policy, expected repository checks, OSV, dependency traversal, artifact inspection, and output format.
- Added action outputs for recommendation, policy status, and JSON report path, with automatic workflow artifact upload before CLI exit-code enforcement.
- Added an action integration workflow covering a passing package and an intentional policy failure.
- Expanded the release workflow to publish immutable GitHub Action releases and update the compatible moving major tag such as `v1`.
- Added optional `RELEASE_TOKEN` authentication for repositories that reject release creation by `GITHUB_TOKEN`, and removed the unnecessary release `target_commitish` that can cause `403` errors for existing annotated tags.
- Added strict `core24` Snapcraft packaging for the `trustcheck` CLI.
- Added release-time Snap build, lint, install, metadata, and CLI version checks.
- Added Snap Store publication using scoped `SNAPCRAFT_STORE_CREDENTIALS`.
- Expanded Snapcraft targets to `amd64`, `arm64`, `armhf`, and `i386`.
- Restructured release publication so PyPI, GitHub Action, and Snap Store jobs run in parallel after shared package and Snap QA.
- Documented one-time PyPI Trusted Publisher, GitHub Marketplace, and Snap Store setup, including GitHub's manual Marketplace release association requirement.
- Added opt-in static wheel and sdist inspection with `--inspect-artifacts`.
- Added wheel `RECORD` hash and size validation, console-script listing, native extension detection, and unexpected top-level file reporting.
- Added sdist checks for suspicious scripts, oversized or unusual files, and wheel/sdist metadata differences.
- Added `wheel_record_invalid`, `artifact_contains_native_code`, `metadata_mismatch`, and `suspicious_entry_point` risk flags.
- Extended the machine-readable per-file report with artifact findings and advanced the schema to `1.5.0`.

### Changed

- Renamed the reusable GitHub Action and Marketplace display name to `TrustCheck Package Scanner`.
- Expanded the Snap Store listing with richer feature copy, quick-start examples, project links, and a dedicated storefront icon.
- Updated Snap release smoke tests and installation documentation to verify the public `trustcheck` command and diagnose shells where `/snap/bin` is missing from `PATH`.

## [1.9.0] - 2026-06-09

Package release `1.9.0` emits machine-readable report schema `1.4.0`.

### Added

- Added Bandit and Semgrep CI workflows plus a pytest coverage badge and README status badges.
- Added optional OSV vulnerability queries, including GitHub Advisory Database records.
- Added vulnerability severity output and cross-source advisory deduplication by aliases such as CVE IDs.
- Added lockfile-aware scans for hashed `requirements.txt`, `uv.lock`, `poetry.lock`, and `pdm.lock`.
- Formalized the machine-readable report contract at schema version `1.4.0`.
- Added the public contract helpers `trustcheck.JSON_SCHEMA_VERSION`, `trustcheck.JSON_SCHEMA_ID`, and `trustcheck.get_json_schema()`.
- Added contract snapshot tests for the JSON schema and representative report payloads.
- Documented the supported public Python API and compatibility guarantees for automation users.
- Split evidence collection from policy evaluation with a dedicated policy layer.
- Added built-in policy profiles, CLI policy overrides, and JSON policy-file support.
- Added configurable network timeout, retry, backoff, cache, and offline controls via CLI, environment variables, and JSON config.
- Added deterministic upstream error subcodes plus structured debug logging for request lifecycle events.
- Added dependency audit, secret scanning, and CodeQL workflows for the package itself.
- Hardened release automation with explicit PyPI artifact attestations, build provenance attestation, SBOM generation, and published checksums.

### Changed

- Preserved resolved lockfile versions during direct and transitive dependency inspection.
- Aligned the README, documentation site, CLI help, changelog, and JSON contract documentation around the same supported feature set.
- Replaced temporary Discord issue and security links with stable GitHub project pages and private vulnerability reporting.

[Unreleased]: https://github.com/Halfblood-Prince/trustcheck/compare/v1.9.0...HEAD
[1.9.0]: https://github.com/Halfblood-Prince/trustcheck/compare/v1.8.0...v1.9.0
