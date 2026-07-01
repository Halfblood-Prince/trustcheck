# Changelog

All notable changes to `trustcheck` will be documented in this file.

The project follows Semantic Versioning for the supported public API described in `README.md`.

## Unreleased

### Added

- Added calibrated malicious-package heuristic metadata, policy-configurable
  aggregate and per-rule thresholds, and advanced the schema to `1.11.0`.
- Added opt-in `--dynamic-analysis` execution in a disposable, no-network,
  non-root Docker sandbox with CPU, memory, process, and wall-clock limits.
- Added `trustcheck manifest init|verify|update` for dependency trust
  baselines that block repository, Trusted Publisher, SLSA, provenance,
  index-origin, native-binary, dynamic-execution, and malicious-score
  regressions.
- Added `trustcheck diff` for lockfile and pull-request trust review across
  changed direct and transitive packages, with text, JSON, Markdown, SARIF,
  Git ref discovery, GitHub PR commenting, and optional trust-manifest
  enforcement.
- Added a pinned GitHub Dependency Review pull-request gate for vulnerable
  dependency.

### Changed

- Split CLI command orchestration, CLI rendering and target loading, service
  support helpers, remediation models/rendering, and export model/XML helpers
  into focused modules while preserving the existing public import facade.
- Removed direct public runtime dependency declarations for transitive
  Sigstore requirements `PyJWT`, `idna`, and `tuf`; the action lockfile still
  constrains the resolved transitive set.

## [2.1.1] - 2026-06-28

Package release `2.1.1` emits machine-readable report schema `1.11.0`.

### Added

- Added JSON/TOML project configuration with automatic `.trustcheck.toml` and
  `[tool.trustcheck]` discovery and CLI-over-environment precedence.
- Added dependency-bound, scheduled live-upstream, real SARIF-upload, mutation,
  property-based, and expanded adversarial fuzz testing workflows.
- Added timestamped Authenticode signing, clean-runner executable validation,
  and Microsoft Store MSIX packaging and execution-alias tests.
- Added Docker image build and smoke testing in CI, plus release-time
  multi-platform GHCR image publication.

### Changed

- Added main-branch CI publication for GHCR Docker preview images.
- Updated pinned GitHub Actions and Docker workflow actions to the latest
  release versions suggested by Dependabot.

## [2.1.0] - 2026-06-22

Package release `2.1.0` emits machine-readable report schema `1.10.0`.

### Added

- Added the first-party `trustcheck` pre-commit hook for fast, hash-aware
  changed dependency-file scans.
- Added signed, API-versioned plugin manifests, plugin and signer allowlists,
  spawned resource-bounded workers, and plugin execution diagnostics.
- Published signed raw benchmark results with exact environments, cache phases,
  timings, peak RSS, corpus hashes, and advisory disagreements.
- Added monorepo discovery, aggregate JSON/SARIF, stable relative locations,
  previous-scan baselines, and glob-scoped policy overrides.
- Added remediation confidence, breaking-change warnings, changelog links,
  transitive causes, and minimal secure upgrade proofs; advanced the schema to `1.10.0`
  and remediation schema to `1.2.0`.

- Hardened artifact handling with streaming download and aggregate scan caps,
  archive member/expansion/compression-ratio limits, and spawned low-privilege
  inspection workers with wall-clock, CPU, and address-space limits.
- Replaced benchmark union recall with a detached-signature-verified truth
  corpus covering advisory aliases, fixes, withdrawals, markers, extras, clean
  packages, and private indexes; correctness regressions now fail CI.
- Added Atheris fuzz targets and CI smoke fuzzing for requirements, every
  supported lockfile family, provenance, wheels/sdists and archive headers,
  malformed RECORD data, and SARIF/SPDX/CycloneDX rendering.

- Added Sigstore-signed advisory snapshot schema 2 with source URLs, canonical
  record SHA-256 digests, generation and expiration times, trusted signer
  identity verification, and `--max-advisory-age` enforcement.
- Added `requirements-action.lock` for hash-locked composite Action runtime and
  build dependencies, plus exact release artifact version validation.
- Added `--sandbox-image` and a digest-pinned default resolver image, plus
  sparse staging of requirement, constraint, dependency-group, and local
  dependency inputs for container and Bubblewrap resolution.
- Added bounded concurrent target scans, OSV `/v1/querybatch` support with
  deduplicated advisory fetches, and configurable `--max-workers` controls.
- Added SHA-256 content-addressed persistent caching with verified references,
  atomic writes, legacy-cache reads, and fail-closed corruption handling.
- Added versioned offline advisory snapshots and fingerprinted, atomic
  `--resume-state` checkpoints that restore successful targets and retry
  failures.
- Added opt-in entry-point plugins for advisory sources, package indexes,
  artifact analyzers, policy rules, and output renderers, including CLI,
  Python API, configuration, and GitHub Action support.
- Added a reproducible, alias-aware performance and correctness benchmark
  against `pip-audit`, a scheduled benchmark workflow, and published raw
  results.
- Added deep SLSA v1 provenance interpretation for build definitions, source
  materials and commits, builder identities, build types, workflow references,
  invocation IDs, and resolved dependencies.
- Added detection of mutable workflow references, unpinned build actions,
  weak material digests, and source, workflow, builder, build-type, or
  cross-artifact inconsistencies.
- Added release-history comparison across signer, repository, workflow,
  builder, source commit, and build type, plus organization-owned verified
  publisher allowlists for CLI, policy files, and the GitHub Action.
- Added deep provenance evidence to text, JSON, CycloneDX, SPDX, and the public
  Python API; advanced the schema to `1.9.0`.
- Added the safe remediation engine with `scan --plan-fixes`, `--fix`, and
  `--fix --dry-run`, bounded minimal-change dependency resolution, isolated
  lockfile regeneration, exact post-write rescans, transactional application,
  machine-readable patch bundles, and optional draft pull requests.
- Added format-preserving requirements, PEP 621, Poetry, PDM, uv, and PEP 751
  updates; native uv, Poetry, PDM, and pip-tools outputs are regenerated by
  their owning tools and accepted only when they reproduce the proven secure
  resolution.
- Added remediation inputs and outputs to the TrustCheck Package Scanner
  action and remediation summaries to reports; advanced the schema to `1.8.0`.
- Added malicious-package heuristic scoring for typosquatting,
  dependency-confusion, maintainer, ownership, repository, and release-cadence
  anomalies.
- Added bounded AST analysis for suspicious install hooks, credential access,
  network calls, subprocess execution, persistence, dynamic execution, and
  obfuscation capability chains.
- Added PE, ELF, and Mach-O inspection for architecture, imported libraries,
  embedded platform signature presence, byte entropy, and embedded payload
  signatures.
- Added `--trusted-project` and the GitHub Action `trusted-projects` input for
  organization-specific typosquatting reference names.
- Added heuristic evidence to native JSON, SARIF, CycloneDX, SPDX, Markdown,
  text output, and the public Python API. All outputs label these findings as
  heuristics rather than proof of malware, and advanced the schema to `1.7.0`.
- Added concurrent vulnerability intelligence aggregation across PyPI, OSV,
  repeatable custom OSV-compatible endpoints, and Ecosyste.ms.
- Added normalized CVSS scores, vectors, versions, CWE identifiers, aliases,
  fix versions, and withdrawn-advisory state across advisory providers.
- Added optional CISA Known Exploited Vulnerabilities and FIRST EPSS
  enrichment, including KEV remediation metadata and EPSS percentiles.
- Added `critical`, `kev`, and `fixable` vulnerability policy modes alongside
  the existing advisory and block-any modes.
- Added auditable vulnerability suppressions with required owner,
  justification, ISO expiration, and active or expired report status.
- Extended native JSON and industry exports with vulnerability intelligence
  and suppression evidence, and advanced the schema to `1.6.0`.
- Added SARIF 2.1.0 output with stable `trustcheck/v1` fingerprints, manifest
  source locations, rule metadata, vulnerabilities, policy violations, risk
  flags, provenance gaps, artifact diagnostics, and scan failures.
- Added CycloneDX 1.6 JSON and XML, SPDX 2.3 JSON, OpenVEX 0.2.0, and Markdown
  exporters with canonical PyPI purls and deterministic document identities.
- Added SBOM trust properties for vulnerabilities, provenance coverage,
  artifact hashes, recommendations, and policy violations.
- Added `--output-file` to `inspect`, `scan`, and `environment`, and enabled
  every industry format in the TrustCheck Package Scanner GitHub Action.
- Added standard PEP 751 `pylock.toml` and named `pylock.<name>.toml` inputs,
  including environment, extras, dependency-group, source, index, and artifact
  validation.
- Added `Pipfile.lock` and hash-preserving pip-tools input support alongside
  the existing installed-environment, uv, Poetry, and PDM inputs.
- Added PEP 503/691 private-index support with `--index-url`, repeatable
  `--extra-index-url`, and pip-compatible `--keyring-provider` selection.
- Added secure-by-default dependency-confusion detection across configured and
  lockfile-recorded indexes, with an explicit reviewed override.
- Added lockfile artifact filename, URL, size, and multi-algorithm hash
  preservation in scan JSON and independent downloaded-byte verification.
- Added source-scoped auditing for direct, local, editable, archive, and VCS
  packages so they cannot silently fall back to a same-named public project.
- Added resolver-correct auditing through pip's `--dry-run --report` installation
  reports instead of selecting every requirement's newest compatible release in
  isolation.
- Added installed-environment auditing with `trustcheck environment`, including
  repeatable `--path` support for arbitrary `site-packages` directories.
- Added recursive requirements and constraints support by delegating
  requirements-file interpretation to pip, including nested `-r`/`-c` files,
  hashes, extras, editable requirements, and VCS/direct references.
- Added `--constraint`, `--extra`, and `--group` scan options, including
  standard dependency groups with `include-group` and Poetry dependency groups.
- Added target resolution controls for Python version, wheel platform,
  implementation, and ABI.
- Added structured resolved-source metadata to combined scan JSON, including
  requested, direct URL, editable, VCS, and commit information.
- Added public resolver models and installed-distribution discovery helpers.
- Added a first-class reusable GitHub Action through `action.yml`.
- Added action inputs for package and dependency-file targets, built-in or custom policy, expected repository checks, OSV, dependency traversal, artifact inspection, and output format.
- Added action outputs for recommendation, policy status, and JSON report path, with automatic workflow artifact upload before CLI exit-code enforcement.
- Added an action integration workflow covering a passing package and an intentional policy failure.
- Expanded the release workflow to publish immutable GitHub Action releases and update the compatible moving major tag such as `v1`.
- Added optional `RELEASE_TOKEN` authentication for repositories that reject release creation by `GITHUB_TOKEN`, and removed the unnecessary release `target_commitish` that can cause `403` errors for existing annotated tags.
- Added strict `core24` Snapcraft packaging for the `trustcheck` CLI.
- Added release-time Snap build, lint, install, metadata, and CLI version checks.
- Added Snap Store publication using scoped `SNAPCRAFT_STORE_CREDENTIALS`.
- Expanded Snapcraft targets to the `core24`-supported `amd64`, `arm64`, and `armhf` architectures.
- Restructured release publication so PyPI, GitHub Action, and Snap Store jobs run in parallel after shared package and Snap QA.
- Documented one-time PyPI Trusted Publisher, GitHub Marketplace, and Snap Store setup, including GitHub's manual Marketplace release association requirement.
- Added opt-in static wheel and sdist inspection with `--inspect-artifacts`.
- Added wheel `RECORD` hash and size validation, console-script listing, native extension detection, and unexpected top-level file reporting.
- Added sdist checks for suspicious scripts, oversized or unusual files, and wheel/sdist metadata differences.
- Added `wheel_record_invalid`, `artifact_contains_native_code`, `metadata_mismatch`, and `suspicious_entry_point` risk flags.
- Extended the machine-readable per-file report with artifact findings.

### Changed

- Pinned every external GitHub Action dependency to a full commit SHA and
  replaced the source-build fallback version with `0.0.0+source`.
- Changed the CLI and Python resolver sandbox default from `warn` to `auto`,
  and the GitHub Action default to `strict`; `warn` remains an explicit
  compatibility mode.

- Replaced the `pypi-attestations` runtime dependency with an internal PEP 740 adapter that delegates certificate, transparency-log, signature, and identity verification directly to Sigstore.
- Raised vulnerable Sigstore transitive dependency floors and added a Windows-only fallback to Sigstore's embedded trusted-root snapshot when TUF refresh cannot create symlinks without elevated privileges.
- Use standard-library `tomllib` on Python 3.11+.
- Moved coverage badge generation and publication into GitHub Actions, with the generated SVG maintained on a dedicated `coverage-badge` branch instead of in the source tree.
- Renamed the reusable GitHub Action and Marketplace display name to `TrustCheck Package Scanner`.
- Expanded the Snap Store listing with richer feature copy, quick-start examples, project links, and a dedicated storefront icon.
- Updated Snap release smoke tests and installation documentation to verify the public `trustcheck` command and diagnose shells where `/snap/bin` is missing from `PATH`.
- Redirected Sigstore XDG data, cache, and configuration into writable Snap-owned storage, fixing errno 13 provenance verification failures under strict confinement.
- Expanded Snap release QA to perform live verified-provenance inspection from the installed snap and reject unexpected verification errors.
- Added a push-triggered binary security workflow that builds standalone Windows and Linux executables with PyInstaller.
- Added a parallel release job that builds, smoke-tests, checksums, and attests a versioned Windows executable, then attaches it to the GitHub release.
- Added Microsoft Defender CLI and ClamAV scanning, retained scan reports, clean binary artifacts, checksums, and independent README check-run badges.

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

[Unreleased]: https://github.com/Halfblood-Prince/trustcheck/compare/v2.1.1...HEAD
[2.1.1]: https://github.com/Halfblood-Prince/trustcheck/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Halfblood-Prince/trustcheck/compare/v2.0.5...v2.1.0
[1.9.0]: https://github.com/Halfblood-Prince/trustcheck/compare/v1.8.0...v1.9.0
