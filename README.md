# trustcheck

`trustcheck` is a small Python package and CLI for checking PyPI package trust signals before installation.

The immediate goal is pragmatic: answer questions like these in one local command:

- Does this release expose PyPI provenance / attestation data?
- Does the attestation verify cryptographically for the exact artifact I would install?
- Was it published through the expected Trusted Publisher identity?
- Which repository URLs does the package claim?
- Do those URLs match the repository I expected?
- Are there known PyPI vulnerability records for the selected release?
- Are there obvious risk flags worth reviewing before install?

`trustcheck` now verifies PyPI attestations with `pypi-attestations` / Sigstore, checks that the attested subject matches the downloaded artifact filename and SHA-256 digest, and fails closed when provenance is missing, invalid, or bound to the wrong publisher identity.

## Install

```bash
pip install trustcheck
```

## Usage

```bash
trustcheck inspect requests
trustcheck inspect sampleproject --version 4.0.0
trustcheck inspect sampleproject --expected-repo https://github.com/pypa/sampleproject
trustcheck inspect sampleproject --format json
```

## What the report includes

- Selected project and version
- Declared project URLs and likely repository URLs
- PyPI ownership metadata when exposed
- Known vulnerabilities from PyPI
- Distribution file hashes
- Provenance / attestation availability per file
- Verification status per file
- Trusted Publisher identity information extracted from provenance bundles
- Risk flags and an overall recommendation tier

## Roadmap

- Stronger repository canonicalization and source matching
- Policy files for CI and org-level enforcement
- Support for lockfiles and dependency trees
- Offline caching and SBOM-style export

