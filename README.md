# trustcheck

`trustcheck` is a small Python package and CLI for checking PyPI package trust signals before installation.

The immediate goal is pragmatic: answer questions like these in one local command:

- Does this release expose PyPI provenance / attestation data?
- Was it published through a Trusted Publisher flow?
- Which repository URLs does the package claim?
- Do those URLs match the repository I expected?
- Are there known PyPI vulnerability records for the selected release?
- Are there obvious risk flags worth reviewing before install?

This MVP is intentionally conservative:

- It fetches metadata from PyPI's JSON API and provenance objects from PyPI's Integrity API.
- It surfaces publisher identity hints from provenance bundles when available.
- It does not yet perform full cryptographic attestation verification. That should be added in a later release via Sigstore / `pypi-attestations` style verification.

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
- Trusted Publisher identity hints extracted from provenance bundles
- Risk flags and an overall recommendation tier

## Roadmap

- Full cryptographic verification of PyPI attestations
- Stronger repository canonicalization and source matching
- Policy files for CI and org-level enforcement
- Support for lockfiles and dependency trees
- Offline caching and SBOM-style export

