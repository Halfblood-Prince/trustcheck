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

## JSON contract

`trustcheck inspect --format json` is the machine-readable interface.

- The JSON payload is versioned with a top-level `schema_version`.
- Patch releases keep the same JSON shape for a given `schema_version`.
- New machine-readable fields should be added in a backward-compatible way within the nested `report` object.
- Breaking changes require a new `schema_version`.
- The text format is presentation output for humans and is not a stability contract.

Current contract: `schema_version = "1"`

Top-level shape:

```json
{
  "schema_version": "1",
  "report": {
    "project": "demo",
    "version": "1.2.3",
    "summary": "Demo package",
    "package_url": "https://pypi.org/project/demo/1.2.3/",
    "declared_repository_urls": ["https://github.com/example/demo"],
    "repository_urls": ["https://github.com/example/demo"],
    "expected_repository": "https://github.com/example/demo",
    "ownership": {"organization": "example-org", "roles": []},
    "vulnerabilities": [],
    "files": [],
    "risk_flags": [],
    "recommendation": "verified"
  }
}
```

Field notes:

- `declared_repository_urls`: forge-normalized repository URLs inferred from explicit project metadata fields.
- `repository_urls`: stable machine-readable repository signals currently equal to `declared_repository_urls`.
- `files[*].publisher_identities`: attestation-derived publisher identity data, distinct from declared project metadata.

## Release process

- Pull requests and pushes to `main` run CI for tests, lint, type checks, and a build smoke test.
- Publishing is triggered from a GitHub Release and rebuilds the tagged source before upload.
- The publish workflow cannot run the upload step unless the release revision passes the same CI gates in the workflow.

## What the report includes

- Selected project and version
- Declared project URLs and likely repository URLs
- PyPI ownership metadata when exposed
- Known vulnerabilities from PyPI
- Distribution file hashes
- Provenance / attestation availability per file
- Verification status per file
- Trusted Publisher identity information extracted from provenance bundles
- Risk flags and an evidence-based status tier: `verified`, `metadata-only`, `review-required`, or `high-risk`

## Roadmap

- Stronger repository canonicalization and source matching
- Policy files for CI and org-level enforcement
- Support for lockfiles and dependency trees
- Offline caching and SBOM-style export

