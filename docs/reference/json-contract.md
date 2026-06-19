# JSON contract

`trustcheck inspect --format json` is the stable machine-readable interface.

## Stability rules

- `schema_version` is semantic and version-controls the JSON shape
- `JSON_SCHEMA_ID` identifies the exact JSON Schema document for a given `schema_version`
- patch releases keep the same JSON contract for a given schema version
- new fields may be added within expandable objects in a backward-compatible way
- breaking JSON changes require a new major `schema_version`

## Current schema identifiers

- `JSON_SCHEMA_VERSION = "1.9.0"`
- `JSON_SCHEMA_ID = "urn:trustcheck:report:1.9.0"`

Package versions and report schema versions are independent. Schema `1.9.0`
adds interpreted SLSA provenance, expanded consistency and release-drift
evidence, and verified-publisher organization policy settings.

## Top-level shape

```json
{
  "schema_version": "1.9.0",
  "report": {
    "project": "demo",
    "version": "1.2.3",
    "summary": "Demo package",
    "package_url": "https://pypi.org/project/demo/1.2.3/",
    "declared_dependencies": ["depalpha>=1.0"],
    "diagnostics": {
      "timeout": 10.0,
      "max_retries": 2,
      "backoff_factor": 0.25,
      "offline": false,
      "cache_dir": null,
      "request_count": 3,
      "retry_count": 1,
      "cache_hit_count": 0,
      "request_failures": [],
      "artifact_failures": []
    },
    "policy": {
      "profile": "default",
      "passed": true,
      "enforced": false,
      "fail_on_severity": "none",
      "require_verified_provenance": "none",
      "require_expected_repository_match": false,
      "allowed_publisher_organizations": [],
      "allow_metadata_only": true,
      "vulnerability_mode": "ignore",
      "suppressions_applied": 0,
      "suppressions_expired": 0,
      "violations": []
    },
    "declared_repository_urls": ["https://github.com/example/demo"],
    "repository_urls": ["https://github.com/example/demo"],
    "expected_repository": "https://github.com/example/demo",
    "ownership": {
      "organization": "example-org",
      "roles": []
    },
    "vulnerabilities": [
      {
        "id": "CVE-2026-1234",
        "summary": "Example vulnerability",
        "aliases": ["GHSA-abcd-1234-5678"],
        "source": "PyPI, OSV",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_version": "3.1",
        "cwes": ["CWE-79"],
        "fixed_in": ["1.2.4"],
        "link": "https://osv.dev/vulnerability/CVE-2026-1234",
        "withdrawn": false,
        "withdrawn_at": null,
        "kev": true,
        "kev_date_added": "2026-05-01",
        "kev_due_date": "2026-05-22",
        "kev_required_action": "Apply the vendor update.",
        "kev_known_ransomware_campaign_use": "Known",
        "epss_score": 0.8123,
        "epss_percentile": 0.9812,
        "epss_date": "2026-06-12",
        "suppression": null
      }
    ],
    "files": [],
    "coverage": {
      "total_files": 0,
      "files_with_provenance": 0,
      "verified_files": 0,
      "status": "none"
    },
    "publisher_trust": {
      "depth_score": 0,
      "depth_label": "none",
      "verified_publishers": [],
      "unique_verified_repositories": [],
      "unique_verified_workflows": []
    },
    "provenance_consistency": {
      "has_sdist": false,
      "has_wheel": false,
      "sdist_wheel_consistent": null,
      "consistent_repositories": [],
      "consistent_workflows": [],
      "builder_consistent": null,
      "source_commit_consistent": null,
      "build_type_consistent": null,
      "consistent_builders": [],
      "consistent_source_commits": [],
      "consistent_build_types": []
    },
    "release_drift": {
      "compared_to_version": null,
      "publisher_repository_drift": null,
      "publisher_workflow_drift": null,
      "signer_drift": null,
      "builder_drift": null,
      "source_commit_drift": null,
      "build_type_drift": null,
      "previous_signers": [],
      "previous_repositories": [],
      "previous_workflows": [],
      "previous_builders": [],
      "previous_source_commits": [],
      "previous_build_types": []
    },
    "malicious_package": {
      "score": 0,
      "level": "none",
      "artifact_analysis": false,
      "trusted_name_count": 56,
      "findings": [],
      "disclaimer": "These findings are heuristic indicators for review, not proof that the package is malicious."
    },
    "dependencies": [
      {
        "requirement": "depalpha>=1.0",
        "project": "depalpha",
        "version": "1.4.0",
        "depth": 1,
        "parent_project": "demo",
        "parent_version": "1.2.3",
        "package_url": "https://pypi.org/project/depalpha/1.4.0/",
        "recommendation": "review-required",
        "risk_flags": [],
        "declared_dependencies": [],
        "error": null
      }
    ],
    "dependency_summary": {
      "requested": true,
      "total_declared": 1,
      "total_inspected": 1,
      "unique_dependencies": 1,
      "max_depth": 1,
      "highest_risk_recommendation": "review-required",
      "highest_risk_projects": ["depalpha"]
    },
    "risk_flags": [],
    "remediation": {
      "status": "not-requested",
      "minimal": false,
      "attempts": 0,
      "upgrades_planned": 0,
      "blocked_fixes": 0,
      "patch_files": [],
      "pull_request_url": null
    },
    "recommendation": "verified"
  }
}
```

## Deep provenance fields

Each `report.files[]` item contains `slsa_provenance`. A verified SLSA v1
statement records:

- signer identity derived from the verified Trusted Publisher
- normalized source URI, repository, and full git commit
- builder identity, build type, and invocation ID
- workflow repository, path, reference, and whether the reference is immutable
- resolved materials with names, URIs, digests, and source designation
- discovered action references and the subset not pinned to full commits
- structured provenance issues with code, severity, message, and evidence

`report.provenance_consistency` compares repository, workflow, builder, source
commit, and build type between verified sdists and wheels.
`report.release_drift` compares signer, repository, workflow, builder, source
commit, and build type with the previous release. Source commit drift is
recorded for auditability but is not by itself treated as suspicious because a
new release normally comes from a new commit.

## Dependency fields

When dependency inspection is enabled with `--with-deps`, `--with-transitive-deps`, `include_dependencies=True`, or `include_transitive_dependencies=True`, the report may include:

- `report.declared_dependencies`: raw `requires_dist` strings from the inspected release metadata
- `report.dependencies`: flattened dependency inspection results for the resolved dependency set
- `report.dependency_summary`: aggregate counts and the highest-risk recommendation seen among inspected dependencies

If dependency inspection is not requested, these fields are still present in the contract with empty or default values so JSON consumers can rely on a stable shape.

## Combined scan resolution metadata

`trustcheck scan --format json` and `trustcheck environment --format json`
include a top-level `resolved` array alongside `reports` and `failures`. Each
entry records:

- the exact resolved project and version
- whether the distribution was explicitly requested
- its direct source URL when pip or PEP 610 metadata provides one
- editable status
- VCS type and immutable commit identifier when available
- the redacted source index URL
- every retained lockfile artifact filename, URL, path, size, kind, and hash
- configured-index collisions in `dependency_confusion`
- the dependency manifest path and best-effort declaration line in
  `source_file` and `source_line`

This scan-level metadata does not change the per-package report schema.

When remediation is requested, combined scan JSON also includes a top-level
`remediation` object using
`urn:trustcheck:remediation:1.1.0`. It contains before/after dependency graph
digests and nodes, advisory IDs removed, source digests, semantic edits,
unified diffs, lockfile hash validation records, post-fix reproduction
commands and result digests, selected upgrades, blocked fixes, minimality
status, validation results, and optional pull-request metadata. The same object
can be written independently with `--remediation-output`.

Artifact URLs and index URLs never expose embedded credentials. Lock hashes
are represented as an algorithm-to-hex-digest object under each item in
`artifacts`.

## Artifact inspection fields

Every item in `report.files` contains an `artifact` object. When artifact
inspection is not requested, `artifact.inspected` is `false` and the remaining
fields use empty defaults.

With `--inspect-artifacts` or `inspect_artifacts=True`, the block includes:

- archive type, validity, member count, and total uncompressed size
- wheel `record_valid` and `record_errors`
- console scripts and suspicious entry points
- native, unexpected top-level, suspicious, oversized, and unusual files
- parsed Name, Version, and Requires-Dist metadata
- parsed Wheel-Version, Root-Is-Purelib, and Tag metadata
- metadata mismatches between PyPI, wheel, and sdist evidence
- `source_files_analyzed` and bounded AST parse errors
- `heuristic_findings` with category, severity, confidence, score, evidence,
  source location, and artifact name
- `native_binaries` with PE, ELF, or Mach-O format, architecture, imports,
  embedded signature presence, entropy, embedded payloads, and parse notes

## Malicious-package heuristic fields

`report.malicious_package` is always present. Metadata and name checks run for
normal package inspection; `artifact_analysis` indicates whether
`--inspect-artifacts` enabled AST and native-binary inspection.

The aggregate `score` is bounded to 0-100 and maps to `none`, `low`,
`elevated`, `high`, or `critical`. Each finding preserves its own score,
confidence, evidence, artifact, and best-effort source location.

The assessment is deliberately heuristic. Neither a finding nor a high score
is proof of malware. Consumers must preserve the `heuristic` marker and
`disclaimer` when presenting or transforming this data.

## Runtime schema access

```python
from trustcheck import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, get_json_schema

print(JSON_SCHEMA_VERSION)
print(JSON_SCHEMA_ID)
schema = get_json_schema()
```

## Other machine-readable formats

The JSON contract above remains the lossless trustcheck-native envelope.
Standard exports are available for SARIF 2.1.0, CycloneDX 1.6 JSON/XML,
SPDX 2.3 JSON, and OpenVEX 0.2.0. See
[Industry output formats](industry-formats.md) for their mappings and
stability guarantees.
