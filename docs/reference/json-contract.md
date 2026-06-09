# JSON contract

`trustcheck inspect --format json` is the stable machine-readable interface.

## Stability rules

- `schema_version` is semantic and version-controls the JSON shape
- `JSON_SCHEMA_ID` identifies the exact JSON Schema document for a given `schema_version`
- patch releases keep the same JSON contract for a given schema version
- new fields may be added within expandable objects in a backward-compatible way
- breaking JSON changes require a new major `schema_version`

## Current schema identifiers

- `JSON_SCHEMA_VERSION = "1.5.0"`
- `JSON_SCHEMA_ID = "urn:trustcheck:report:1.5.0"`

Package versions and report schema versions are independent. Schema `1.5.0`
adds per-file artifact inspection findings.

## Top-level shape

```json
{
  "schema_version": "1.5.0",
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
      "allow_metadata_only": true,
      "vulnerability_mode": "ignore",
      "violations": []
    },
    "declared_repository_urls": ["https://github.com/example/demo"],
    "repository_urls": ["https://github.com/example/demo"],
    "expected_repository": "https://github.com/example/demo",
    "ownership": {
      "organization": "example-org",
      "roles": []
    },
    "vulnerabilities": [],
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
      "consistent_workflows": []
    },
    "release_drift": {
      "compared_to_version": null,
      "publisher_repository_drift": null,
      "publisher_workflow_drift": null,
      "previous_repositories": [],
      "previous_workflows": []
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
    "recommendation": "verified"
  }
}
```

## Dependency fields

When dependency inspection is enabled with `--with-deps`, `--with-transitive-deps`, `include_dependencies=True`, or `include_transitive_dependencies=True`, the report may include:

- `report.declared_dependencies`: raw `requires_dist` strings from the inspected release metadata
- `report.dependencies`: flattened dependency inspection results for the resolved dependency set
- `report.dependency_summary`: aggregate counts and the highest-risk recommendation seen among inspected dependencies

If dependency inspection is not requested, these fields are still present in the contract with empty or default values so JSON consumers can rely on a stable shape.

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

## Runtime schema access

```python
from trustcheck import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, get_json_schema

print(JSON_SCHEMA_VERSION)
print(JSON_SCHEMA_ID)
schema = get_json_schema()
```
