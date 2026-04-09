from __future__ import annotations

import json
import unittest
from pathlib import Path

from trustcheck import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, TrustReport, get_json_schema
from trustcheck.models import (
    CoverageSummary,
    FileProvenance,
    ProvenanceConsistency,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    RiskFlag,
    VulnerabilityRecord,
)

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def _read_snapshot(name: str) -> str:
    return (SNAPSHOT_DIR / name).read_text(encoding="utf-8").strip()


def _dump_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


class ContractTests(unittest.TestCase):
    def test_json_schema_snapshot(self) -> None:
        schema = get_json_schema()

        self.assertEqual(schema["$id"], JSON_SCHEMA_ID)
        self.assertEqual(schema["properties"]["schema_version"]["const"], JSON_SCHEMA_VERSION)
        self.assertEqual(_dump_json(schema), _read_snapshot("contract_schema.json"))

    def test_report_payload_snapshot_verified_release(self) -> None:
        report = TrustReport(
            project="demo",
            version="1.2.3",
            summary="Demo package",
            package_url="https://pypi.org/project/demo/1.2.3/",
            declared_repository_urls=["https://github.com/example/demo"],
            repository_urls=["https://github.com/example/demo"],
            expected_repository="https://github.com/example/demo",
            ownership={
                "organization": "example-org",
                "roles": [{"role": "Owner", "user": "maintainer"}],
                "support": "security@example.com",
            },
            vulnerabilities=[
                VulnerabilityRecord(
                    id="PYSEC-2026-1",
                    summary="Example vuln",
                    aliases=["CVE-2026-0001"],
                    source="PyPI",
                    fixed_in=["1.2.4"],
                    link="https://example.com/advisory",
                )
            ],
            files=[
                FileProvenance(
                    filename="demo-1.2.3-py3-none-any.whl",
                    url="https://files.pythonhosted.org/packages/demo.whl",
                    sha256="abc123",
                    has_provenance=True,
                    verified=True,
                    attestation_count=1,
                    verified_attestation_count=1,
                    observed_sha256="abc123",
                    publisher_identities=[
                        PublisherIdentity(
                            kind="GitHub",
                            repository="https://github.com/example/demo",
                            workflow=".github/workflows/release.yml",
                            environment="release",
                            raw={"repository": "example/demo"},
                        )
                    ],
                )
            ],
            coverage=CoverageSummary(
                total_files=1,
                files_with_provenance=1,
                verified_files=1,
                status="all-verified",
            ),
            publisher_trust=PublisherTrustSummary(
                depth_score=5,
                depth_label="strong",
                verified_publishers=[
                    "GitHub:https://github.com/example/demo:.github/workflows/release.yml"
                ],
                unique_verified_repositories=["https://github.com/example/demo"],
                unique_verified_workflows=[".github/workflows/release.yml"],
            ),
            provenance_consistency=ProvenanceConsistency(
                has_sdist=False,
                has_wheel=True,
                sdist_wheel_consistent=None,
            ),
            release_drift=ReleaseDriftSummary(
                compared_to_version="1.2.2",
                publisher_repository_drift=False,
                publisher_workflow_drift=False,
                previous_repositories=["https://github.com/example/demo"],
                previous_workflows=[".github/workflows/release.yml"],
            ),
            risk_flags=[
                RiskFlag(
                    code="manual_review",
                    severity="medium",
                    message="Review publisher change window.",
                    why=["Change landed recently."],
                    remediation=["Require reviewer sign-off."],
                )
            ],
            recommendation="review-required",
        )

        self.assertEqual(
            _dump_json(report.to_dict()),
            _read_snapshot("report_verified.json"),
        )

    def test_report_payload_snapshot_minimal_release(self) -> None:
        report = TrustReport(
            project="demo",
            version="0.0.1",
            summary=None,
            package_url="https://pypi.org/project/demo/0.0.1/",
        )

        self.assertEqual(
            _dump_json(report.to_dict()),
            _read_snapshot("report_minimal.json"),
        )
