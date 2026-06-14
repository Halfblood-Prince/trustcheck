from __future__ import annotations

import json
import unittest
from pathlib import Path

from trustcheck import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, TrustReport, get_json_schema
from trustcheck.models import (
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    ProvenanceConsistency,
    ProvenanceIssue,
    ProvenanceMaterial,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    RiskFlag,
    SlsaProvenance,
    VulnerabilityRecord,
    VulnerabilitySuppression,
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
            declared_dependencies=["depalpha>=1.0"],
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
                    severity="HIGH",
                    cvss_score=8.8,
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                    ),
                    cvss_version="3.1",
                    cwes=["CWE-79", "CWE-89"],
                    fixed_in=["1.2.4"],
                    link="https://example.com/advisory",
                    kev=True,
                    kev_date_added="2026-05-01",
                    kev_due_date="2026-05-22",
                    kev_required_action="Apply the vendor update.",
                    kev_known_ransomware_campaign_use="Known",
                    epss_score=0.8123,
                    epss_percentile=0.9812,
                    epss_date="2026-06-12",
                    suppression=VulnerabilitySuppression(
                        vulnerability_id="CVE-2026-0001",
                        owner="security@example.com",
                        justification="Upgrade is scheduled for the next release.",
                        expires="2026-06-30",
                        status="active",
                    ),
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
                    slsa_provenance=[
                        SlsaProvenance(
                            valid=True,
                            signer_identity=(
                                "GitHub:https://github.com/example/demo:"
                                ".github/workflows/release.yml"
                            ),
                            source_uri=(
                                "git+https://github.com/example/demo"
                                "@refs/tags/v1.2.3"
                            ),
                            source_repository="https://github.com/example/demo",
                            source_commit="a" * 40,
                            builder_id="https://github.com/actions/runner",
                            build_type=(
                                "https://slsa-framework.github.io/"
                                "github-actions-buildtypes/workflow/v1"
                            ),
                            workflow_uri="https://github.com/example/demo",
                            workflow_path=".github/workflows/release.yml",
                            workflow_ref="refs/tags/v1.2.3",
                            workflow_ref_immutable=False,
                            invocation_id=(
                                "https://github.com/example/demo/"
                                "actions/runs/123/attempts/1"
                            ),
                            materials=[
                                ProvenanceMaterial(
                                    uri=(
                                        "git+https://github.com/example/demo"
                                        "@refs/tags/v1.2.3"
                                    ),
                                    digests={"gitcommit": "a" * 40},
                                    source=True,
                                )
                            ],
                            issues=[
                                ProvenanceIssue(
                                    code="mutable_workflow_reference",
                                    severity="medium",
                                    message=(
                                        "The SLSA workflow reference is mutable."
                                    ),
                                    evidence=["refs/tags/v1.2.3"],
                                )
                            ],
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
                builder_consistent=None,
                source_commit_consistent=None,
                build_type_consistent=None,
            ),
            release_drift=ReleaseDriftSummary(
                compared_to_version="1.2.2",
                publisher_repository_drift=False,
                publisher_workflow_drift=False,
                signer_drift=False,
                builder_drift=False,
                source_commit_drift=True,
                build_type_drift=False,
                previous_signers=[
                    "GitHub:https://github.com/example/demo:"
                    ".github/workflows/release.yml"
                ],
                previous_repositories=["https://github.com/example/demo"],
                previous_workflows=[".github/workflows/release.yml"],
                previous_builders=["https://github.com/actions/runner"],
                previous_source_commits=["b" * 40],
                previous_build_types=[
                    "https://slsa-framework.github.io/"
                    "github-actions-buildtypes/workflow/v1"
                ],
            ),
            dependencies=[
                DependencyInspection(
                    requirement="depalpha>=1.0",
                    project="depalpha",
                    version="1.4.0",
                    depth=1,
                    parent_project="demo",
                    parent_version="1.2.3",
                    package_url="https://pypi.org/project/depalpha/1.4.0/",
                    recommendation="review-required",
                )
            ],
            dependency_summary=DependencySummary(
                requested=True,
                total_declared=1,
                total_inspected=1,
                unique_dependencies=1,
                max_depth=1,
                highest_risk_recommendation="review-required",
                highest_risk_projects=["depalpha"],
                review_required_projects=["depalpha"],
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
