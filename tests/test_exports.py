from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch
from xml.etree import ElementTree

import trustcheck.exports as exports
from trustcheck.exports import (
    CYCLONEDX_NAMESPACE,
    ExportPackage,
    SourceLocation,
    export_packages_from_payload,
    package_purl,
    recommended_extension,
    render_export,
    render_payload_export,
)
from trustcheck.models import (
    ArtifactDiagnostic,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    PolicyEvaluation,
    PolicyViolation,
    ReportDiagnostics,
    RiskFlag,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from trustcheck.resolver import ArtifactReference

GENERATED_AT = datetime(2026, 6, 13, 9, 30, tzinfo=timezone.utc)


def make_report() -> TrustReport:
    return TrustReport(
        project="Demo_Package",
        version="1.2.3",
        summary="Example | package",
        package_url="https://pypi.org/project/demo-package/1.2.3/",
        repository_urls=["https://github.com/example/demo-package"],
        vulnerabilities=[
            VulnerabilityRecord(
                id="CVE-2026-1234",
                summary="Example vulnerability",
                aliases=["GHSA-abcd-1234-5678"],
                source="OSV",
                severity="HIGH",
                cvss_score=8.8,
                cvss_vector=(
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                ),
                cvss_version="3.1",
                cwes=["CWE-79", "CWE-89"],
                fixed_in=["1.2.4"],
                link="https://osv.dev/vulnerability/CVE-2026-1234",
                kev=True,
                kev_date_added="2026-05-01",
                kev_due_date="2026-05-22",
                kev_required_action="Apply the vendor update.",
                kev_known_ransomware_campaign_use="Known",
                epss_score=0.8123,
                epss_percentile=0.9812,
                epss_date="2026-06-12",
                suppression=VulnerabilitySuppression(
                    vulnerability_id="CVE-2026-1234",
                    owner="security@example.com",
                    justification="Upgrade is scheduled for the next release.",
                    expires="2026-06-30",
                    status="active",
                ),
            )
        ],
        files=[
            FileProvenance(
                filename="demo_package-1.2.3-py3-none-any.whl",
                url="https://files.example/demo.whl",
                sha256="a" * 64,
                observed_sha256="a" * 64,
                has_provenance=True,
                verified=False,
                attestation_count=1,
                verified_attestation_count=0,
                error="signature did not verify",
            )
        ],
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1,
            verified_files=0,
            status="unverified",
        ),
        dependencies=[
            DependencyInspection(
                requirement="child>=2",
                project="child",
                version="2.0.0",
                depth=1,
                parent_project="Demo_Package",
                parent_version="1.2.3",
                package_url="https://pypi.org/project/child/2.0.0/",
                recommendation="metadata-only",
            )
        ],
        dependency_summary=DependencySummary(
            requested=True,
            total_declared=1,
            total_inspected=1,
            unique_dependencies=1,
            max_depth=1,
            highest_risk_recommendation="metadata-only",
            metadata_only_projects=["child"],
        ),
        risk_flags=[
            RiskFlag(
                code="artifact_signature_invalid",
                severity="high",
                message="Artifact signature is invalid.",
                why=["Verification failed."],
                remediation=["Reject the artifact."],
            )
        ],
        recommendation="high-risk",
        policy=PolicyEvaluation(
            profile="strict",
            passed=False,
            enforced=True,
            violations=[
                PolicyViolation(
                    code="verified_provenance_required",
                    severity="high",
                    message="Every artifact must verify.",
                )
            ],
        ),
        diagnostics=ReportDiagnostics(
            artifact_failures=[
                ArtifactDiagnostic(
                    filename="demo_package-1.2.3-py3-none-any.whl",
                    stage="verification",
                    code="verification",
                    subcode="attestation_verification_failed",
                    message="signature did not verify",
                )
            ]
        ),
    )


def make_package() -> ExportPackage:
    return ExportPackage(
        report=make_report(),
        source=SourceLocation("requirements.txt", 7),
        artifacts=(
            ArtifactReference(
                filename="demo_package-1.2.3-py3-none-any.whl",
                url="https://files.example/demo.whl",
                hashes=(
                    ("sha256", "a" * 64),
                    ("sha512", "b" * 128),
                ),
                size=42,
            ),
        ),
    )


def make_sparse_report() -> TrustReport:
    return TrustReport(
        project="Sparse",
        version="0.1",
        summary=None,
        package_url="https://packages.example/sparse/0.1",
        vulnerabilities=[
            VulnerabilityRecord(
                id="GHSA-sparse",
                summary="Review manually",
            )
        ],
        dependencies=[
            DependencyInspection(
                requirement="empty==1",
                project="empty",
                version="1",
                depth=1,
                package_url=None,
                recommendation="review-required",
            )
        ],
        risk_flags=[
            RiskFlag(
                code="needs review",
                severity="moderate",
                message="Review this package.",
            ),
            RiskFlag(
                code="informational",
                severity="low",
                message="Informational finding.",
            ),
        ],
        recommendation="review-required",
        policy=PolicyEvaluation(
            profile="default",
            passed=False,
            violations=[
                PolicyViolation(
                    code="manual_review",
                    severity="warning",
                    message="Manual review is required.",
                )
            ],
        ),
    )


class ExportTests(unittest.TestCase):
    def test_sarif_uses_stable_fingerprints_rules_and_source_locations(self) -> None:
        first = json.loads(
            render_export(
                "sarif",
                [make_package()],
                source_name="requirements.txt",
                generated_at=GENERATED_AT,
            )
        )
        second = json.loads(
            render_export(
                "sarif",
                [make_package()],
                source_name="requirements.txt",
                generated_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            )
        )

        self.assertEqual(first["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", first["$schema"])
        results = first["runs"][0]["results"]
        self.assertGreaterEqual(len(results), 5)
        self.assertEqual(
            [item["partialFingerprints"] for item in results],
            [
                item["partialFingerprints"]
                for item in second["runs"][0]["results"]
            ],
        )
        self.assertTrue(
            all(
                item["locations"][0]["physicalLocation"]["region"]["startLine"]
                == 7
                for item in results
            )
        )
        self.assertTrue(
            any(item["ruleId"] == "TC-VULNERABILITY" for item in results)
        )
        self.assertTrue(
            any(item["ruleId"].startswith("TC-POLICY-") for item in results)
        )
        vulnerability = next(
            item for item in results
            if item["ruleId"] == "TC-VULNERABILITY"
        )
        self.assertTrue(vulnerability["properties"]["cisaKev"])
        self.assertEqual(vulnerability["properties"]["epssScore"], 0.8123)
        self.assertEqual(
            vulnerability["properties"]["suppression"]["status"],
            "active",
        )

    def test_cyclonedx_json_contains_inventory_hashes_and_trust_properties(self) -> None:
        payload = json.loads(
            render_export(
                "cyclonedx-json",
                [make_package()],
                source_name="requirements.txt",
                generated_at=GENERATED_AT,
            )
        )

        self.assertEqual(payload["bomFormat"], "CycloneDX")
        self.assertEqual(payload["specVersion"], "1.6")
        self.assertEqual(payload["metadata"]["timestamp"], "2026-06-13T09:30:00Z")
        root = next(
            item for item in payload["components"]
            if item["name"] == "Demo_Package"
        )
        property_names = {item["name"] for item in root["properties"]}
        self.assertIn("trustcheck:policy:passed", property_names)
        self.assertIn("trustcheck:provenance:status", property_names)
        self.assertIn(
            "trustcheck:artifact:demo_package-1.2.3-py3-none-any.whl:sha512",
            property_names,
        )
        self.assertEqual(root["hashes"][0]["content"], "a" * 64)
        self.assertEqual(payload["vulnerabilities"][0]["id"], "CVE-2026-1234")
        vulnerability = payload["vulnerabilities"][0]
        self.assertEqual(vulnerability["cwes"], [79, 89])
        self.assertEqual(vulnerability["ratings"][0]["score"], 8.8)
        self.assertEqual(vulnerability["ratings"][0]["method"], "CVSSv31")
        self.assertEqual(
            vulnerability["ratings"][0]["vector"],
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        )
        vulnerability_properties = {
            item["name"]: item["value"]
            for item in vulnerability["properties"]
        }
        self.assertEqual(
            vulnerability_properties["trustcheck:vulnerability:cisa-kev"],
            "true",
        )
        self.assertIn(
            '"status":"active"',
            vulnerability_properties["trustcheck:vulnerability:suppression"],
        )
        self.assertIn(
            package_purl("child", "2.0.0"),
            {
                component["bom-ref"]
                for component in payload["components"]
            },
        )

    def test_cyclonedx_xml_matches_json_semantics(self) -> None:
        rendered = render_export(
            "cyclonedx-xml",
            [make_package()],
            source_name="requirements.txt",
            generated_at=GENERATED_AT,
        )
        root = ElementTree.fromstring(rendered)
        namespace = {"cdx": CYCLONEDX_NAMESPACE}

        self.assertEqual(root.tag, f"{{{CYCLONEDX_NAMESPACE}}}bom")
        self.assertEqual(
            root.findtext("cdx:metadata/cdx:timestamp", namespaces=namespace),
            "2026-06-13T09:30:00Z",
        )
        self.assertEqual(
            root.findtext(
                "cdx:vulnerabilities/cdx:vulnerability/cdx:id",
                namespaces=namespace,
            ),
            "CVE-2026-1234",
        )
        self.assertEqual(
            root.findtext(
                "cdx:vulnerabilities/cdx:vulnerability/"
                "cdx:affects/cdx:target/cdx:ref",
                namespaces=namespace,
            ),
            package_purl("demo-package", "1.2.3"),
        )
        self.assertEqual(
            root.findtext(
                "cdx:vulnerabilities/cdx:vulnerability/"
                "cdx:ratings/cdx:rating/cdx:score",
                namespaces=namespace,
            ),
            "8.8",
        )
        self.assertEqual(
            root.findtext(
                "cdx:vulnerabilities/cdx:vulnerability/"
                "cdx:ratings/cdx:rating/cdx:method",
                namespaces=namespace,
            ),
            "CVSSv31",
        )
        self.assertEqual(
            [
                item.text
                for item in root.findall(
                    "cdx:vulnerabilities/cdx:vulnerability/"
                    "cdx:cwes/cdx:cwe",
                    namespace,
                )
            ],
            ["79", "89"],
        )
        properties = root.findall(
            ".//cdx:component/cdx:properties/cdx:property",
            namespace,
        )
        self.assertTrue(
            any(
                item.attrib["name"] == "trustcheck:provenance:status"
                and item.text == "unverified"
                for item in properties
            )
        )

    def test_spdx_contains_packages_relationships_annotations_and_checksums(self) -> None:
        payload = json.loads(
            render_export(
                "spdx-json",
                [make_package()],
                source_name="requirements.txt",
                generated_at=GENERATED_AT,
            )
        )

        self.assertEqual(payload["spdxVersion"], "SPDX-2.3")
        self.assertEqual(payload["dataLicense"], "CC0-1.0")
        self.assertTrue(payload["documentNamespace"].startswith(
            "https://trustcheck.dev/spdx/"
        ))
        root = next(
            item for item in payload["packages"]
            if item["name"] == "Demo_Package"
        )
        self.assertIn("trustcheck:provenance:status=unverified", root["comment"])
        self.assertEqual(
            {item["algorithm"] for item in root["checksums"]},
            {"SHA256", "SHA512"},
        )
        self.assertTrue(
            any(
                item["relationshipType"] == "DEPENDS_ON"
                for item in payload["relationships"]
            )
        )
        self.assertTrue(
            any(
                "trustcheck:vulnerability:CVE-2026-1234"
                in item["comment"]
                for item in payload["annotations"]
            )
        )
        self.assertIn("kev=true", root["comment"])
        self.assertIn("epss=0.8123", root["comment"])

    def test_openvex_marks_observed_vulnerability_affected(self) -> None:
        payload = json.loads(
            render_export(
                "openvex",
                [make_package()],
                source_name="requirements.txt",
                generated_at=GENERATED_AT,
            )
        )

        self.assertEqual(payload["@context"], "https://openvex.dev/ns/v0.2.0")
        statement = payload["statements"][0]
        self.assertEqual(statement["status"], "affected")
        self.assertEqual(statement["vulnerability"]["name"], "CVE-2026-1234")
        self.assertEqual(
            statement["products"][0]["identifiers"]["purl"],
            package_purl("Demo_Package", "1.2.3"),
        )
        self.assertIn("1.2.4", statement["action_statement"])
        self.assertIn("CISA KEV", statement["status_notes"])
        self.assertIn("EPSS probability 0.8123", statement["status_notes"])
        self.assertIn("owned by security@example.com", statement["status_notes"])
        with self.assertRaisesRegex(
            ValueError,
            "requires at least one vulnerability statement",
        ):
            render_export(
                "openvex",
                [],
                source_name="empty",
                generated_at=GENERATED_AT,
            )

    def test_markdown_and_failure_rendering_escape_tables(self) -> None:
        rendered = render_export(
            "markdown",
            [make_package()],
            source_name="requirements.txt",
            failures=[
                {
                    "requirement": "broken|package",
                    "message": "resolver | failed",
                }
            ],
            generated_at=GENERATED_AT,
        )

        self.assertIn("# Trustcheck Report", rendered)
        self.assertIn("Example vulnerability", rendered)
        self.assertIn("Example \\| package", rendered)
        self.assertIn("broken\\|package", rendered)
        self.assertIn("Every artifact must verify.", rendered)
        self.assertIn("0.8123", rendered)
        self.assertIn("security@example.com", rendered)

    def test_json_payload_round_trip_supports_action_conversion(self) -> None:
        package = make_package()
        payload = {
            "file": "requirements.txt",
            "reports": [package.report.to_dict()["report"]],
            "resolved": [
                {
                    "project": package.report.project,
                    "version": package.report.version,
                    "source_file": "requirements.txt",
                    "source_line": 7,
                    "artifacts": [
                        artifact.to_dict()
                        for artifact in package.artifacts
                    ],
                }
            ],
            "failures": [],
        }

        packages, source_name, failures = export_packages_from_payload(payload)
        rendered = json.loads(
            render_payload_export(
                "sarif",
                payload,
                generated_at=GENERATED_AT,
            )
        )

        self.assertEqual(source_name, "requirements.txt")
        self.assertEqual(failures, [])
        self.assertEqual(packages[0].source, SourceLocation("requirements.txt", 7))
        self.assertEqual(
            rendered["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"
            ]["region"]["startLine"],
            7,
        )

    def test_recommended_extensions_and_invalid_format(self) -> None:
        self.assertEqual(recommended_extension("sarif"), ".sarif")
        self.assertEqual(recommended_extension("cyclonedx-json"), ".cdx.json")
        self.assertEqual(recommended_extension("spdx-json"), ".spdx.json")
        with self.assertRaisesRegex(ValueError, "unsupported output format"):
            recommended_extension("unknown")
        with self.assertRaisesRegex(ValueError, "unsupported industry"):
            render_export(
                "json",
                [make_package()],
                source_name="requirements.txt",
            )

    def test_sparse_reports_cover_optional_fields_and_url_locations(self) -> None:
        package = ExportPackage(report=make_sparse_report())
        sarif = json.loads(
            render_export(
                "sarif",
                [package],
                source_name="sparse",
                generated_at=GENERATED_AT,
            )
        )
        results = sarif["runs"][0]["results"]
        self.assertTrue(all(
            "region" not in item["locations"][0]["physicalLocation"]
            for item in results
        ))
        self.assertEqual(
            {item["level"] for item in results},
            {"note", "warning"},
        )
        self.assertTrue(all(
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == package.report.package_url
            for item in results
        ))

        cyclonedx = json.loads(
            render_export(
                "cyclonedx-json",
                [package],
                source_name="sparse",
                generated_at=GENERATED_AT,
            )
        )
        self.assertNotIn("ratings", cyclonedx["vulnerabilities"][0])
        self.assertNotIn("advisories", cyclonedx["vulnerabilities"][0])
        root_component = next(
            item for item in cyclonedx["components"]
            if item["name"] == "Sparse"
        )
        self.assertNotIn("description", root_component)
        self.assertNotIn("hashes", root_component)
        dependency = next(
            item for item in cyclonedx["components"]
            if item["name"] == "empty"
        )
        self.assertNotIn("externalReferences", dependency)

        xml_root = ElementTree.fromstring(
            render_export(
                "cyclonedx-xml",
                [package],
                source_name="sparse",
                generated_at=GENERATED_AT,
            )
        )
        namespace = {"cdx": CYCLONEDX_NAMESPACE}
        vulnerability = xml_root.find(
            "cdx:vulnerabilities/cdx:vulnerability",
            namespace,
        )
        self.assertIsNotNone(vulnerability)
        assert vulnerability is not None
        self.assertIsNone(vulnerability.find("cdx:ratings", namespace))
        self.assertIsNone(
            vulnerability.find("cdx:source/cdx:url", namespace)
        )

        openvex = json.loads(
            render_export(
                "openvex",
                [package],
                source_name="sparse",
                generated_at=GENERATED_AT,
            )
        )
        statement = openvex["statements"][0]
        self.assertNotIn("hashes", statement["products"][0])
        self.assertIn("vendor-recommended mitigation", statement[
            "action_statement"
        ])

        markdown = render_export(
            "markdown",
            [package],
            source_name="sparse",
            generated_at=GENERATED_AT,
        )
        self.assertNotIn("### Artifacts", markdown)
        self.assertIn("### Risk Flags", markdown)

    def test_failure_only_documents_preserve_operational_findings(self) -> None:
        failures = [
            {
                "requirement": "",
                "message": "",
            }
        ]
        sarif = json.loads(
            render_export(
                "sarif",
                [],
                source_name=r"C:\work\requirements.txt",
                failures=failures,
                generated_at=GENERATED_AT,
            )
        )
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "TC-SCAN-FAILURE")
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"],
            "C:/work/requirements.txt",
        )
        self.assertEqual(
            sarif["runs"][0]["properties"]["trustcheck.recommendation"],
            "error",
        )

        cyclonedx = json.loads(
            render_export(
                "cyclonedx-json",
                [],
                source_name="requirements.txt",
                failures=failures,
                generated_at=GENERATED_AT,
            )
        )
        self.assertEqual(cyclonedx["components"], [])
        self.assertTrue(any(
            item["name"] == "trustcheck:scan-failure"
            for item in cyclonedx["metadata"]["properties"]
        ))
        xml_root = ElementTree.fromstring(
            render_export(
                "cyclonedx-xml",
                [],
                source_name="requirements.txt",
                failures=failures,
                generated_at=GENERATED_AT,
            )
        )
        namespace = {"cdx": CYCLONEDX_NAMESPACE}
        self.assertIsNone(xml_root.find("cdx:vulnerabilities", namespace))

        spdx = json.loads(
            render_export(
                "spdx-json",
                [],
                source_name="requirements.txt",
                failures=failures,
                generated_at=GENERATED_AT,
            )
        )
        self.assertIn(
            "trustcheck:scan-failure:unknown=unknown failure",
            spdx["annotations"][0]["comment"],
        )
        markdown = render_export(
            "markdown",
            [],
            source_name="requirements.txt",
            failures=failures,
            generated_at=GENERATED_AT,
        )
        self.assertIn("## Scan Failures", markdown)
        self.assertIn("`unknown`: unknown failure", markdown)

    def test_payload_conversion_handles_single_reports_and_noisy_metadata(self) -> None:
        report_payload = make_report().to_dict()["report"]
        packages, source_name, failures = export_packages_from_payload(
            {"report": report_payload}
        )
        self.assertEqual(source_name, "Demo_Package 1.2.3")
        self.assertEqual(packages[0].source.uri, make_report().package_url)
        self.assertEqual(failures, [])

        with self.assertRaisesRegex(ValueError, "no report"):
            export_packages_from_payload({})

        noisy_payload = {
            "reports": [None, report_payload],
            "resolved": [
                None,
                {"project": 1, "version": "1"},
                {
                    "project": "Demo_Package",
                    "version": "1.2.3",
                    "source_file": "pylock.toml",
                    "source_line": "not-an-integer",
                    "artifacts": [
                        None,
                        {
                            "filename": "demo.whl",
                            "hashes": "not-a-table",
                            "size": "unknown",
                        },
                        {
                            "url": "https://files.example/demo.tar.gz",
                            "path": "cache/demo.tar.gz",
                            "hashes": {"sha256": "c" * 64},
                            "size": 12,
                            "kind": "sdist",
                        },
                    ],
                },
            ],
            "failures": [None, {"requirement": "", "message": ""}],
        }
        packages, source_name, failures = export_packages_from_payload(
            noisy_payload
        )
        self.assertEqual(source_name, "trustcheck scan")
        self.assertEqual(packages[0].source, SourceLocation("pylock.toml"))
        self.assertEqual(len(packages[0].artifacts), 2)
        self.assertEqual(
            packages[0].artifacts[1].hashes,
            (("sha256", "c" * 64),),
        )
        self.assertEqual(
            failures,
            [{"requirement": "unknown", "message": "unknown failure"}],
        )

        packages, _, failures = export_packages_from_payload({
            "reports": [report_payload],
            "resolved": "invalid",
            "failures": "invalid",
        })
        self.assertEqual(packages[0].source.uri, "trustcheck scan")
        self.assertEqual(failures, [])

    def test_conflicting_and_unknown_hashes_are_not_misrepresented(self) -> None:
        package = ExportPackage(
            report=replace(
                make_sparse_report(),
                vulnerabilities=[],
                dependencies=[],
                risk_flags=[],
                policy=PolicyEvaluation(),
            ),
            artifacts=(
                ArtifactReference(
                    filename="one.whl",
                    hashes=(("sha256", "a" * 64),),
                ),
                ArtifactReference(
                    filename="two.whl",
                    hashes=(
                        ("sha256", "b" * 64),
                        ("crc32", "12345678"),
                    ),
                ),
            ),
        )
        cyclonedx = json.loads(
            render_export(
                "cyclonedx-json",
                [package],
                source_name="hashes",
                generated_at=GENERATED_AT,
            )
        )
        component = cyclonedx["components"][0]
        self.assertNotIn("hashes", component)

        spdx = json.loads(
            render_export(
                "spdx-json",
                [package],
                source_name="hashes",
                generated_at=GENERATED_AT,
            )
        )
        self.assertNotIn("checksums", spdx["packages"][0])
        openvex = json.loads(
            render_export(
                "openvex",
                [replace(package, report=replace(
                    package.report,
                    vulnerabilities=[
                        VulnerabilityRecord(
                            id="CVE-no-supported-hash",
                            summary="No supported product hash",
                        )
                    ],
                ))],
                source_name="hashes",
                generated_at=GENERATED_AT,
            )
        )
        self.assertNotIn("hashes", openvex["statements"][0]["products"][0])

    def test_internal_serialization_guards_are_deterministic(self) -> None:
        naive = datetime(2026, 6, 13, 9, 30)
        payload = json.loads(
            render_export(
                "cyclonedx-json",
                [],
                source_name="empty",
                generated_at=naive,
            )
        )
        self.assertEqual(payload["metadata"]["timestamp"], "2026-06-13T09:30:00Z")

        with patch.object(
            exports,
            "package_version",
            side_effect=PackageNotFoundError,
        ):
            payload = json.loads(
                render_export(
                    "cyclonedx-json",
                    [],
                    source_name="empty",
                    generated_at=GENERATED_AT,
                )
            )
        self.assertEqual(
            payload["metadata"]["tools"]["components"][0]["version"],
            "0+unknown",
        )

        parent = ElementTree.Element("parent")
        exports._xml_properties(parent, None)
        exports._xml_properties(
            parent,
            [None, {"name": "", "value": ""}],
        )
        self.assertEqual(len(parent), 1)
        self.assertEqual(
            parent[0][0].attrib["name"],
            "trustcheck:property",
        )
        self.assertEqual(
            exports._dedupe_dicts([{"a": "1"}, {"a": "1"}]),
            [{"a": "1"}],
        )
        self.assertEqual(exports._rule_token("***"), "TRUSTCHECK")
        self.assertEqual(exports._property_token("***"), "artifact")


if __name__ == "__main__":
    unittest.main()
