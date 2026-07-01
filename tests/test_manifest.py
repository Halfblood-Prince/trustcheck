from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import EXIT_OK, EXIT_POLICY_FAILURE, ScanTarget, main
from trustcheck.manifest import (
    TRUST_MANIFEST_SCHEMA,
    ManifestIssue,
    ManifestVerificationResult,
    build_manifest,
    load_manifest,
    normalize_manifest,
    render_manifest_verification_text,
    verify_manifest,
    write_manifest,
)
from trustcheck.models import (
    ArtifactInspection,
    CoverageSummary,
    DynamicAnalysisResult,
    FileProvenance,
    MaliciousPackageAssessment,
    PublisherIdentity,
    SlsaProvenance,
    TrustReport,
)
from trustcheck.pypi import PypiClientError
from trustcheck.resolver import ArtifactReference


def make_report(
    *,
    project: str = "requests",
    version: str = "2.32.5",
    repository: str = "https://github.com/psf/requests",
    workflow: str = ".github/workflows/release.yml",
    builder: str = "https://github.com/actions/runner",
    build_type: str = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
    has_provenance: bool = True,
    verified: bool = True,
    native_files: tuple[str, ...] = (),
    malicious_score: int = 0,
    dynamic_executed: bool = False,
) -> TrustReport:
    files = [
        FileProvenance(
            filename=f"{project}-{version}-py3-none-any.whl",
            url=f"https://files.pythonhosted.org/packages/{project}.whl",
            sha256="a" * 64,
            has_provenance=has_provenance,
            verified=verified,
            attestation_count=1 if has_provenance else 0,
            verified_attestation_count=1 if verified else 0,
            publisher_identities=(
                [
                    PublisherIdentity(
                        kind="GitHub",
                        repository=repository,
                        workflow=workflow,
                        environment=None,
                    )
                ]
                if verified
                else []
            ),
            slsa_provenance=(
                [
                    SlsaProvenance(
                        valid=True,
                        source_repository=repository,
                        builder_id=builder,
                        build_type=build_type,
                        workflow_path=workflow,
                    )
                ]
                if verified
                else []
            ),
            artifact=ArtifactInspection(
                inspected=True,
                native_files=list(native_files),
            ),
            dynamic_analysis=DynamicAnalysisResult(
                enabled=dynamic_executed,
                executed=dynamic_executed,
            ),
        )
    ]
    return TrustReport(
        project=project,
        version=version,
        summary=f"{project} package",
        package_url=f"https://pypi.org/project/{project}/{version}/",
        declared_repository_urls=[repository],
        repository_urls=[repository],
        files=files,
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1 if has_provenance else 0,
            verified_files=1 if verified else 0,
            status=(
                "all-verified"
                if verified
                else "partial"
                if has_provenance
                else "none"
            ),
        ),
        malicious_package=MaliciousPackageAssessment(score=malicious_score),
    )


def make_target(
    *,
    project: str = "requests",
    version: str = "2.32.5",
    index_url: str | None = "https://pypi.org/simple",
    source_type: str = "index",
    dependency_confusion: tuple[str, ...] = (),
) -> ScanTarget:
    return ScanTarget(
        requirement=f"{project}=={version}",
        project=project,
        version=version,
        index_url=index_url,
        source_type=source_type,
        dependency_confusion=dependency_confusion,
    )


class ManifestModelTests(unittest.TestCase):
    def test_build_manifest_records_trust_baseline(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])

        self.assertEqual(manifest["schema"], TRUST_MANIFEST_SCHEMA)
        package = manifest["packages"]["requests"]
        self.assertEqual(package["approved_version"], "2.32.5")
        self.assertEqual(package["repository"], "https://github.com/psf/requests")
        self.assertEqual(package["owner"], "psf")
        self.assertEqual(package["trusted_publisher"]["provider"], "github")
        self.assertEqual(package["trusted_publisher"]["organization"], "psf")
        self.assertEqual(
            package["trusted_publisher"]["workflow"],
            ".github/workflows/release.yml",
        )
        self.assertEqual(package["slsa"]["builder"], "https://github.com/actions/runner")
        self.assertEqual(package["require_verified_provenance"], "all")
        self.assertEqual(package["min_verified_attestations"], 1)
        self.assertEqual(package["permitted_indexes"], ["https://pypi.org/simple/"])
        self.assertFalse(package["allow_private_indexes"])
        self.assertFalse(package["allow_native_binaries"])
        self.assertEqual(package["max_malicious_score"], 15)

    def test_verify_manifest_passes_when_trust_matches(self) -> None:
        report = make_report()
        target = make_target()
        manifest = build_manifest([report], [target])

        result = verify_manifest(manifest, [report], [target])

        self.assertTrue(result.passed)
        self.assertEqual(result.violations, [])
        self.assertIn("No trust regressions", render_manifest_verification_text(result))

    def test_verify_manifest_detects_identity_build_index_and_artifact_regressions(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        regressed = make_report(
            version="2.33.0",
            repository="https://github.com/other/requests",
            workflow=".github/workflows/publish.yml",
            builder="https://example.com/custom-builder",
            build_type="https://example.com/build/v1",
            native_files=("requests/_speedups.so",),
            malicious_score=30,
        )
        target = make_target(
            version="2.33.0",
            index_url="https://private.example/simple",
            dependency_confusion=(
                "https://pypi.org/simple/",
                "https://private.example/simple/",
            ),
        )

        result = verify_manifest(manifest, [regressed], [target])
        codes = {issue.code for issue in result.violations}

        self.assertFalse(result.passed)
        self.assertIn("repository_changed", codes)
        self.assertIn("repository_owner_changed", codes)
        self.assertIn("trusted_publisher_organization_changed", codes)
        self.assertIn("trusted_publisher_workflow_changed", codes)
        self.assertIn("slsa_builder_changed", codes)
        self.assertIn("slsa_build_type_changed", codes)
        self.assertIn("index_origin_changed", codes)
        self.assertIn("private_index_not_allowed", codes)
        self.assertIn("dependency_confusion_detected", codes)
        self.assertIn("malicious_score_exceeded", codes)
        self.assertIn("native_binaries_introduced", codes)

    def test_verify_manifest_detects_disappearing_provenance(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        current = make_report(has_provenance=False, verified=False)

        result = verify_manifest(manifest, [current], [make_target()])
        codes = {issue.code for issue in result.violations}

        self.assertIn("trusted_publisher_missing", codes)
        self.assertIn("slsa_provenance_missing", codes)
        self.assertIn("provenance_missing", codes)
        self.assertIn("provenance_coverage_regressed", codes)
        self.assertIn("attestation_coverage_regressed", codes)

    def test_verify_manifest_applies_and_expires_package_exceptions(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        package = manifest["packages"]["requests"]
        package["exceptions"] = [
            {
                "code": "native_binaries_introduced",
                "owner": "security",
                "reason": "Reviewed platform wheel rollout.",
                "expires": "2026-07-02",
            }
        ]
        current = make_report(native_files=("requests/_speedups.so",))

        active = verify_manifest(
            manifest,
            [current],
            [make_target()],
            now=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        expired = verify_manifest(
            manifest,
            [current],
            [make_target()],
            now=datetime(2026, 7, 3, tzinfo=timezone.utc),
        )

        self.assertTrue(active.passed)
        self.assertEqual(active.suppressed[0].suppressed_by, "security")
        self.assertFalse(expired.passed)
        self.assertEqual(expired.violations[0].code, "native_binaries_introduced")

    def test_verify_manifest_flags_new_and_stale_packages(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        current = make_report(project="urllib3", repository="https://github.com/urllib3/urllib3")
        target = make_target(project="urllib3")

        result = verify_manifest(manifest, [current], [target])

        self.assertEqual(result.violations[0].code, "manifest_missing_package")
        self.assertEqual(result.warnings[0].code, "manifest_package_not_present")

    def test_manifest_issue_and_result_json_include_optional_fields(self) -> None:
        issue = ManifestIssue(
            package="requests",
            code="native_binaries_introduced",
            severity="high",
            message="Native binaries appeared.",
            expected="none",
            observed="requests/_speedups.so",
            suppressed_by="security",
            exception_expires="2026-07-02",
        )
        result = ManifestVerificationResult(
            checked_packages=1,
            violations=[issue],
            suppressed=[issue],
            warnings=[issue],
        )

        payload = result.to_dict()

        self.assertFalse(payload["passed"])
        self.assertEqual(payload["violations"][0]["expected"], "none")
        self.assertEqual(payload["suppressed"][0]["suppressed_by"], "security")
        self.assertEqual(payload["warnings"][0]["exception_expires"], "2026-07-02")

    def test_manifest_load_write_and_validation_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trustcheck.manifest.json"
            write_manifest(path, build_manifest([make_report()], [make_target()]))
            loaded = load_manifest(path)

        self.assertEqual(loaded["packages"]["requests"]["owner"], "psf")
        invalid_payloads = [
            [],
            {"schema": "urn:trustcheck:manifest:0", "packages": {}},
            {"schema": TRUST_MANIFEST_SCHEMA, "packages": []},
            {"schema": TRUST_MANIFEST_SCHEMA, "packages": {"": {}}},
            {"schema": TRUST_MANIFEST_SCHEMA, "packages": {"requests": []}},
            {
                "schema": TRUST_MANIFEST_SCHEMA,
                "packages": {"Requests": {}, "requests": {}},
            },
            {
                "schema": TRUST_MANIFEST_SCHEMA,
                "packages": {"requests": {"exceptions": "temporary"}},
            },
            {
                "schema": TRUST_MANIFEST_SCHEMA,
                "packages": {"requests": {"exceptions": [[]]}},
            },
            {
                "schema": TRUST_MANIFEST_SCHEMA,
                "packages": {"requests": {"exceptions": [{"owner": "security"}]}},
            },
            {
                "schema": TRUST_MANIFEST_SCHEMA,
                "packages": {
                    "requests": {
                        "exceptions": [
                            {
                                "code": "native_binaries_introduced",
                                "owner": "security",
                                "reason": "review",
                                "expires": "soon",
                            }
                        ]
                    }
                },
            },
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    normalize_manifest(payload)

    def test_manifest_baseline_handles_minimal_private_and_direct_origins(self) -> None:
        minimal = TrustReport(
            project="internal-sdk",
            version="1.0.0",
            summary=None,
            package_url="https://packages.example/internal-sdk/1.0.0/",
        )
        private_target = make_target(
            project="internal-sdk",
            version="1.0.0",
            index_url="https://user:token@packages.example/simple",
        )
        direct_target = ScanTarget(
            requirement="internal-sdk==1.0.0",
            project="internal-sdk",
            version="1.0.0",
            artifacts=(
                ArtifactReference(url="https://downloads.example/internal-sdk.whl"),
            ),
        )
        pypi_artifact_target = ScanTarget(
            requirement="requests==2.32.5",
            project="requests",
            version="2.32.5",
            artifacts=(
                ArtifactReference(url="https://files.pythonhosted.org/packages/requests.whl"),
            ),
        )

        private = build_manifest([minimal], [private_target])
        direct = build_manifest([minimal], [direct_target])
        pypi = build_manifest([make_report()], [pypi_artifact_target])

        private_package = private["packages"]["internal-sdk"]
        self.assertNotIn("repository", private_package)
        self.assertTrue(private_package["allow_private_indexes"])
        self.assertEqual(
            private_package["permitted_indexes"],
            ["https://<redacted>@packages.example/simple/"],
        )
        self.assertEqual(
            direct["packages"]["internal-sdk"]["permitted_indexes"],
            ["https://downloads.example/"],
        )
        self.assertEqual(
            pypi["packages"]["requests"]["permitted_indexes"],
            ["https://pypi.org/simple/"],
        )

    def test_verify_manifest_covers_policy_relaxations_and_edge_regressions(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        package = manifest["packages"]["requests"]
        package["trusted_publisher"]["provider"] = "gitlab"
        package["require_verified_provenance"] = "any"
        package["min_verified_attestations"] = "invalid"
        package["max_malicious_score"] = "invalid"
        package["allow_native_binaries"] = True
        package["allow_dynamic_execution"] = True
        package["permitted_indexes"] = None
        package["source_type"] = "index"

        current = make_report(
            has_provenance=True,
            verified=False,
            native_files=("requests/_speedups.so",),
            malicious_score=99,
            dynamic_executed=True,
        )
        target = make_target(source_type="vcs")

        result = verify_manifest(manifest, [current], [target])
        codes = {issue.code for issue in result.violations}

        self.assertIn("trusted_publisher_missing", codes)
        self.assertIn("slsa_provenance_missing", codes)
        self.assertIn("verified_provenance_missing", codes)
        self.assertIn("source_type_changed", codes)
        self.assertNotIn("malicious_score_exceeded", codes)
        self.assertNotIn("native_binaries_introduced", codes)
        self.assertNotIn("dynamic_execution_introduced", codes)

    def test_verify_manifest_reports_dynamic_execution_and_provider_change(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        package = manifest["packages"]["requests"]
        package["trusted_publisher"]["provider"] = "gitlab"
        package["slsa"].pop("builder")
        package["slsa"].pop("build_type")
        current = make_report(dynamic_executed=True)

        result = verify_manifest(manifest, [current], [make_target()])
        codes = {issue.code for issue in result.violations}

        self.assertIn("trusted_publisher_provider_changed", codes)
        self.assertIn("dynamic_execution_introduced", codes)

    def test_manifest_exceptions_support_wildcards_datetimes_and_naive_now(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        manifest["packages"]["requests"]["exceptions"] = [
            {
                "code": "unrelated",
                "owner": "security",
                "reason": "Does not match this issue.",
                "expires": "2026-07-02T00:00:00Z",
            },
            {
                "code": "*",
                "owner": "platform",
                "reason": "Temporarily reviewing dynamic analysis.",
                "expires": "2026-07-02T00:00:00Z",
            },
        ]
        current = make_report(dynamic_executed=True)

        result = verify_manifest(
            manifest,
            [current],
            [make_target()],
            now=datetime(2026, 7, 1),
        )
        rendered = render_manifest_verification_text(result)

        self.assertTrue(result.passed)
        self.assertEqual(result.suppressed[0].suppressed_by, "platform")
        self.assertIn("suppressed_by=platform", rendered)

    def test_verify_manifest_rejects_invalid_permitted_indexes_shape(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        manifest["packages"]["requests"]["permitted_indexes"] = "https://pypi.org/simple"

        with self.assertRaises(ValueError):
            verify_manifest(manifest, [make_report()], [make_target()])

    def test_manifest_covers_omitted_fields_provider_variants_and_fallback_origins(self) -> None:
        no_optional = ManifestIssue(
            package="requests",
            code="repository_changed",
            severity="high",
            message="Repository changed.",
        )
        self.assertEqual(
            sorted(no_optional.to_dict()),
            ["code", "message", "package", "severity"],
        )

        manifest = build_manifest([make_report()], [make_target()])
        package = manifest["packages"]["requests"]
        package.pop("owner")
        package.pop("trusted_publisher")
        package.pop("slsa")
        package["require_verified_provenance"] = "any"
        package["min_verified_attestations"] = False
        package["max_malicious_score"] = False
        result = verify_manifest(manifest, [make_report()], [make_target()])
        self.assertTrue(result.passed)

        stale = verify_manifest(manifest, [], [])
        self.assertIn("warnings:", render_manifest_verification_text(stale))

        without_owner = make_report(repository="https://example.com/not-a-forge")
        no_target_manifest = build_manifest([without_owner])
        self.assertEqual(
            no_target_manifest["packages"]["requests"]["permitted_indexes"],
            ["https://pypi.org/simple/"],
        )
        self.assertNotIn("owner", no_target_manifest["packages"]["requests"])

        fallback_target = ScanTarget(
            requirement="requests==2.32.5",
            project="requests",
            version="2.32.5",
            source_url="file:///tmp/requests.whl",
        )
        self.assertEqual(
            build_manifest([make_report()], [fallback_target])["packages"]["requests"][
                "permitted_indexes"
            ],
            ["https://pypi.org/simple/"],
        )
        source_url_target = ScanTarget(
            requirement="requests==2.32.5",
            project="requests",
            version="2.32.5",
            source_url="https://downloads.example/requests.whl",
        )
        self.assertEqual(
            build_manifest([make_report()], [source_url_target])["packages"]["requests"][
                "permitted_indexes"
            ],
            ["https://downloads.example/"],
        )

        provider_cases = [
            ("GitLab", "Group/Sub/Repo", "gitlab", "group/sub"),
            ("CircleCI", "https://example.com/org/repo", "circleci", None),
            ("Google", "https://example.com/org/repo", "google", None),
            ("Other", "https://example.com/org/repo", "other", None),
        ]
        for kind, repository, provider, organization in provider_cases:
            with self.subTest(kind=kind):
                report = make_report(project=f"demo-{provider}", repository=repository)
                report.files[0].publisher_identities[0].kind = kind
                report.files[0].slsa_provenance = [SlsaProvenance(valid=True)]
                baseline = build_manifest([report])["packages"][f"demo-{provider}"]
                self.assertEqual(baseline["trusted_publisher"]["provider"], provider)
                if organization is None:
                    self.assertNotIn("organization", baseline["trusted_publisher"])
                else:
                    self.assertEqual(
                        baseline["trusted_publisher"]["organization"],
                        organization,
                    )
                self.assertNotIn("slsa", baseline)

    def test_manifest_exception_validation_reports_each_required_field(self) -> None:
        invalid_exceptions = [
            {"code": "native_binaries_introduced", "reason": "review", "expires": "2026-07-01"},
            {"code": "native_binaries_introduced", "owner": "security", "expires": "2026-07-01"},
            {"code": "native_binaries_introduced", "owner": "security", "reason": "review"},
            {
                "code": "native_binaries_introduced",
                "owner": "security",
                "reason": "review",
                "expires": "2026-13-01T00:00:00Z",
            },
            None,
        ]
        for exception in invalid_exceptions:
            with self.subTest(exception=exception):
                with self.assertRaises(ValueError):
                    normalize_manifest(
                        {
                            "schema": TRUST_MANIFEST_SCHEMA,
                            "packages": {"requests": {"exceptions": [exception]}},
                        }
                    )


class ManifestCliTests(unittest.TestCase):
    def test_manifest_init_writes_json_baseline(self) -> None:
        targets = [make_target()]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trustcheck.manifest.json"
            stdout = io.StringIO()
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=targets),
                patch("trustcheck.cli.inspect_package", return_value=make_report()) as inspect,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "manifest",
                        "init",
                        "-f",
                        "requirements.lock",
                        "--output",
                        str(output),
                        "--format",
                        "json",
                    ]
                )

            self.assertEqual(exit_code, EXIT_OK)
            self.assertEqual(load_manifest(output)["packages"]["requests"]["owner"], "psf")
            self.assertEqual(json.loads(stdout.getvalue())["action"], "init")
            self.assertEqual(inspect.call_args.kwargs["scan_profile"], "full")
            self.assertEqual(inspect.call_args.kwargs["artifact_scope"], "all")
            self.assertTrue(inspect.call_args.kwargs["include_vulnerabilities"])

    def test_manifest_verify_returns_policy_failure_for_regression(self) -> None:
        targets = [make_target(version="2.33.0")]
        manifest = build_manifest([make_report()], [make_target()])
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "trustcheck.manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=targets),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=make_report(
                        version="2.33.0",
                        workflow=".github/workflows/publish.yml",
                    ),
                ),
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "manifest",
                        "verify",
                        "-f",
                        "requirements.lock",
                        "--manifest",
                        str(manifest_path),
                    ]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("Trusted Publisher workflow changed", stdout.getvalue())

    def test_manifest_update_refreshes_baseline_and_preserves_exceptions(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        manifest["packages"]["requests"]["exceptions"] = [
            {
                "code": "native_binaries_introduced",
                "owner": "security",
                "reason": "Temporary review window.",
                "expires": "2026-08-01",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "trustcheck.manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[make_target()]),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=make_report(native_files=("requests/_speedups.so",)),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "manifest",
                        "update",
                        "-f",
                        "requirements.lock",
                        "--manifest",
                        str(manifest_path),
                    ]
                )

            updated = load_manifest(manifest_path)

        package = updated["packages"]["requests"]
        self.assertEqual(exit_code, EXIT_OK)
        self.assertTrue(package["allow_native_binaries"])
        self.assertEqual(package["exceptions"][0]["owner"], "security")

    def test_manifest_rejects_negative_default_malicious_score(self) -> None:
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            main(
                [
                    "manifest",
                    "init",
                    "-f",
                    "requirements.lock",
                    "--max-malicious-score",
                    "-1",
                ]
            )

        self.assertEqual(raised.exception.code, 2)

    def test_manifest_verify_json_success_output(self) -> None:
        manifest = build_manifest([make_report()], [make_target()])
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "trustcheck.manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[make_target()]),
                patch("trustcheck.cli.inspect_package", return_value=make_report()),
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "manifest",
                        "verify",
                        "-f",
                        "requirements.lock",
                        "--manifest",
                        str(manifest_path),
                        "--format",
                        "json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["violations"], [])

    def test_manifest_evidence_collection_renders_target_failures(self) -> None:
        failing_target = ScanTarget(
            requirement="requests>=2",
            project="requests",
            failure_message="error: unable to resolve requests>=2",
            failure_exit_code=3,
        )
        stdout = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", return_value=[failing_target]),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(["manifest", "verify", "-f", "requirements.lock"])

        self.assertEqual(exit_code, 3)
        self.assertIn("evidence collection failed", stdout.getvalue())

    def test_manifest_evidence_collection_renders_json_failures(self) -> None:
        targets = [
            make_target(project="requests"),
            make_target(project="urllib3"),
        ]

        def fail_inspection(project: str, **kwargs):
            if project == "requests":
                raise PypiClientError("resource not found", transient=False)
            raise ValueError("bad payload")

        stdout = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", return_value=targets),
            patch("trustcheck.cli.inspect_package", side_effect=fail_inspection),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(
                [
                    "manifest",
                    "verify",
                    "-f",
                    "requirements.lock",
                    "--format",
                    "json",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertNotEqual(exit_code, EXIT_OK)
        self.assertEqual(len(payload["failures"]), 2)
        self.assertIn("resource not found", payload["failures"][0]["message"])
        self.assertIn("bad payload", payload["failures"][1]["message"])

    def test_manifest_missing_manifest_returns_data_error_after_scan(self) -> None:
        stderr = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", return_value=[make_target()]),
            patch("trustcheck.cli.inspect_package", return_value=make_report()),
            redirect_stdout(io.StringIO()),
            redirect_stderr(stderr),
        ):
            exit_code = main(
                [
                    "manifest",
                    "verify",
                    "-f",
                    "requirements.lock",
                    "--manifest",
                    "missing-manifest.json",
                ]
            )

        self.assertEqual(exit_code, 3)
        self.assertIn("unable to read trust manifest", stderr.getvalue())

    def test_manifest_write_error_returns_data_error(self) -> None:
        stderr = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", return_value=[make_target()]),
            patch("trustcheck.cli.inspect_package", return_value=make_report()),
            patch(
                "trustcheck.cli_commands.manifest.write_manifest",
                side_effect=OSError("disk full"),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(stderr),
        ):
            exit_code = main(["manifest", "init", "-f", "requirements.lock"])

        self.assertEqual(exit_code, 3)
        self.assertIn("unable to write trust manifest", stderr.getvalue())
