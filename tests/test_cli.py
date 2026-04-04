from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from trustcheck.cli import (
    EXIT_DATA_ERROR,
    EXIT_OK,
    EXIT_POLICY_FAILURE,
    EXIT_UPSTREAM_FAILURE,
    main,
)
from trustcheck.models import (
    JSON_SCHEMA_VERSION,
    CoverageSummary,
    FileProvenance,
    ProvenanceConsistency,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    RiskFlag,
    TrustReport,
)
from trustcheck.pypi import PypiClientError


def make_report() -> TrustReport:
    return TrustReport(
        project="demo",
        version="1.2.3",
        summary="Demo package",
        package_url="https://pypi.org/project/demo/1.2.3/",
        declared_repository_urls=["https://github.com/example/demo"],
        repository_urls=["https://github.com/example/demo"],
        expected_repository="https://github.com/example/demo",
        ownership={
            "organization": "example-org",
            "roles": [{"role": "Owner", "user": "alice"}],
        },
        vulnerabilities=[],
        files=[
            FileProvenance(
                filename="demo-1.2.3-py3-none-any.whl",
                url="https://files.pythonhosted.org/packages/demo.whl",
                sha256="abc123",
                observed_sha256="abc123",
                has_provenance=True,
                verified=True,
                attestation_count=1,
                verified_attestation_count=1,
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
            verified_publishers=["GitHub:https://github.com/example/demo:release.yml"],
            unique_verified_repositories=["https://github.com/example/demo"],
            unique_verified_workflows=["release.yml"],
        ),
        provenance_consistency=ProvenanceConsistency(
            has_sdist=False,
            has_wheel=True,
            sdist_wheel_consistent=None,
        ),
        release_drift=ReleaseDriftSummary(),
        risk_flags=[],
        recommendation="verified",
    )


class CliBehaviorTests(unittest.TestCase):
    def test_cli_success_text_output(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("trustcheck report for demo 1.2.3", stdout.getvalue())
        self.assertIn("summary:", stdout.getvalue())
        self.assertIn("recommendation: verified", stdout.getvalue())
        self.assertIn("why this result: cryptographic verification succeeded", stdout.getvalue())
        self.assertIn("verification: 1/1 artifact(s) verified (all-verified)", stdout.getvalue())
        self.assertIn("publisher trust: strong", stdout.getvalue())

    def test_cli_success_json_output_contract(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo", "--format", "json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(sorted(payload.keys()), ["report", "schema_version"])
        self.assertEqual(payload["schema_version"], JSON_SCHEMA_VERSION)
        report = payload["report"]
        self.assertEqual(
            sorted(report.keys()),
            [
                "coverage",
                "declared_repository_urls",
                "expected_repository",
                "files",
                "ownership",
                "package_url",
                "project",
                "provenance_consistency",
                "publisher_trust",
                "recommendation",
                "release_drift",
                "repository_urls",
                "risk_flags",
                "summary",
                "version",
                "vulnerabilities",
            ],
        )
        self.assertEqual(report["project"], "demo")
        self.assertEqual(
            report["declared_repository_urls"],
            ["https://github.com/example/demo"],
        )
        self.assertEqual(report["files"][0]["verified"], True)
        self.assertEqual(report["files"][0]["observed_sha256"], "abc123")
        self.assertEqual(report["coverage"]["status"], "all-verified")
        self.assertEqual(report["publisher_trust"]["depth_label"], "strong")

    def test_cli_text_output_shows_file_errors_in_verbose_mode(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.files[0].error = "resource not found"
        report.recommendation = "high-risk"
        report.risk_flags = [
            RiskFlag(
                code="no_provenance",
                severity="high",
                message="No provenance bundles were found.",
                why=["No verified provenance bundle was attached to the artifact."],
                remediation=["Require a release that publishes provenance before use."],
            )
        ]
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "demo", "--verbose"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("note: resource not found", stdout.getvalue())
        self.assertIn("[high] no_provenance", stdout.getvalue())
        self.assertIn("why:", stdout.getvalue())
        self.assertIn("remediation:", stdout.getvalue())

    def test_cli_non_verbose_output_is_concise(self) -> None:
        report = make_report()
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertNotIn("files:", stdout.getvalue())
        self.assertNotIn("sha256:", stdout.getvalue())

    def test_cli_strict_mode_fails_on_missing_verification(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.coverage.verified_files = 0
        report.coverage.status = "all-attested"
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo", "--strict"])

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("recommendation:", stdout.getvalue())

    def test_cli_strict_mode_passes_for_fully_verified_release(self) -> None:
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "demo", "--strict"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_network_outage_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError("unable to reach PyPI: timed out"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unable to inspect package from PyPI", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_missing_package_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError(
                "resource not found: https://pypi.org/pypi/demo/json"
            ),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo", "--version", "9.9.9"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("resource not found", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_server_response_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=ValueError("missing required provenance fields"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("received an invalid response", stderr.getvalue())
        self.assertIn("missing required provenance fields", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_unexpected_failure_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=RuntimeError("unexpected explosion"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unexpected failure", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_debug_mode_prints_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", side_effect=ValueError("broken payload")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "inspect", "demo"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("Traceback", stderr.getvalue())
