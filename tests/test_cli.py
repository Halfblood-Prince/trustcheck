from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from trustcheck.cli import EXIT_DATA_ERROR, EXIT_OK, EXIT_UPSTREAM_FAILURE, main
from trustcheck.models import FileProvenance, RiskFlag, TrustReport
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
        self.assertIn("recommendation: verified", stdout.getvalue())
        self.assertIn("evidence: cryptographic verification succeeded", stdout.getvalue())

    def test_cli_success_json_output_contract(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo", "--format", "json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            sorted(payload.keys()),
            [
                "declared_repository_urls",
                "expected_repository",
                "files",
                "ownership",
                "package_url",
                "project",
                "recommendation",
                "repository_urls",
                "risk_flags",
                "summary",
                "version",
                "vulnerabilities",
            ],
        )
        self.assertEqual(payload["project"], "demo")
        self.assertEqual(
            payload["declared_repository_urls"],
            ["https://github.com/example/demo"],
        )
        self.assertEqual(payload["files"][0]["verified"], True)
        self.assertEqual(payload["files"][0]["observed_sha256"], "abc123")

    def test_cli_text_output_shows_file_errors(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.files[0].error = "resource not found"
        report.recommendation = "high-risk"
        report.risk_flags = [
            RiskFlag(
                code="no_provenance",
                severity="high",
                message="No provenance bundles were found.",
            )
        ]
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("note: resource not found", stdout.getvalue())
        self.assertIn("[high] no_provenance", stdout.getvalue())

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
