from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import (
    EXIT_DATA_ERROR,
    EXIT_OK,
    EXIT_POLICY_FAILURE,
    EXIT_UPSTREAM_FAILURE,
    main,
)
from trustcheck.contract import JSON_SCHEMA_VERSION
from trustcheck.models import (
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    ProvenanceConsistency,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    ReportDiagnostics,
    RiskFlag,
    TrustReport,
    VulnerabilityRecord,
)
from trustcheck.pypi import PypiClientError


def make_report() -> TrustReport:
    return TrustReport(
        project="gridoptim",
        version="2.2.0",
        summary="gridoptim package",
        package_url="https://pypi.org/project/gridoptim/2.2.0/",
        declared_dependencies=["depalpha>=1.0"],
        declared_repository_urls=["https://github.com/Halfblood-Prince/gridoptim"],
        repository_urls=["https://github.com/Halfblood-Prince/gridoptim"],
        expected_repository="https://github.com/Halfblood-Prince/gridoptim",
        ownership={
            "organization": "Halfblood-Prince",
            "roles": [{"role": "Owner", "user": "Halfblood-Prince"}],
        },
        vulnerabilities=[],
        files=[
            FileProvenance(
                filename="gridoptim-2.2.0-py3-none-any.whl",
                url="https://files.pythonhosted.org/packages/gridoptim.whl",
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
            verified_publishers=[
                "GitHub:https://github.com/Halfblood-Prince/gridoptim:release.yml"
            ],
            unique_verified_repositories=["https://github.com/Halfblood-Prince/gridoptim"],
            unique_verified_workflows=["release.yml"],
        ),
        provenance_consistency=ProvenanceConsistency(
            has_sdist=False,
            has_wheel=True,
            sdist_wheel_consistent=None,
        ),
        release_drift=ReleaseDriftSummary(),
        dependencies=[
            DependencyInspection(
                requirement="depalpha>=1.0",
                project="depalpha",
                version="1.4.0",
                depth=1,
                parent_project="gridoptim",
                parent_version="2.2.0",
                package_url="https://pypi.org/project/depalpha/1.4.0/",
                recommendation="review-required",
                risk_flags=[
                    RiskFlag(
                        code="missing_repository_url",
                        severity="medium",
                        message="No repository metadata.",
                    )
                ],
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
        ),
        risk_flags=[],
        recommendation="verified",
        diagnostics=ReportDiagnostics(),
    )


class CliBehaviorTests(unittest.TestCase):
    def test_cli_success_text_output(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())
        self.assertIn("summary:", stdout.getvalue())
        self.assertIn("recommendation: verified", stdout.getvalue())
        self.assertIn("why this result: cryptographic verification succeeded", stdout.getvalue())
        self.assertIn("verification: 1/1 artifact(s) verified (all-verified)", stdout.getvalue())
        self.assertIn("publisher trust: strong", stdout.getvalue())
        self.assertIn("dependencies:", stdout.getvalue())
        self.assertIn("highest_risk=review-required", stdout.getvalue())
        self.assertIn(
            "diagnostics: requests=0 retries=0 failures=0 cache_hits=0",
            stdout.getvalue(),
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_text_output_emits_progress_to_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            progress_callback = kwargs["progress_callback"]
            progress_callback("gridoptim-2.2.0-py3-none-any.whl", 1, 2)
            progress_callback("gridoptim-2.2.0.tar.gz", 2, 2)
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn(
            "[progress] verifying artifact 1/2: gridoptim-2.2.0-py3-none-any.whl",
            stderr.getvalue(),
        )
        self.assertIn(
            "[progress] verifying artifact 2/2: gridoptim-2.2.0.tar.gz",
            stderr.getvalue(),
        )
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())

    def test_cli_text_output_emits_dependency_progress_to_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            dependency_progress_callback = kwargs["dependency_progress_callback"]
            dependency_progress_callback("depalpha", 1)
            dependency_progress_callback("depbeta", 2)
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--with-deps"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn(
            "[progress] inspecting dependency depth=1: depalpha",
            stderr.getvalue(),
        )
        self.assertIn(
            "[progress] inspecting dependency depth=2: depbeta",
            stderr.getvalue(),
        )
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())

    def test_cli_success_json_output_contract(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--format", "json"])

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
                "declared_dependencies",
                "declared_repository_urls",
                "dependencies",
                "dependency_summary",
                "diagnostics",
                "expected_repository",
                "files",
                "ownership",
                "package_url",
                "policy",
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
        self.assertEqual(report["project"], "gridoptim")
        self.assertEqual(
            report["declared_repository_urls"],
            ["https://github.com/Halfblood-Prince/gridoptim"],
        )
        self.assertEqual(report["files"][0]["verified"], True)
        self.assertEqual(report["files"][0]["observed_sha256"], "abc123")
        self.assertEqual(report["coverage"]["status"], "all-verified")
        self.assertEqual(report["publisher_trust"]["depth_label"], "strong")
        self.assertEqual(report["policy"]["profile"], "default")
        self.assertEqual(report["policy"]["passed"], True)
        self.assertEqual(report["diagnostics"]["request_count"], 0)

    def test_cli_json_output_does_not_emit_progress(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertIsNone(kwargs["progress_callback"])
            self.assertIsNone(kwargs["dependency_progress_callback"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["report"]["project"], "gridoptim")

    def test_cli_cve_output_only_shows_vulnerabilities(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="Example advisory",
                aliases=["CVE-2026-0001"],
                source="PyPI",
                fixed_in=["2.2.1"],
                link="https://example.com/advisory",
            )
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--cve"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("known vulnerabilities for gridoptim 2.2.0", stdout.getvalue())
        self.assertIn("PYSEC-2026-1: Example advisory", stdout.getvalue())
        self.assertIn("aliases: CVE-2026-0001", stdout.getvalue())
        self.assertIn("fixed in: 2.2.1", stdout.getvalue())
        self.assertNotIn("summary:", stdout.getvalue())
        self.assertNotIn("risk flags:", stdout.getvalue())

    def test_cli_cve_output_handles_empty_vulnerability_list(self) -> None:
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--cve"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("No known vulnerability records reported by PyPI.", stdout.getvalue())

    def test_cli_cve_json_output_is_minimal(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="Example advisory",
                aliases=["CVE-2026-0001"],
                source="PyPI",
                fixed_in=["2.2.1"],
                link="https://example.com/advisory",
            )
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--cve", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            sorted(payload.keys()),
            ["package_url", "project", "version", "vulnerabilities"],
        )
        self.assertEqual(payload["project"], "gridoptim")
        self.assertEqual(payload["vulnerabilities"][0]["id"], "PYSEC-2026-1")

    def test_cli_cve_mode_respects_policy_failure(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(id="PYSEC-2026-1", summary="Example advisory")
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--cve",
                        "--fail-on-vulnerability",
                        "any",
                    ]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("PYSEC-2026-1: Example advisory", stdout.getvalue())

    def test_cli_with_deps_flag_enables_dependency_inspection(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["include_dependencies"])
            self.assertFalse(kwargs["include_transitive_dependencies"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--with-deps"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_with_transitive_deps_flag_enables_recursive_dependency_inspection(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertFalse(kwargs["include_dependencies"])
            self.assertTrue(kwargs["include_transitive_dependencies"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--with-transitive-deps"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_text_output_shows_file_errors_in_verbose_mode(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.files[0].error = "resource not found"
        report.recommendation = "review-required"
        report.risk_flags = [
            RiskFlag(
                code="no_provenance",
                severity="medium",
                message="No provenance bundles were found.",
                why=["No verified provenance bundle was attached to the artifact."],
                remediation=["Require a release that publishes provenance before use."],
            )
        ]
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--verbose"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("note: resource not found", stdout.getvalue())
        self.assertIn("[medium] no_provenance", stdout.getvalue())
        self.assertIn("why:", stdout.getvalue())
        self.assertIn("remediation:", stdout.getvalue())
        self.assertIn("requirement: depalpha>=1.0", stdout.getvalue())

    def test_cli_non_verbose_output_is_concise(self) -> None:
        report = make_report()
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim"])

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
                exit_code = main(["inspect", "gridoptim", "--strict"])

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("recommendation:", stdout.getvalue())
        self.assertIn("policy: strict (fail)", stdout.getvalue())

    def test_cli_strict_mode_passes_for_fully_verified_release(self) -> None:
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--strict"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_policy_file_can_require_expected_repository(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.expected_repository = None
        policy_path = Path(__file__).parent / "fixtures" / "policy_require_expected_repo.json"

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    ["inspect", "gridoptim", "--policy-file", str(policy_path)]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("policy: team-policy (fail)", stdout.getvalue())
        self.assertIn("expected_repository_required", stdout.getvalue())

    def test_cli_policy_flags_override_builtin_policy(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = []

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--policy",
                        "strict",
                        "--require-verified-provenance",
                        "none",
                        "--fail-on-risk-severity",
                        "none",
                        "--allow-metadata-only",
                    ]
                )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("policy: strict (pass)", stdout.getvalue())

    def test_cli_builds_client_from_config_file(self) -> None:
        config_path = Path(__file__).parent / "fixtures" / "client_config.json"

        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            self.assertEqual(client.timeout, 3.5)
            self.assertEqual(client.max_retries, 4)
            self.assertEqual(client.backoff_factor, 0.75)
            self.assertTrue(client.offline)
            self.assertEqual(client.cache_dir, ".cache/trustcheck")
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main(
                    ["inspect", "gridoptim", "--config-file", str(config_path)]
                )

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_env_overrides_network_settings(self) -> None:
        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            self.assertEqual(client.timeout, 1.5)
            self.assertEqual(client.max_retries, 5)
            self.assertEqual(client.backoff_factor, 0.6)
            self.assertTrue(client.offline)
            self.assertEqual(client.cache_dir, ".env-cache")
            return make_report()

        with patch.dict(
            "os.environ",
            {
                "TRUSTCHECK_TIMEOUT": "1.5",
                "TRUSTCHECK_RETRIES": "5",
                "TRUSTCHECK_BACKOFF": "0.6",
                "TRUSTCHECK_OFFLINE": "true",
                "TRUSTCHECK_CACHE_DIR": ".env-cache",
            },
            clear=False,
        ):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_network_outage_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError("unable to reach PyPI: timed out"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

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
                "resource not found: https://pypi.org/pypi/gridoptim/json"
            ),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--version", "9.9.9"])

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
                exit_code = main(["inspect", "gridoptim"])

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
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unexpected failure", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_debug_mode_prints_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", side_effect=ValueError("broken payload")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("Traceback", stderr.getvalue())

    def test_cli_json_debug_logs_are_structured(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            assert client.request_hook is not None
            client.request_hook(
                "retry",
                {
                    "url": "https://pypi.org/pypi/gridoptim/json",
                    "attempt": 1,
                    "delay": 0.25,
                },
            )
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "--log-format", "json", "inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn('"event": "retry"', stderr.getvalue())
