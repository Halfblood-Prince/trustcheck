from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import EXIT_DATA_ERROR, EXIT_OK, EXIT_POLICY_FAILURE, EXIT_USAGE
from trustcheck.github_action import (
    ActionInputError,
    ActionResult,
    ActionSettings,
    _resolve_workspace_path,
    build_cli_arguments,
    main,
    render_result,
    run_action,
    summarize_payload,
)


def report_payload(*, recommendation: str = "verified", policy_passed: bool = True):
    return {
        "schema_version": "1.5.0",
        "report": {
            "policy": {"passed": policy_passed},
            "recommendation": recommendation,
        },
    }


class GitHubActionTests(unittest.TestCase):
    def test_package_target_maps_all_supported_inputs_to_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            policy_path = workspace / "policy.json"
            policy_path.write_text("{}", encoding="utf-8")
            settings = ActionSettings(
                target="sampleproject",
                policy="policy.json",
                expected_repo="https://github.com/pypa/sampleproject",
                with_osv=True,
                with_transitive_deps=True,
                inspect_artifacts=True,
            )

            arguments = build_cli_arguments(settings, workspace=workspace)

        self.assertEqual(arguments[:2], ["inspect", "sampleproject"])
        self.assertIn("--expected-repo", arguments)
        self.assertIn("https://github.com/pypa/sampleproject", arguments)
        self.assertIn("--policy-file", arguments)
        self.assertIn("--with-osv", arguments)
        self.assertIn("--with-transitive-deps", arguments)
        self.assertIn("--inspect-artifacts", arguments)
        self.assertEqual(arguments[-2:], ["--format", "json"])

    def test_all_documented_dependency_files_use_scan_command(self) -> None:
        for filename in (
            "requirements.txt",
            "pyproject.toml",
            "uv.lock",
            "poetry.lock",
            "pdm.lock",
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmpdir:
                workspace = Path(tmpdir)
                target = workspace / filename
                target.write_text("", encoding="utf-8")

                arguments = build_cli_arguments(
                    ActionSettings(target=filename, policy="strict"),
                    workspace=workspace,
                )

                self.assertEqual(arguments[:2], ["scan", str(target.resolve())])
                self.assertIn("--policy", arguments)
                self.assertIn("strict", arguments)

    def test_invalid_action_inputs_create_json_error_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            result = run_action(
                ActionSettings(
                    target="requirements.txt",
                    with_deps=True,
                    with_transitive_deps=True,
                ),
                workspace=workspace,
            )

            payload = json.loads(result.report_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, EXIT_USAGE)
        self.assertEqual(result.recommendation, "error")
        self.assertFalse(result.policy_passed)
        self.assertIn("mutually exclusive", payload["action_error"]["message"])

    def test_build_cli_arguments_rejects_invalid_target_combinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            dependency_file = workspace / "requirements.txt"
            dependency_file.write_text("", encoding="utf-8")

            cases = [
                (
                    ActionSettings(target="sampleproject", output_format="sarif"),
                    "format",
                ),
                (
                    ActionSettings(target="missing.lock"),
                    "does not exist",
                ),
                (
                    ActionSettings(
                        target="requirements.txt",
                        expected_repo="https://github.com/example/project",
                    ),
                    "dependency files",
                ),
                (
                    ActionSettings(target="sampleproject", policy="missing.json"),
                    "policy",
                ),
            ]
            for settings, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(ActionInputError, message):
                        build_cli_arguments(settings, workspace=workspace)

            arguments = build_cli_arguments(
                ActionSettings(target="sampleproject", with_deps=True),
                workspace=workspace,
            )
            self.assertIn("--with-deps", arguments)
            self.assertEqual(
                _resolve_workspace_path(str(dependency_file.resolve()), workspace),
                dependency_file.resolve(),
            )

    def test_cli_policy_exit_code_is_preserved_and_report_is_written(self) -> None:
        def failing_runner(arguments):
            self.assertEqual(arguments[:2], ["inspect", "blocked-package"])
            print(json.dumps(report_payload(recommendation="review-required", policy_passed=False)))
            return EXIT_POLICY_FAILURE

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            result = run_action(
                ActionSettings(target="blocked-package", policy="strict"),
                workspace=workspace,
                runner=failing_runner,
            )

            persisted = json.loads(result.report_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, EXIT_POLICY_FAILURE)
        self.assertEqual(result.recommendation, "review-required")
        self.assertFalse(result.policy_passed)
        self.assertEqual(persisted, report_payload(
            recommendation="review-required",
            policy_passed=False,
        ))

    def test_invalid_cli_json_becomes_operational_error(self) -> None:
        def invalid_runner(arguments):
            print("not json")
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_action(
                ActionSettings(target="sampleproject"),
                workspace=Path(tmpdir),
                runner=invalid_runner,
            )

        self.assertEqual(result.exit_code, EXIT_DATA_ERROR)
        self.assertEqual(result.recommendation, "error")
        self.assertFalse(result.policy_passed)

    def test_non_object_cli_json_becomes_operational_error(self) -> None:
        def invalid_runner(arguments):
            del arguments
            print("[]")
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_action(
                ActionSettings(target="sampleproject"),
                workspace=Path(tmpdir),
                runner=invalid_runner,
            )

        self.assertEqual(result.exit_code, EXIT_DATA_ERROR)
        self.assertIn("must be an object", result.stderr)

    def test_scan_summary_uses_worst_recommendation_and_failures(self) -> None:
        payload = {
            "reports": [
                {
                    "recommendation": "verified",
                    "policy": {"passed": True},
                },
                {
                    "recommendation": "review-required",
                    "policy": {"passed": True},
                },
            ],
            "failures": [],
        }
        self.assertEqual(
            summarize_payload(payload, exit_code=EXIT_OK),
            ("review-required", True),
        )
        payload["failures"] = [{"requirement": "broken"}]
        self.assertEqual(
            summarize_payload(payload, exit_code=1),
            ("review-required", False),
        )
        self.assertEqual(
            summarize_payload({"reports": [], "failures": []}, exit_code=EXIT_OK),
            ("error", False),
        )
        self.assertEqual(
            summarize_payload({"unexpected": True}, exit_code=EXIT_OK),
            ("error", False),
        )

    def test_main_writes_outputs_summary_and_report_path(self) -> None:
        def passing_runner(arguments):
            print(json.dumps(report_payload()))
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            output_path = workspace / "github-output.txt"
            summary_path = workspace / "summary.md"
            environment = {
                "GITHUB_OUTPUT": str(output_path),
                "GITHUB_STEP_SUMMARY": str(summary_path),
                "GITHUB_WORKSPACE": str(workspace),
                "TRUSTCHECK_ACTION_FORMAT": "text",
                "TRUSTCHECK_ACTION_POLICY": "default",
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
            }
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(environment, runner=passing_runner)

            outputs = output_path.read_text(encoding="utf-8")
            summary = summary_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("recommendation=verified", outputs)
        self.assertIn("policy-passed=true", outputs)
        self.assertIn("report-path=", outputs)
        self.assertIn("exit-code=0", outputs)
        self.assertIn("Policy: **passed**", summary)
        self.assertIn("recommendation: verified", stdout.getvalue())

    def test_main_uses_process_environment_and_json_rendering(self) -> None:
        def passing_runner(arguments):
            print(json.dumps(report_payload()))
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            environment = {
                "GITHUB_WORKSPACE": tmpdir,
                "TRUSTCHECK_ACTION_FORMAT": "json",
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
            }
            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(runner=passing_runner)

            result = ActionResult(
                exit_code=EXIT_OK,
                recommendation="verified",
                policy_passed=True,
                report_path=Path(tmpdir) / "trustcheck-report.json",
                payload=report_payload(),
            )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(
            json.loads(render_result(result, output_format="json", target="sampleproject")),
            report_payload(),
        )

    def test_action_metadata_uploads_before_enforcing_cli_exit_code(self) -> None:
        action = Path("action.yml").read_text(encoding="utf-8")
        upload_position = action.index("- name: Upload trustcheck JSON report")
        enforcement_position = action.index("- name: Enforce trustcheck result")

        self.assertTrue(action.startswith("name: TrustCheck Package Scanner\n"))
        self.assertLess(upload_position, enforcement_position)
        self.assertIn("actions/upload-artifact@v7", action)
        self.assertIn("continue-on-error: true", action)
        self.assertIn('exit "$TRUSTCHECK_EXIT_CODE"', action)

    def test_action_validation_workflow_has_pass_and_failure_cases(self) -> None:
        workflow = Path(".github/workflows/action-integration.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("safe-package:", workflow)
        self.assertIn("blocked-package:", workflow)
        self.assertIn("uses: ./", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("trustcheck-action-fail-policy.json", workflow)

    def test_publish_workflow_releases_immutable_and_major_action_tags(self) -> None:
        workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")

        self.assertIn('- "v*.*.*"', workflow)
        self.assertNotIn("target_commitish:", workflow)
        self.assertIn("Validate stable release version", workflow)
        self.assertIn("action_major_tag:", workflow)
        self.assertIn("needs['verify-tag'].outputs.action_major_tag", workflow)
        self.assertIn("publish-github-action:", workflow)
        self.assertIn("Publish moving major action tag", workflow)
        self.assertIn('get_endpoint="repos/${GITHUB_REPOSITORY}/git/ref/tags/', workflow)
        self.assertIn("--method PATCH", workflow)
        self.assertIn("-F force=true", workflow)
        self.assertIn("--method POST", workflow)
        self.assertIn("Immutable: `uses: Halfblood-Prince/trustcheck@", workflow)
        self.assertIn("Compatible major: `uses: Halfblood-Prince/trustcheck@", workflow)
        self.assertIn("secrets.RELEASE_TOKEN || github.token", workflow)
        self.assertIn("Record Marketplace association step", workflow)

    def test_environment_rejects_invalid_boolean(self) -> None:
        with self.assertRaisesRegex(ValueError, "with-osv"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                    "TRUSTCHECK_ACTION_WITH_OSV": "yes",
                }
            )

    def test_environment_accepts_true_boolean(self) -> None:
        settings = ActionSettings.from_environment(
            {
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                "TRUSTCHECK_ACTION_WITH_OSV": "TRUE",
            }
        )

        self.assertTrue(settings.with_osv)

    def test_missing_target_is_reported_by_main(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            output_path = workspace / "github-output.txt"
            with patch.dict("os.environ", {}, clear=True):
                exit_code = main(
                    {
                        "GITHUB_OUTPUT": str(output_path),
                        "GITHUB_WORKSPACE": str(workspace),
                    }
                )

            outputs = output_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, EXIT_USAGE)
        self.assertIn("policy-passed=false", outputs)
        self.assertIn("exit-code=2", outputs)


if __name__ == "__main__":
    unittest.main()
