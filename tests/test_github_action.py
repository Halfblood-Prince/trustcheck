from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import EXIT_DATA_ERROR, EXIT_OK, EXIT_POLICY_FAILURE, EXIT_USAGE
from trustcheck.contract import JSON_SCHEMA_VERSION
from trustcheck.github_action import (
    ActionInputError,
    ActionResult,
    ActionSettings,
    _resolve_workspace_path,
    _write_step_summary,
    build_cli_arguments,
    main,
    render_result,
    run_action,
    summarize_payload,
)


def report_payload(*, recommendation: str = "verified", policy_passed: bool = True):
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "report": {
            "policy": {"passed": policy_passed},
            "recommendation": recommendation,
        },
    }


def complete_report_payload(
    *,
    recommendation: str = "verified",
    policy_passed: bool = True,
):
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "report": {
            "project": "sampleproject",
            "version": "4.0.0",
            "package_url": "https://pypi.org/project/sampleproject/4.0.0/",
            "recommendation": recommendation,
            "policy": {"passed": policy_passed},
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
                trusted_publisher_organizations=(
                    "github:pypa",
                    "github:example",
                ),
                with_transitive_deps=True,
                inspect_artifacts=True,
                index_url="https://packages.example/simple",
                extra_index_urls=("https://pypi.org/simple",),
                keyring_provider="subprocess",
                allow_dependency_confusion=True,
                trusted_projects=("requests", "internal-sdk"),
            )

            arguments = build_cli_arguments(settings, workspace=workspace)

        self.assertEqual(arguments[:2], ["inspect", "sampleproject"])
        self.assertIn("--expected-repo", arguments)
        self.assertIn("https://github.com/pypa/sampleproject", arguments)
        self.assertEqual(
            arguments.count("--trusted-publisher-organization"),
            2,
        )
        self.assertIn("github:pypa", arguments)
        self.assertIn("--policy-file", arguments)
        self.assertIn("--with-transitive-deps", arguments)
        self.assertIn("--inspect-artifacts", arguments)
        self.assertIn("--index-url", arguments)
        self.assertIn("https://packages.example/simple", arguments)
        self.assertIn("--extra-index-url", arguments)
        self.assertIn("https://pypi.org/simple", arguments)
        self.assertIn("--keyring-provider", arguments)
        self.assertIn("subprocess", arguments)
        self.assertIn("--allow-dependency-confusion", arguments)
        self.assertEqual(arguments.count("--trusted-project"), 2)
        self.assertIn("internal-sdk", arguments)
        self.assertEqual(arguments[-2:], ["--format", "json"])

    def test_package_target_maps_advisory_inputs_to_scan_cli(self) -> None:
        settings = ActionSettings(
            target="sampleproject",
            with_osv=True,
            osv_urls=("https://osv.internal.example",),
            with_ecosystems=True,
            with_kev=True,
            with_epss=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            arguments = build_cli_arguments(settings, workspace=Path(tmpdir))

        self.assertEqual(arguments[:2], ["scan", "sampleproject"])
        self.assertIn("--with-osv", arguments)
        self.assertIn("--osv-url", arguments)
        self.assertIn("https://osv.internal.example", arguments)
        self.assertIn("--with-ecosystems", arguments)
        self.assertIn("--with-kev", arguments)
        self.assertIn("--with-epss", arguments)
        self.assertEqual(arguments[-2:], ["--format", "json"])

    def test_all_documented_dependency_files_use_scan_command(self) -> None:
        for filename in (
            "requirements.txt",
            "pyproject.toml",
            "pylock.toml",
            "pylock.production.toml",
            "Pipfile.lock",
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

                self.assertEqual(arguments[:3], ["scan", "-f", str(target.resolve())])
                self.assertIn("--policy", arguments)
                self.assertIn("strict", arguments)

    def test_dependency_file_maps_remediation_and_pull_request_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            target = workspace / "requirements.txt"
            source = workspace / "requirements.in"
            target.write_text("demo==1\n", encoding="utf-8")
            source.write_text("demo\n", encoding="utf-8")

            arguments = build_cli_arguments(
                ActionSettings(
                    target="requirements.txt",
                    remediation="fix",
                    allow_constraint_changes=True,
                    source_manifest="requirements.in",
                    remediation_path="reports/remediation.json",
                    max_fix_attempts=42,
                    create_pr=True,
                    pr_base="main",
                    pr_branch="trustcheck/fix-demo",
                    pr_title="Fix demo",
                    pr_ready=True,
                ),
                workspace=workspace,
            )

        self.assertIn("--fix", arguments)
        self.assertIn("--allow-constraint-changes", arguments)
        self.assertIn("--source-manifest", arguments)
        self.assertIn("--remediation-output", arguments)
        self.assertIn("--max-fix-attempts", arguments)
        self.assertIn("42", arguments)
        self.assertIn("--create-pr", arguments)
        self.assertIn("--pr-base", arguments)
        self.assertIn("--pr-branch", arguments)
        self.assertIn("--pr-title", arguments)
        self.assertIn("--pr-ready", arguments)

    def test_action_rejects_invalid_remediation_combinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            target = workspace / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            cases = [
                ActionSettings(
                    target="requirements.txt",
                    remediation="plan",
                    dry_run=True,
                ),
                ActionSettings(
                    target="requirements.txt",
                    remediation="fix",
                    dry_run=True,
                    create_pr=True,
                ),
                ActionSettings(
                    target="requirements.txt",
                    remediation="unknown",
                ),
            ]
            for settings in cases:
                with self.subTest(settings=settings):
                    with self.assertRaises(ActionInputError):
                        build_cli_arguments(settings, workspace=workspace)

            with self.assertRaisesRegex(ActionInputError, "dependency files"):
                build_cli_arguments(
                    ActionSettings(target="demo", remediation="plan"),
                    workspace=workspace,
                )

    def test_action_maps_plan_and_valid_fix_dry_run_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            target = workspace / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")

            planned = build_cli_arguments(
                ActionSettings(
                    target="requirements.txt",
                    remediation="plan",
                ),
                workspace=workspace,
            )
            dry_run = build_cli_arguments(
                ActionSettings(
                    target="requirements.txt",
                    remediation="fix",
                    dry_run=True,
                ),
                workspace=workspace,
            )

            self.assertIn("--plan-fixes", planned)
            self.assertIn("--remediation-output", planned)
            self.assertIn("--fix", dry_run)
            self.assertIn("--dry-run", dry_run)

            with self.assertRaisesRegex(ActionInputError, "source manifest"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        remediation="plan",
                        source_manifest="missing.in",
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "at least 1"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        remediation="plan",
                        max_fix_attempts=0,
                    ),
                    workspace=workspace,
                )

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
                    ActionSettings(
                        target="sampleproject",
                        keyring_provider="unknown",
                    ),
                    "keyring-provider",
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
                (
                    ActionSettings(target="sampleproject", output_format="unknown"),
                    "format",
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

    def test_build_cli_arguments_rejects_trust_options_in_scan_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            dependency_file = workspace / "requirements.txt"
            dependency_file.write_text("demo==1\n", encoding="utf-8")

            with self.assertRaisesRegex(ActionInputError, "expected-repo"):
                build_cli_arguments(
                    ActionSettings(
                        target="sampleproject",
                        with_osv=True,
                        expected_repo="https://github.com/example/project",
                        trusted_publisher_organizations=("github:pypa",),
                        with_deps=True,
                        with_transitive_deps=False,
                        inspect_artifacts=True,
                        trusted_projects=("internal-sdk",),
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "with-transitive-deps"):
                build_cli_arguments(
                    ActionSettings(
                        target="sampleproject",
                        with_osv=True,
                        with_transitive_deps=True,
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "trusted-publisher"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        trusted_publisher_organizations=("github:pypa",),
                        with_deps=True,
                        inspect_artifacts=True,
                        trusted_projects=("internal-sdk",),
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "with-transitive-deps"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        with_transitive_deps=True,
                    ),
                    workspace=workspace,
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
        self.assertIn("remediation-status=not-requested", outputs)
        self.assertIn("applied-fixes=0", outputs)
        self.assertIn("patch-path=", outputs)
        self.assertIn("pr-url=", outputs)
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

    def test_action_writes_sarif_without_repeating_the_audit(self) -> None:
        calls = 0

        def passing_runner(arguments):
            nonlocal calls
            calls += 1
            self.assertEqual(arguments[-2:], ["--format", "json"])
            print(json.dumps(complete_report_payload()))
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            result = run_action(
                ActionSettings(
                    target="sampleproject",
                    output_format="sarif",
                    report_path="reports/trustcheck.sarif",
                ),
                workspace=workspace,
                runner=passing_runner,
            )
            sarif = json.loads(result.report_path.read_text(encoding="utf-8"))

        self.assertEqual(calls, 1)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(result.recommendation, "verified")

    def test_action_reports_openvex_conversion_without_vulnerabilities(self) -> None:
        def passing_runner(arguments):
            print(json.dumps(complete_report_payload()))
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            result = run_action(
                ActionSettings(
                    target="sampleproject",
                    output_format="openvex",
                    report_path="reports/trustcheck.openvex.json",
                ),
                workspace=workspace,
                runner=passing_runner,
            )
            payload = json.loads(
                result.report_path.read_text(encoding="utf-8")
            )

        self.assertEqual(result.exit_code, EXIT_DATA_ERROR)
        self.assertEqual(result.recommendation, "error")
        self.assertIn("requires at least one", payload["action_error"]["message"])

    def test_action_metadata_uploads_before_enforcing_cli_exit_code(self) -> None:
        action = Path("action.yml").read_text(encoding="utf-8")
        upload_position = action.index("- name: Upload trustcheck report")
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
                "TRUSTCHECK_ACTION_OSV_URLS": (
                    "https://osv-one.example\nhttps://osv-two.example"
                ),
                "TRUSTCHECK_ACTION_WITH_ECOSYSTEMS": "true",
                "TRUSTCHECK_ACTION_WITH_KEV": "true",
                "TRUSTCHECK_ACTION_WITH_EPSS": "true",
                "TRUSTCHECK_ACTION_INDEX_URL": "https://packages.example/simple",
                "TRUSTCHECK_ACTION_EXTRA_INDEX_URLS": (
                    "https://mirror-one.example/simple\n"
                    "https://mirror-two.example/simple"
                ),
                "TRUSTCHECK_ACTION_KEYRING_PROVIDER": "subprocess",
                "TRUSTCHECK_ACTION_ALLOW_DEPENDENCY_CONFUSION": "true",
                "TRUSTCHECK_ACTION_TRUSTED_PUBLISHER_ORGANIZATIONS": (
                    "github:pypa\ngitlab:example/platform"
                ),
                "TRUSTCHECK_ACTION_REMEDIATION": "fix",
                "TRUSTCHECK_ACTION_DRY_RUN": "true",
                "TRUSTCHECK_ACTION_ALLOW_CONSTRAINT_CHANGES": "true",
                "TRUSTCHECK_ACTION_MAX_FIX_ATTEMPTS": "99",
            }
        )

        self.assertTrue(settings.with_osv)
        self.assertEqual(
            settings.osv_urls,
            ("https://osv-one.example", "https://osv-two.example"),
        )
        self.assertTrue(settings.with_ecosystems)
        self.assertTrue(settings.with_kev)
        self.assertTrue(settings.with_epss)
        self.assertEqual(
            settings.extra_index_urls,
            (
                "https://mirror-one.example/simple",
                "https://mirror-two.example/simple",
            ),
        )
        self.assertEqual(settings.keyring_provider, "subprocess")
        self.assertTrue(settings.allow_dependency_confusion)
        self.assertEqual(
            settings.trusted_publisher_organizations,
            ("github:pypa", "gitlab:example/platform"),
        )
        self.assertEqual(settings.remediation, "fix")
        self.assertTrue(settings.dry_run)
        self.assertTrue(settings.allow_constraint_changes)
        self.assertEqual(settings.max_fix_attempts, 99)

    def test_environment_rejects_invalid_remediation_and_attempt_values(self) -> None:
        cases = (
            (
                {
                    "TRUSTCHECK_ACTION_TARGET": "requirements.txt",
                    "TRUSTCHECK_ACTION_REMEDIATION": "invalid",
                },
                "remediation",
            ),
            (
                {
                    "TRUSTCHECK_ACTION_TARGET": "requirements.txt",
                    "TRUSTCHECK_ACTION_MAX_FIX_ATTEMPTS": "many",
                },
                "integer",
            ),
            (
                {
                    "TRUSTCHECK_ACTION_TARGET": "requirements.txt",
                    "TRUSTCHECK_ACTION_MAX_FIX_ATTEMPTS": "0",
                },
                "at least 1",
            ),
        )
        for environment, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ActionInputError, message):
                    ActionSettings.from_environment(environment)

    def test_action_exposes_remediation_and_pull_request_results(self) -> None:
        payload = {
            "schema_version": JSON_SCHEMA_VERSION,
            "reports": [
                {
                    "recommendation": "verified",
                    "policy": {"passed": True},
                }
            ],
            "failures": [],
            "remediation": {
                "status": "pull-request-created",
                "upgrades": [{"project": "demo"}],
                "pull_request": {
                    "branch": "trustcheck/fix-demo",
                    "url": "https://github.com/example/repo/pull/1",
                },
            },
        }

        def passing_runner(arguments):
            self.assertIn("--fix", arguments)
            print(json.dumps(payload))
            return EXIT_OK

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            target = workspace / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            result = run_action(
                ActionSettings(
                    target="requirements.txt",
                    remediation="fix",
                    create_pr=True,
                    remediation_path="remediation.json",
                ),
                workspace=workspace,
                runner=passing_runner,
            )
            summary = workspace / "summary.md"
            environment = {"GITHUB_STEP_SUMMARY": str(summary)}
            _write_step_summary(
                result,
                ActionSettings(target="requirements.txt"),
                environment,
            )
            rendered_summary = summary.read_text(encoding="utf-8")

        self.assertEqual(result.remediation_status, "pull-request-created")
        self.assertEqual(result.applied_fixes, 1)
        self.assertEqual(result.pr_branch, "trustcheck/fix-demo")
        self.assertEqual(
            result.pr_url,
            "https://github.com/example/repo/pull/1",
        )
        self.assertIn("Pull request:", rendered_summary)

    def test_environment_derives_report_extension_from_format(self) -> None:
        settings = ActionSettings.from_environment(
            {
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                "TRUSTCHECK_ACTION_FORMAT": "cyclonedx-xml",
            }
        )

        self.assertEqual(settings.report_path, "trustcheck-report.cdx.xml")
        with self.assertRaisesRegex(ActionInputError, "format"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                    "TRUSTCHECK_ACTION_FORMAT": "unknown",
                }
            )

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
