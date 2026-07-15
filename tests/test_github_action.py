from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import trustcheck.github_action as action_mod
from trustcheck.action_options import ACTION_INPUTS, RUNTIME_ACTION_INPUTS
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


def action_yaml_inputs() -> dict[str, dict[str, str]]:
    inputs: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_inputs = False
    for line in Path("action.yml").read_text(encoding="utf-8").splitlines():
        if line == "inputs:":
            in_inputs = True
            continue
        if in_inputs and line and not line.startswith(" "):
            break
        if not in_inputs:
            continue
        match = re.match(r"^  ([a-z0-9-]+):$", line)
        if match:
            current = match.group(1)
            inputs[current] = {}
            continue
        field = re.match(r"^    ([a-z-]+):\s*(.*)$", line)
        if current is not None and field:
            raw_value = field.group(2).strip()
            inputs[current][field.group(1)] = raw_value.strip('"')
    return inputs


def action_runtime_environment_variables() -> tuple[str, ...]:
    action = Path("action.yml").read_text(encoding="utf-8")
    run_step = action.split("- name: Run trustcheck", maxsplit=1)[1]
    env_block = run_step.split("run: python -m trustcheck.github_action", maxsplit=1)[0]
    return tuple(re.findall(r"^\s+(TRUSTCHECK_ACTION_[A-Z0-9_]+):", env_block, re.M))


def documented_action_inputs() -> tuple[str, ...]:
    document = Path("docs/guides/ci-integration.md").read_text(encoding="utf-8")
    table = document.split("| `target` |", maxsplit=1)[1].split("## Outputs", maxsplit=1)[0]
    rows = re.findall(r"^\| `([^`]+)` \|", "| `target` |" + table, re.M)
    return tuple(rows)


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
                allow_insecure_index=True,
                trusted_projects=("requests", "internal-sdk"),
                sandbox="container",
                sandbox_image=(
                    "registry.example/resolver@sha256:" + "c" * 64
                ),
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
        self.assertIn("--allow-insecure-index", arguments)
        self.assertEqual(arguments.count("--trusted-project"), 2)
        self.assertIn("internal-sdk", arguments)
        self.assertIn("--sandbox", arguments)
        self.assertEqual(arguments[arguments.index("--sandbox") + 1], "container")
        self.assertEqual(
            arguments[arguments.index("--sandbox-image") + 1],
            "registry.example/resolver@sha256:" + "c" * 64,
        )
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

            rendered = result.report_path.read_text(encoding="utf-8")

        self.assertEqual(result.exit_code, EXIT_USAGE)
        self.assertEqual(result.recommendation, "error")
        self.assertFalse(result.policy_passed)
        self.assertEqual(result.report_path.name, "trustcheck-report.txt")
        self.assertIn("trustcheck action error", rendered)
        self.assertIn("mutually exclusive", rendered)

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
            with self.assertRaisesRegex(ActionInputError, "sandbox"):
                build_cli_arguments(
                    ActionSettings(target="sampleproject", sandbox="invalid"),
                    workspace=workspace,
                )
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
                ActionSettings(
                    target="blocked-package",
                    policy="strict",
                    output_format="json",
                    report_path="trustcheck-report.json",
                ),
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

    def test_action_text_rendering_and_input_parser_edge_cases(self) -> None:
        action_error = action_mod._render_text_payload(
            {
                "action_error": {
                    "target": "demo",
                    "exit_code": EXIT_USAGE,
                    "message": "bad input",
                }
            },
            exit_code=EXIT_USAGE,
        )
        self.assertIn("trustcheck action error", action_error)
        self.assertIn("bad input", action_error)

        report = action_mod._render_fallback_text_payload(
            {
                "report": {
                    "project": "demo",
                    "version": "1.0.0",
                    "recommendation": "review-required",
                    "policy": {"passed": True},
                }
            },
            exit_code=EXIT_OK,
        )
        self.assertIn("trustcheck report for demo 1.0.0", report)
        self.assertIn("policy: passed", report)
        report_without_version = action_mod._render_fallback_text_payload(
            {
                "report": {
                    "project": "demo",
                    "recommendation": "verified",
                    "policy": {"passed": False},
                }
            },
            exit_code=EXIT_DATA_ERROR,
        )
        self.assertIn("trustcheck report for demo", report_without_version)
        self.assertNotIn("demo 1.0.0", report_without_version)

        vulnerabilities = action_mod._render_fallback_text_payload(
            {
                "project": "demo",
                "version": "1.0.0",
                "package_url": "pkg:pypi/demo@1.0.0",
                "vulnerabilities": [
                    {"id": "CVE-1", "summary": "first"},
                    "ignored",
                ],
            },
            exit_code=EXIT_DATA_ERROR,
        )
        self.assertIn("count: 2", vulnerabilities)
        self.assertIn("CVE-1: first", vulnerabilities)

        generic = action_mod._render_fallback_text_payload(
            {"unexpected": True},
            exit_code=EXIT_DATA_ERROR,
        )
        self.assertIn("recommendation: error", generic)
        single_report = action_mod._render_text_payload(
            complete_report_payload(),
            exit_code=EXIT_OK,
        )
        self.assertIn("sampleproject", single_report)
        scan_report = action_mod._render_text_payload(
            {
                "schema_version": JSON_SCHEMA_VERSION,
                "file": "requirements.txt",
                "reports": [complete_report_payload()["report"]],
                "failures": [],
                "remediation": {
                    "status": "planned",
                    "upgrades": [{"project": "demo"}],
                },
            },
            exit_code=EXIT_OK,
        )
        self.assertIn("requirements.txt", scan_report)
        self.assertIn("remediation:", scan_report)
        with patch.object(
            action_mod,
            "export_packages_from_payload",
            return_value=(
                [SimpleNamespace(report=object()), SimpleNamespace(report=object())],
                "source",
                [],
            ),
        ):
            fallback = action_mod._render_text_payload(
                {"schema_version": JSON_SCHEMA_VERSION},
                exit_code=EXIT_DATA_ERROR,
            )
        self.assertIn("trustcheck report", fallback)
        remediation = action_mod._render_remediation_payload_summary(
            {
                "status": "planned",
                "upgrades": [{"project": "demo"}],
                "patch_files": ["fix.patch", 3],
            }
        )
        self.assertIn("status: planned", remediation)
        self.assertIn("upgrades: 1", remediation)
        self.assertIn("fix.patch", remediation)
        unknown_remediation = action_mod._render_remediation_payload_summary(
            {
                "status": 3,
                "upgrades": "bad",
                "patch_files": [],
            }
        )
        self.assertIn("status: unknown", unknown_remediation)
        self.assertNotIn("upgrades:", unknown_remediation)
        self.assertEqual(action_mod._render_remediation_payload_summary(None), "")

        with self.assertRaisesRegex(ValueError, "unsupported output format"):
            action_mod._render_report_artifact("unknown", {}, exit_code=EXIT_OK)

        self.assertEqual(action_mod._parse_multi_value("one two\nthree"), ("one", "two", "three"))
        with patch.object(
            action_mod,
            "RUNTIME_ACTION_INPUTS",
            (
                action_mod.ActionInputSpec("ignored", None, "ignored input"),
                *RUNTIME_ACTION_INPUTS,
            ),
        ):
            self.assertEqual(
                ActionSettings.from_environment(
                    {"TRUSTCHECK_ACTION_TARGET": "sampleproject"}
                ).target,
                "sampleproject",
            )
        for overrides, message in (
            ({"output_format": "unknown"}, "format"),
            ({"remediation": "unknown"}, "remediation"),
            ({"sandbox": "unknown"}, "sandbox"),
        ):
            def fake_parse(spec, raw_value, overrides=overrides):
                del raw_value
                if spec.field == "target":
                    return "sampleproject"
                return overrides.get(spec.field, spec.default)

            with self.subTest(message=message), patch.object(
                action_mod,
                "_parse_action_input",
                side_effect=fake_parse,
            ), self.assertRaisesRegex(ActionInputError, message):
                ActionSettings.from_environment(
                    {"TRUSTCHECK_ACTION_TARGET": "sampleproject"}
                )
        args = build_cli_arguments(
            ActionSettings(
                target="sampleproject",
                allow_unsigned_advisory_snapshot=True,
            ),
            workspace=Path.cwd(),
        )
        self.assertIn("--allow-unsigned-advisory-snapshot", args)
        alias_spec = action_mod.ActionInputSpec(
            "demo",
            "demo",
            "demo input",
            default="fallback",
            env_aliases=("TRUSTCHECK_DEMO_ALIAS",),
        )
        self.assertEqual(
            action_mod._action_environment_value(
                {"TRUSTCHECK_DEMO_ALIAS": "aliased"},
                alias_spec,
            ),
            "aliased",
        )
        int_spec = action_mod.ActionInputSpec(
            "count",
            "count",
            "count input",
            default="1",
            kind="int",
            minimum=1,
            maximum=2,
        )
        with self.assertRaisesRegex(ActionInputError, "at most 2"):
            action_mod._parse_int_action_input(int_spec, "3")
        float_spec = action_mod.ActionInputSpec(
            "ratio",
            "ratio",
            "ratio input",
            default="1",
            kind="float",
            minimum=0,
            maximum=2,
        )
        for value, message in (("bad", "number"), ("0", "positive"), ("3", "at most 2")):
            with self.subTest(value=value), self.assertRaisesRegex(ActionInputError, message):
                action_mod._parse_float_action_input(float_spec, value)

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
            report = (workspace / "trustcheck-report.txt").read_text(
                encoding="utf-8"
            )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("recommendation=verified", outputs)
        self.assertIn("policy-passed=true", outputs)
        self.assertIn("report-path=", outputs)
        self.assertIn("trustcheck-report.txt", outputs)
        self.assertIn("exit-code=0", outputs)
        self.assertIn("remediation-status=not-requested", outputs)
        self.assertIn("applied-fixes=0", outputs)
        self.assertIn("patch-path=", outputs)
        self.assertIn("pr-url=", outputs)
        self.assertIn("Policy: **passed**", summary)
        self.assertIn("trustcheck report", report)
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
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            action,
        )
        self.assertIn("continue-on-error: true", action)
        self.assertIn('exit "$TRUSTCHECK_EXIT_CODE"', action)
        self.assertIn("default: strict", action)
        self.assertIn("sandbox-image:", action)
        self.assertIn("TRUSTCHECK_ACTION_REF: ${{ github.action_ref }}", action)
        self.assertIn('action_ref="${TRUSTCHECK_ACTION_REF:-}"', action)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION", action)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK", action)

    def test_action_option_schema_matches_action_metadata_and_docs(self) -> None:
        inputs = action_yaml_inputs()
        expected_names = tuple(spec.name for spec in ACTION_INPUTS)
        self.assertEqual(tuple(inputs), expected_names)
        for spec in ACTION_INPUTS:
            with self.subTest(input=spec.name):
                self.assertTrue(inputs[spec.name]["description"])
                self.assertEqual(
                    inputs[spec.name].get("required", "false"),
                    str(spec.required).lower(),
                )
                if spec.action_default is None:
                    self.assertNotIn("default", inputs[spec.name])
                else:
                    self.assertEqual(inputs[spec.name].get("default", ""), spec.action_default)

        self.assertEqual(
            action_runtime_environment_variables(),
            tuple(spec.environment_name for spec in RUNTIME_ACTION_INPUTS),
        )
        self.assertEqual(documented_action_inputs(), expected_names)

    def test_all_external_actions_are_commit_pinned(self) -> None:
        files = [Path("action.yml"), *Path(".github/workflows").glob("*.yml")]
        found = 0
        for path in files:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(),
                1,
            ):
                match = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
                if match is None or match.group(1).startswith("./"):
                    continue
                found += 1
                reference = match.group(1)
                self.assertRegex(
                    reference,
                    r"^[^@]+@[0-9a-f]{40}$",
                    f"mutable action reference at {path}:{line_number}",
                )
        self.assertGreater(found, 0)

    def test_composite_action_uses_hash_locked_installation(self) -> None:
        action = Path("action.yml").read_text(encoding="utf-8")
        lock = Path("requirements/action.lock").read_text(encoding="utf-8")

        self.assertIn("--require-hashes", action)
        self.assertIn('requirements/action.lock"', action)
        self.assertIn("--no-build-isolation", action)
        self.assertIn("--no-deps", action)
        for dependency in (
            "idna",
            "packaging",
            "pyjwt",
            "pydantic",
            "setuptools",
            "setuptools-scm",
            "sigstore",
            "tomlkit",
            "tuf",
            "urllib3",
            "wheel",
        ):
            block = re.search(
                rf"(?ms)^{re.escape(dependency)}==.*?(?=^[a-z0-9_.-]+==|\Z)",
                lock,
            )
            self.assertIsNotNone(block, dependency)
            self.assertIn("--hash=sha256:", block.group(0))  # type: ignore[union-attr]

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
        self.assertIn('version="${TAG_NAME#v}"', workflow)
        self.assertIn('IFS=. read -r major minor patch extra <<< "$version"', workflow)
        self.assertIn('echo "major_tag=v${major}" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn("needs['verify-tag'].outputs.action_major_tag", workflow)
        self.assertIn("publish-github-action:", workflow)
        self.assertIn("Publish moving major action tag", workflow)
        self.assertIn('get_endpoint="repos/${GITHUB_REPOSITORY}/git/ref/tags/', workflow)
        self.assertIn("--method PATCH", workflow)
        self.assertIn("-F force=true", workflow)
        self.assertIn("--method POST", workflow)
        self.assertIn("for attempt in {1..5}", workflow)
        self.assertIn("sleep 2", workflow)
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
                "TRUSTCHECK_ACTION_SANDBOX": "strict",
                "TRUSTCHECK_ACTION_SANDBOX_IMAGE": (
                    "registry.example/resolver@sha256:" + "d" * 64
                ),
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
        self.assertEqual(settings.sandbox, "strict")
        self.assertEqual(
            settings.sandbox_image,
            "registry.example/resolver@sha256:" + "d" * 64,
        )

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
            (
                {
                    "TRUSTCHECK_ACTION_TARGET": "requirements.txt",
                    "TRUSTCHECK_ACTION_SANDBOX": "virtual-machine",
                },
                "sandbox",
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
        text = ActionSettings.from_environment(
            {
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
            }
        )
        self.assertEqual(text.report_path, "trustcheck-report.txt")

        settings = ActionSettings.from_environment(
            {
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                "TRUSTCHECK_ACTION_FORMAT": "cyclonedx-xml",
            }
        )

        self.assertEqual(settings.report_path, "trustcheck-report.cdx.xml")
        self.assertEqual(settings.sandbox, "strict")

        spdx3 = ActionSettings.from_environment(
            {
                "TRUSTCHECK_ACTION_TARGET": "sampleproject",
                "TRUSTCHECK_ACTION_FORMAT": "spdx-3-json",
            }
        )
        self.assertEqual(spdx3.report_path, "trustcheck-report.spdx3.json")

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
