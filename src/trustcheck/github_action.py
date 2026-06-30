from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .cli import EXIT_DATA_ERROR, EXIT_OK, EXIT_USAGE
from .cli import main as cli_main
from .contract import JSON_SCHEMA_VERSION
from .exports import (
    INDUSTRY_OUTPUT_FORMATS,
    OUTPUT_FORMATS,
    recommended_extension,
    render_payload_export,
)
from .resolver import SANDBOX_MODES

SUPPORTED_SCAN_FILENAMES = {
    "pipfile.lock",
    "pdm.lock",
    "poetry.lock",
    "pylock.toml",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
}
RECOMMENDATION_ORDER = {
    "verified": 0,
    "metadata-only": 1,
    "review-required": 2,
    "high-risk": 3,
    "error": 4,
}
CliRunner = Callable[[Sequence[str]], int]


class ActionInputError(ValueError):
    pass


@dataclass(slots=True)
class ActionSettings:
    target: str
    policy: str = "default"
    expected_repo: str = ""
    trusted_publisher_organizations: tuple[str, ...] = ()
    with_osv: bool = False
    osv_urls: tuple[str, ...] = ()
    with_ecosystems: bool = False
    with_kev: bool = False
    with_epss: bool = False
    with_deps: bool = False
    with_transitive_deps: bool = False
    inspect_artifacts: bool = False
    index_url: str = ""
    extra_index_urls: tuple[str, ...] = ()
    keyring_provider: str = "auto"
    allow_dependency_confusion: bool = False
    trusted_projects: tuple[str, ...] = ()
    max_workers: int = 8
    sandbox: str = "strict"
    sandbox_image: str = ""
    advisory_snapshots: tuple[str, ...] = ()
    write_advisory_snapshot: str = ""
    max_advisory_age: float = 168.0
    advisory_snapshot_identity: str = ""
    advisory_snapshot_issuer: str = ""
    sign_advisory_snapshot: bool = False
    allow_unsigned_advisory_snapshot: bool = False
    resume_state: str = ""
    enable_plugins: bool = False
    plugins: tuple[str, ...] = ()
    plugin_config: str = ""
    remediation: str = "none"
    dry_run: bool = False
    allow_constraint_changes: bool = False
    source_manifest: str = ""
    remediation_path: str = "trustcheck-remediation.json"
    max_fix_attempts: int = 256
    create_pr: bool = False
    pr_base: str = ""
    pr_branch: str = ""
    pr_title: str = ""
    pr_ready: bool = False
    output_format: str = "text"
    report_path: str = "trustcheck-report.json"

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> ActionSettings:
        target = environment.get("TRUSTCHECK_ACTION_TARGET", "").strip()
        if not target:
            raise ActionInputError("the action input 'target' is required")
        output_format = (
            environment.get("TRUSTCHECK_ACTION_FORMAT", "text").strip()
            or "text"
        )
        if output_format not in OUTPUT_FORMATS:
            raise ActionInputError(
                "'format' must be one of: " + ", ".join(OUTPUT_FORMATS)
            )
        remediation = (
            environment.get("TRUSTCHECK_ACTION_REMEDIATION", "none").strip()
            or "none"
        )
        if remediation not in {"none", "plan", "fix"}:
            raise ActionInputError(
                "'remediation' must be 'none', 'plan', or 'fix'"
            )
        try:
            max_fix_attempts = int(
                environment.get(
                    "TRUSTCHECK_ACTION_MAX_FIX_ATTEMPTS",
                    "256",
                )
            )
        except ValueError as exc:
            raise ActionInputError(
                "'max-fix-attempts' must be an integer"
            ) from exc
        if max_fix_attempts < 1:
            raise ActionInputError(
                "'max-fix-attempts' must be at least 1"
            )
        try:
            max_workers = int(
                environment.get(
                    "TRUSTCHECK_ACTION_WORKERS",
                    environment.get("TRUSTCHECK_ACTION_MAX_WORKERS", "8"),
                )
            )
        except ValueError as exc:
            raise ActionInputError("'workers' must be an integer") from exc
        if max_workers != -1 and not 1 <= max_workers <= 64:
            raise ActionInputError("'workers' must be -1 or between 1 and 64")
        try:
            max_advisory_age = float(
                environment.get("TRUSTCHECK_ACTION_MAX_ADVISORY_AGE", "168")
            )
        except ValueError as exc:
            raise ActionInputError("'max-advisory-age' must be a number") from exc
        if max_advisory_age <= 0:
            raise ActionInputError("'max-advisory-age' must be positive")
        sandbox = (
            environment.get("TRUSTCHECK_ACTION_SANDBOX", "strict").strip()
            or "strict"
        )
        if sandbox not in SANDBOX_MODES:
            raise ActionInputError(
                "'sandbox' must be off, warn, auto, container, bubblewrap, or strict"
            )
        report_path = environment.get(
            "TRUSTCHECK_ACTION_REPORT_PATH", ""
        ).strip() or _default_report_path(output_format)
        return cls(
            target=target,
            policy=environment.get("TRUSTCHECK_ACTION_POLICY", "default").strip()
            or "default",
            expected_repo=environment.get(
                "TRUSTCHECK_ACTION_EXPECTED_REPO", ""
            ).strip(),
            trusted_publisher_organizations=_parse_multi_value(
                environment.get(
                    "TRUSTCHECK_ACTION_TRUSTED_PUBLISHER_ORGANIZATIONS",
                    "",
                )
            ),
            with_osv=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_WITH_OSV", "false"),
                name="with-osv",
            ),
            osv_urls=_parse_multi_value(
                environment.get("TRUSTCHECK_ACTION_OSV_URLS", "")
            ),
            with_ecosystems=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_WITH_ECOSYSTEMS",
                    "false",
                ),
                name="with-ecosystems",
            ),
            with_kev=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_WITH_KEV", "false"),
                name="with-kev",
            ),
            with_epss=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_WITH_EPSS", "false"),
                name="with-epss",
            ),
            with_deps=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_WITH_DEPS", "false"),
                name="with-deps",
            ),
            with_transitive_deps=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_WITH_TRANSITIVE_DEPS", "false"),
                name="with-transitive-deps",
            ),
            inspect_artifacts=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_INSPECT_ARTIFACTS", "false"),
                name="inspect-artifacts",
            ),
            index_url=environment.get("TRUSTCHECK_ACTION_INDEX_URL", "").strip(),
            extra_index_urls=_parse_multi_value(
                environment.get("TRUSTCHECK_ACTION_EXTRA_INDEX_URLS", "")
            ),
            keyring_provider=environment.get(
                "TRUSTCHECK_ACTION_KEYRING_PROVIDER", "auto"
            ).strip()
            or "auto",
            allow_dependency_confusion=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_ALLOW_DEPENDENCY_CONFUSION", "false"
                ),
                name="allow-dependency-confusion",
            ),
            trusted_projects=_parse_multi_value(
                environment.get("TRUSTCHECK_ACTION_TRUSTED_PROJECTS", "")
            ),
            max_workers=max_workers,
            sandbox=sandbox,
            sandbox_image=environment.get(
                "TRUSTCHECK_ACTION_SANDBOX_IMAGE", ""
            ).strip(),
            advisory_snapshots=_parse_multi_value(
                environment.get(
                    "TRUSTCHECK_ACTION_ADVISORY_SNAPSHOTS",
                    "",
                )
            ),
            write_advisory_snapshot=environment.get(
                "TRUSTCHECK_ACTION_WRITE_ADVISORY_SNAPSHOT",
                "",
            ).strip(),
            max_advisory_age=max_advisory_age,
            advisory_snapshot_identity=environment.get(
                "TRUSTCHECK_ACTION_ADVISORY_SNAPSHOT_IDENTITY",
                "",
            ).strip(),
            advisory_snapshot_issuer=environment.get(
                "TRUSTCHECK_ACTION_ADVISORY_SNAPSHOT_ISSUER",
                "",
            ).strip(),
            sign_advisory_snapshot=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_SIGN_ADVISORY_SNAPSHOT",
                    "false",
                ),
                name="sign-advisory-snapshot",
            ),
            allow_unsigned_advisory_snapshot=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_ALLOW_UNSIGNED_ADVISORY_SNAPSHOT",
                    "false",
                ),
                name="allow-unsigned-advisory-snapshot",
            ),
            resume_state=environment.get(
                "TRUSTCHECK_ACTION_RESUME_STATE",
                "",
            ).strip(),
            enable_plugins=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_ENABLE_PLUGINS",
                    "false",
                ),
                name="enable-plugins",
            ),
            plugins=_parse_multi_value(
                environment.get("TRUSTCHECK_ACTION_PLUGINS", "")
            ),
            plugin_config=environment.get(
                "TRUSTCHECK_ACTION_PLUGIN_CONFIG",
                "",
            ).strip(),
            remediation=remediation,
            dry_run=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_DRY_RUN", "false"),
                name="dry-run",
            ),
            allow_constraint_changes=_parse_bool(
                environment.get(
                    "TRUSTCHECK_ACTION_ALLOW_CONSTRAINT_CHANGES",
                    "false",
                ),
                name="allow-constraint-changes",
            ),
            source_manifest=environment.get(
                "TRUSTCHECK_ACTION_SOURCE_MANIFEST",
                "",
            ).strip(),
            remediation_path=environment.get(
                "TRUSTCHECK_ACTION_REMEDIATION_PATH",
                "",
            ).strip()
            or "trustcheck-remediation.json",
            max_fix_attempts=max_fix_attempts,
            create_pr=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_CREATE_PR", "false"),
                name="create-pr",
            ),
            pr_base=environment.get(
                "TRUSTCHECK_ACTION_PR_BASE",
                "",
            ).strip(),
            pr_branch=environment.get(
                "TRUSTCHECK_ACTION_PR_BRANCH",
                "",
            ).strip(),
            pr_title=environment.get(
                "TRUSTCHECK_ACTION_PR_TITLE",
                "",
            ).strip(),
            pr_ready=_parse_bool(
                environment.get("TRUSTCHECK_ACTION_PR_READY", "false"),
                name="pr-ready",
            ),
            output_format=output_format,
            report_path=report_path,
        )


@dataclass(slots=True)
class ActionResult:
    exit_code: int
    recommendation: str
    policy_passed: bool
    report_path: Path
    payload: dict[str, object]
    stderr: str = ""
    remediation_status: str = "not-requested"
    applied_fixes: int = 0
    remediation_path: Path | None = None
    pr_branch: str = ""
    pr_url: str = ""


def build_cli_arguments(settings: ActionSettings, *, workspace: Path) -> list[str]:
    if settings.with_deps and settings.with_transitive_deps:
        raise ActionInputError(
            "'with-deps' and 'with-transitive-deps' are mutually exclusive"
        )
    if settings.output_format not in OUTPUT_FORMATS:
        raise ActionInputError(
            "'format' must be one of: " + ", ".join(OUTPUT_FORMATS)
        )
    if settings.keyring_provider not in {
        "auto",
        "disabled",
        "import",
        "subprocess",
    }:
        raise ActionInputError(
            "'keyring-provider' must be 'auto', 'disabled', 'import', or 'subprocess'"
        )
    if settings.remediation not in {"none", "plan", "fix"}:
        raise ActionInputError(
            "'remediation' must be 'none', 'plan', or 'fix'"
        )
    if settings.max_fix_attempts < 1:
        raise ActionInputError("'max-fix-attempts' must be at least 1")
    if settings.max_workers != -1 and not 1 <= settings.max_workers <= 64:
        raise ActionInputError("'workers' must be -1 or between 1 and 64")
    if settings.sandbox not in SANDBOX_MODES:
        raise ActionInputError(
            "'sandbox' must be off, warn, auto, container, bubblewrap, or strict"
        )
    if settings.dry_run and settings.remediation != "fix":
        raise ActionInputError("'dry-run' requires remediation mode 'fix'")
    if settings.create_pr and (
        settings.remediation != "fix" or settings.dry_run
    ):
        raise ActionInputError(
            "'create-pr' requires non-dry-run remediation mode 'fix'"
        )

    target_path = _resolve_workspace_path(settings.target, workspace)
    target_is_file = target_path.is_file()
    if not target_is_file and _looks_like_scan_file(settings.target):
        raise ActionInputError(f"scan target file does not exist: {settings.target}")
    scan_mode = target_is_file or (
        settings.with_osv
        or bool(settings.osv_urls)
        or settings.with_ecosystems
        or settings.with_kev
        or settings.with_epss
    )
    if scan_mode and not target_is_file:
        unsupported_scan_options = []
        if settings.expected_repo:
            unsupported_scan_options.append("expected-repo")
        if settings.trusted_publisher_organizations:
            unsupported_scan_options.append("trusted-publisher-organizations")
        if settings.with_deps:
            unsupported_scan_options.append("with-deps")
        if settings.with_transitive_deps:
            unsupported_scan_options.append("with-transitive-deps")
        if settings.inspect_artifacts:
            unsupported_scan_options.append("inspect-artifacts")
        if settings.trusted_projects:
            unsupported_scan_options.append("trusted-projects")
        if unsupported_scan_options:
            joined = ", ".join(unsupported_scan_options)
            raise ActionInputError(
                "package vulnerability scans do not support trust-inspection "
                f"options: {joined}"
            )

    if target_is_file:
        if settings.expected_repo:
            raise ActionInputError(
                "'expected-repo' applies to package targets, not dependency files"
            )
        unsupported_file_scan_options = []
        if settings.trusted_publisher_organizations:
            unsupported_file_scan_options.append("trusted-publisher-organizations")
        if settings.with_deps:
            unsupported_file_scan_options.append("with-deps")
        if settings.with_transitive_deps:
            unsupported_file_scan_options.append("with-transitive-deps")
        if settings.inspect_artifacts:
            unsupported_file_scan_options.append("inspect-artifacts")
        if settings.trusted_projects:
            unsupported_file_scan_options.append("trusted-projects")
        if unsupported_file_scan_options:
            joined = ", ".join(unsupported_file_scan_options)
            raise ActionInputError(
                "dependency-file vulnerability scans do not support "
                f"trust-inspection options: {joined}"
            )
        arguments = ["scan", "-f", str(target_path)]
        if settings.remediation == "plan":
            arguments.append("--plan-fixes")
        elif settings.remediation == "fix":
            arguments.append("--fix")
        if settings.dry_run:
            arguments.append("--dry-run")
        if settings.allow_constraint_changes:
            arguments.append("--allow-constraint-changes")
        if settings.source_manifest:
            source_manifest = _resolve_workspace_path(
                settings.source_manifest,
                workspace,
            )
            if not source_manifest.is_file():
                raise ActionInputError(
                    f"source manifest does not exist: {settings.source_manifest}"
                )
            arguments.extend(["--source-manifest", str(source_manifest)])
        if settings.remediation != "none":
            remediation_path = _resolve_workspace_path(
                settings.remediation_path,
                workspace,
            )
            arguments.extend(
                ["--remediation-output", str(remediation_path)]
            )
            arguments.extend(
                ["--max-fix-attempts", str(settings.max_fix_attempts)]
            )
        if settings.create_pr:
            arguments.append("--create-pr")
            if settings.pr_base:
                arguments.extend(["--pr-base", settings.pr_base])
            if settings.pr_branch:
                arguments.extend(["--pr-branch", settings.pr_branch])
            if settings.pr_title:
                arguments.extend(["--pr-title", settings.pr_title])
            if settings.pr_ready:
                arguments.append("--pr-ready")
        if settings.resume_state:
            resume_state = _resolve_workspace_path(
                settings.resume_state,
                workspace,
            )
            arguments.extend(["--resume-state", str(resume_state)])
    else:
        if settings.remediation != "none":
            raise ActionInputError(
                "remediation applies to dependency files, not package targets"
            )
        arguments = ["scan" if scan_mode else "inspect", settings.target]
        if settings.expected_repo:
            arguments.extend(["--expected-repo", settings.expected_repo])

    if not scan_mode:
        for organization in settings.trusted_publisher_organizations:
            arguments.extend(
                ["--trusted-publisher-organization", organization]
            )

    policy_path = _resolve_workspace_path(settings.policy, workspace)
    if settings.policy in {"default", "strict"}:
        arguments.extend(["--policy", settings.policy])
    elif policy_path.is_file():
        arguments.extend(["--policy-file", str(policy_path)])
    else:
        raise ActionInputError(
            "'policy' must be 'default', 'strict', or an existing custom policy file"
        )

    if settings.with_osv:
        arguments.append("--with-osv")
    for url in settings.osv_urls:
        arguments.extend(["--osv-url", url])
    if settings.with_ecosystems:
        arguments.append("--with-ecosystems")
    if settings.with_kev:
        arguments.append("--with-kev")
    if settings.with_epss:
        arguments.append("--with-epss")
    if not scan_mode and settings.with_deps:
        arguments.append("--with-deps")
    if not scan_mode and settings.with_transitive_deps:
        arguments.append("--with-transitive-deps")
    if not scan_mode and settings.inspect_artifacts:
        arguments.append("--inspect-artifacts")
    if settings.index_url:
        arguments.extend(["--index-url", settings.index_url])
    for index_url in settings.extra_index_urls:
        arguments.extend(["--extra-index-url", index_url])
    arguments.extend(["--keyring-provider", settings.keyring_provider])
    if settings.allow_dependency_confusion:
        arguments.append("--allow-dependency-confusion")
    if not scan_mode:
        for project in settings.trusted_projects:
            arguments.extend(["--trusted-project", project])
    arguments.extend(["--workers", str(settings.max_workers)])
    arguments.extend(["--sandbox", settings.sandbox])
    if settings.sandbox_image:
        arguments.extend(["--sandbox-image", settings.sandbox_image])
    for snapshot in settings.advisory_snapshots:
        snapshot_path = _resolve_workspace_path(snapshot, workspace)
        if not snapshot_path.is_file():
            raise ActionInputError(
                f"advisory snapshot does not exist: {snapshot}"
            )
        arguments.extend(["--advisory-snapshot", str(snapshot_path)])
    if settings.write_advisory_snapshot:
        snapshot_output = _resolve_workspace_path(
            settings.write_advisory_snapshot,
            workspace,
        )
        arguments.extend(
            ["--write-advisory-snapshot", str(snapshot_output)]
        )
    arguments.extend(["--max-advisory-age", str(settings.max_advisory_age)])
    if settings.advisory_snapshot_identity:
        arguments.extend(
            ["--advisory-snapshot-identity", settings.advisory_snapshot_identity]
        )
    if settings.advisory_snapshot_issuer:
        arguments.extend(
            ["--advisory-snapshot-issuer", settings.advisory_snapshot_issuer]
        )
    if settings.sign_advisory_snapshot:
        arguments.append("--sign-advisory-snapshot")
    if settings.allow_unsigned_advisory_snapshot:
        arguments.append("--allow-unsigned-advisory-snapshot")
    if settings.enable_plugins:
        arguments.append("--enable-plugins")
    for plugin in settings.plugins:
        arguments.extend(["--plugin", plugin])
    if settings.plugin_config:
        plugin_config = _resolve_workspace_path(
            settings.plugin_config,
            workspace,
        )
        if not plugin_config.is_file():
            raise ActionInputError(
                f"plugin config does not exist: {settings.plugin_config}"
            )
        arguments.extend(["--plugin-config", str(plugin_config)])
    arguments.extend(["--format", "json"])
    return arguments


def run_action(
    settings: ActionSettings,
    *,
    workspace: Path,
    runner: CliRunner = cli_main,
) -> ActionResult:
    report_path = _resolve_workspace_path(settings.report_path, workspace)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        arguments = build_cli_arguments(settings, workspace=workspace)
    except ActionInputError as exc:
        return _write_error_result(
            settings,
            report_path=report_path,
            exit_code=EXIT_USAGE,
            message=str(exc),
        )

    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = runner(arguments)

    raw_output = stdout.getvalue().strip()
    stderr_output = stderr.getvalue().strip()
    try:
        decoded = json.loads(raw_output)
        if not isinstance(decoded, dict):
            raise ValueError("CLI JSON output must be an object")
        payload: dict[str, object] = decoded
    except (json.JSONDecodeError, ValueError) as exc:
        message = stderr_output or f"unable to parse trustcheck JSON output: {exc}"
        return _write_error_result(
            settings,
            report_path=report_path,
            exit_code=exit_code or EXIT_DATA_ERROR,
            message=message,
        )

    try:
        rendered_report = (
            render_payload_export(settings.output_format, payload)
            if settings.output_format in INDUSTRY_OUTPUT_FORMATS
            else json.dumps(payload, indent=2, sort_keys=True)
        )
    except ValueError as exc:
        return _write_error_result(
            settings,
            report_path=report_path,
            exit_code=EXIT_DATA_ERROR,
            message=f"unable to render {settings.output_format} report: {exc}",
        )
    report_path.write_text(
        rendered_report
        + ("" if rendered_report.endswith("\n") else "\n"),
        encoding="utf-8",
    )
    recommendation, policy_passed = summarize_payload(payload, exit_code=exit_code)
    remediation = payload.get("remediation")
    remediation_status = "not-requested"
    applied_fixes = 0
    pr_branch = ""
    pr_url = ""
    if isinstance(remediation, dict):
        status = remediation.get("status")
        if isinstance(status, str):
            remediation_status = status
        upgrades = remediation.get("upgrades")
        if isinstance(upgrades, list):
            applied_fixes = len(upgrades)
        pull_request = remediation.get("pull_request")
        if isinstance(pull_request, dict):
            raw_branch = pull_request.get("branch")
            raw_url = pull_request.get("url")
            pr_branch = raw_branch if isinstance(raw_branch, str) else ""
            pr_url = raw_url if isinstance(raw_url, str) else ""
    return ActionResult(
        exit_code=exit_code,
        recommendation=recommendation,
        policy_passed=policy_passed,
        report_path=report_path,
        payload=payload,
        stderr=stderr_output,
        remediation_status=remediation_status,
        applied_fixes=applied_fixes,
        remediation_path=(
            _resolve_workspace_path(settings.remediation_path, workspace)
            if settings.remediation != "none"
            else None
        ),
        pr_branch=pr_branch,
        pr_url=pr_url,
    )


def summarize_payload(
    payload: Mapping[str, object],
    *,
    exit_code: int,
) -> tuple[str, bool]:
    report = payload.get("report")
    if isinstance(report, dict):
        recommendation = _report_recommendation(report)
        policy_passed = _report_policy_passed(report)
        return recommendation, exit_code == EXIT_OK and policy_passed

    reports = payload.get("reports")
    failures = payload.get("failures")
    if isinstance(reports, list):
        report_items = [item for item in reports if isinstance(item, dict)]
        recommendations = [_report_recommendation(item) for item in report_items]
        recommendation = _worst_recommendation(recommendations)
        has_failures = isinstance(failures, list) and bool(failures)
        policy_passed = (
            exit_code == EXIT_OK
            and bool(report_items)
            and not has_failures
            and all(_report_policy_passed(item) for item in report_items)
        )
        return recommendation, policy_passed

    return "error", False


def render_result(result: ActionResult, *, output_format: str, target: str) -> str:
    if output_format == "json":
        return json.dumps(result.payload, indent=2, sort_keys=True)
    policy_label = "passed" if result.policy_passed else "failed"
    return "\n".join(
        [
            f"trustcheck action result for {target}",
            f"  recommendation: {result.recommendation}",
            f"  policy: {policy_label}",
            f"  report: {result.report_path}",
            f"  remediation: {result.remediation_status}",
        ]
    )


def main(
    environment: Mapping[str, str] | None = None,
    *,
    runner: CliRunner = cli_main,
) -> int:
    if environment is None:
        environment = os.environ
    workspace = Path(environment.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
    try:
        settings = ActionSettings.from_environment(environment)
    except ActionInputError as exc:
        settings = ActionSettings(target="<missing>")
        result = _write_error_result(
            settings,
            report_path=workspace / "trustcheck-report.json",
            exit_code=EXIT_USAGE,
            message=str(exc),
        )
    else:
        result = run_action(settings, workspace=workspace, runner=runner)

    if result.stderr:
        print(result.stderr, file=sys.stderr)
    print(render_result(result, output_format=settings.output_format, target=settings.target))
    _write_action_outputs(result, environment)
    _write_step_summary(result, settings, environment)
    return result.exit_code


def _write_error_result(
    settings: ActionSettings,
    *,
    report_path: Path,
    exit_code: int,
    message: str,
) -> ActionResult:
    payload: dict[str, object] = {
        "action_error": {
            "exit_code": exit_code,
            "message": message,
            "target": settings.target,
        },
        "schema_version": JSON_SCHEMA_VERSION,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return ActionResult(
        exit_code=exit_code,
        recommendation="error",
        policy_passed=False,
        report_path=report_path,
        payload=payload,
        stderr=f"error: {message}",
    )


def _write_action_outputs(
    result: ActionResult,
    environment: Mapping[str, str],
) -> None:
    output_path = environment.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8") as output:
        output.write(f"recommendation={result.recommendation}\n")
        output.write(f"policy-passed={str(result.policy_passed).lower()}\n")
        output.write(f"report-path={result.report_path}\n")
        output.write(f"exit-code={result.exit_code}\n")
        output.write(f"remediation-status={result.remediation_status}\n")
        output.write(f"applied-fixes={result.applied_fixes}\n")
        output.write(
            "patch-path="
            f"{result.remediation_path or ''}\n"
        )
        output.write(f"pr-branch={result.pr_branch}\n")
        output.write(f"pr-url={result.pr_url}\n")


def _write_step_summary(
    result: ActionResult,
    settings: ActionSettings,
    environment: Mapping[str, str],
) -> None:
    summary_path = environment.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    policy_label = "passed" if result.policy_passed else "failed"
    with Path(summary_path).open("a", encoding="utf-8") as summary:
        summary.write("## trustcheck\n\n")
        summary.write(f"- Target: `{settings.target}`\n")
        summary.write(f"- Recommendation: `{result.recommendation}`\n")
        summary.write(f"- Policy: **{policy_label}**\n")
        summary.write(f"- Report: `{result.report_path}`\n")
        summary.write(f"- Remediation: `{result.remediation_status}`\n")
        if result.pr_url:
            summary.write(f"- Pull request: {result.pr_url}\n")


def _report_recommendation(report: Mapping[str, object]) -> str:
    value = report.get("recommendation")
    return value if isinstance(value, str) and value else "error"


def _report_policy_passed(report: Mapping[str, object]) -> bool:
    policy = report.get("policy")
    return isinstance(policy, dict) and policy.get("passed") is True


def _worst_recommendation(recommendations: Sequence[str]) -> str:
    if not recommendations:
        return "error"
    return max(
        recommendations,
        key=lambda item: RECOMMENDATION_ORDER.get(item, RECOMMENDATION_ORDER["error"]),
    )


def _resolve_workspace_path(value: str, workspace: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def _looks_like_scan_file(target: str) -> bool:
    path = Path(target)
    filename = path.name.lower()
    return (
        filename in SUPPORTED_SCAN_FILENAMES
        or (filename.startswith("pylock.") and filename.endswith(".toml"))
        or path.suffix.lower() in {".lock", ".toml", ".txt"}
    )


def _parse_multi_value(value: str) -> tuple[str, ...]:
    return tuple(item for line in value.splitlines() for item in line.split())


def _default_report_path(output_format: str) -> str:
    format_for_file = "json" if output_format == "text" else output_format
    return "trustcheck-report" + recommended_extension(format_for_file)


def _parse_bool(value: str, *, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ActionInputError(f"'{name}' must be 'true' or 'false'")


if __name__ == "__main__":
    raise SystemExit(main())
