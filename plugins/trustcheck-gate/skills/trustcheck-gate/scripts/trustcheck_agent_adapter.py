from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import signal
import subprocess  # nosec B404 - invoked with fixed argv and shell=False.
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ADAPTER_SCHEMA_VERSION = "0.1.0"
SUPPORTED_TRUSTCHECK_SPEC = ">=2.2,<3.0"
SUPPORTED_TRUSTCHECK_MIN = (2, 2, 0)
SUPPORTED_TRUSTCHECK_MAX = (3, 0, 0)
SUPPORTED_REPORT_SCHEMA_SPEC = "1.11.0"
SUPPORTED_REPORT_SCHEMA_VERSIONS = {SUPPORTED_REPORT_SCHEMA_SPEC}
TRUSTCHECK_COMMAND = "__trustcheck__"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_OUTPUT_BYTES = 500_000
DEFAULT_MAX_STDERR_BYTES = 200_000
MAX_REQUEST_BYTES = 100_000
MAX_TIMEOUT_SECONDS = 600
MAX_PROJECT_FILES = 5
MAX_PACKAGE_CHECKS = 2
MAX_PATH_LENGTH = 4096
MAX_URL_LENGTH = 2048
PROCESS_TERMINATION_GRACE_SECONDS = 2.0

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!+._~-]{0,127}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/-]{0,127}$")
POLICIES = {"default", "strict"}
DEPTHS = {"fast", "standard", "full"}
ARTIFACT_SCOPES = {"target", "sdist", "all"}
REPORT_FORMATS = {
    "json",
    "markdown",
    "sarif",
    "cyclonedx-json",
    "cyclonedx-1.7-json",
    "spdx-json",
    "spdx-3-json",
    "openvex",
}
DEPENDENCY_FILE_NAMES = (
    "requirements.txt",
    "requirements.lock",
    "pylock.toml",
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "pyproject.toml",
)
DEPENDENCY_FILE_GLOBS = (
    "requirements/*.txt",
    "requirements/*.lock",
    "requirements-*.txt",
    "*requirements*.txt",
)
SECRET_PATTERNS = (
    re.compile(r"(?i)(token|password|passwd|secret|api[_-]?key)=([^&\s]+)"),
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)\b([A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|API[_-]?KEY|AUTH)[A-Z0-9_]*)=([^\s]+)"
    ),
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "key",
    "password",
    "secret",
    "signature",
    "sig",
    "token",
}
FORBIDDEN_REQUEST_FIELDS = {
    "apply",
    "container_image",
    "create_pr",
    "dynamic_analysis",
    "enable_plugins",
    "extra_index_url",
    "fix",
    "index_url",
    "install",
    "plugin",
    "plugin_config",
    "plugins",
    "trusted_host",
}
COMMON_REQUEST_FIELDS = {
    "operation",
    "workspace",
    "policy",
    "analysis_depth",
    "advanced_analysis",
    "artifact_scope",
    "offline",
    "timeout_seconds",
    "max_output_bytes",
}
OPERATION_FIELDS = {
    "check_package": {
        "package",
        "version",
        "with_osv",
        "source_release_provenance",
        "release_tag",
    },
    "verify_release": {
        "package",
        "version",
        "expected_repository",
        "release_tag",
    },
    "check_requirements": {
        "path",
        "with_osv",
        "no_deps",
    },
    "scan_project": {
        "path",
        "max_files",
        "with_osv",
        "no_deps",
    },
    "plan_remediation": {
        "path",
        "max_fix_attempts",
    },
    "compare_versions": {
        "package",
        "current_version",
        "proposed_version",
        "with_osv",
        "source_release_provenance",
        "release_tag",
    },
    "generate_report": {
        "target_type",
        "format",
        "package",
        "version",
        "path",
        "with_osv",
    },
    "explain_findings": {
        "report",
        "report_path",
    },
}
REQUIRED_OPERATION_FIELDS = {
    "check_package": {"package"},
    "verify_release": {"package"},
    "check_requirements": {"path"},
    "scan_project": set(),
    "plan_remediation": {"path"},
    "compare_versions": {"package", "current_version", "proposed_version"},
    "generate_report": {"target_type", "format"},
    "explain_findings": set(),
}
READ_ONLY_OPERATION_COUNT = {
    "check_package": 1,
    "verify_release": 1,
    "check_requirements": 1,
    "scan_project": MAX_PROJECT_FILES,
    "plan_remediation": 1,
    "compare_versions": 2,
    "generate_report": 1,
    "explain_findings": 0,
}


class AdapterError(ValueError):
    pass


class TrustcheckRuntimeError(AdapterError):
    def __init__(self, message: str, *, returncode: int = 127) -> None:
        super().__init__(message)
        self.returncode = returncode


@dataclass(frozen=True)
class TrustcheckRuntime:
    command_prefix: tuple[str, ...]
    source: str
    version: str


@dataclass(frozen=True)
class ReportValidation:
    payload: Mapping[str, Any] | None
    findings: dict[str, Any]
    execution_status: str
    report_status: str
    security_status: str
    classification: str
    policy_permits_install: bool
    report_schema_version: str | None
    errors: list[str]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run fixed Trustcheck operations for AI dependency gating."
    )
    parser.add_argument(
        "request",
        nargs="?",
        help="JSON request file. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print adapter JSON output.",
    )
    args = parser.parse_args(argv)

    try:
        request = _load_request(args.request)
        result = run_operation(request)
        print(
            json.dumps(
                result,
                indent=2 if args.pretty else None,
                sort_keys=True,
            )
        )
        return _adapter_exit_code(result)
    except AdapterError as exc:
        print(
            json.dumps(
                _base_result("invalid-request")
                | {
                    "classification": "usage_error",
                    "policy_permits_install": False,
                    "errors": [str(exc)],
                },
                indent=2 if args.pretty else None,
                sort_keys=True,
            )
        )
        return 2


def run_operation(request: Mapping[str, Any]) -> dict[str, Any]:
    _validate_request_schema(request)
    operation = _required_str(request, "operation")
    workspace = _workspace(request.get("workspace"))
    timeout = _bounded_int(
        request.get("timeout_seconds"),
        default=DEFAULT_TIMEOUT_SECONDS,
        minimum=1,
        maximum=MAX_TIMEOUT_SECONDS,
        field="timeout_seconds",
    )
    max_output_bytes = _bounded_int(
        request.get("max_output_bytes"),
        default=DEFAULT_MAX_OUTPUT_BYTES,
        minimum=10_000,
        maximum=5_000_000,
        field="max_output_bytes",
    )

    if operation == "check_package":
        return _check_package(request, workspace, timeout, max_output_bytes)
    if operation == "verify_release":
        return _verify_release(request, workspace, timeout, max_output_bytes)
    if operation == "check_requirements":
        return _check_requirements(request, workspace, timeout, max_output_bytes)
    if operation == "scan_project":
        return _scan_project(request, workspace, timeout, max_output_bytes)
    if operation == "plan_remediation":
        return _plan_remediation(request, workspace, timeout, max_output_bytes)
    if operation == "compare_versions":
        return _compare_versions(request, workspace, timeout, max_output_bytes)
    if operation == "generate_report":
        return _generate_report(request, workspace, timeout, max_output_bytes)
    if operation == "explain_findings":
        return _explain_findings(request, workspace)

    raise AdapterError(
        "operation must be one of: check_package, verify_release, "
        "check_requirements, scan_project, plan_remediation, compare_versions, "
        "generate_report, explain_findings"
    )


def _validate_request_schema(request: Mapping[str, Any]) -> None:
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in OPERATION_FIELDS:
        raise AdapterError(
            "operation must be one of: " + ", ".join(sorted(OPERATION_FIELDS))
        )
    forbidden = sorted(FORBIDDEN_REQUEST_FIELDS & set(request))
    if forbidden:
        raise AdapterError(
            "unsupported read-only adapter field(s): " + ", ".join(forbidden)
        )
    allowed = COMMON_REQUEST_FIELDS | OPERATION_FIELDS[operation]
    unexpected = sorted(set(request) - allowed)
    if unexpected:
        raise AdapterError("unexpected request field(s): " + ", ".join(unexpected))
    missing = sorted(
        field for field in REQUIRED_OPERATION_FIELDS[operation] if field not in request
    )
    if missing:
        raise AdapterError("missing required field(s): " + ", ".join(missing))
    package_checks = READ_ONLY_OPERATION_COUNT[operation]
    if package_checks > MAX_PACKAGE_CHECKS and operation != "scan_project":
        raise AdapterError("request exceeds package-check quota")
    if operation == "generate_report":
        target_type = request.get("target_type")
        if target_type == "package" and "package" not in request:
            raise AdapterError("generate_report target_type=package requires package")
        if target_type == "requirements" and "path" not in request:
            raise AdapterError("generate_report target_type=requirements requires path")
    if operation == "explain_findings":
        has_report = "report" in request
        has_report_path = "report_path" in request
        if has_report == has_report_path:
            raise AdapterError("explain_findings requires exactly one of report or report_path")


def _check_package(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    package = _package(request, "package")
    version = _optional_version(request.get("version"), "version")
    depth = _analysis_depth(request)
    command = _trustcheck_command(
        [
            "scan",
            package,
            *_version_args(version),
            f"--{depth}",
            "--format",
            "json",
            *_policy_args(request),
            *_optional_flag(request, "with_osv", "--with-osv"),
            *_offline_args(request),
            *_artifact_scope_args(request, depth),
            *_source_release_args(request),
        ]
    )
    return _run_json_operation(
        "check_package",
        command,
        workspace,
        timeout,
        max_output_bytes,
    )


def _verify_release(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    package = _package(request, "package")
    version = _optional_version(request.get("version"), "version")
    expected_repo = _optional_https_url(request.get("expected_repository"), "expected_repository")
    release_tag = _optional_token(request.get("release_tag"), "release_tag")
    advanced = _bool(request.get("advanced_analysis"), default=False)
    command = _trustcheck_command(
        [
            "inspect",
            package,
            *_version_args(version),
            "--format",
            "json",
            *_policy_args(request),
            *_offline_args(request),
            *(
                ["--expected-repo", expected_repo]
                if expected_repo is not None
                else []
            ),
            "--source-release-provenance",
            *(["--release-tag", release_tag] if release_tag is not None else []),
            *(["--inspect-artifacts"] if advanced else []),
        ]
    )
    return _run_json_operation(
        "verify_release",
        command,
        workspace,
        timeout,
        max_output_bytes,
    )


def _check_requirements(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    path = _workspace_file(workspace, _required_str(request, "path"))
    command = _scan_file_command(request, path)
    return _run_json_operation(
        "check_requirements",
        command,
        workspace,
        timeout,
        max_output_bytes,
    )


def _scan_project(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    explicit_path = request.get("path")
    files = (
        [_workspace_file(workspace, _required_str(request, "path"))]
        if explicit_path is not None
        else _discover_dependency_files(workspace)
    )
    max_files = _bounded_int(
        request.get("max_files"),
        default=MAX_PROJECT_FILES,
        minimum=1,
        maximum=MAX_PROJECT_FILES,
        field="max_files",
    )
    selected_files = files[:max_files]
    result = _base_result("scan_project") | {
        "workspace": str(workspace),
        "dependency_files": [str(path) for path in selected_files],
        "skipped_dependency_files": [str(path) for path in files[max_files:]],
        "reports": [],
        "findings": {"blocking_reasons": []},
        "execution_status": "completed",
        "report_status": "missing",
        "security_status": "scan_failed",
        "policy_permits_install": False,
    }
    if not selected_files:
        return result | {
            "classification": "scan_failed",
            "errors": ["no supported dependency files were found"],
        }

    classifications: list[str] = []
    execution_statuses: list[str] = []
    report_statuses: list[str] = []
    security_statuses: list[str] = []
    all_blocking: list[str] = []
    errors: list[str] = []
    deadline = time.monotonic() + timeout
    for path in selected_files:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            child = _deadline_exceeded_result(path)
        else:
            child = _run_json_operation(
                "check_requirements",
                _scan_file_command(request, path),
                workspace,
                remaining,
                max_output_bytes,
            )
        classifications.append(str(child.get("classification")))
        execution_statuses.append(str(child.get("execution_status", "completed")))
        report_statuses.append(str(child.get("report_status", "missing")))
        security_statuses.append(str(child.get("security_status", "scan_failed")))
        errors.extend(str(item) for item in _list(child.get("errors")) if item)
        child_findings = child.get("findings")
        if isinstance(child_findings, Mapping):
            all_blocking.extend(
                str(item)
                for item in child_findings.get("blocking_reasons", [])
                if item
            )
        result["reports"].append(
            {
                "path": str(path),
                "classification": child.get("classification"),
                "exit_code": child.get("exit_code"),
                "command": child.get("command"),
                "execution_status": child.get("execution_status"),
                "report_status": child.get("report_status"),
                "security_status": child.get("security_status"),
                "report_schema_version": child.get("report_schema_version"),
                "trustcheck_version": child.get("trustcheck_version"),
                "trustcheck_command_source": child.get("trustcheck_command_source"),
                "findings": child.get("findings"),
                "report": child.get("report"),
                "errors": child.get("errors", []),
            }
        )

    classification = _merge_classifications(classifications)
    result["classification"] = classification
    result["execution_status"] = _merge_execution_statuses(execution_statuses)
    result["report_status"] = _merge_report_statuses(report_statuses)
    result["security_status"] = _merge_security_statuses(security_statuses)
    result["policy_permits_install"] = classification == "passed"
    result["findings"] = {
        "blocking_reasons": _dedupe(all_blocking),
        "scanned_files": len(selected_files),
        "skipped_files": len(files[max_files:]),
    }
    result["errors"] = _dedupe(errors)
    versions = [
        str(report["trustcheck_version"])
        for report in result["reports"]
        if isinstance(report, Mapping) and report.get("trustcheck_version")
    ]
    sources = [
        str(report["trustcheck_command_source"])
        for report in result["reports"]
        if isinstance(report, Mapping) and report.get("trustcheck_command_source")
    ]
    if versions:
        result["trustcheck_version"] = versions[0]
    if sources:
        result["trustcheck_command_source"] = sources[0]
    return result


def _deadline_exceeded_result(path: Path) -> dict[str, Any]:
    validation = _invalid_report(
        execution_status="timed_out",
        report_status="missing",
        security_status="scan_failed",
        errors=[f"total scan deadline was exhausted before scanning {path.name}"],
    )
    return _base_result("check_requirements") | _validation_fields(validation) | {
        "exit_code": 124,
        "command": [],
        "stderr": validation.errors[0],
        "duration_seconds": 0,
        "trustcheck_version": None,
        "trustcheck_command_source": None,
        "report": None,
        "findings": {},
    }


def _plan_remediation(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    path = _workspace_file(workspace, _required_str(request, "path"))
    command = _trustcheck_command(
        [
            "scan",
            "-f",
            str(path),
            "--format",
            "json",
            "--with-osv",
            "--plan-fixes",
            "--max-fix-attempts",
            str(
                _bounded_int(
                    request.get("max_fix_attempts"),
                    default=256,
                    minimum=1,
                    maximum=2048,
                    field="max_fix_attempts",
                )
            ),
            *_policy_args(request),
            *_offline_args(request),
        ]
    )
    return _run_json_operation(
        "plan_remediation",
        command,
        workspace,
        timeout,
        max_output_bytes,
    )


def _compare_versions(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    package = _package(request, "package")
    current_version = _optional_version(
        request.get("current_version"),
        "current_version",
    )
    proposed_version = _optional_version(
        request.get("proposed_version"),
        "proposed_version",
    )
    if current_version is None or proposed_version is None:
        raise AdapterError("compare_versions requires current_version and proposed_version")

    request_base = dict(request)
    request_base["package"] = package
    current_request = request_base | {"version": current_version}
    proposed_request = request_base | {"version": proposed_version}
    current = _check_package(current_request, workspace, timeout, max_output_bytes)
    proposed = _check_package(proposed_request, workspace, timeout, max_output_bytes)
    comparison = _compare_findings(
        _mapping(current.get("findings")),
        _mapping(proposed.get("findings")),
    )
    classification = (
        "passed"
        if proposed.get("classification") == "passed"
        and comparison.get("proposed_is_not_worse") is True
        else "security_findings"
    )
    if (
        current.get("classification") == "scan_failed"
        or proposed.get("classification") == "scan_failed"
    ):
        classification = "scan_failed"
    return _base_result("compare_versions") | {
        "classification": classification,
        "policy_permits_install": classification == "passed",
        "package": package,
        "current_version": current_version,
        "proposed_version": proposed_version,
        "execution_status": _merge_execution_statuses(
            [
                str(current.get("execution_status", "completed")),
                str(proposed.get("execution_status", "completed")),
            ]
        ),
        "report_status": _merge_report_statuses(
            [
                str(current.get("report_status", "missing")),
                str(proposed.get("report_status", "missing")),
            ]
        ),
        "security_status": _merge_security_statuses(
            [
                str(current.get("security_status", "scan_failed")),
                str(proposed.get("security_status", "scan_failed")),
            ]
        ),
        "report_schema_version": proposed.get("report_schema_version")
        or current.get("report_schema_version"),
        "trustcheck_version": proposed.get("trustcheck_version")
        or current.get("trustcheck_version"),
        "trustcheck_command_source": proposed.get("trustcheck_command_source")
        or current.get("trustcheck_command_source"),
        "current": {
            "classification": current.get("classification"),
            "command": current.get("command"),
            "execution_status": current.get("execution_status"),
            "report_status": current.get("report_status"),
            "security_status": current.get("security_status"),
            "report_schema_version": current.get("report_schema_version"),
            "findings": current.get("findings"),
            "report": current.get("report"),
            "trustcheck_version": current.get("trustcheck_version"),
            "trustcheck_command_source": current.get("trustcheck_command_source"),
            "errors": current.get("errors", []),
        },
        "proposed": {
            "classification": proposed.get("classification"),
            "command": proposed.get("command"),
            "execution_status": proposed.get("execution_status"),
            "report_status": proposed.get("report_status"),
            "security_status": proposed.get("security_status"),
            "report_schema_version": proposed.get("report_schema_version"),
            "findings": proposed.get("findings"),
            "report": proposed.get("report"),
            "trustcheck_version": proposed.get("trustcheck_version"),
            "trustcheck_command_source": proposed.get("trustcheck_command_source"),
            "errors": proposed.get("errors", []),
        },
        "comparison": comparison,
    }


def _generate_report(
    request: Mapping[str, Any],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    output_format = _choice(
        request.get("format", "json"),
        REPORT_FORMATS,
        "format",
    )
    target_type = _choice(
        request.get("target_type", "requirements"),
        {"package", "requirements"},
        "target_type",
    )
    if target_type == "package":
        package = _package(request, "package")
        version = _optional_version(request.get("version"), "version")
        command = _trustcheck_command(
            [
                "scan",
                package,
                *_version_args(version),
                f"--{_analysis_depth(request)}",
                "--format",
                output_format,
                *_policy_args(request),
                *_optional_flag(request, "with_osv", "--with-osv"),
                *_artifact_scope_args(request, _analysis_depth(request)),
                *_offline_args(request),
            ]
        )
    else:
        path = _workspace_file(workspace, _required_str(request, "path"))
        command = _trustcheck_command(
            [
                "scan",
                "-f",
                str(path),
                f"--{_analysis_depth(request)}",
                "--format",
                output_format,
                *_policy_args(request),
                *_optional_flag(request, "with_osv", "--with-osv"),
                *_artifact_scope_args(request, _analysis_depth(request)),
                *_offline_args(request),
            ]
        )
    completed = _run_command(command, workspace, timeout, max_output_bytes)
    output_text = completed["stdout"]
    result = _base_result("generate_report") | {
        "command": completed.get("command", _redacted_argv(command)),
        "exit_code": completed["returncode"],
        "stderr": completed["stderr"],
        "duration_seconds": completed.get("duration_seconds"),
        "trustcheck_version": completed.get("trustcheck_version"),
        "trustcheck_command_source": completed.get("trustcheck_command_source"),
        "format": output_format,
    }
    if output_format == "json":
        validation = _validate_completed_report(completed)
        result |= _validation_fields(validation)
        result["report"] = validation.payload
        result["findings"] = validation.findings
    else:
        errors = [str(completed["error"])] if completed.get("error") else []
        if int(completed["returncode"]) != 0:
            errors.append(
                f"trustcheck exited with code {completed['returncode']}; report is not trusted"
            )
        errors.append(
            "non-JSON reports cannot provide explicit policy approval for installation"
        )
        execution_status = str(completed.get("execution_status", "completed"))
        result |= {
            "classification": "scan_failed",
            "policy_permits_install": False,
            "execution_status": execution_status,
            "report_status": "missing",
            "security_status": "unknown" if execution_status == "completed" else "scan_failed",
            "report_schema_version": None,
            "errors": _dedupe(errors),
        }
        result["report_text"] = output_text
    return result


def _explain_findings(request: Mapping[str, Any], workspace: Path) -> dict[str, Any]:
    if "report" in request:
        payload = request["report"]
    else:
        path = _workspace_file(workspace, _required_str(request, "report_path"))
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            validation = _invalid_report(
                execution_status="completed",
                report_status="malformed",
                security_status="scan_failed",
                errors=[f"trustcheck did not return valid JSON: {exc}"],
            )
            return _base_result("explain_findings") | _validation_fields(validation)
    validation = _validate_report_payload(payload)
    return _base_result("explain_findings") | _validation_fields(validation) | {
        "findings": validation.findings,
        "explanation": _plain_explanation(validation.findings),
    }


def _scan_file_command(request: Mapping[str, Any], path: Path) -> list[str]:
    depth = _analysis_depth(request)
    return _trustcheck_command(
        [
            "scan",
            "-f",
            str(path),
            f"--{depth}",
            "--format",
            "json",
            *_policy_args(request),
            *_optional_flag(request, "with_osv", "--with-osv"),
            *_offline_args(request),
            *_artifact_scope_args(request, depth),
            *_optional_flag(request, "no_deps", "--no-deps"),
        ]
    )


def _trustcheck_command(args: list[str]) -> list[str]:
    return [TRUSTCHECK_COMMAND, *args]


def _run_json_operation(
    operation: str,
    command: list[str],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    completed = _run_command(command, workspace, timeout, max_output_bytes)
    validation = _validate_completed_report(completed)
    return _base_result(operation) | {
        "command": completed.get("command", _redacted_argv(command)),
        "exit_code": completed["returncode"],
        "duration_seconds": completed["duration_seconds"],
        "stderr": completed["stderr"],
        "trustcheck_version": completed.get("trustcheck_version"),
        "trustcheck_command_source": completed.get("trustcheck_command_source"),
        "report": validation.payload,
        "findings": validation.findings,
    } | _validation_fields(validation)


def _run_command(
    command: list[str],
    workspace: Path,
    timeout: float,
    max_output_bytes: int,
) -> dict[str, Any]:
    start = time.monotonic()
    actual_command = list(command)
    trustcheck_version: str | None = None
    trustcheck_source: str | None = None
    if command and command[0] == TRUSTCHECK_COMMAND:
        try:
            runtime = _resolve_trustcheck_runtime(timeout=min(timeout, 30))
        except TrustcheckRuntimeError as exc:
            return {
                "returncode": exc.returncode,
                "stdout": "",
                "stderr": _redact(str(exc)),
                "duration_seconds": round(time.monotonic() - start, 3),
                "command": _redacted_argv(["trustcheck", *command[1:]]),
                "trustcheck_version": None,
                "trustcheck_command_source": None,
                "execution_status": "failed_to_start",
                "error": str(exc),
            }
        actual_command = [*runtime.command_prefix, *command[1:]]
        trustcheck_version = runtime.version
        trustcheck_source = runtime.source
    completed = _run_process(
        actual_command,
        cwd=workspace,
        timeout=timeout,
        max_stdout_bytes=max_output_bytes,
        max_stderr_bytes=min(max_output_bytes, DEFAULT_MAX_STDERR_BYTES),
    )
    return {
        "returncode": completed["returncode"],
        "stdout": completed["stdout"],
        "stderr": completed["stderr"],
        "duration_seconds": round(time.monotonic() - start, 3),
        "command": _redacted_argv(actual_command),
        "trustcheck_version": trustcheck_version,
        "trustcheck_command_source": trustcheck_source,
        "execution_status": completed["execution_status"],
        **({"error": completed["error"]} if completed.get("error") else {}),
    }


def _run_process(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> dict[str, Any]:
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    exceeded_streams: set[str] = set()
    limit_event = threading.Event()
    reader_errors: list[str] = []
    start = time.monotonic()
    try:
        process = subprocess.Popen(  # nosec B603 - fixed argv, shell=False.
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_safe_environment(),
            **_process_group_kwargs(),
        )
    except OSError as exc:
        message = f"failed to start trustcheck: {exc}"
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": _redact(message),
            "execution_status": "failed_to_start",
            "error": message,
        }

    stdout_thread = threading.Thread(
        target=_read_limited_stream,
        args=(
            process.stdout,
            stdout_buffer,
            max_stdout_bytes,
            "stdout",
            exceeded_streams,
            limit_event,
            reader_errors,
        ),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_limited_stream,
        args=(
            process.stderr,
            stderr_buffer,
            max_stderr_bytes,
            "stderr",
            exceeded_streams,
            limit_event,
            reader_errors,
        ),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    execution_status = "completed"
    error: str | None = None
    while True:
        returncode = process.poll()
        if returncode is not None:
            break
        if limit_event.is_set():
            execution_status = "output_limit_exceeded"
            stream_label = ", ".join(sorted(exceeded_streams)) or "output"
            error = f"trustcheck {stream_label} exceeded max_output_bytes"
            _terminate_process_tree(process)
            break
        if time.monotonic() - start >= timeout:
            execution_status = "timed_out"
            error = "trustcheck timed out"
            _terminate_process_tree(process)
            break
        time.sleep(0.02)

    try:
        returncode = process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        execution_status = "terminated"
        error = error or "trustcheck did not terminate after signal"
        _kill_process_tree(process)
        returncode = process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)

    stdout_thread.join(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    stderr_thread.join(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    if limit_event.is_set() and execution_status == "completed":
        execution_status = "output_limit_exceeded"
        stream_label = ", ".join(sorted(exceeded_streams)) or "output"
        error = f"trustcheck {stream_label} exceeded max_output_bytes"
    if reader_errors and execution_status == "completed":
        execution_status = "terminated"
        error = "; ".join(reader_errors)

    stdout_text = _redact(_decode_bytes(bytes(stdout_buffer), max_stdout_bytes))
    stderr_text = _redact(_decode_bytes(bytes(stderr_buffer), max_stderr_bytes))
    if error:
        stderr_text = _redact((stderr_text + "\n" + error).strip())
    return {
        "returncode": (
            returncode
            if execution_status == "completed"
            else _status_returncode(execution_status)
        ),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "execution_status": execution_status,
        **({"error": error} if error else {}),
    }


def _read_limited_stream(
    stream: Any,
    buffer: bytearray,
    limit: int,
    name: str,
    exceeded_streams: set[str],
    limit_event: threading.Event,
    reader_errors: list[str],
) -> None:
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            remaining = limit - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                exceeded_streams.add(name)
                limit_event.set()
                break
    except OSError as exc:
        reader_errors.append(f"failed to read trustcheck {name}: {exc}")
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _status_returncode(execution_status: str) -> int:
    if execution_status == "timed_out":
        return 124
    if execution_status == "output_limit_exceeded":
        return 3
    if execution_status == "failed_to_start":
        return 127
    return 1


def _process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError):
            pass
        try:
            process.wait(timeout=0.5)
            return
        except subprocess.TimeoutExpired:
            pass
        _kill_process_tree(process)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        process.terminate()


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(  # nosec B603 - fixed argv, shell=False.
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                env=_safe_environment(),
                timeout=PROCESS_TERMINATION_GRACE_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()


def _safe_environment() -> dict[str, str]:
    allowed_exact = {
        "COMSPEC",
        "CURL_CA_BUNDLE",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    env: dict[str, str] = {}
    for name, value in os.environ.items():
        upper = name.upper()
        if upper in allowed_exact or upper.startswith("LC_"):
            env[name] = value
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return env


def _resolve_trustcheck_runtime(*, timeout: int) -> TrustcheckRuntime:
    discovered = _discover_trustcheck_command()
    if discovered is None:
        raise TrustcheckRuntimeError(
            "trustcheck executable was not found. Install trustcheck "
            f"{SUPPORTED_TRUSTCHECK_SPEC} with pip, pipx, Homebrew, a system "
            "package, or a standalone executable on PATH."
    )
    command_prefix, source = discovered
    completed = _run_process(
        [*command_prefix, "--version"],
        cwd=Path.cwd(),
        timeout=timeout,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
    )
    if completed["execution_status"] == "timed_out":
        raise TrustcheckRuntimeError(
            "trustcheck --version timed out before compatibility could be verified",
            returncode=124,
        )
    if completed["execution_status"] == "output_limit_exceeded":
        raise TrustcheckRuntimeError(
            "trustcheck --version exceeded the output limit before compatibility "
            "could be verified",
            returncode=125,
        )
    if completed["execution_status"] == "failed_to_start":
        raise TrustcheckRuntimeError(str(completed.get("error") or "failed to start trustcheck"))

    stdout = str(completed["stdout"])
    stderr = str(completed["stderr"])
    returncode = int(completed["returncode"])
    if returncode != 0:
        detail = _redact((stderr or stdout).strip())
        suffix = f": {detail}" if detail else ""
        raise TrustcheckRuntimeError(
            f"trustcheck --version failed with exit code {returncode}{suffix}",
            returncode=returncode or 1,
        )

    version_text = (stdout or stderr).strip()
    version = _parse_trustcheck_version(version_text)
    if version is None:
        raise TrustcheckRuntimeError(
            "could not parse trustcheck version from `trustcheck --version` output",
            returncode=125,
        )
    if not _is_supported_trustcheck_version(version):
        raise TrustcheckRuntimeError(
            f"trustcheck-gate {ADAPTER_SCHEMA_VERSION} supports trustcheck "
            f"{SUPPORTED_TRUSTCHECK_SPEC}; found trustcheck {version}.",
            returncode=125,
        )
    return TrustcheckRuntime(
        command_prefix=command_prefix,
        source=source,
        version=version,
    )


def _discover_trustcheck_command() -> tuple[tuple[str, ...], str] | None:
    executable = which("trustcheck")
    if executable:
        return ((executable,), "path")
    if importlib.util.find_spec("trustcheck") is not None:
        return ((sys.executable, "-m", "trustcheck"), "python-module")
    return None


def _parse_trustcheck_version(output: str) -> str | None:
    match = re.search(r"(?i)\btrustcheck\s+([0-9]+(?:\.[0-9]+){0,2}[^\s)]*)", output)
    return match.group(1) if match else None


def _is_supported_trustcheck_version(version: str) -> bool:
    parsed = _version_tuple(version)
    return SUPPORTED_TRUSTCHECK_MIN <= parsed < SUPPORTED_TRUSTCHECK_MAX


def _version_tuple(version: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if match is None:
        return (0, 0, 0)
    major, minor, patch = match.groups()
    return (
        int(major),
        int(minor) if minor is not None else 0,
        int(patch) if patch is not None else 0,
    )


def _validate_completed_report(completed: Mapping[str, Any]) -> ReportValidation:
    execution_status = str(completed.get("execution_status", "completed"))
    runtime_errors = [str(completed["error"])] if completed.get("error") else []
    if execution_status != "completed":
        report_status = (
            "malformed"
            if execution_status == "output_limit_exceeded"
            else "missing"
        )
        return _invalid_report(
            execution_status=execution_status,
            report_status=report_status,
            security_status="scan_failed",
            errors=runtime_errors
            or [f"trustcheck execution did not complete: {execution_status}"],
        )

    validation = _validate_report_text(str(completed.get("stdout", "")))
    exit_code = int(completed.get("returncode", 1))
    if exit_code != 0:
        errors = [
            *runtime_errors,
            *validation.errors,
            f"trustcheck exited with code {exit_code}; report is not trusted",
        ]
        return ReportValidation(
            payload=validation.payload,
            findings=validation.findings,
            execution_status=execution_status,
            report_status=validation.report_status,
            security_status="scan_failed",
            classification="scan_failed",
            policy_permits_install=False,
            report_schema_version=validation.report_schema_version,
            errors=_dedupe(errors),
        )
    if runtime_errors:
        return ReportValidation(
            payload=validation.payload,
            findings=validation.findings,
            execution_status=execution_status,
            report_status=validation.report_status,
            security_status="scan_failed",
            classification="scan_failed",
            policy_permits_install=False,
            report_schema_version=validation.report_schema_version,
            errors=_dedupe([*runtime_errors, *validation.errors]),
        )
    return validation


def _validate_report_text(text: str) -> ReportValidation:
    if not text.strip():
        return _invalid_report(
            execution_status="completed",
            report_status="missing",
            security_status="scan_failed",
            errors=["trustcheck returned empty stdout"],
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return _invalid_report(
            execution_status="completed",
            report_status="malformed",
            security_status="scan_failed",
            errors=[f"trustcheck did not return valid JSON: {exc}"],
        )
    return _validate_report_payload(payload)


def _validate_report_payload(payload: Any) -> ReportValidation:
    if not isinstance(payload, Mapping):
        return _invalid_report(
            execution_status="completed",
            report_status="malformed",
            security_status="scan_failed",
            errors=["trustcheck returned JSON that was not an object"],
        )

    schema_version = _schema_version(payload)
    if schema_version is None:
        return _invalid_report(
            execution_status="completed",
            report_status="invalid_schema",
            security_status="scan_failed",
            errors=["trustcheck report is missing schema_version"],
        )
    if schema_version not in SUPPORTED_REPORT_SCHEMA_VERSIONS:
        return _invalid_report(
            execution_status="completed",
            report_status="incompatible",
            security_status="scan_failed",
            report_schema_version=schema_version,
            errors=[
                "incompatible_report: trustcheck-gate adapter "
                f"{ADAPTER_SCHEMA_VERSION} supports report schema "
                f"{SUPPORTED_REPORT_SCHEMA_SPEC}; found {schema_version}"
            ],
        )

    shape_errors = _report_shape_errors(payload)
    if shape_errors:
        return _invalid_report(
            execution_status="completed",
            report_status="invalid_schema",
            security_status="scan_failed",
            report_schema_version=schema_version,
            errors=shape_errors,
        )

    findings = _extract_findings(payload)
    failures = _list(findings.get("failures"))
    blocking_reasons = _list(findings.get("blocking_reasons"))
    if failures:
        security_status = "scan_failed"
    elif findings.get("policy_passed") is not True:
        security_status = "blocked"
    elif blocking_reasons:
        security_status = "findings"
    else:
        security_status = "passed"

    classification = _classification_from_security_status(security_status)
    return ReportValidation(
        payload=payload,
        findings=findings,
        execution_status="completed",
        report_status="valid",
        security_status=security_status,
        classification=classification,
        policy_permits_install=security_status == "passed",
        report_schema_version=schema_version,
        errors=[],
    )


def _report_shape_errors(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    has_report = "report" in payload
    has_reports = "reports" in payload
    if has_report and has_reports:
        errors.append("trustcheck report must not contain both report and reports")
    if not has_report and not has_reports:
        errors.append("trustcheck report must contain report or reports")

    reports: list[Mapping[str, Any]] = []
    if has_report:
        raw_report = payload.get("report")
        if isinstance(raw_report, Mapping):
            reports = [raw_report]
        else:
            errors.append("trustcheck report field must be an object")
    elif has_reports:
        raw_reports = payload.get("reports")
        if not isinstance(raw_reports, list):
            errors.append("trustcheck reports field must be a list")
        else:
            for index, item in enumerate(raw_reports):
                if isinstance(item, Mapping):
                    reports.append(item)
                else:
                    errors.append(f"trustcheck reports[{index}] must be an object")

    raw_failures = payload.get("failures", [])
    if "failures" in payload and not isinstance(raw_failures, list):
        errors.append("trustcheck failures field must be a list")
    elif isinstance(raw_failures, list):
        for index, item in enumerate(raw_failures):
            if not isinstance(item, Mapping):
                errors.append(f"trustcheck failures[{index}] must be an object")
                continue
            if not isinstance(item.get("message"), str) or not item["message"].strip():
                errors.append(
                    f"trustcheck failures[{index}].message must be a non-empty string"
                )

    if not reports and not raw_failures:
        errors.append("trustcheck report contains no package reports or failures")

    for index, report in enumerate(reports):
        errors.extend(_package_report_shape_errors(report, index))
    return errors


def _package_report_shape_errors(report: Mapping[str, Any], index: int) -> list[str]:
    errors: list[str] = []
    prefix = f"trustcheck report[{index}]"
    if not isinstance(report.get("project"), str) or not report["project"].strip():
        errors.append(f"{prefix}.project must be a non-empty string")
    if not isinstance(report.get("version"), str) or not report["version"].strip():
        errors.append(f"{prefix}.version must be a non-empty string")
    policy = report.get("policy")
    if not isinstance(policy, Mapping):
        errors.append(f"{prefix}.policy must be an object with explicit passed state")
    else:
        if not isinstance(policy.get("passed"), bool):
            errors.append(f"{prefix}.policy.passed must be true or false")
        if not isinstance(policy.get("violations"), list):
            errors.append(f"{prefix}.policy.violations must be a list")
    if not isinstance(report.get("vulnerabilities"), list):
        errors.append(f"{prefix}.vulnerabilities must be a list")
    if not isinstance(report.get("risk_flags"), list):
        errors.append(f"{prefix}.risk_flags must be a list")
    malicious = report.get("malicious_package")
    if not isinstance(malicious, Mapping):
        errors.append(f"{prefix}.malicious_package must be an object")
    elif not isinstance(malicious.get("findings"), list):
        errors.append(f"{prefix}.malicious_package.findings must be a list")
    return errors


def _invalid_report(
    *,
    execution_status: str,
    report_status: str,
    security_status: str,
    errors: list[str],
    report_schema_version: str | None = None,
) -> ReportValidation:
    return ReportValidation(
        payload=None,
        findings={},
        execution_status=execution_status,
        report_status=report_status,
        security_status=security_status,
        classification=_classification_from_security_status(security_status),
        policy_permits_install=False,
        report_schema_version=report_schema_version,
        errors=_dedupe(errors),
    )


def _validation_fields(validation: ReportValidation) -> dict[str, Any]:
    return {
        "classification": validation.classification,
        "policy_permits_install": validation.policy_permits_install,
        "execution_status": validation.execution_status,
        "report_status": validation.report_status,
        "security_status": validation.security_status,
        "report_schema_version": validation.report_schema_version,
        "errors": validation.errors,
    }


def _classification_from_security_status(security_status: str) -> str:
    if security_status == "passed":
        return "passed"
    if security_status in {"findings", "blocked"}:
        return "security_findings"
    return "scan_failed"


def _merge_execution_statuses(statuses: Iterable[str]) -> str:
    return _first_status(
        statuses,
        ("failed_to_start", "timed_out", "output_limit_exceeded", "terminated"),
        default="completed",
    )


def _merge_report_statuses(statuses: Iterable[str]) -> str:
    return _first_status(
        statuses,
        ("incompatible", "invalid_schema", "malformed", "missing"),
        default="valid",
    )


def _merge_security_statuses(statuses: Iterable[str]) -> str:
    return _first_status(
        statuses,
        ("scan_failed", "unknown", "blocked", "findings"),
        default="passed",
    )


def _first_status(
    statuses: Iterable[str],
    priority: tuple[str, ...],
    *,
    default: str,
) -> str:
    items = set(statuses)
    for status in priority:
        if status in items:
            return status
    return default


def _extract_findings(payload: Any) -> dict[str, Any]:
    reports = _report_objects(payload)
    failures = _failures(payload)
    policy_passed = bool(reports) and all(
        _nested_bool(report, ("policy", "passed"), default=False)
        for report in reports
    ) and not failures
    recommendations = [
        str(report.get("recommendation"))
        for report in reports
        if isinstance(report.get("recommendation"), str)
    ]
    vulnerabilities = [
        {
            "project": str(report.get("project", "")),
            "version": str(report.get("version", "")),
            "id": str(vuln.get("id", "")),
            "severity": str(vuln.get("severity", "")),
            "summary": str(vuln.get("summary", "")),
            "fixed_in": vuln.get("fixed_in", []),
        }
        for report in reports
        for vuln in _list(report.get("vulnerabilities"))
    ]
    risk_flags = [
        {
            "project": str(report.get("project", "")),
            "version": str(report.get("version", "")),
            "code": str(flag.get("code", "")),
            "severity": str(flag.get("severity", "")),
            "message": str(flag.get("message", "")),
            "remediation": str(flag.get("remediation", "")),
        }
        for report in reports
        for flag in _list(report.get("risk_flags"))
    ]
    policy_violations = [
        {
            "project": str(report.get("project", "")),
            "version": str(report.get("version", "")),
            "code": str(violation.get("code", "")),
            "severity": str(violation.get("severity", "")),
            "message": str(violation.get("message", "")),
        }
        for report in reports
        for violation in _list(_mapping(report.get("policy")).get("violations"))
    ]
    heuristic_findings = [
        {
            "project": str(report.get("project", "")),
            "version": str(report.get("version", "")),
            "code": str(finding.get("code", "")),
            "severity": str(finding.get("severity", "")),
            "confidence": str(finding.get("confidence", "")),
            "score": finding.get("score"),
            "message": str(finding.get("message", "")),
            "artifact": finding.get("artifact"),
            "location": finding.get("location"),
        }
        for report in reports
        for finding in _list(
            _mapping(report.get("malicious_package")).get("findings")
        )
    ]
    package_summaries = []
    for report in reports:
        malicious = _mapping(report.get("malicious_package"))
        coverage = _mapping(report.get("coverage"))
        package_summaries.append(
            {
                "project": report.get("project"),
                "version": report.get("version"),
                "recommendation": report.get("recommendation"),
                "policy_passed": _nested_bool(report, ("policy", "passed"), default=False),
                "malicious_level": malicious.get("level"),
                "malicious_score": malicious.get("score"),
                "provenance_status": coverage.get("status"),
                "verified_files": coverage.get("verified_files"),
                "total_files": coverage.get("total_files"),
                "vulnerability_count": len(_list(report.get("vulnerabilities"))),
                "risk_flag_count": len(_list(report.get("risk_flags"))),
            }
        )
    blocking = _blocking_reasons(
        policy_violations,
        vulnerabilities,
        risk_flags,
        heuristic_findings,
        failures,
        package_summaries,
    )
    return {
        "schema_version": _schema_version(payload),
        "policy_passed": policy_passed,
        "recommendation": _worst_recommendation(recommendations),
        "package_count": len(reports),
        "packages": package_summaries,
        "vulnerabilities": vulnerabilities[:50],
        "risk_flags": risk_flags[:50],
        "policy_violations": policy_violations[:50],
        "malicious_findings": heuristic_findings[:50],
        "failures": failures[:50],
        "blocking_reasons": blocking[:50],
    }


def _blocking_reasons(
    policy_violations: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    risk_flags: list[dict[str, Any]],
    heuristic_findings: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    package_summaries: list[dict[str, Any]],
) -> list[str]:
    reasons: list[str] = []
    for failure in failures:
        reasons.append(
            f"scan failed for {failure.get('requirement', 'unknown')}: "
            f"{failure.get('message', 'unknown failure')}"
        )
    for violation in policy_violations:
        reasons.append(
            f"{violation.get('project', 'package')} policy violation "
            f"{violation.get('code', '')}: {violation.get('message', '')}"
        )
    for vulnerability in vulnerabilities:
        fixed = vulnerability.get("fixed_in") or []
        fixed_text = f"; fixed in {', '.join(map(str, fixed))}" if fixed else ""
        reasons.append(
            f"{vulnerability.get('project', 'package')} has "
            f"{vulnerability.get('severity', 'unknown')} vulnerability "
            f"{vulnerability.get('id', 'unknown')}{fixed_text}"
        )
    for flag in risk_flags:
        reasons.append(
            f"{flag.get('project', 'package')} risk flag "
            f"{flag.get('code', '')}: {flag.get('message', '')}"
        )
    for finding in heuristic_findings:
        reasons.append(
            f"{finding.get('project', 'package')} heuristic "
            f"{finding.get('code', '')}: {finding.get('message', '')}"
        )
    for package in package_summaries:
        if package.get("policy_passed") is False:
            reasons.append(
                f"{package.get('project', 'package')} did not pass the configured policy"
            )
    return _dedupe(reason for reason in reasons if reason.strip())


def _compare_findings(
    current: Mapping[str, Any],
    proposed: Mapping[str, Any],
) -> dict[str, Any]:
    current_score = _risk_score(current)
    proposed_score = _risk_score(proposed)
    return {
        "current_risk_score": current_score,
        "proposed_risk_score": proposed_score,
        "proposed_is_not_worse": proposed_score <= current_score,
        "current_policy_passed": current.get("policy_passed"),
        "proposed_policy_passed": proposed.get("policy_passed"),
        "delta": proposed_score - current_score,
    }


def _risk_score(findings: Mapping[str, Any]) -> int:
    score = 0
    score += 100 if findings.get("policy_passed") is False else 0
    score += 40 * len(_list(findings.get("failures")))
    score += 35 * len(_list(findings.get("policy_violations")))
    score += 25 * len(_list(findings.get("vulnerabilities")))
    score += 15 * len(_list(findings.get("risk_flags")))
    score += 10 * len(_list(findings.get("malicious_findings")))
    recommendation = str(findings.get("recommendation") or "")
    score += {
        "verified": 0,
        "metadata-only": 10,
        "review-required": 25,
        "high-risk": 60,
        "error": 100,
    }.get(recommendation, 20)
    return score


def _plain_explanation(findings: Mapping[str, Any]) -> list[str]:
    lines = []
    if findings.get("policy_passed") is True:
        lines.append("Trustcheck policy passed.")
    else:
        lines.append("Trustcheck policy did not pass.")
    for reason in _list(findings.get("blocking_reasons"))[:10]:
        lines.append(str(reason))
    if not _list(findings.get("blocking_reasons")):
        lines.append("No blocking findings were reported in the structured output.")
    return lines


def _classification_from_exit(
    exit_code: int,
    findings: Mapping[str, Any] | None,
) -> str:
    if exit_code == 0:
        if findings and findings.get("policy_passed") is False:
            return "security_findings"
        return "passed"
    if exit_code == 4:
        return "security_findings"
    if exit_code == 2:
        return "usage_error"
    return "scan_failed"


def _classification_from_findings(findings: Mapping[str, Any]) -> str:
    if findings.get("failures"):
        return "scan_failed"
    if findings.get("policy_passed") is True and not findings.get("blocking_reasons"):
        return "passed"
    return "security_findings"


def _merge_classifications(classifications: Iterable[str]) -> str:
    items = set(classifications)
    if "scan_failed" in items:
        return "scan_failed"
    if "usage_error" in items:
        return "usage_error"
    if "security_findings" in items:
        return "security_findings"
    return "passed"


def _adapter_exit_code(result: Mapping[str, Any]) -> int:
    classification = result.get("classification")
    if classification == "passed":
        return 0
    if classification == "security_findings":
        return 4
    if classification == "usage_error":
        return 2
    return 1


def _base_result(operation: str) -> dict[str, Any]:
    return {
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "operation": operation,
        "classification": "scan_failed",
        "policy_permits_install": False,
    }


def _load_request(path: str | None) -> Mapping[str, Any]:
    if path:
        request_path = Path(path)
        try:
            if request_path.stat().st_size > MAX_REQUEST_BYTES:
                raise AdapterError(
                    f"request exceeds maximum size of {MAX_REQUEST_BYTES} bytes"
                )
        except OSError as exc:
            raise AdapterError(f"could not read request file: {exc}") from exc
        text = request_path.read_text(encoding="utf-8")
    else:
        text = sys.stdin.read(MAX_REQUEST_BYTES + 1)
        if len(text.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise AdapterError(
                f"request exceeds maximum size of {MAX_REQUEST_BYTES} bytes"
            )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"request is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AdapterError("request must be a JSON object")
    return payload


def _workspace(value: Any) -> Path:
    root = Path.cwd().resolve()
    if value is None:
        return root
    if not isinstance(value, str) or not value.strip():
        raise AdapterError("workspace must be a non-empty path string")
    raw = _path_text(value.strip(), "workspace")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise AdapterError(f"workspace does not exist or is not a directory: {candidate}")
    return candidate


def _workspace_file(workspace: Path, value: str) -> Path:
    raw = _path_text(value, "path")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise AdapterError(f"path is outside workspace: {value}") from exc
    if not candidate.is_file():
        raise AdapterError(f"path does not exist or is not a file: {value}")
    return candidate


def _path_text(value: str, field: str) -> str:
    if not value or len(value) > MAX_PATH_LENGTH:
        raise AdapterError(f"{field} must be a non-empty path no longer than {MAX_PATH_LENGTH}")
    if any(ord(char) < 32 for char in value):
        raise AdapterError(f"{field} must not contain control characters")
    return value


def _discover_dependency_files(workspace: Path) -> list[Path]:
    seen: set[Path] = set()
    found: list[Path] = []
    for name in DEPENDENCY_FILE_NAMES:
        path = workspace / name
        if path.is_file() and path not in seen:
            seen.add(path)
            found.append(path)
    for pattern in DEPENDENCY_FILE_GLOBS:
        for path in sorted(workspace.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                found.append(path)
    return found


def _required_str(request: Mapping[str, Any], field: str) -> str:
    value = request.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{field} must be a non-empty string")
    return value.strip()


def _package(request: Mapping[str, Any], field: str) -> str:
    value = _required_str(request, field)
    if not PACKAGE_RE.fullmatch(value):
        raise AdapterError(f"{field} is not a valid package name")
    return value


def _optional_version(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise AdapterError(f"{field} is not a valid version token")
    return value


def _optional_token(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{field} must be a non-empty string")
    token = value.strip()
    if any(ord(char) < 32 for char in token) or not TOKEN_RE.fullmatch(token):
        raise AdapterError(f"{field} is not a valid token")
    return token


def _optional_https_url(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterError(f"{field} must be an HTTPS URL")
    raw = value.strip()
    if not raw or len(raw) > MAX_URL_LENGTH or any(ord(char) < 32 for char in raw):
        raise AdapterError(f"{field} must be a valid HTTPS URL")
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise AdapterError(f"{field} must be an HTTPS URL")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise AdapterError(f"{field} must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise AdapterError(f"{field} must not contain query strings or fragments")
    if "%" in parsed.netloc or re.search(r"(?i)%2f|%5c", parsed.path):
        raise AdapterError(f"{field} contains ambiguous URL encoding")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AdapterError(f"{field} has an invalid port") from exc
    if port not in (None, 443):
        raise AdapterError(f"{field} may only use the default HTTPS port")
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AdapterError(f"{field} has an invalid hostname") from exc
    if not re.fullmatch(r"[a-z0-9.-]+", hostname) or ".." in hostname:
        raise AdapterError(f"{field} has an invalid hostname")
    netloc = hostname
    path = parsed.path.rstrip("/")
    if "\\" in path:
        raise AdapterError(f"{field} path must not contain backslashes")
    return urlunsplit(("https", netloc, path, "", ""))


def _choice(value: Any, allowed: set[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise AdapterError(f"{field} must be one of: {', '.join(sorted(allowed))}")
    return value


def _analysis_depth(request: Mapping[str, Any]) -> str:
    depth = _choice(request.get("analysis_depth", "standard"), DEPTHS, "analysis_depth")
    if depth == "full" and not _bool(request.get("advanced_analysis"), default=False):
        raise AdapterError(
            "analysis_depth=full requires advanced_analysis=true because it may inspect artifacts"
        )
    return depth


def _policy_args(request: Mapping[str, Any]) -> list[str]:
    policy = _choice(request.get("policy", "default"), POLICIES, "policy")
    if policy == "strict":
        return ["--strict"]
    return ["--policy", "default"]


def _artifact_scope_args(request: Mapping[str, Any], depth: str) -> list[str]:
    if depth != "full":
        return []
    scope = _choice(
        request.get("artifact_scope", "target"),
        ARTIFACT_SCOPES,
        "artifact_scope",
    )
    if scope != "target" and not _bool(request.get("advanced_analysis"), default=False):
        raise AdapterError(
            "artifact_scope other than target requires advanced_analysis=true"
        )
    return ["--artifact-scope", scope]


def _source_release_args(request: Mapping[str, Any]) -> list[str]:
    if not _bool(request.get("source_release_provenance"), default=False):
        return []
    release_tag = _optional_token(request.get("release_tag"), "release_tag")
    return ["--source-release-provenance"] + (
        ["--release-tag", release_tag] if release_tag is not None else []
    )


def _offline_args(request: Mapping[str, Any]) -> list[str]:
    return ["--offline"] if _bool(request.get("offline"), default=False) else []


def _optional_flag(request: Mapping[str, Any], field: str, flag: str) -> list[str]:
    return [flag] if _bool(request.get(field), default=False) else []


def _version_args(version: str | None) -> list[str]:
    return ["--version", version] if version is not None else []


def _bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    field: str,
) -> int:
    if value is None:
        return default
    if not isinstance(value, int):
        raise AdapterError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise AdapterError(f"{field} must be between {minimum} and {maximum}")
    return value


def _bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise AdapterError("boolean fields must be true or false")
    return value


def _json_from_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"trustcheck did not return valid JSON: {exc}") from exc


def _report_objects(payload: Any) -> list[Mapping[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    report = payload.get("report")
    if isinstance(report, Mapping):
        return [report]
    reports = payload.get("reports")
    if isinstance(reports, list):
        return [item for item in reports if isinstance(item, Mapping)]
    return []


def _schema_version(payload: Any) -> str | None:
    if isinstance(payload, Mapping) and isinstance(payload.get("schema_version"), str):
        return str(payload["schema_version"])
    return None


def _failures(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, Mapping):
        return []
    raw = payload.get("failures")
    if not isinstance(raw, list):
        return []
    failures = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        failures.append(
            {
                "requirement": str(item.get("requirement") or "unknown"),
                "message": str(item.get("message") or "unknown failure"),
            }
        )
    return failures


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _nested_bool(
    value: Mapping[str, Any],
    path: tuple[str, ...],
    *,
    default: bool,
) -> bool:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping):
            return default
        current = current.get(key)
    return current if isinstance(current, bool) else default


def _worst_recommendation(values: list[str]) -> str | None:
    if not values:
        return None
    order = {
        "verified": 0,
        "metadata-only": 1,
        "review-required": 2,
        "high-risk": 3,
        "error": 4,
    }
    return max(values, key=lambda value: order.get(value, order["error"]))


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _decode_bytes(value: bytes, max_bytes: int) -> str:
    return value[:max_bytes].decode("utf-8", errors="replace")


def _redacted_argv(command: list[str]) -> list[str]:
    return [_redact(item) for item in command]


def _redact(value: str) -> str:
    redacted = URL_RE.sub(lambda match: _redact_url(match.group(0)), value)
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
    return redacted


def _redact_url(value: str) -> str:
    trailing = ""
    while value and value[-1] in ".,);]":
        trailing = value[-1] + trailing
        value = value[:-1]
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED_URL]" + trailing
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return value + trailing
    hostname = parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = hostname
    if parsed.username or parsed.password:
        netloc = f"[REDACTED]@{hostname}"
    if port is not None:
        netloc = f"{netloc}:{port}"
    query = ""
    if parsed.query:
        query_items = []
        for key, item_value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS:
                query_items.append((key, "[REDACTED]"))
            else:
                query_items.append((key, item_value))
        query = urlencode(query_items, doseq=True)
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment)) + trailing


if __name__ == "__main__":
    raise SystemExit(main())
