from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404 - invoked with fixed argv and shell=False.
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

ADAPTER_SCHEMA_VERSION = "0.1.0"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_OUTPUT_BYTES = 500_000
MAX_TIMEOUT_SECONDS = 600
MAX_PROJECT_FILES = 5

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9!+._~-]{0,127}$")
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
)


class AdapterError(ValueError):
    pass


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
        "policy_permits_install": False,
    }
    if not selected_files:
        return result | {
            "classification": "scan_failed",
            "errors": ["no supported dependency files were found"],
        }

    classifications: list[str] = []
    all_blocking: list[str] = []
    for path in selected_files:
        child = _run_json_operation(
            "check_requirements",
            _scan_file_command(request, path),
            workspace,
            timeout,
            max_output_bytes,
        )
        classifications.append(str(child.get("classification")))
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
                "findings": child.get("findings"),
                "report": child.get("report"),
                "errors": child.get("errors", []),
            }
        )

    classification = _merge_classifications(classifications)
    result["classification"] = classification
    result["policy_permits_install"] = classification == "passed"
    result["findings"] = {
        "blocking_reasons": _dedupe(all_blocking),
        "scanned_files": len(selected_files),
        "skipped_files": len(files[max_files:]),
    }
    return result


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
        _extract_findings(current.get("report")),
        _extract_findings(proposed.get("report")),
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
        "current": {
            "classification": current.get("classification"),
            "findings": current.get("findings"),
            "report": current.get("report"),
            "errors": current.get("errors", []),
        },
        "proposed": {
            "classification": proposed.get("classification"),
            "findings": proposed.get("findings"),
            "report": proposed.get("report"),
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
        "classification": _classification_from_exit(int(completed["returncode"]), None),
        "policy_permits_install": int(completed["returncode"]) == 0,
        "command": _redacted_argv(command),
        "exit_code": completed["returncode"],
        "stderr": completed["stderr"],
        "format": output_format,
    }
    if output_format == "json":
        payload = _json_from_text(output_text)
        result["report"] = payload
        result["findings"] = _extract_findings(payload)
    else:
        result["report_text"] = output_text
    return result


def _explain_findings(request: Mapping[str, Any], workspace: Path) -> dict[str, Any]:
    if "report" in request:
        payload = request["report"]
        if not isinstance(payload, Mapping):
            raise AdapterError("report must be an object")
    else:
        path = _workspace_file(workspace, _required_str(request, "report_path"))
        payload = _json_from_text(path.read_text(encoding="utf-8"))
    findings = _extract_findings(payload)
    return _base_result("explain_findings") | {
        "classification": _classification_from_findings(findings),
        "policy_permits_install": findings.get("policy_passed") is True,
        "findings": findings,
        "explanation": _plain_explanation(findings),
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
    return [sys.executable, "-m", "trustcheck", *args]


def _run_json_operation(
    operation: str,
    command: list[str],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    completed = _run_command(command, workspace, timeout, max_output_bytes)
    payload: Mapping[str, Any] | None = None
    errors: list[str] = []
    try:
        parsed = _json_from_text(str(completed["stdout"]))
        if isinstance(parsed, Mapping):
            payload = parsed
        else:
            errors.append("trustcheck returned JSON that was not an object")
    except AdapterError as exc:
        errors.append(str(exc))

    findings = _extract_findings(payload) if payload is not None else {}
    classification = _classification_from_exit(
        int(completed["returncode"]),
        findings if findings else None,
    )
    return _base_result(operation) | {
        "classification": classification,
        "policy_permits_install": classification == "passed",
        "command": _redacted_argv(command),
        "exit_code": completed["returncode"],
        "duration_seconds": completed["duration_seconds"],
        "stderr": completed["stderr"],
        "report": payload,
        "findings": findings,
        "errors": errors,
    }


def _run_command(
    command: list[str],
    workspace: Path,
    timeout: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    repo_root = _repo_root_from_adapter()
    env = os.environ.copy()
    src = str(repo_root / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(workspace),
            env=env,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_bytes(exc.stdout or b"", max_output_bytes)
        stderr = _decode_bytes(exc.stderr or b"", max_output_bytes)
        return {
            "returncode": 124,
            "stdout": stdout,
            "stderr": _redact(stderr + "\ntrustcheck timed out"),
            "duration_seconds": round(time.monotonic() - start, 3),
        }
    stdout_bytes = completed.stdout or b""
    stderr_bytes = completed.stderr or b""
    if len(stdout_bytes) > max_output_bytes:
        stdout = _decode_bytes(stdout_bytes[:max_output_bytes], max_output_bytes)
        stderr = _decode_bytes(stderr_bytes, max_output_bytes)
        return {
            "returncode": 3,
            "stdout": stdout,
            "stderr": _redact(stderr + "\ntrustcheck output exceeded max_output_bytes"),
            "duration_seconds": round(time.monotonic() - start, 3),
        }
    return {
        "returncode": completed.returncode,
        "stdout": _redact(_decode_bytes(stdout_bytes, max_output_bytes)),
        "stderr": _redact(_decode_bytes(stderr_bytes, max_output_bytes)),
        "duration_seconds": round(time.monotonic() - start, 3),
    }


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
    text = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"request is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AdapterError("request must be a JSON object")
    return payload


def _repo_root_from_adapter() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "src" / "trustcheck").is_dir():
            return parent
    raise AdapterError("could not locate trustcheck repository root")


def _workspace(value: Any) -> Path:
    root = _repo_root_from_adapter()
    if value is None:
        return root
    candidate = Path(str(value))
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise AdapterError(f"workspace does not exist or is not a directory: {candidate}")
    return candidate


def _workspace_file(workspace: Path, value: str) -> Path:
    candidate = Path(value)
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
    if any(char in token for char in "\r\n\t"):
        raise AdapterError(f"{field} must not contain control characters")
    return token


def _optional_https_url(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterError(f"{field} must be an HTTPS URL")
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise AdapterError(f"{field} must be an HTTPS URL")
    return urlunsplit(parsed)


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
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
    redacted = re.sub(r"://([^/@\s]+):([^/@\s]+)@", "://[REDACTED]@", redacted)
    return redacted


if __name__ == "__main__":
    raise SystemExit(main())
