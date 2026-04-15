from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Callable, Sequence

from .models import TrustReport
from .policy import BUILTIN_POLICIES, evaluate_policy, resolve_policy
from .pypi import PypiClient, PypiClientError
from .service import ProgressCallback, inspect_package

EXIT_OK = 0
EXIT_UPSTREAM_FAILURE = 1
EXIT_USAGE = 2
EXIT_DATA_ERROR = 3
EXIT_POLICY_FAILURE = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustcheck",
        description="Inspect PyPI package trust and provenance signals.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show tracebacks for operational failures.",
    )
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default="text",
        help="Structured debug log format when --debug is enabled.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a package on PyPI.")
    inspect_parser.add_argument("project", help="Project name on PyPI.")
    inspect_parser.add_argument("--version", help="Specific version to inspect.")
    inspect_parser.add_argument(
        "--config-file",
        help="Path to a JSON config file with optional network settings.",
    )
    inspect_parser.add_argument(
        "--expected-repo",
        help="Repository URL you expect the package to come from.",
    )
    inspect_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    inspect_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed per-file verification evidence.",
    )
    inspect_parser.add_argument(
        "--with-deps",
        action="store_true",
        help=(
            "Inspect declared runtime dependencies recursively and "
            "summarize the worst-risk dependency."
        ),
    )
    inspect_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply the built-in strict policy.",
    )
    inspect_parser.add_argument(
        "--policy",
        choices=tuple(BUILTIN_POLICIES),
        default="default",
        help="Built-in policy profile to evaluate after evidence collection.",
    )
    inspect_parser.add_argument(
        "--policy-file",
        help="Path to a JSON file containing policy settings.",
    )
    inspect_parser.add_argument(
        "--require-verified-provenance",
        choices=("none", "all"),
        help="Override whether policy requires verified provenance for every artifact.",
    )
    inspect_parser.add_argument(
        "--allow-metadata-only",
        action="store_true",
        default=None,
        help="Allow metadata-only outcomes under the selected policy.",
    )
    inspect_parser.add_argument(
        "--disallow-metadata-only",
        action="store_false",
        dest="allow_metadata_only",
        default=None,
        help="Fail policy evaluation when the result is metadata-only.",
    )
    inspect_parser.add_argument(
        "--require-expected-repo-match",
        action="store_true",
        default=None,
        help="Require a provided expected repository to match the collected evidence.",
    )
    inspect_parser.add_argument(
        "--fail-on-vulnerability",
        choices=("ignore", "any"),
        help="Override vulnerability handling for policy evaluation.",
    )
    inspect_parser.add_argument(
        "--fail-on-risk-severity",
        choices=("none", "medium", "high"),
        help="Fail policy evaluation when risk flags meet or exceed this severity.",
    )
    inspect_parser.add_argument(
        "--timeout",
        type=float,
        help="Network timeout in seconds.",
    )
    inspect_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    inspect_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    inspect_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    inspect_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            config_payload = _load_config_file(args.config_file)
            progress_callback = None
            if args.format == "text":
                progress_callback = _build_progress_callback()
            client = _build_client(
                args,
                config_payload=config_payload,
                request_hook=_build_debug_request_hook(
                    enabled=args.debug,
                    log_format=args.log_format,
                ),
            )
            report = inspect_package(
                args.project,
                version=args.version,
                expected_repository=args.expected_repo,
                client=client,
                progress_callback=progress_callback,
                include_dependencies=args.with_deps,
            )
            policy_name = "strict" if args.strict else args.policy
            policy = resolve_policy(
                builtin_name=policy_name,
                config_path=args.policy_file,
                cli_overrides={
                    "require_verified_provenance": args.require_verified_provenance,
                    "allow_metadata_only": args.allow_metadata_only,
                    "require_expected_repository_match": args.require_expected_repo_match,
                    "vulnerability_mode": args.fail_on_vulnerability,
                    "fail_on_severity": args.fail_on_risk_severity,
                },
            )
            evaluation = evaluate_policy(report, policy)
            if args.format == "json":
                print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            else:
                print(_render_text_report(report, verbose=args.verbose))
            if not evaluation.passed:
                return EXIT_POLICY_FAILURE
            return EXIT_OK

        parser.error("unknown command")
        return EXIT_USAGE
    except PypiClientError as exc:
        return _handle_error(
            _format_upstream_error(exc),
            EXIT_UPSTREAM_FAILURE,
            debug=args.debug,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _handle_error(
            f"error: received an invalid response while inspecting the package: {exc}",
            EXIT_DATA_ERROR,
            debug=args.debug,
        )
    except Exception as exc:
        return _handle_error(
            f"error: unexpected failure while inspecting the package: {exc}",
            EXIT_DATA_ERROR,
            debug=args.debug,
        )


def _handle_error(message: str, exit_code: int, *, debug: bool) -> int:
    print(message, file=sys.stderr)
    if debug:
        traceback.print_exc(file=sys.stderr)
    return exit_code


def _build_progress_callback() -> ProgressCallback:
    def emit(filename: str, current: int, total: int) -> None:
        print(
            f"[progress] verifying artifact {current}/{total}: {filename}",
            file=sys.stderr,
            flush=True,
        )

    return emit


def _build_client(
    args: argparse.Namespace,
    *,
    config_payload: dict[str, object],
    request_hook: Callable[[str, dict[str, object]], None] | None,
) -> PypiClient:
    network_config = config_payload.get("network")
    if network_config is not None and not isinstance(network_config, dict):
        raise ValueError("config file field 'network' must be an object")
    network_config = network_config or {}
    return PypiClient(
        timeout=_resolve_float(
            args.timeout,
            env_name="TRUSTCHECK_TIMEOUT",
            config_value=network_config.get("timeout"),
            default=10.0,
        ),
        max_retries=_resolve_int(
            args.retries,
            env_name="TRUSTCHECK_RETRIES",
            config_value=network_config.get("retries"),
            default=2,
        ),
        backoff_factor=_resolve_float(
            args.backoff,
            env_name="TRUSTCHECK_BACKOFF",
            config_value=network_config.get("backoff_factor"),
            default=0.25,
        ),
        cache_dir=_resolve_str(
            args.cache_dir,
            env_name="TRUSTCHECK_CACHE_DIR",
            config_value=network_config.get("cache_dir"),
        ),
        offline=_resolve_bool(
            args.offline,
            env_name="TRUSTCHECK_OFFLINE",
            config_value=network_config.get("offline"),
            default=False,
        ),
        request_hook=request_hook,
    )


def _load_config_file(path: str | None) -> dict[str, object]:
    if not path:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("config file must contain a top-level JSON object")
    return payload


def _resolve_float(
    cli_value: float | None,
    *,
    env_name: str,
    config_value: object,
    default: float,
) -> float:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return float(env_value)
    if config_value is not None and isinstance(config_value, (str, int, float)):
        return float(config_value)
    return default


def _resolve_int(
    cli_value: int | None,
    *,
    env_name: str,
    config_value: object,
    default: int,
) -> int:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return int(env_value)
    if config_value is not None and isinstance(config_value, (str, int, float)):
        return int(config_value)
    return default


def _resolve_str(
    cli_value: str | None,
    *,
    env_name: str,
    config_value: object,
) -> str | None:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return env_value
    if config_value is not None:
        return str(config_value)
    return None


def _resolve_bool(
    cli_value: bool,
    *,
    env_name: str,
    config_value: object,
    default: bool,
) -> bool:
    if cli_value:
        return True
    env_value = os.getenv(env_name)
    if env_value is not None:
        return env_value.strip().lower() in {"1", "true", "yes", "on"}
    if config_value is not None:
        if isinstance(config_value, bool):
            return config_value
        return str(config_value).strip().lower() in {"1", "true", "yes", "on"}
    return default


def _build_debug_request_hook(
    *,
    enabled: bool,
    log_format: str,
) -> Callable[[str, dict[str, object]], None] | None:
    if not enabled:
        return None

    def emit(event: str, payload: dict[str, object]) -> None:
        record = {"event": event, **payload}
        if log_format == "json":
            print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
        else:
            parts = [f"event={event}"] + [
                f"{key}={value}" for key, value in sorted(payload.items())
            ]
            print("[debug] " + " ".join(parts), file=sys.stderr, flush=True)

    return emit


def _format_upstream_error(exc: PypiClientError) -> str:
    return (
        "error: unable to inspect package from PyPI: "
        f"{exc} [code={exc.code} subcode={exc.subcode}]"
    )


def _render_text_report(report: TrustReport, *, verbose: bool = False) -> str:
    lines: list[str] = [
        f"trustcheck report for {report.project} {report.version}",
        "",
        "summary:",
        f"  recommendation: {report.recommendation}",
        f"  package: {report.package_url}",
    ]

    if report.summary:
        lines.append(f"  package summary: {report.summary}")

    lines.append(
        "  verification: "
        f"{report.coverage.verified_files}/{report.coverage.total_files} artifact(s) verified "
        f"({report.coverage.status})"
    )
    lines.append(
        "  publisher trust: "
        f"{report.publisher_trust.depth_label} "
        f"(score={report.publisher_trust.depth_score})"
    )
    lines.append(
        "  policy: "
        f"{report.policy.profile} "
        f"({'pass' if report.policy.passed else 'fail'})"
    )
    lines.append(
        "  diagnostics: "
        f"requests={report.diagnostics.request_count} "
        f"retries={report.diagnostics.retry_count} "
        f"failures={len(report.diagnostics.request_failures)} "
        f"cache_hits={report.diagnostics.cache_hit_count}"
    )
    lines.append(f"  why this result: {_evidence_summary(report)}")

    reasons = _recommendation_reasons(report)
    if reasons:
        lines.append("  why this result details:")
        lines.extend(f"    - {reason}" for reason in reasons)

    if report.declared_repository_urls:
        lines.append("")
        lines.append("declared repository urls:")
        lines.extend(f"  - {url}" for url in report.declared_repository_urls)

    if report.dependency_summary.requested:
        lines.append("")
        lines.append("dependencies:")
        lines.append(
            "  summary: "
            f"declared={report.dependency_summary.total_declared} "
            f"inspected={report.dependency_summary.total_inspected} "
            f"unique={report.dependency_summary.unique_dependencies} "
            f"max_depth={report.dependency_summary.max_depth} "
            f"highest_risk={report.dependency_summary.highest_risk_recommendation}"
        )
        if report.dependency_summary.highest_risk_projects:
            lines.append(
                "  highest-risk dependencies: "
                + ", ".join(report.dependency_summary.highest_risk_projects)
            )
        if verbose and report.dependencies:
            for dependency in report.dependencies:
                lines.append(
                    "  - "
                    f"{dependency.project} {dependency.version} "
                    f"(depth={dependency.depth}, recommendation={dependency.recommendation})"
                )
                lines.append(f"    requirement: {dependency.requirement}")
                if dependency.parent_project:
                    lines.append(
                        "    parent: "
                        f"{dependency.parent_project} {dependency.parent_version or 'unknown'}"
                    )
                if dependency.error:
                    lines.append(f"    note: {dependency.error}")
                elif dependency.risk_flags:
                    lines.append("    risk flags:")
                    lines.extend(
                        f"      - [{flag.severity}] {flag.code}: {flag.message}"
                        for flag in dependency.risk_flags[:3]
                    )

    if report.expected_repository:
        lines.append(f"expected repository: {report.expected_repository}")
    if report.provenance_consistency.sdist_wheel_consistent is not None:
        consistency_label = (
            "consistent"
            if report.provenance_consistency.sdist_wheel_consistent
            else "mismatch"
        )
        lines.append("")
        lines.append(
            "sdist/wheel provenance consistency: "
            f"{consistency_label}"
        )
    if report.release_drift.compared_to_version:
        lines.append(
            "release drift baseline: "
            f"{report.release_drift.compared_to_version}"
        )

    ownership = report.ownership or {}
    roles = ownership.get("roles") or []
    organization = ownership.get("organization")
    if organization or roles:
        lines.append("")
        lines.append("ownership:")
        if organization:
            lines.append(f"  - organization: {organization}")
        for role in roles:
            lines.append(f"  - {role.get('role')}: {role.get('user')}")

    if report.vulnerabilities:
        lines.append("")
        lines.append("vulnerabilities:")
        for vuln in report.vulnerabilities:
            lines.append(f"  - {vuln.id}: {vuln.summary}")

    if verbose:
        lines.append("")
        lines.append("files:")
        for file in report.files:
            lines.append(f"  - {file.filename}")
            lines.append(f"    provenance: {'yes' if file.has_provenance else 'no'}")
            lines.append(f"    verified: {'yes' if file.verified else 'no'}")
            lines.append(
                "    attestations: "
                f"{file.verified_attestation_count}/{file.attestation_count} verified"
            )
            if file.sha256:
                lines.append(f"    sha256: {file.sha256}")
            if file.observed_sha256:
                lines.append(f"    observed sha256: {file.observed_sha256}")
            if file.publisher_identities:
                for identity in file.publisher_identities:
                    lines.append(
                        "    publisher: "
                        f"kind={identity.kind} "
                        f"repository={identity.repository or '-'} "
                        f"workflow={identity.workflow or '-'}"
                    )
            if file.error:
                lines.append(f"    note: {file.error}")

    lines.append("")
    lines.append("diagnostics:")
    lines.append(
        "  network: "
        f"timeout={report.diagnostics.timeout} "
        f"retries={report.diagnostics.max_retries} "
        f"backoff={report.diagnostics.backoff_factor} "
        f"offline={report.diagnostics.offline} "
        f"cache_dir={report.diagnostics.cache_dir or '-'}"
    )
    if report.diagnostics.request_failures:
        lines.append("  request failures:")
        lines.extend(
            "    - "
            f"[{failure.subcode}] attempt={failure.attempt} "
            f"status={failure.status_code if failure.status_code is not None else '-'} "
            f"url={failure.url}"
            for failure in report.diagnostics.request_failures
        )
    else:
        lines.append("  request failures: none")
    if report.diagnostics.artifact_failures:
        lines.append("  artifact failures:")
        lines.extend(
            "    - "
            f"{item.filename} stage={item.stage} "
            f"[{item.subcode}] {item.message}"
            for item in report.diagnostics.artifact_failures
        )
    else:
        lines.append("  artifact failures: none")

    lines.append("")
    lines.append("policy evaluation:")
    lines.append(
        "  settings: "
        f"verified_provenance={report.policy.require_verified_provenance} "
        f"expected_repo={report.policy.require_expected_repository_match} "
        f"metadata_only={report.policy.allow_metadata_only} "
        f"vulnerabilities={report.policy.vulnerability_mode} "
        f"risk_severity={report.policy.fail_on_severity}"
    )
    if report.policy.violations:
        lines.append("  violations:")
        lines.extend(
            f"    - [{violation.severity}] {violation.code}: {violation.message}"
            for violation in report.policy.violations
        )
    else:
        lines.append("  violations: none")

    lines.append("")
    if report.risk_flags:
        lines.append("risk flags:")
        for flag in report.risk_flags:
            lines.append(f"  - [{flag.severity}] {flag.code}: {flag.message}")
            if flag.why:
                lines.append("    why:")
                lines.extend(f"      - {reason}" for reason in flag.why)
            if flag.remediation:
                lines.append("    remediation:")
                lines.extend(f"      - {step}" for step in flag.remediation)
    else:
        lines.append("risk flags: none")
    return "\n".join(lines)


def _evidence_summary(report: TrustReport) -> str:
    if report.files and all(file.verified for file in report.files):
        return "cryptographic verification succeeded for all discovered release artifacts"
    if any(file.verified for file in report.files):
        return "mixed evidence; some release artifacts verified cryptographically, others did not"
    return (
        "heuristic metadata and provenance signals only; "
        "no cryptographically verified artifact set"
    )


def _recommendation_reasons(report: TrustReport) -> list[str]:
    reasons: list[str] = []
    if report.risk_flags:
        reasons.extend(flag.message for flag in report.risk_flags[:3])
    if report.files and not all(file.verified for file in report.files):
        reasons.append(
            "Only "
            f"{report.coverage.verified_files} of "
            f"{report.coverage.total_files} discovered artifact(s) "
            "verified successfully."
        )
    elif report.files:
        reasons.append("Every discovered release artifact verified successfully.")
    if (
        report.expected_repository
        and not any(flag.code.startswith("expected_repository") for flag in report.risk_flags)
    ):
        reasons.append("The expected repository matched available package and publisher evidence.")
    return reasons[:4]
