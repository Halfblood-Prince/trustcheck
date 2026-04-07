from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import Sequence

from .models import TrustReport
from .pypi import PypiClientError
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
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a package on PyPI.")
    inspect_parser.add_argument("project", help="Project name on PyPI.")
    inspect_parser.add_argument("--version", help="Specific version to inspect.")
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
        "--strict",
        action="store_true",
        help="Fail if every discovered release artifact is not cryptographically verified.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            progress_callback = None
            if args.format == "text":
                progress_callback = _build_progress_callback()
            report = inspect_package(
                args.project,
                version=args.version,
                expected_repository=args.expected_repo,
                progress_callback=progress_callback,
            )
            if args.format == "json":
                print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            else:
                print(_render_text_report(report, verbose=args.verbose))
            if args.strict and _strict_failure(report):
                return EXIT_POLICY_FAILURE
            return EXIT_OK

        parser.error("unknown command")
        return EXIT_USAGE
    except PypiClientError as exc:
        return _handle_error(
            f"error: unable to inspect package from PyPI: {exc}",
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
    lines.append(f"  why this result: {_evidence_summary(report)}")

    reasons = _recommendation_reasons(report)
    if reasons:
        lines.append("  why this result details:")
        lines.extend(f"    - {reason}" for reason in reasons)

    if report.declared_repository_urls:
        lines.append("")
        lines.append("declared repository urls:")
        lines.extend(f"  - {url}" for url in report.declared_repository_urls)

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


def _strict_failure(report: TrustReport) -> bool:
    if not report.files:
        return True
    return not all(file.verified for file in report.files)
