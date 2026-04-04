from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import Sequence

from .models import TrustReport
from .pypi import PypiClientError
from .service import inspect_package

EXIT_OK = 0
EXIT_UPSTREAM_FAILURE = 1
EXIT_USAGE = 2
EXIT_DATA_ERROR = 3


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_package(
                args.project,
                version=args.version,
                expected_repository=args.expected_repo,
            )
            if args.format == "json":
                print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            else:
                print(_render_text_report(report))
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


def _render_text_report(report: TrustReport) -> str:
    lines: list[str] = [
        f"trustcheck report for {report.project} {report.version}",
        f"recommendation: {report.recommendation}",
        f"evidence: {_evidence_summary(report)}",
        f"package: {report.package_url}",
    ]

    if report.summary:
        lines.append(f"summary: {report.summary}")

    if report.repository_urls:
        lines.append("repository urls:")
        lines.extend(f"  - {url}" for url in report.repository_urls)

    if report.expected_repository:
        lines.append(f"expected repository: {report.expected_repository}")

    ownership = report.ownership or {}
    roles = ownership.get("roles") or []
    organization = ownership.get("organization")
    if organization or roles:
        lines.append("ownership:")
        if organization:
            lines.append(f"  - organization: {organization}")
        for role in roles:
            lines.append(f"  - {role.get('role')}: {role.get('user')}")

    if report.vulnerabilities:
        lines.append("vulnerabilities:")
        for vuln in report.vulnerabilities:
            lines.append(f"  - {vuln.id}: {vuln.summary}")

    lines.append("files:")
    for file in report.files:
        lines.append(f"  - {file.filename}")
        lines.append(f"    provenance: {'yes' if file.has_provenance else 'no'}")
        lines.append(f"    verified: {'yes' if file.verified else 'no'}")
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

    if report.risk_flags:
        lines.append("risk flags:")
        for flag in report.risk_flags:
            lines.append(f"  - [{flag.severity}] {flag.code}: {flag.message}")
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
