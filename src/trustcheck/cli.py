from __future__ import annotations

import argparse
import json
from typing import Sequence

from .service import inspect_package


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustcheck",
        description="Inspect PyPI package trust and provenance signals.",
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
        return 0

    parser.error("unknown command")
    return 2


def _render_text_report(report) -> str:
    lines: list[str] = [
        f"trustcheck report for {report.project} {report.version}",
        f"recommendation: {report.recommendation}",
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
                    f"    publisher: kind={identity.kind} repository={identity.repository or '-'} workflow={identity.workflow or '-'}"
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
