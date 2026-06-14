from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


@dataclass(frozen=True, slots=True)
class RunResult:
    seconds: float
    exit_code: int
    payload: object


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark trustcheck against pip-audit on one pinned corpus."
    )
    parser.add_argument(
        "--requirements",
        default="benchmarks/corpus/requirements.txt",
    )
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument(
        "--output",
        default="benchmarks/results/latest.json",
    )
    args = parser.parse_args(argv)
    if args.iterations < 1 or args.warmups < 0:
        parser.error("iterations must be positive and warmups cannot be negative")

    requirements = Path(args.requirements).resolve()
    if not requirements.is_file():
        parser.error(f"requirements file does not exist: {requirements}")

    trustcheck_command = [
        sys.executable,
        "-m",
        "trustcheck",
        "scan",
        str(requirements),
        "--with-osv",
        "--format",
        "json",
        "--max-workers",
        str(args.max_workers),
    ]
    pip_audit_command = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements),
        "--vulnerability-service",
        "osv",
        "--format",
        "json",
        "--progress-spinner",
        "off",
    ]

    for _ in range(args.warmups):
        _run(
            trustcheck_command,
            timeout=args.timeout,
            accepted_exit_codes={0, 1, 4},
        )
        _run(pip_audit_command, timeout=args.timeout, accepted_exit_codes={0, 1})

    trustcheck_runs = [
        _run(
            trustcheck_command,
            timeout=args.timeout,
            accepted_exit_codes={0, 1, 4},
        )
        for _ in range(args.iterations)
    ]
    pip_audit_runs = [
        _run(pip_audit_command, timeout=args.timeout, accepted_exit_codes={0, 1})
        for _ in range(args.iterations)
    ]
    trustcheck_findings = _trustcheck_findings(trustcheck_runs[-1].payload)
    pip_audit_findings = _pip_audit_findings(pip_audit_runs[-1].payload)
    correctness = _compare_findings(trustcheck_findings, pip_audit_findings)

    output = {
        "schema": "urn:trustcheck:benchmark:pip-audit:1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor() or None,
            "trustcheck": _tool_version([sys.executable, "-m", "trustcheck", "--version"]),
            "pip_audit": _tool_version([sys.executable, "-m", "pip_audit", "--version"]),
        },
        "corpus": {
            "requirements": _published_path(requirements),
            "sha256": _sha256(requirements),
            "entries": _requirement_entries(requirements),
        },
        "configuration": {
            "iterations": args.iterations,
            "warmups": args.warmups,
            "timeout_seconds": args.timeout,
            "max_workers": args.max_workers,
            "advisory_service": "OSV",
        },
        "commands": {
            "trustcheck": _published_command(
                trustcheck_command,
                requirements=requirements,
            ),
            "pip_audit": _published_command(
                pip_audit_command,
                requirements=requirements,
            ),
        },
        "performance": {
            "trustcheck": _timing_summary(trustcheck_runs),
            "pip_audit": _timing_summary(pip_audit_runs),
        },
        "correctness": correctness,
        "findings": {
            "trustcheck": _json_findings(trustcheck_findings),
            "pip_audit": _json_findings(pip_audit_findings),
        },
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output["performance"], indent=2, sort_keys=True))
    print(json.dumps(correctness, indent=2, sort_keys=True))
    return 0


def _run(
    command: Sequence[str],
    *,
    timeout: float,
    accepted_exit_codes: set[int],
) -> RunResult:
    started = time.perf_counter()
    completed = subprocess.run(  # nosec B603
        list(command),
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    elapsed = time.perf_counter() - started
    if completed.returncode not in accepted_exit_codes:
        raise RuntimeError(
            f"command failed with exit code {completed.returncode}: "
            f"{' '.join(command)}\n{completed.stderr.strip()}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"command did not emit JSON: {' '.join(command)}\n"
            f"{completed.stdout[:500]}"
        ) from exc
    return RunResult(
        seconds=elapsed,
        exit_code=completed.returncode,
        payload=payload,
    )


def _trustcheck_findings(
    payload: object,
) -> dict[tuple[str, str], list[set[str]]]:
    if not isinstance(payload, dict):
        raise ValueError("trustcheck benchmark payload must be an object")
    reports = payload.get("reports")
    if not isinstance(reports, list):
        report = payload.get("report")
        reports = [report] if isinstance(report, dict) else []
    findings: dict[tuple[str, str], list[set[str]]] = {}
    for report in reports:
        if not isinstance(report, dict):
            continue
        project = report.get("project")
        version = report.get("version")
        vulnerabilities = report.get("vulnerabilities")
        if (
            not isinstance(project, str)
            or not isinstance(version, str)
            or not isinstance(vulnerabilities, list)
        ):
            continue
        findings[(project.lower(), version)] = _dedupe_identities([
            _identity_set(item)
            for item in vulnerabilities
            if isinstance(item, dict)
        ])
    return findings


def _pip_audit_findings(
    payload: object,
) -> dict[tuple[str, str], list[set[str]]]:
    dependencies: object = payload
    if isinstance(payload, dict):
        dependencies = payload.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit benchmark payload must contain dependencies")
    findings: dict[tuple[str, str], list[set[str]]] = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        name = dependency.get("name")
        version = dependency.get("version")
        vulnerabilities = dependency.get("vulns", [])
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        identities = [
            _identity_set(item)
            for item in vulnerabilities
            if isinstance(item, dict)
        ] if isinstance(vulnerabilities, list) else []
        key = (name.lower(), version)
        findings[key] = _dedupe_identities(
            [*findings.get(key, []), *identities]
        )
    return findings


def _identity_set(item: dict[str, Any]) -> set[str]:
    identifiers = {
        str(item.get("id") or "").strip().upper(),
    }
    aliases = item.get("aliases", [])
    if isinstance(aliases, list):
        identifiers.update(
            str(alias).strip().upper()
            for alias in aliases
            if str(alias).strip()
        )
    identifiers.discard("")
    return identifiers


def _dedupe_identities(identities: Sequence[set[str]]) -> list[set[str]]:
    merged: list[set[str]] = []
    for identity in identities:
        overlapping = [
            existing for existing in merged if existing & identity
        ]
        if not overlapping:
            merged.append(set(identity))
            continue
        combined = set(identity)
        for existing in overlapping:
            combined.update(existing)
            merged.remove(existing)
        merged.append(combined)
    return merged


def _compare_findings(
    left: dict[tuple[str, str], list[set[str]]],
    right: dict[tuple[str, str], list[set[str]]],
) -> dict[str, Any]:
    matched = 0
    left_only: list[dict[str, Any]] = []
    right_only: list[dict[str, Any]] = []
    packages = sorted(set(left) | set(right))
    for package in packages:
        unmatched_right = list(right.get(package, []))
        for identity in left.get(package, []):
            match_index = next(
                (
                    index
                    for index, candidate in enumerate(unmatched_right)
                    if identity & candidate
                ),
                None,
            )
            if match_index is None:
                left_only.append(_finding_summary(package, identity))
            else:
                matched += 1
                unmatched_right.pop(match_index)
        right_only.extend(
            _finding_summary(package, identity)
            for identity in unmatched_right
        )
    denominator = matched + len(left_only) + len(right_only)
    agreement = matched / denominator if denominator else 1.0
    return {
        "matched_advisories": matched,
        "trustcheck_only": left_only,
        "pip_audit_only": right_only,
        "alias_aware_agreement": round(agreement, 6),
        "packages_compared": len(packages),
        "trustcheck_vulnerable_packages": sum(bool(items) for items in left.values()),
        "pip_audit_vulnerable_packages": sum(bool(items) for items in right.values()),
    }


def _finding_summary(
    package: tuple[str, str],
    identity: set[str],
) -> dict[str, Any]:
    return {
        "project": package[0],
        "version": package[1],
        "identifiers": sorted(identity),
    }


def _json_findings(
    findings: dict[tuple[str, str], list[set[str]]],
) -> list[dict[str, Any]]:
    return [
        {
            "project": project,
            "version": version,
            "advisories": [sorted(identity) for identity in identities],
        }
        for (project, version), identities in sorted(findings.items())
    ]


def _timing_summary(runs: Sequence[RunResult]) -> dict[str, Any]:
    samples = [run.seconds for run in runs]
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999) - 1))
    return {
        "samples_seconds": [round(sample, 6) for sample in samples],
        "median_seconds": round(statistics.median(samples), 6),
        "p95_seconds": round(ordered[rank], 6),
        "exit_codes": [run.exit_code for run in runs],
    }


def _tool_version(command: Sequence[str]) -> str:
    completed = subprocess.run(  # nosec B603
        list(command),
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    return (completed.stdout or completed.stderr).strip()


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _requirement_entries(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _published_path(path: Path) -> str:
    repository_root = Path(__file__).resolve().parents[1]
    try:
        return path.resolve().relative_to(repository_root).as_posix()
    except ValueError:
        return f"<external>/{path.name}"


def _published_command(
    command: Sequence[str],
    *,
    requirements: Path,
) -> list[str]:
    requirements_path = str(requirements)
    published_requirements = _published_path(requirements)
    return [
        (
            "python"
            if index == 0
            else published_requirements
            if argument == requirements_path
            else argument
        )
        for index, argument in enumerate(command)
    ]


if __name__ == "__main__":
    raise SystemExit(main())
