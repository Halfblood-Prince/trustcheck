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

BENCHMARK_SCHEMA = "urn:trustcheck:benchmark:pip-audit:2.0.0"
CORPUS_SCHEMA = "urn:trustcheck:benchmark-corpus:1.0.0"
MIN_CORPUS_PACKAGES = 100
MAX_CORPUS_PACKAGES = 500


@dataclass(frozen=True, slots=True)
class CorpusCase:
    case_id: str
    path: Path
    kind: str
    category: str
    package_count: int
    compare_with_pip_audit: bool
    description: str = ""


@dataclass(frozen=True, slots=True)
class Corpus:
    manifest: Path
    version: str
    cases: tuple[CorpusCase, ...]
    package_count: int


@dataclass(frozen=True, slots=True)
class RunResult:
    seconds: float
    exit_code: int
    payload: object


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark trustcheck against the latest installed pip-audit on a "
            "versioned package corpus."
        )
    )
    parser.add_argument(
        "--corpus",
        default="benchmarks/corpus/corpus.json",
        help="Versioned benchmark corpus manifest.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Corpus case id to benchmark; repeatable. Defaults to all comparable cases.",
    )
    parser.add_argument(
        "--requirements",
        help=(
            "Legacy single requirements input. Bypasses corpus-size validation "
            "and is intended only for ad hoc local comparisons."
        ),
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

    corpus = (
        _legacy_corpus(Path(args.requirements).resolve())
        if args.requirements
        else _load_corpus(Path(args.corpus).resolve())
    )
    benchmark_cases = _benchmark_cases(corpus, args.case)
    if not benchmark_cases:
        parser.error("no pip-audit-comparable corpus cases were selected")

    trustcheck_commands = [
        _trustcheck_command(case, max_workers=args.max_workers)
        for case in benchmark_cases
    ]
    pip_audit_commands = [
        _pip_audit_command(case)
        for case in benchmark_cases
    ]

    for _ in range(args.warmups):
        _run_suite(
            trustcheck_commands,
            timeout=args.timeout,
            accepted_exit_codes={0, 1, 4},
        )
        _run_suite(
            pip_audit_commands,
            timeout=args.timeout,
            accepted_exit_codes={0, 1},
        )

    trustcheck_runs = [
        _run_suite(
            trustcheck_commands,
            timeout=args.timeout,
            accepted_exit_codes={0, 1, 4},
        )
        for _ in range(args.iterations)
    ]
    pip_audit_runs = [
        _run_suite(
            pip_audit_commands,
            timeout=args.timeout,
            accepted_exit_codes={0, 1},
        )
        for _ in range(args.iterations)
    ]
    trustcheck_findings = _trustcheck_findings(trustcheck_runs[-1].payload)
    pip_audit_findings = _pip_audit_findings(pip_audit_runs[-1].payload)
    correctness = _compare_findings(trustcheck_findings, pip_audit_findings)

    corpus_paths = [case.path for case in benchmark_cases]
    output = {
        "schema": BENCHMARK_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor() or None,
            "trustcheck": _tool_version([sys.executable, "-m", "trustcheck", "--version"]),
            "pip_audit": _tool_version([sys.executable, "-m", "pip_audit", "--version"]),
        },
        "corpus": _corpus_summary(corpus, benchmark_cases),
        "configuration": {
            "iterations": args.iterations,
            "warmups": args.warmups,
            "timeout_seconds": args.timeout,
            "max_workers": args.max_workers,
            "advisory_service": "OSV",
            "selected_cases": [case.case_id for case in benchmark_cases],
        },
        "commands": {
            "trustcheck": [
                _published_command(command, paths=corpus_paths)
                for command in trustcheck_commands
            ],
            "pip_audit": [
                _published_command(command, paths=corpus_paths)
                for command in pip_audit_commands
            ],
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


def _load_corpus(manifest: Path) -> Corpus:
    if not manifest.is_file():
        raise ValueError(f"benchmark corpus manifest does not exist: {manifest}")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("benchmark corpus manifest must be a JSON object")
    if payload.get("schema") != CORPUS_SCHEMA:
        raise ValueError(f"unsupported benchmark corpus schema: {payload.get('schema')!r}")
    raw_version = payload.get("version")
    if not isinstance(raw_version, str) or not raw_version.strip():
        raise ValueError("benchmark corpus manifest must declare a version")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("benchmark corpus manifest must contain cases")

    cases = tuple(_load_corpus_case(manifest.parent, item) for item in raw_cases)
    package_count = sum(case.package_count for case in cases)
    if not MIN_CORPUS_PACKAGES <= package_count <= MAX_CORPUS_PACKAGES:
        raise ValueError(
            "benchmark corpus must contain "
            f"{MIN_CORPUS_PACKAGES}-{MAX_CORPUS_PACKAGES} package entries; "
            f"found {package_count}"
        )
    return Corpus(
        manifest=manifest,
        version=raw_version,
        cases=cases,
        package_count=package_count,
    )


def _load_corpus_case(root: Path, payload: object) -> CorpusCase:
    if not isinstance(payload, dict):
        raise ValueError("benchmark corpus cases must be objects")
    case_id = _required_string(payload, "id")
    relative_path = _required_string(payload, "path")
    path = (root / relative_path).resolve()
    if not path.is_file():
        raise ValueError(f"benchmark corpus case {case_id!r} is missing {path}")
    kind = _required_string(payload, "kind")
    category = _required_string(payload, "category")
    package_count = payload.get("package_count")
    if package_count is None and kind == "requirements":
        package_count = len(_requirement_entries(path))
    if not isinstance(package_count, int) or package_count < 1:
        raise ValueError(f"benchmark corpus case {case_id!r} needs package_count")
    compare = payload.get("compare_with_pip_audit") is True
    if compare and kind != "requirements":
        raise ValueError(
            f"benchmark corpus case {case_id!r} is marked comparable but is {kind!r}"
        )
    description = payload.get("description", "")
    if not isinstance(description, str):
        raise ValueError(f"benchmark corpus case {case_id!r} has invalid description")
    return CorpusCase(
        case_id=case_id,
        path=path,
        kind=kind,
        category=category,
        package_count=package_count,
        compare_with_pip_audit=compare,
        description=description,
    )


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"benchmark corpus case missing {key!r}")
    return value


def _legacy_corpus(requirements: Path) -> Corpus:
    if not requirements.is_file():
        raise ValueError(f"requirements file does not exist: {requirements}")
    case = CorpusCase(
        case_id="legacy-requirements",
        path=requirements,
        kind="requirements",
        category="legacy",
        package_count=len(_requirement_entries(requirements)),
        compare_with_pip_audit=True,
        description="Ad hoc single requirements input.",
    )
    return Corpus(
        manifest=requirements,
        version="legacy",
        cases=(case,),
        package_count=case.package_count,
    )


def _benchmark_cases(
    corpus: Corpus,
    selected: Sequence[str],
) -> tuple[CorpusCase, ...]:
    requested = set(selected)
    cases = tuple(
        case
        for case in corpus.cases
        if case.compare_with_pip_audit
        and (not requested or case.case_id in requested)
    )
    missing = sorted(requested.difference(case.case_id for case in corpus.cases))
    if missing:
        raise ValueError("unknown benchmark corpus case(s): " + ", ".join(missing))
    return cases


def _trustcheck_command(case: CorpusCase, *, max_workers: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "trustcheck",
        "scan",
        "-f",
        str(case.path),
        "--with-osv",
        "--format",
        "json",
        "--no-deps",
        "--max-workers",
        str(max_workers),
    ]


def _pip_audit_command(case: CorpusCase) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(case.path),
        "--vulnerability-service",
        "osv",
        "--format",
        "json",
        "--progress-spinner",
        "off",
        "--no-deps",
        "--disable-pip",
    ]


def _run_suite(
    commands: Sequence[Sequence[str]],
    *,
    timeout: float,
    accepted_exit_codes: set[int],
) -> RunResult:
    started = time.perf_counter()
    payloads = []
    exit_code = 0
    for command in commands:
        result = _run(
            command,
            timeout=timeout,
            accepted_exit_codes=accepted_exit_codes,
        )
        exit_code = max(exit_code, result.exit_code)
        payloads.append(result.payload)
    return RunResult(
        seconds=time.perf_counter() - started,
        exit_code=exit_code,
        payload=payloads,
    )


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
    if isinstance(payload, list):
        merged: dict[tuple[str, str], list[set[str]]] = {}
        for item in payload:
            _merge_findings(merged, _trustcheck_findings(item))
        return merged
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
    if isinstance(payload, list):
        merged: dict[tuple[str, str], list[set[str]]] = {}
        for item in payload:
            _merge_findings(merged, _pip_audit_findings(item))
        return merged
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


def _merge_findings(
    target: dict[tuple[str, str], list[set[str]]],
    incoming: dict[tuple[str, str], list[set[str]]],
) -> None:
    for package, identities in incoming.items():
        target[package] = _dedupe_identities(
            [*target.get(package, []), *identities]
        )


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


def _corpus_summary(
    corpus: Corpus,
    benchmark_cases: Sequence[CorpusCase],
) -> dict[str, object]:
    return {
        "schema": CORPUS_SCHEMA,
        "version": corpus.version,
        "manifest": _published_path(corpus.manifest),
        "sha256": _sha256(corpus.manifest),
        "package_count": corpus.package_count,
        "case_count": len(corpus.cases),
        "categories": sorted({case.category for case in corpus.cases}),
        "benchmark_case_count": len(benchmark_cases),
        "benchmark_package_count": sum(case.package_count for case in benchmark_cases),
        "cases": [
            {
                "id": case.case_id,
                "path": _published_path(case.path),
                "sha256": _sha256(case.path),
                "kind": case.kind,
                "category": case.category,
                "package_count": case.package_count,
                "compare_with_pip_audit": case.compare_with_pip_audit,
                "description": case.description,
            }
            for case in corpus.cases
        ],
    }


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _requirement_entries(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.lstrip().startswith(("-", "--"))
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
    requirements: Path | None = None,
    paths: Sequence[Path] = (),
) -> list[str]:
    published_paths = {
        str(path.resolve()): _published_path(path)
        for path in ((*paths, requirements) if requirements is not None else paths)
        if path is not None
    }
    return [
        (
            "python"
            if index == 0
            else published_paths.get(argument, argument)
        )
        for index, argument in enumerate(command)
    ]


if __name__ == "__main__":
    raise SystemExit(main())
