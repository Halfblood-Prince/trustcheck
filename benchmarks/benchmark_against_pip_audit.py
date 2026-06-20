from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

BENCHMARK_SCHEMA = "urn:trustcheck:benchmark:pip-audit:3.0.0"
CORPUS_SCHEMA = "urn:trustcheck:benchmark-corpus:1.0.0"
MIN_CORPUS_PACKAGES = 100
MAX_CORPUS_PACKAGES = 500
TRUSTCHECK_BENCHMARK_SUBCOMMAND = "scan"


@dataclass(frozen=True, slots=True)
class CorpusCase:
    case_id: str
    path: Path
    kind: str
    category: str
    package_count: int
    compare_with_pip_audit: bool
    benchmark_roles: tuple[str, ...] = ()
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
    peak_memory_bytes: int | None = None
    request_count: int | None = None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark trustcheck scan against the latest installed pip-audit "
            "on a versioned package corpus."
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
    parser.add_argument(
        "--evidence-iterations",
        type=int,
        default=3,
        help="Warm-cache samples for resolution and profile evidence suites.",
    )
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--command-retries",
        type=int,
        default=2,
        help="Retry accepted-exit commands that emit no output.",
    )
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument(
        "--output",
        default="benchmarks/results/latest.json",
    )
    args = parser.parse_args(argv)
    if (
        args.iterations < 1
        or args.evidence_iterations < 1
        or args.warmups < 0
        or args.command_retries < 0
    ):
        parser.error(
            "iterations must be positive; warmups and command retries "
            "cannot be negative"
        )

    corpus = (
        _legacy_corpus(Path(args.requirements).resolve())
        if args.requirements
        else _load_corpus(Path(args.corpus).resolve())
    )
    benchmark_cases = _benchmark_cases(corpus, args.case)
    if not benchmark_cases:
        parser.error("no pip-audit-comparable corpus cases were selected")

    resolution_case = _case_for_role(corpus, "resolution")
    profiles_case = _case_for_role(corpus, "profiles")
    with tempfile.TemporaryDirectory(prefix="trustcheck-benchmark-") as temporary:
        cache_root = Path(temporary)
        direct_trust_cache = cache_root / "direct-trustcheck"
        direct_pip_cache = cache_root / "direct-pip-audit"
        trustcheck_commands = [
            _trustcheck_command(
                case,
                max_workers=args.max_workers,
                cache_dir=direct_trust_cache,
            )
            for case in benchmark_cases
        ]
        pip_audit_commands = [
            _pip_audit_command(case, cache_dir=direct_pip_cache)
            for case in benchmark_cases
        ]
        trustcheck_cold, trustcheck_runs = _run_cold_warm(
            trustcheck_commands,
            cache_roots=(direct_trust_cache,),
            iterations=args.iterations,
            warmups=args.warmups,
            timeout=args.timeout,
            accepted_exit_codes={0, 1, 4},
            command_retries=args.command_retries,
        )
        pip_audit_cold, pip_audit_runs = _run_cold_warm(
            pip_audit_commands,
            cache_roots=(direct_pip_cache,),
            iterations=args.iterations,
            warmups=args.warmups,
            timeout=args.timeout,
            accepted_exit_codes={0, 1},
            command_retries=args.command_retries,
        )
        trustcheck_findings = _trustcheck_findings(trustcheck_runs[-1].payload)
        pip_audit_findings = _pip_audit_findings(pip_audit_runs[-1].payload)
        correctness = _compare_findings(trustcheck_findings, pip_audit_findings)

        evidence: dict[str, Any] = {}
        evidence_commands: dict[str, Any] = {}
        if resolution_case is not None:
            resolution_trust_cache = cache_root / "resolution-trustcheck"
            resolution_pip_cache = cache_root / "resolution-pip-audit"
            resolution_trust_command = _trustcheck_command(
                resolution_case,
                max_workers=args.max_workers,
                resolve_dependencies=True,
                cache_dir=resolution_trust_cache,
            )
            resolution_pip_command = _pip_audit_command(
                resolution_case,
                resolve_dependencies=True,
                cache_dir=resolution_pip_cache,
            )
            resolution_trust_cold, resolution_trust_warm = _run_cold_warm(
                [resolution_trust_command],
                cache_roots=(resolution_trust_cache,),
                iterations=args.evidence_iterations,
                warmups=args.warmups,
                timeout=args.timeout,
                accepted_exit_codes={0, 1, 4},
                command_retries=args.command_retries,
            )
            resolution_pip_cold, resolution_pip_warm = _run_cold_warm(
                [resolution_pip_command],
                cache_roots=(resolution_pip_cache,),
                iterations=args.evidence_iterations,
                warmups=args.warmups,
                timeout=args.timeout,
                accepted_exit_codes={0, 1},
                command_retries=args.command_retries,
            )
            resolution_correctness = _compare_resolutions(
                resolution_trust_warm[-1].payload,
                resolution_pip_warm[-1].payload,
            )
            resolution_findings = _compare_findings(
                _trustcheck_findings(resolution_trust_warm[-1].payload),
                _pip_audit_findings(resolution_pip_warm[-1].payload),
            )
            evidence["dependency_resolution"] = {
                "case": resolution_case.case_id,
                "performance": {
                    "trustcheck": _phase_summary(
                        resolution_trust_cold,
                        resolution_trust_warm,
                    ),
                    "pip_audit": _phase_summary(
                        resolution_pip_cold,
                        resolution_pip_warm,
                    ),
                },
                "resolver_correctness": resolution_correctness,
                "advisory_correctness": resolution_findings,
            }
            evidence_commands["dependency_resolution"] = {
                "trustcheck": _published_command(
                    resolution_trust_command,
                    paths=(resolution_case.path,),
                ),
                "pip_audit": _published_command(
                    resolution_pip_command,
                    paths=(resolution_case.path,),
                ),
            }

        if profiles_case is not None:
            profile_evidence: dict[str, Any] = {}
            profile_commands: dict[str, Any] = {}
            for profile in ("standard", "full"):
                profile_cache = cache_root / f"profile-{profile}"
                profile_command = _trustcheck_command(
                    profiles_case,
                    max_workers=args.max_workers,
                    profile=profile,
                    artifact_scope="target",
                    cache_dir=profile_cache,
                )
                profile_cold, profile_warm = _run_cold_warm(
                    [profile_command],
                    cache_roots=(profile_cache,),
                    iterations=args.evidence_iterations,
                    warmups=args.warmups,
                    timeout=args.timeout,
                    accepted_exit_codes={0, 1, 4},
                    command_retries=args.command_retries,
                )
                profile_evidence[profile] = {
                    "performance": _phase_summary(profile_cold, profile_warm),
                    "work": _profile_work_summary(profile_warm[-1].payload),
                }
                profile_commands[profile] = _published_command(
                    profile_command,
                    paths=(profiles_case.path,),
                )
            evidence["trustcheck_profiles"] = {
                "case": profiles_case.case_id,
                "profiles": profile_evidence,
            }
            evidence_commands["trustcheck_profiles"] = profile_commands

        corpus_paths = [case.path for case in benchmark_cases]
        performance = {
            "trustcheck": _phase_summary(trustcheck_cold, trustcheck_runs),
            "pip_audit": _phase_summary(pip_audit_cold, pip_audit_runs),
        }
        published_commands = {
            "trustcheck": [
                _published_command(command, paths=corpus_paths)
                for command in trustcheck_commands
            ],
            "pip_audit": [
                _published_command(command, paths=corpus_paths)
                for command in pip_audit_commands
            ],
            "evidence": evidence_commands,
        }

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
            "evidence_iterations": args.evidence_iterations,
            "warmups": args.warmups,
            "timeout_seconds": args.timeout,
            "command_retries": args.command_retries,
            "max_workers": args.max_workers,
            "advisory_service": "OSV",
            "request_measurement": {
                "trustcheck": "tool-reported diagnostics.request_count",
                "pip_audit": "not exposed by pip-audit; recorded as null",
            },
            "memory_measurement": (
                "GNU time maximum resident set size"
                if platform.system() == "Linux"
                else "unavailable on this platform; recorded as null"
            ),
            "selected_cases": [case.case_id for case in benchmark_cases],
        },
        "commands": published_commands,
        "performance": performance,
        "evidence": evidence,
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
    raw_roles = payload.get("benchmark_roles", [])
    if not isinstance(raw_roles, list) or any(
        not isinstance(role, str) for role in raw_roles
    ):
        raise ValueError(f"benchmark corpus case {case_id!r} has invalid benchmark_roles")
    benchmark_roles = tuple(dict.fromkeys(raw_roles))
    if any(role not in {"resolution", "profiles"} for role in benchmark_roles):
        raise ValueError(f"benchmark corpus case {case_id!r} has unknown benchmark role")
    return CorpusCase(
        case_id=case_id,
        path=path,
        kind=kind,
        category=category,
        package_count=package_count,
        compare_with_pip_audit=compare,
        benchmark_roles=benchmark_roles,
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


def _case_for_role(corpus: Corpus, role: str) -> CorpusCase | None:
    return next(
        (case for case in corpus.cases if role in case.benchmark_roles),
        None,
    )


def _trustcheck_command(
    case: CorpusCase,
    *,
    max_workers: int,
    profile: str = "fast",
    artifact_scope: str = "target",
    resolve_dependencies: bool = False,
    cache_dir: Path | None = None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "trustcheck",
        TRUSTCHECK_BENCHMARK_SUBCOMMAND,
        f"--{profile}",
        "--artifact-scope",
        artifact_scope,
        "-f",
        str(case.path),
        "--with-osv",
        "--format",
        "json",
        "--max-workers",
        str(max_workers),
    ]
    if not resolve_dependencies:
        command.append("--no-deps")
    if cache_dir is not None:
        command.extend(["--cache-dir", str(cache_dir)])
    return command


def _pip_audit_command(
    case: CorpusCase,
    *,
    resolve_dependencies: bool = False,
    cache_dir: Path | None = None,
) -> list[str]:
    command = [
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
    ]
    if not resolve_dependencies:
        command.extend(["--no-deps", "--disable-pip"])
    if cache_dir is not None:
        command.extend(["--cache-dir", str(cache_dir)])
    return command


def _run_suite(
    commands: Sequence[Sequence[str]],
    *,
    timeout: float,
    accepted_exit_codes: set[int],
    command_retries: int,
) -> RunResult:
    started = time.perf_counter()
    payloads = []
    exit_code = 0
    peak_memory: list[int] = []
    request_counts: list[int] = []
    for command in commands:
        result = _run(
            command,
            timeout=timeout,
            accepted_exit_codes=accepted_exit_codes,
            command_retries=command_retries,
        )
        exit_code = max(exit_code, result.exit_code)
        payloads.append(result.payload)
        if result.peak_memory_bytes is not None:
            peak_memory.append(result.peak_memory_bytes)
        if result.request_count is not None:
            request_counts.append(result.request_count)
    return RunResult(
        seconds=time.perf_counter() - started,
        exit_code=exit_code,
        payload=payloads,
        peak_memory_bytes=max(peak_memory, default=None),
        request_count=sum(request_counts) if request_counts else None,
    )


def _run(
    command: Sequence[str],
    *,
    timeout: float,
    accepted_exit_codes: set[int],
    command_retries: int,
) -> RunResult:
    started = time.perf_counter()
    for attempt in range(command_retries + 1):
        measured_command = _memory_wrapped_command(command)
        completed = subprocess.run(  # nosec B603
            measured_command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        peak_memory_bytes, stderr = _extract_memory_measurement(completed.stderr)
        if completed.returncode not in accepted_exit_codes:
            raise RuntimeError(
                f"command failed with exit code {completed.returncode}: "
                f"{' '.join(command)}\n{stderr.strip()}"
            )
        if completed.stdout.strip():
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "command emitted invalid JSON with exit code "
                    f"{completed.returncode}: {' '.join(command)}\n"
                    f"stdout:\n{completed.stdout[:500]}\n"
                    f"stderr:\n{stderr[:500]}"
                ) from exc
            return RunResult(
                seconds=time.perf_counter() - started,
                exit_code=completed.returncode,
                payload=payload,
                peak_memory_bytes=peak_memory_bytes,
                request_count=_reported_request_count(payload),
            )
        if attempt < command_retries:
            time.sleep(2**attempt)
            continue
        raise RuntimeError(
            f"command emitted no JSON after {attempt + 1} attempt(s) "
            f"with exit code {completed.returncode}: {' '.join(command)}\n"
            f"stderr:\n{stderr[:2000]}"
        )
    raise RuntimeError("benchmark command retry loop terminated unexpectedly")


_MEMORY_MARKER = "__trustcheck_max_rss_kib__="


def _memory_wrapped_command(command: Sequence[str]) -> list[str]:
    time_binary = Path("/usr/bin/time")
    if platform.system() == "Linux" and time_binary.is_file():
        return [
            str(time_binary),
            "-f",
            _MEMORY_MARKER + "%M",
            *command,
        ]
    return list(command)


def _extract_memory_measurement(stderr: str) -> tuple[int | None, str]:
    peak_memory_bytes: int | None = None
    retained: list[str] = []
    for line in stderr.splitlines():
        if line.startswith(_MEMORY_MARKER):
            raw_value = line.removeprefix(_MEMORY_MARKER).strip()
            if raw_value.isdigit():
                peak_memory_bytes = int(raw_value) * 1024
            continue
        retained.append(line)
    return peak_memory_bytes, "\n".join(retained)


def _reported_request_count(payload: object) -> int | None:
    if isinstance(payload, list):
        counts = [_reported_request_count(item) for item in payload]
        measured = [count for count in counts if count is not None]
        return sum(measured) if measured else None
    if not isinstance(payload, dict):
        return None
    reports = payload.get("reports")
    if not isinstance(reports, list):
        report = payload.get("report")
        reports = [report] if isinstance(report, dict) else []
    counts: list[int] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        diagnostics = report.get("diagnostics")
        if isinstance(diagnostics, dict) and isinstance(
            diagnostics.get("request_count"),
            int,
        ):
            counts.append(diagnostics["request_count"])
    return sum(counts) if counts else None


def _run_cold_warm(
    commands: Sequence[Sequence[str]],
    *,
    cache_roots: Sequence[Path],
    iterations: int,
    warmups: int,
    timeout: float,
    accepted_exit_codes: set[int],
    command_retries: int,
) -> tuple[RunResult, list[RunResult]]:
    for cache_root in cache_roots:
        if cache_root.exists():
            shutil.rmtree(cache_root)
        cache_root.mkdir(parents=True, exist_ok=True)
    cold = _run_suite(
        commands,
        timeout=timeout,
        accepted_exit_codes=accepted_exit_codes,
        command_retries=command_retries,
    )
    for _ in range(warmups):
        _run_suite(
            commands,
            timeout=timeout,
            accepted_exit_codes=accepted_exit_codes,
            command_retries=command_retries,
        )
    warm = [
        _run_suite(
            commands,
            timeout=timeout,
            accepted_exit_codes=accepted_exit_codes,
            command_retries=command_retries,
        )
        for _ in range(iterations)
    ]
    return cold, warm


def _phase_summary(cold: RunResult, warm: Sequence[RunResult]) -> dict[str, Any]:
    summary = _timing_summary(warm)
    summary["cold"] = _timing_summary([cold])
    summary["warm"] = dict(summary)
    summary["warm"].pop("cold", None)
    return summary


def _resolved_packages(payload: object, *, tool: str) -> set[tuple[str, str]]:
    if isinstance(payload, list):
        packages: set[tuple[str, str]] = set()
        for item in payload:
            packages.update(_resolved_packages(item, tool=tool))
        return packages
    if not isinstance(payload, dict):
        return set()
    if tool == "trustcheck":
        reports = payload.get("reports")
        if not isinstance(reports, list):
            report = payload.get("report")
            reports = [report] if isinstance(report, dict) else []
        return {
            (str(report["project"]).lower(), str(report["version"]))
            for report in reports
            if isinstance(report, dict)
            and isinstance(report.get("project"), str)
            and isinstance(report.get("version"), str)
        }
    dependencies = payload.get("dependencies", [])
    return {
        (str(item["name"]).lower(), str(item["version"]))
        for item in dependencies
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("version"), str)
    } if isinstance(dependencies, list) else set()


def _compare_resolutions(left_payload: object, right_payload: object) -> dict[str, Any]:
    left = _resolved_packages(left_payload, tool="trustcheck")
    right = _resolved_packages(right_payload, tool="pip_audit")
    return {
        "exact_match": left == right,
        "trustcheck_package_count": len(left),
        "pip_audit_package_count": len(right),
        "trustcheck_only": [f"{name}=={version}" for name, version in sorted(left - right)],
        "pip_audit_only": [f"{name}=={version}" for name, version in sorted(right - left)],
    }


def _profile_work_summary(payload: object) -> dict[str, int]:
    if isinstance(payload, list):
        summaries = [_profile_work_summary(item) for item in payload]
        return {
            key: sum(summary[key] for summary in summaries)
            for key in (
                "packages",
                "artifacts",
                "provenance_artifacts",
                "verified_artifacts",
                "inspected_artifacts",
                "native_binaries",
                "heuristic_findings",
            )
        }
    if not isinstance(payload, dict):
        return _profile_work_summary([])
    reports = payload.get("reports")
    if not isinstance(reports, list):
        report = payload.get("report")
        reports = [report] if isinstance(report, dict) else []
    files = [
        item
        for report in reports
        if isinstance(report, dict)
        for item in report.get("files", [])
        if isinstance(report.get("files"), list) and isinstance(item, dict)
    ]
    artifact_payloads = [
        item.get("artifact")
        for item in files
        if isinstance(item.get("artifact"), dict)
    ]
    return {
        "packages": sum(isinstance(report, dict) for report in reports),
        "artifacts": len(files),
        "provenance_artifacts": sum(bool(item.get("has_provenance")) for item in files),
        "verified_artifacts": sum(bool(item.get("verified")) for item in files),
        "inspected_artifacts": sum(
            bool(item.get("inspected"))
            for item in artifact_payloads
            if isinstance(item, dict)
        ),
        "native_binaries": sum(
            len(item.get("native_binaries", []))
            for item in artifact_payloads
            if isinstance(item, dict) and isinstance(item.get("native_binaries"), list)
        ),
        "heuristic_findings": sum(
            len(item.get("heuristic_findings", []))
            for item in artifact_payloads
            if isinstance(item, dict) and isinstance(item.get("heuristic_findings"), list)
        ),
    }


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
    expected = {
        package: _dedupe_identities(
            [*left.get(package, []), *right.get(package, [])]
        )
        for package in packages
    }
    return {
        "matched_advisories": matched,
        "trustcheck_only": left_only,
        "pip_audit_only": right_only,
        "alias_aware_agreement": round(agreement, 6),
        "advisory_recall": {
            "reference": "union-of-tool-findings",
            "trustcheck": _advisory_recall(left, expected),
            "pip_audit": _advisory_recall(right, expected),
        },
        "packages_compared": len(packages),
        "trustcheck_vulnerable_packages": sum(bool(items) for items in left.values()),
        "pip_audit_vulnerable_packages": sum(bool(items) for items in right.values()),
    }


def _advisory_recall(
    observed: dict[tuple[str, str], list[set[str]]],
    expected: dict[tuple[str, str], list[set[str]]],
) -> float:
    expected_count = sum(len(identities) for identities in expected.values())
    if expected_count == 0:
        return 1.0
    recalled = sum(
        1
        for package, identities in expected.items()
        for identity in identities
        if any(identity & candidate for candidate in observed.get(package, []))
    )
    return round(recalled / expected_count, 6)


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
    memory_samples = [
        run.peak_memory_bytes
        for run in runs
        if run.peak_memory_bytes is not None
    ]
    request_samples = [
        run.request_count
        for run in runs
        if run.request_count is not None
    ]
    return {
        "samples_seconds": [round(sample, 6) for sample in samples],
        "p50_seconds": round(statistics.median(samples), 6),
        "median_seconds": round(statistics.median(samples), 6),
        "p95_seconds": round(ordered[rank], 6),
        "peak_memory_bytes": max(memory_samples, default=None),
        "memory_samples_bytes": memory_samples,
        "request_count_p50": (
            round(statistics.median(request_samples), 3)
            if request_samples
            else None
        ),
        "request_count_samples": request_samples,
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
                "benchmark_roles": list(case.benchmark_roles),
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
    published: list[str] = []
    redact_cache_value = False
    for index, argument in enumerate(command):
        if redact_cache_value:
            published.append("<cache>")
            redact_cache_value = False
            continue
        published.append(
            "python"
            if index == 0
            else published_paths.get(argument, argument)
        )
        if argument == "--cache-dir":
            redact_cache_value = True
    return published


if __name__ == "__main__":
    raise SystemExit(main())
