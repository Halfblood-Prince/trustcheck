from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import parse

from packaging.utils import canonicalize_name

from ..cli_models import (
    EXIT_DATA_ERROR,
    EXIT_OK,
    EXIT_POLICY_FAILURE,
    EXIT_UPSTREAM_FAILURE,
    ScanTarget,
)
from ..models import FileProvenance, PolicyEvaluation, TrustReport
from ..plugins import PluginManager
from ..policy import PolicySettings
from ..pypi import PypiClient, PypiClientError
from .context import CommandContext

INSTALL_LOCK_SCHEMA = "urn:trustcheck:install-lock:1.0.0"
INSTALL_REPORT_SCHEMA = "urn:trustcheck:install-report:1.0.0"
INSTALL_ATTESTATION_SCHEMA = "urn:trustcheck:install-attestation:1.0.0"


@dataclass(slots=True)
class InstallArtifact:
    filename: str
    url: str
    sha256: str | None = None
    observed_sha256: str | None = None
    size: int | None = None
    wheelhouse_filename: str | None = None


@dataclass(slots=True)
class InstallPlanItem:
    target: ScanTarget
    report: TrustReport | None = None
    evaluation: PolicyEvaluation | None = None
    artifact: InstallArtifact | None = None
    failures: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvidencePaths:
    lock: Path
    report: Path
    attestation: Path


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.requirement_file and args.requirements:
        parser.error("install accepts either PACKAGE... or -r/--requirement, not both")
    if not args.requirement_file and not args.requirements:
        parser.error("install requires PACKAGE... or -r/--requirement")
    if _has_cross_target_options(args):
        parser.error(
            "install targets the current interpreter; "
            "--python-version/--platform/--implementation/--abi are not supported"
        )
    paths = [Path(args.lock), Path(args.report), Path(args.attestation)]
    normalized = {_normalized_path_key(path) for path in paths}
    if len(normalized) != len(paths):
        parser.error("--lock, --report, and --attestation must be distinct paths")
    if args.requirement_file and _normalized_path_key(Path(args.requirement_file)) in normalized:
        parser.error("install evidence outputs must not overwrite the input file")


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    config_payload = context.config_payload
    plugin_manager = context.plugin_manager

    args.max_workers = cli._resolve_max_workers(args, config_payload)
    client = cli._build_client(
        args,
        config_payload=config_payload,
        request_hook=cli._build_debug_request_hook(
            enabled=args.debug,
            log_format=args.log_format,
        ),
    )
    vulnerability_client = cli._build_vulnerability_client(
        args,
        client,
        config_payload=config_payload,
        plugin_manager=plugin_manager,
    )
    policy_name = "strict" if args.strict else args.policy
    policy = cli.resolve_policy(
        builtin_name=policy_name,
        config_path=args.policy_file,
        cli_overrides={
            "require_verified_provenance": (
                "all" if args.require_provenance else None
            ),
            "vulnerability_mode": args.fail_on_vulnerability,
        },
    )
    resolver = cli._resolver_from_args(args, plugin_manager=plugin_manager)
    source_label, targets = _load_install_targets(
        args,
        cli=cli,
        client=client,
        resolver=resolver,
    )
    plans, exit_code = _inspect_install_plan(
        args,
        cli=cli,
        targets=targets,
        client=client,
        policy=policy,
        resolver=resolver,
        vulnerability_client=vulnerability_client,
        plugin_manager=plugin_manager,
    )
    if vulnerability_client is not None:
        vulnerability_client.flush_snapshots()

    _select_install_artifacts(plans, allow_sdist=args.allow_sdist)
    if _has_blockers(plans):
        report_payload = _write_evidence(
            args,
            cli=cli,
            source_label=source_label,
            plans=plans,
            policy=policy,
            status="blocked",
            installed=False,
        )
        _emit_install_result(args, cli=cli, payload=report_payload, plans=plans)
        return int(_merge_plan_exit_code(cli, exit_code, EXIT_POLICY_FAILURE))

    with tempfile.TemporaryDirectory(prefix="trustcheck-install-") as tempdir:
        root = Path(tempdir)
        wheelhouse = root / "verified-wheelhouse"
        resolved = root / "resolved.txt"
        download_exit = _materialize_verified_wheelhouse(
            plans,
            wheelhouse,
            args=args,
            cli=cli,
            client=client,
            plugin_manager=plugin_manager,
        )
        if _has_blockers(plans):
            report_payload = _write_evidence(
                args,
                cli=cli,
                source_label=source_label,
                plans=plans,
                policy=policy,
                status="blocked",
                installed=False,
            )
            _emit_install_result(
                args,
                cli=cli,
                payload=report_payload,
                plans=plans,
            )
            return int(_merge_plan_exit_code(cli, exit_code, download_exit))

        _write_resolved_requirements(resolved, plans)
        pip_command = _pip_install_command(
            wheelhouse,
            resolved,
            allow_sdist=args.allow_sdist,
        )
        report_payload = _write_evidence(
            args,
            cli=cli,
            source_label=source_label,
            plans=plans,
            policy=policy,
            status="verified",
            installed=False,
            pip_command=pip_command,
        )
        if args.dry_run:
            _emit_install_result(
                args,
                cli=cli,
                payload=report_payload,
                plans=plans,
            )
            return EXIT_OK

        completed = _run_pip_install(pip_command)
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            if not detail:
                detail = f"pip exited with status {completed.returncode}"
            report_payload = _write_evidence(
                args,
                cli=cli,
                source_label=source_label,
                plans=plans,
                policy=policy,
                status="install-failed",
                installed=False,
                install_error=detail,
                pip_command=pip_command,
            )
            _emit_install_result(
                args,
                cli=cli,
                payload=report_payload,
                plans=plans,
            )
            return EXIT_UPSTREAM_FAILURE

        report_payload = _write_evidence(
            args,
            cli=cli,
            source_label=source_label,
            plans=plans,
            policy=policy,
            status="installed",
            installed=True,
            pip_command=pip_command,
        )
        _emit_install_result(args, cli=cli, payload=report_payload, plans=plans)
        return EXIT_OK


def _load_install_targets(
    args: argparse.Namespace,
    *,
    cli: Any,
    client: PypiClient,
    resolver: Any,
) -> tuple[str, list[ScanTarget]]:
    if args.requirement_file:
        targets = cli._load_scan_targets(
            args.requirement_file,
            client,
            resolver=resolver,
            constraints=args.constraint,
            extras=args.extra,
            groups=args.group,
            target_environment=cli._target_environment_from_args(args),
            offline=client.offline,
        )
        return args.requirement_file, targets

    resolution = resolver.resolve_requirements(
        args.requirements,
        constraints=args.constraint,
        target=cli._target_environment_from_args(args),
        cwd=Path.cwd(),
        offline=client.offline,
    )
    return "command line requirements", cli._scan_targets_from_resolution(resolution)


def _inspect_install_plan(
    args: argparse.Namespace,
    *,
    cli: Any,
    targets: list[ScanTarget],
    client: PypiClient,
    policy: PolicySettings,
    resolver: Any,
    vulnerability_client: Any,
    plugin_manager: PluginManager,
) -> tuple[list[InstallPlanItem], int]:
    plans = [InstallPlanItem(target=target) for target in targets]
    exit_code = EXIT_OK
    artifact_cache = cli.ArtifactDigestCache()
    artifact_executor = ThreadPoolExecutor(
        max_workers=max(1, args.max_workers),
        thread_name_prefix="trustcheck-install-artifact",
    )
    try:
        for plan in plans:
            target = plan.target
            if target.failure_message is not None:
                plan.failures.append(target.failure_message)
                exit_code = cli._merge_exit_codes(
                    exit_code,
                    target.failure_exit_code,
                )
                continue
            if target.version is None:
                plan.failures.append(
                    "resolver did not produce an exact version for installation"
                )
                exit_code = cli._merge_exit_codes(exit_code, EXIT_DATA_ERROR)
                continue
            try:
                target_client = cli._client_for_target(
                    cli._clone_pypi_client(client),
                    target,
                    keyring_provider=args.keyring_provider,
                    plugin_manager=plugin_manager,
                )
                report = cli.inspect_package(
                    target.project,
                    version=target.version,
                    client=target_client,
                    include_dependencies=False,
                    include_transitive_dependencies=False,
                    include_vulnerabilities=True,
                    include_osv=vulnerability_client is not None,
                    vulnerability_only=False,
                    inspect_artifacts=True,
                    dynamic_analysis=args.dynamic_analysis,
                    vulnerability_client=vulnerability_client,
                    locked_versions=target.locked_versions,
                    complete_locked_versions=target.complete_locked_versions,
                    expected_artifacts=target.artifacts,
                    dependency_confusion_indexes=target.dependency_confusion,
                    trusted_projects=args.trusted_project,
                    resolver=resolver,
                    target_environment=cli._target_environment_from_args(args),
                    plugin_manager=plugin_manager,
                    scan_profile="full",
                    artifact_scope="target",
                    max_workers=args.max_workers,
                    artifact_cache=artifact_cache,
                    artifact_executor=artifact_executor,
                )
                plan.report = report
                plan.evaluation = cli.evaluate_policy(
                    report,
                    policy,
                    plugin_manager=plugin_manager,
                )
                if not plan.evaluation.passed:
                    exit_code = cli._merge_exit_codes(
                        exit_code,
                        EXIT_POLICY_FAILURE,
                    )
            except PypiClientError as exc:
                plan.failures.append(cli._format_upstream_error(exc))
                exit_code = cli._merge_exit_codes(exit_code, EXIT_UPSTREAM_FAILURE)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                plan.failures.append(
                    "error: received an invalid response while inspecting "
                    f"the package: {exc}"
                )
                exit_code = cli._merge_exit_codes(exit_code, EXIT_DATA_ERROR)
    finally:
        artifact_executor.shutdown(wait=True)
    return plans, exit_code


def _select_install_artifacts(
    plans: list[InstallPlanItem],
    *,
    allow_sdist: bool,
) -> None:
    for plan in plans:
        if plan.report is None or plan.failures:
            continue
        files = plan.report.files
        if not files:
            plan.failures.append(
                "artifact rule blocks installation: no target-compatible "
                "artifact was selected"
            )
            continue
        if len(files) != 1:
            plan.failures.append(
                "artifact rule blocks installation: expected exactly one "
                f"target artifact, found {len(files)}"
            )
            continue
        selected = files[0]
        try:
            filename = _artifact_filename(selected)
        except ValueError as exc:
            plan.failures.append(f"artifact rule blocks installation: {exc}")
            continue
        if not _is_wheel(filename) and not _is_sdist(filename):
            plan.failures.append(
                f"artifact rule blocks {filename}: only wheels"
                " and source distributions are installable"
            )
            continue
        if _is_sdist(filename) and not allow_sdist:
            plan.failures.append(
                f"artifact rule blocks {filename}: source distributions are "
                "disabled by default; pass --allow-sdist to permit this package"
            )
            continue
        if not selected.url:
            plan.failures.append(
                f"artifact rule blocks {filename}: selected artifact has no URL"
            )
            continue
        plan.artifact = InstallArtifact(
            filename=filename,
            url=selected.url,
            sha256=selected.sha256 or selected.observed_sha256,
            observed_sha256=selected.observed_sha256,
            size=None,
        )


def _materialize_verified_wheelhouse(
    plans: list[InstallPlanItem],
    wheelhouse: Path,
    *,
    args: argparse.Namespace,
    cli: Any,
    client: PypiClient,
    plugin_manager: PluginManager,
) -> int:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    exit_code = EXIT_OK
    for plan in plans:
        artifact = plan.artifact
        if artifact is None:
            continue
        try:
            target_client = cli._client_for_target(
                cli._clone_pypi_client(client),
                plan.target,
                keyring_provider=args.keyring_provider,
                plugin_manager=plugin_manager,
            )
            payload = target_client.download_distribution(artifact.url)
        except PypiClientError as exc:
            plan.failures.append(cli._format_upstream_error(exc))
            exit_code = cli._merge_exit_codes(exit_code, EXIT_UPSTREAM_FAILURE)
            continue
        observed = hashlib.sha256(payload).hexdigest()
        expected = artifact.sha256
        if expected is not None and observed.lower() != expected.lower():
            plan.failures.append(
                f"hash verification failed for {artifact.filename}: expected "
                f"sha256:{expected}, observed sha256:{observed}"
            )
            exit_code = cli._merge_exit_codes(exit_code, EXIT_POLICY_FAILURE)
            continue
        expected_from_target = _target_sha256s(plan.target)
        if expected_from_target and observed.lower() not in expected_from_target:
            plan.failures.append(
                f"hash verification failed for {artifact.filename}: downloaded "
                "artifact does not match the resolver-selected hash"
            )
            exit_code = cli._merge_exit_codes(exit_code, EXIT_POLICY_FAILURE)
            continue

        destination = wheelhouse / artifact.filename
        try:
            if destination.exists():
                existing = destination.read_bytes()
                if hashlib.sha256(existing).hexdigest() != observed:
                    plan.failures.append(
                        f"wheelhouse filename collision for {artifact.filename}"
                    )
                    exit_code = cli._merge_exit_codes(
                        exit_code,
                        EXIT_POLICY_FAILURE,
                    )
                    continue
            else:
                _atomic_write_bytes(destination, payload)
        except OSError as exc:
            plan.failures.append(
                f"unable to write verified artifact {artifact.filename}: {exc}"
            )
            exit_code = cli._merge_exit_codes(exit_code, EXIT_DATA_ERROR)
            continue
        artifact.sha256 = artifact.sha256 or observed
        artifact.observed_sha256 = observed
        artifact.size = len(payload)
        artifact.wheelhouse_filename = artifact.filename
    return exit_code


def _write_resolved_requirements(path: Path, plans: list[InstallPlanItem]) -> None:
    lines: list[str] = []
    for plan in sorted(plans, key=lambda item: canonicalize_name(item.target.project)):
        artifact = plan.artifact
        if plan.target.version is None or artifact is None or artifact.observed_sha256 is None:
            raise ValueError(
                f"install plan for {plan.target.project!r} is missing verified bytes"
            )
        lines.append(
            f"{plan.target.project}=={plan.target.version} "
            f"--hash=sha256:{artifact.observed_sha256}"
        )
    _atomic_write_text(path, "\n".join(lines) + "\n")


def _pip_install_command(
    wheelhouse: Path,
    resolved: Path,
    *,
    allow_sdist: bool,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--require-hashes",
        "--no-deps",
    ]
    if not allow_sdist:
        command.extend(["--only-binary", ":all:"])
    command.extend(["-r", str(resolved)])
    return command


def _run_pip_install(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr=f"unable to start pip install: {exc}",
        )


def _write_evidence(
    args: argparse.Namespace,
    *,
    cli: Any,
    source_label: str,
    plans: list[InstallPlanItem],
    policy: PolicySettings,
    status: str,
    installed: bool,
    install_error: str | None = None,
    pip_command: list[str] | None = None,
) -> dict[str, Any]:
    paths = EvidencePaths(
        lock=Path(args.lock),
        report=Path(args.report),
        attestation=Path(args.attestation),
    )
    generated_at = _utc_now()
    lock_payload = _lock_payload(
        args,
        cli=cli,
        source_label=source_label,
        plans=plans,
        policy=policy,
        generated_at=generated_at,
    )
    _atomic_write_json(paths.lock, lock_payload)
    report_payload = _report_payload(
        args,
        cli=cli,
        source_label=source_label,
        plans=plans,
        policy=policy,
        status=status,
        installed=installed,
        generated_at=generated_at,
        install_error=install_error,
        pip_command=pip_command,
        evidence_paths=paths,
    )
    _atomic_write_json(paths.report, report_payload)
    attestation_payload = _attestation_payload(
        plans,
        status=status,
        installed=installed,
        generated_at=generated_at,
        lock_sha256=_file_sha256(paths.lock),
        report_sha256=_file_sha256(paths.report),
    )
    _atomic_write_json(paths.attestation, attestation_payload)
    return report_payload


def _lock_payload(
    args: argparse.Namespace,
    *,
    cli: Any,
    source_label: str,
    plans: list[InstallPlanItem],
    policy: PolicySettings,
    generated_at: str,
) -> dict[str, Any]:
    return {
        "schema": INSTALL_LOCK_SCHEMA,
        "generated_at": generated_at,
        "trustcheck_version": cli.__version__,
        "source": _source_payload(args, source_label),
        "policy": asdict(policy),
        "target_environment": asdict(cli._target_environment_from_args(args)),
        "packages": [_package_payload(plan, include_report=False) for plan in plans],
    }


def _report_payload(
    args: argparse.Namespace,
    *,
    cli: Any,
    source_label: str,
    plans: list[InstallPlanItem],
    policy: PolicySettings,
    status: str,
    installed: bool,
    generated_at: str,
    install_error: str | None,
    pip_command: list[str] | None,
    evidence_paths: EvidencePaths,
) -> dict[str, Any]:
    blockers = _blocker_payloads(plans)
    return {
        "schema": INSTALL_REPORT_SCHEMA,
        "generated_at": generated_at,
        "trustcheck_version": cli.__version__,
        "source": _source_payload(args, source_label),
        "status": status,
        "installed": installed,
        "dry_run": bool(args.dry_run),
        "package_count": len(plans),
        "verified_package_count": len(plans) - len({item["package"] for item in blockers}),
        "policy": asdict(policy),
        "allow_sdist": bool(args.allow_sdist),
        "require_provenance": bool(args.require_provenance),
        "pip_command": pip_command,
        "install_error": install_error,
        "evidence": {
            "lock": str(evidence_paths.lock),
            "report": str(evidence_paths.report),
            "attestation": str(evidence_paths.attestation),
        },
        "blockers": blockers,
        "packages": [_package_payload(plan, include_report=True) for plan in plans],
    }


def _attestation_payload(
    plans: list[InstallPlanItem],
    *,
    status: str,
    installed: bool,
    generated_at: str,
    lock_sha256: str,
    report_sha256: str,
) -> dict[str, Any]:
    subjects = []
    for plan in plans:
        artifact = plan.artifact
        if artifact is None or artifact.observed_sha256 is None:
            continue
        subjects.append(
            {
                "name": artifact.filename,
                "digest": {"sha256": artifact.observed_sha256},
            }
        )
    return {
        "schema": INSTALL_ATTESTATION_SCHEMA,
        "generated_at": generated_at,
        "predicate_type": "https://trustcheck.dev/install/v1",
        "subject": subjects,
        "predicate": {
            "status": status,
            "installed": installed,
            "package_count": len(plans),
            "lock_sha256": lock_sha256,
            "report_sha256": report_sha256,
        },
    }


def _package_payload(
    plan: InstallPlanItem,
    *,
    include_report: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "requirement": plan.target.requirement,
        "name": plan.target.project,
        "version": plan.target.version,
        "requested": plan.target.requested,
        "source_type": plan.target.source_type,
        "source_url": _redact(plan.target.source_url),
        "index_url": _redact(plan.target.index_url),
        "artifacts": [artifact.to_dict() for artifact in plan.target.artifacts],
        "install_artifact": _artifact_payload(plan.artifact),
        "policy": asdict(plan.evaluation) if plan.evaluation is not None else None,
        "failures": list(plan.failures),
    }
    if include_report:
        payload["trust_report"] = (
            plan.report.to_dict()["report"] if plan.report is not None else None
        )
    return payload


def _artifact_payload(artifact: InstallArtifact | None) -> dict[str, Any] | None:
    if artifact is None:
        return None
    return {
        "filename": artifact.filename,
        "url": _redact(artifact.url),
        "sha256": artifact.sha256,
        "observed_sha256": artifact.observed_sha256,
        "size": artifact.size,
        "wheelhouse_filename": artifact.wheelhouse_filename,
    }


def _source_payload(args: argparse.Namespace, source_label: str) -> dict[str, Any]:
    if args.requirement_file:
        return {
            "type": "requirement-file",
            "label": source_label,
            "path": str(Path(args.requirement_file).resolve()),
        }
    return {
        "type": "requirements",
        "label": source_label,
        "requirements": list(args.requirements),
    }


def _emit_install_result(
    args: argparse.Namespace,
    *,
    cli: Any,
    payload: dict[str, Any],
    plans: list[InstallPlanItem],
) -> None:
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True)
        if args.format == "json"
        else _render_install_text(payload, plans)
    )
    cli._emit_output(rendered, args.output_file)


def _render_install_text(
    payload: dict[str, Any],
    plans: list[InstallPlanItem],
) -> str:
    lines = [f"Verified install plan: {len(plans)} packages"]
    for plan in plans:
        lines.append("")
        status = "[blocked]" if _plan_blockers(plan) else "[ok]"
        version = plan.target.version or "-"
        lines.append(f"{status} {plan.target.project} {version}")
        blockers = _plan_blockers(plan)
        if blockers:
            for blocker in blockers:
                lines.append(f"  blocked: {blocker}")
            continue
        reason = _success_reason(plan)
        if reason:
            lines.append(f"  {reason}")

    lines.append("")
    status = str(payload["status"])
    if status == "installed":
        lines.append("Installed packages from the verified local wheelhouse.")
    elif status == "verified":
        lines.append("Dry run: no packages were installed.")
    elif status == "install-failed":
        lines.append("pip install failed after verification.")
        if payload.get("install_error"):
            lines.append(f"error: {payload['install_error']}")
    else:
        lines.append("No packages were installed.")
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        lines.append(
            "Evidence written: "
            f"{evidence.get('lock')}, {evidence.get('report')}, "
            f"{evidence.get('attestation')}"
        )
    return "\n".join(lines)


def _success_reason(plan: InstallPlanItem) -> str:
    report = plan.report
    artifact = plan.artifact
    reasons: list[str] = []
    if report is not None and report.files and all(file.verified for file in report.files):
        reasons.append("provenance verified")
    if artifact is not None and artifact.observed_sha256:
        reasons.append("hash verified")
    if report is not None and not report.vulnerabilities:
        reasons.append("no advisory found")
    if plan.evaluation is not None and plan.evaluation.passed:
        reasons.append("policy passed")
    return "; ".join(dict.fromkeys(reasons))


def _has_blockers(plans: list[InstallPlanItem]) -> bool:
    return any(_plan_blockers(plan) for plan in plans)


def _plan_blockers(plan: InstallPlanItem) -> list[str]:
    blockers = list(plan.failures)
    if plan.evaluation is not None:
        blockers.extend(violation.message for violation in plan.evaluation.violations)
    return blockers


def _blocker_payloads(plans: list[InstallPlanItem]) -> list[dict[str, str]]:
    blocked: list[dict[str, str]] = []
    for plan in plans:
        for message in _plan_blockers(plan):
            blocked.append(
                {
                    "package": plan.target.project,
                    "version": plan.target.version or "",
                    "message": message,
                }
            )
    return blocked


def _merge_plan_exit_code(cli: Any, first: int, second: int) -> int:
    if first == EXIT_OK:
        return second
    if second == EXIT_OK:
        return first
    return cli._merge_exit_codes(first, second)


def _has_cross_target_options(args: argparse.Namespace) -> bool:
    return bool(args.python_version or args.platform or args.implementation or args.abi)


def _artifact_filename(file: FileProvenance) -> str:
    raw = file.filename
    if not raw and file.url:
        raw = Path(parse.unquote(parse.urlsplit(file.url).path)).name
    filename = Path(raw).name
    if not filename:
        raise ValueError("selected artifact has no filename")
    return filename


def _target_sha256s(target: ScanTarget) -> set[str]:
    return {
        digest.lower()
        for artifact in target.artifacts
        for algorithm, digest in artifact.hashes
        if algorithm.lower() == "sha256"
    }


def _is_wheel(filename: str) -> bool:
    return filename.endswith(".whl")


def _is_sdist(filename: str) -> bool:
    return filename.endswith((".tar.gz", ".zip"))


def _redact(url: str | None) -> str | None:
    if url is None:
        return None
    from ..indexes import redact_url_credentials

    return redact_url_credentials(url)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalized_path_key(path: Path) -> str:
    resolved = str(path.resolve())
    return resolved.lower() if os.name == "nt" else resolved


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _atomic_write_text(path: Path, payload: str) -> None:
    _atomic_write_bytes(path, payload.encode("utf-8"))


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
