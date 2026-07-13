from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..cli_models import EXIT_DATA_ERROR, EXIT_OK, ScanTarget
from ..manifest import (
    build_manifest,
    load_manifest,
    render_manifest_verification_text,
    verify_manifest,
    write_manifest,
)
from ..models import TrustReport
from ..plugins import PluginManager
from ..pypi import PypiClient, PypiClientError
from .context import CommandContext


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.max_malicious_score < 0:
        parser.error("--max-malicious-score must be zero or greater")


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    config_payload = context.config_payload
    plugin_manager = context.plugin_manager

    args.max_workers = cli._resolve_max_workers(args, config_payload)
    progress_callback = None
    dependency_progress_callback = None
    if args.format == "text":
        progress_callback = cli._build_progress_callback()
        dependency_progress_callback = cli._build_dependency_progress_callback()

    client = cli._build_client(
        args,
        config_payload=config_payload,
        request_hook=cli._build_debug_request_hook(
            enabled=args.debug,
            log_format=args.log_format,
        ),
    )
    resolver = cli._resolver_from_args(args, plugin_manager=plugin_manager)
    targets = cli._load_scan_targets(
        args.filename,
        client,
        resolver=resolver,
        constraints=args.constraint,
        extras=args.extra,
        groups=args.group,
        target_environment=cli._target_environment_from_args(args),
        offline=client.offline,
    )
    reports, failures, failure_exit_code = _inspect_manifest_targets(
        args,
        cli=cli,
        targets=targets,
        client=client,
        resolver=resolver,
        plugin_manager=plugin_manager,
        progress_callback=progress_callback,
        dependency_progress_callback=dependency_progress_callback,
    )
    if failures:
        rendered = _render_failures(args, failures)
        cli._emit_output(rendered, args.output_file)
        return int(failure_exit_code)

    if args.manifest_action == "verify":
        manifest = _load_manifest_for_cli(args.manifest)
        result = verify_manifest(manifest, reports, targets)
        rendered = (
            json.dumps(result.to_dict(), indent=2, sort_keys=True)
            if args.format == "json"
            else render_manifest_verification_text(result)
        )
        cli._emit_output(rendered, args.output_file)
        return int(cli.EXIT_OK if result.passed else cli.EXIT_POLICY_FAILURE)

    existing_manifest = (
        _load_manifest_for_cli(args.manifest)
        if args.manifest_action == "update"
        else None
    )
    manifest = build_manifest(
        reports,
        targets,
        existing_manifest=existing_manifest,
        default_max_malicious_score=args.max_malicious_score,
    )
    manifest_path = args.output if args.manifest_action == "init" else args.manifest
    _write_manifest_for_cli(manifest_path, manifest)
    rendered = _render_write_result(
        args,
        manifest_path=manifest_path,
        package_count=len(manifest["packages"]),
    )
    cli._emit_output(rendered, args.output_file)
    return int(EXIT_OK)


def _inspect_manifest_targets(
    args: argparse.Namespace,
    *,
    cli: Any,
    targets: list[ScanTarget],
    client: PypiClient,
    resolver: Any,
    plugin_manager: PluginManager,
    progress_callback: Any,
    dependency_progress_callback: Any,
) -> tuple[list[TrustReport], list[dict[str, str]], int]:
    reports: list[TrustReport] = []
    failures: list[dict[str, str]] = []
    exit_code = EXIT_OK
    artifact_cache = cli.ArtifactDigestCache()
    artifact_executor = ThreadPoolExecutor(
        max_workers=max(1, args.max_workers),
        thread_name_prefix="trustcheck-manifest-artifact",
    )
    try:
        for target in targets:
            if target.failure_message is not None:
                failures.append(
                    {
                        "requirement": target.requirement,
                        "message": target.failure_message,
                    }
                )
                exit_code = cli._merge_exit_codes(
                    exit_code,
                    target.failure_exit_code,
                )
                continue
            try:
                isolated_client = cli._clone_pypi_client(client)
                target_client = cli._client_for_target(
                    isolated_client,
                    target,
                    keyring_provider=args.keyring_provider,
                    plugin_manager=plugin_manager,
                )
                reports.append(
                    cli.inspect_package(
                        target.project,
                        version=target.version,
                        client=target_client,
                        progress_callback=progress_callback,
                        dependency_progress_callback=dependency_progress_callback,
                        include_dependencies=False,
                        include_transitive_dependencies=False,
                        include_vulnerabilities=True,
                        include_osv=False,
                        vulnerability_only=False,
                        inspect_artifacts=True,
                        dynamic_analysis=args.dynamic_analysis,
                        dynamic_analysis_image=getattr(args, "dynamic_image", None),
                        dynamic_analysis_python=getattr(args, "dynamic_python", "3.12"),
                        vulnerability_client=None,
                        locked_versions=target.locked_versions,
                        complete_locked_versions=target.complete_locked_versions,
                        expected_artifacts=target.artifacts,
                        dependency_confusion_indexes=target.dependency_confusion,
                        trusted_projects=args.trusted_project,
                        resolver=resolver,
                        target_environment=cli._target_environment_from_args(args),
                        plugin_manager=plugin_manager,
                        scan_profile="full",
                        artifact_scope=args.manifest_artifact_scope,
                        max_workers=args.max_workers,
                        artifact_cache=artifact_cache,
                        artifact_executor=artifact_executor,
                    )
                )
            except PypiClientError as exc:
                failures.append(
                    {
                        "requirement": target.requirement,
                        "message": cli._format_upstream_error(exc),
                    }
                )
                exit_code = cli._merge_exit_codes(
                    exit_code,
                    cli.EXIT_UPSTREAM_FAILURE,
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                failures.append(
                    {
                        "requirement": target.requirement,
                        "message": (
                            "error: received an invalid response while "
                            f"inspecting the package: {exc}"
                        ),
                    }
                )
                exit_code = cli._merge_exit_codes(exit_code, EXIT_DATA_ERROR)
    finally:
        artifact_executor.shutdown(wait=True)
    return reports, failures, exit_code


def _load_manifest_for_cli(path: str) -> dict[str, Any]:
    try:
        return load_manifest(path)
    except OSError as exc:
        raise ValueError(f"unable to read trust manifest {path!r}: {exc}") from exc


def _write_manifest_for_cli(path: str, manifest: dict[str, Any]) -> None:
    try:
        write_manifest(path, manifest)
    except OSError as exc:
        raise ValueError(f"unable to write trust manifest {path!r}: {exc}") from exc


def _render_write_result(
    args: argparse.Namespace,
    *,
    manifest_path: str,
    package_count: int,
) -> str:
    if args.format == "json":
        return json.dumps(
            {
                "action": args.manifest_action,
                "manifest": str(Path(manifest_path)),
                "packages": package_count,
            },
            indent=2,
            sort_keys=True,
        )
    return (
        f"trust manifest {args.manifest_action}: wrote {manifest_path}\n"
        f"packages: {package_count}"
    )


def _render_failures(
    args: argparse.Namespace,
    failures: list[dict[str, str]],
) -> str:
    if args.format == "json":
        return json.dumps(
            {
                "action": args.manifest_action,
                "passed": False,
                "failures": failures,
            },
            indent=2,
            sort_keys=True,
        )
    lines = ["trust manifest evidence collection failed:"]
    lines.extend(
        f"  - {failure['requirement']}: {failure['message']}"
        for failure in failures
    )
    return "\n".join(lines)
