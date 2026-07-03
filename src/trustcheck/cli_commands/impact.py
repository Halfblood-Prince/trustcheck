from __future__ import annotations

import argparse
import json
from typing import Any

from ..cli_models import EXIT_DATA_ERROR, EXIT_OK, EXIT_UPSTREAM_FAILURE, ScanTarget
from ..impact import (
    analyze_source,
    build_impact_report,
    render_impact_json,
    render_impact_text,
)
from ..models import TrustReport
from ..pypi import PypiClient, PypiClientError
from .context import CommandContext


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.filename:
        parser.error("impact requires -f/--file")
    if not args.source:
        parser.error("impact requires at least one --source path")


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
    import_graph = analyze_source(args.source)
    reports, failures, exit_code = _inspect_impact_targets(
        args,
        cli=cli,
        targets=targets,
        client=client,
        resolver=resolver,
        vulnerability_client=vulnerability_client,
        plugin_manager=plugin_manager,
    )
    if vulnerability_client is not None:
        vulnerability_client.flush_snapshots()
    report = build_impact_report(
        dependency_file=args.filename,
        source_roots=args.source,
        targets=targets,
        reports=reports,
        import_graph=import_graph,
        failures=failures,
    )
    rendered = (
        render_impact_json(report)
        if args.format == "json"
        else render_impact_text(report)
    )
    cli._emit_output(rendered, args.output_file)
    return int(exit_code)


def _inspect_impact_targets(
    args: argparse.Namespace,
    *,
    cli: Any,
    targets: list[ScanTarget],
    client: PypiClient,
    resolver: Any,
    vulnerability_client: Any,
    plugin_manager: Any,
) -> tuple[dict[str, TrustReport], list[dict[str, str]], int]:
    reports: dict[str, TrustReport] = {}
    failures: list[dict[str, str]] = []
    exit_code = EXIT_OK
    if vulnerability_client is not None:
        vulnerability_client.prefetch(
            [
                (target.project, target.version)
                for target in targets
                if target.failure_message is None and target.version is not None
            ]
        )
    for target in targets:
        if target.failure_message is not None:
            failures.append(
                {
                    "requirement": target.requirement,
                    "message": target.failure_message,
                }
            )
            exit_code = cli._merge_exit_codes(exit_code, target.failure_exit_code)
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
                vulnerability_only=True,
                inspect_artifacts=False,
                dynamic_analysis=False,
                vulnerability_client=vulnerability_client,
                locked_versions=target.locked_versions,
                complete_locked_versions=target.complete_locked_versions,
                expected_artifacts=target.artifacts,
                dependency_confusion_indexes=target.dependency_confusion,
                trusted_projects=getattr(args, "trusted_project", ()),
                resolver=resolver,
                target_environment=cli._target_environment_from_args(args),
                plugin_manager=plugin_manager,
                scan_profile="fast",
                artifact_scope="target",
                max_workers=args.max_workers,
            )
            reports[cli.canonicalize_name(target.project)] = report
        except PypiClientError as exc:
            failures.append(
                {
                    "requirement": target.requirement,
                    "message": cli._format_upstream_error(exc),
                }
            )
            exit_code = cli._merge_exit_codes(exit_code, EXIT_UPSTREAM_FAILURE)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            failures.append(
                {
                    "requirement": target.requirement,
                    "message": (
                        "error: received an invalid response while inspecting "
                        f"the package: {exc}"
                    ),
                }
            )
            exit_code = cli._merge_exit_codes(exit_code, EXIT_DATA_ERROR)
    return reports, failures, exit_code
