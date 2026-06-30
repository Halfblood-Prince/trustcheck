from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .context import CommandContext


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
            "require_verified_provenance": args.require_verified_provenance,
            "allow_metadata_only": args.allow_metadata_only,
            "allowed_publisher_organizations": (
                args.trusted_publisher_organization or None
            ),
            "vulnerability_mode": args.fail_on_vulnerability,
            "fail_on_severity": args.fail_on_risk_severity,
        },
    )
    resolution = cli.discover_installed_distributions(args.path)
    if cli._uses_nondefault_indexes(args):
        resolution = cli._resolver_from_args(
            args,
            plugin_manager=plugin_manager,
        ).annotate_indexes(resolution)
    targets = cli._scan_targets_from_resolution(resolution)
    source_label = (
        ", ".join(str(Path(path).resolve()) for path in args.path)
        if args.path
        else "active Python environment"
    )
    return int(cli._run_scan_targets(
        source_label,
        targets,
        args=args,
        client=client,
        vulnerability_client=vulnerability_client,
        policy=policy,
        include_vulnerabilities=True,
        vulnerability_only=False,
        progress_callback=progress_callback,
        dependency_progress_callback=dependency_progress_callback,
        resolver=None,
        plugin_manager=plugin_manager,
    ))
