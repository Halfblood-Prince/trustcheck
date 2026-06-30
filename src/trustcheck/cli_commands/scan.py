from __future__ import annotations

import argparse
import json
from typing import Any

from .context import CommandContext


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.dry_run and not args.fix:
        parser.error("--dry-run requires --fix")
    if args.create_pr and not args.fix:
        parser.error("--create-pr requires --fix")
    if args.create_pr and args.dry_run:
        parser.error("--create-pr cannot be combined with --dry-run")
    if args.max_fix_attempts < 1:
        parser.error("--max-fix-attempts must be at least 1")
    if args.no_deps and not args.filename:
        parser.error("--no-deps requires -f/--file")
    if args.no_deps and (args.plan_fixes or args.fix):
        parser.error("--no-deps cannot be combined with remediation")
    if args.no_deps and args.constraint:
        parser.error("--no-deps cannot be combined with --constraint")


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    parser = context.parser
    config_payload = context.config_payload
    plugin_manager = context.plugin_manager

    if args.filename and args.project:
        parser.error("scan accepts either PROJECT or -f/--file, not both")
    if not args.filename and not args.project:
        parser.error("scan requires PROJECT or -f/--file")
    if not args.filename and (args.plan_fixes or args.fix):
        parser.error("remediation requires -f/--file")
    args.max_workers = cli._resolve_max_workers(args, config_payload)
    progress_callback = None
    dependency_progress_callback = None
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
            "require_verified_provenance": "none",
            "allow_metadata_only": True,
            "allowed_publisher_organizations": [],
            "vulnerability_mode": args.fail_on_vulnerability,
            "fail_on_severity": "none",
        },
    )
    resolver = cli._resolver_from_args(args, plugin_manager=plugin_manager)
    if not args.filename:
        report = cli._scan_project_vulnerabilities(
            args.project,
            version=args.version,
            args=args,
            client=client,
            vulnerability_client=vulnerability_client,
            policy=policy,
            resolver=resolver,
            plugin_manager=plugin_manager,
        )
        evaluation = cli.evaluate_policy(
            report,
            policy,
            plugin_manager=plugin_manager,
        )
        vulnerability_only = args.scan_profile == "fast" and not args.dynamic_analysis
        if args.format == "json" and vulnerability_only:
            rendered = json.dumps(
                cli._render_cve_json(report),
                indent=2,
                sort_keys=True,
            )
        elif args.format == "json":
            rendered = json.dumps(
                report.to_dict(),
                indent=2,
                sort_keys=True,
            )
        elif args.format == "text" and vulnerability_only:
            rendered = cli._render_cve_report(report)
        elif args.format == "text":
            rendered = cli._render_text_report(report, verbose=True)
        else:
            rendered = cli.render_export(
                args.format,
                [
                    cli.ExportPackage(
                        report=report,
                        source=cli.SourceLocation(report.package_url),
                        artifacts=(),
                    )
                ],
                source_name=f"{report.project} {report.version}",
                plugin_manager=plugin_manager,
            )
        if vulnerability_client is not None:
            vulnerability_client.flush_snapshots()
        cli._emit_output(rendered, args.output_file)
        return int(cli.EXIT_OK if evaluation.passed else cli.EXIT_POLICY_FAILURE)

    targets = cli._load_scan_targets(
        args.filename,
        client,
        resolver=None if args.no_deps else resolver,
        constraints=args.constraint,
        extras=args.extra,
        groups=args.group,
        target_environment=cli._target_environment_from_args(args),
        offline=client.offline,
    )
    return int(cli._run_scan_targets(
        args.filename,
        targets,
        args=args,
        client=client,
        vulnerability_client=vulnerability_client,
        policy=policy,
        include_vulnerabilities=True,
        vulnerability_only=(args.scan_profile == "fast" and not args.dynamic_analysis),
        progress_callback=progress_callback,
        dependency_progress_callback=dependency_progress_callback,
        resolver=resolver,
        plugin_manager=plugin_manager,
    ))
