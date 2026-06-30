from __future__ import annotations

import argparse
import json
from typing import Any

from .context import CommandContext


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    parser = context.parser
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
    if args.filename and args.project:
        parser.error("inspect accepts either PROJECT or -f/--file, not both")
    if not args.filename and not args.project:
        parser.error("inspect requires PROJECT or -f/--file")
    if args.filename and (args.version or args.expected_repo):
        parser.error("--version and --expected-repo apply to package inspection")
    resolver = cli._resolver_from_args(args, plugin_manager=plugin_manager)
    policy_name = "strict" if args.strict else args.policy
    policy = cli.resolve_policy(
        builtin_name=policy_name,
        config_path=args.policy_file,
        cli_overrides={
            "require_verified_provenance": args.require_verified_provenance,
            "allow_metadata_only": args.allow_metadata_only,
            "require_expected_repository_match": args.require_expected_repo_match,
            "allowed_publisher_organizations": (
                args.trusted_publisher_organization or None
            ),
            "fail_on_severity": args.fail_on_risk_severity,
        },
    )
    if args.filename:
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
        return int(cli._run_scan_targets(
            args.filename,
            targets,
            args=args,
            client=client,
            vulnerability_client=None,
            policy=policy,
            include_vulnerabilities=False,
            vulnerability_only=False,
            progress_callback=progress_callback,
            dependency_progress_callback=dependency_progress_callback,
            resolver=resolver,
            plugin_manager=plugin_manager,
        ))

    inspection_client = client
    expected_artifacts = ()
    dependency_confusion_indexes = ()
    selected_version = args.version
    if cli._uses_nondefault_indexes(args):
        root_requirement = (
            f"{args.project}=={args.version}" if args.version else args.project
        )
        resolution = resolver.resolve_requirements(
            [root_requirement],
            target=cli._target_environment_from_args(args),
            offline=client.offline,
        )
        root = next(
            (
                item
                for item in resolution.distributions
                if cli.canonicalize_name(item.name)
                == cli.canonicalize_name(args.project)
            ),
            None,
        )
        if root is None:
            raise cli.ResolutionError(
                f"resolver did not return root package {args.project!r}"
            )
        selected_version = root.version
        expected_artifacts = root.artifacts
        dependency_confusion_indexes = next(
            (
                finding.indexes
                for finding in resolution.dependency_confusion
                if cli.canonicalize_name(finding.project)
                == cli.canonicalize_name(args.project)
            ),
            (),
        )
        inspection_client = cli._client_for_target(
            client,
            cli.ScanTarget(
                requirement=f"{root.name}=={root.version}",
                project=root.name,
                version=root.version,
                artifacts=root.artifacts,
                index_url=root.index_url,
                requires_dist=root.requires_dist,
            ),
            keyring_provider=args.keyring_provider,
            plugin_manager=plugin_manager,
        )
    report = cli.inspect_package(
        args.project,
        version=selected_version,
        expected_repository=args.expected_repo,
        client=inspection_client,
        progress_callback=progress_callback,
        dependency_progress_callback=dependency_progress_callback,
        include_dependencies=args.with_deps,
        include_transitive_dependencies=args.with_transitive_deps,
        include_vulnerabilities=False,
        include_osv=False,
        inspect_artifacts=args.inspect_artifacts,
        dynamic_analysis=args.dynamic_analysis,
        vulnerability_client=None,
        resolver=resolver,
        target_environment=cli._target_environment_from_args(args),
        expected_artifacts=expected_artifacts,
        dependency_confusion_indexes=dependency_confusion_indexes,
        trusted_projects=args.trusted_project,
        plugin_manager=plugin_manager,
        max_workers=args.max_workers,
    )
    evaluation = cli.evaluate_policy(
        report,
        policy,
        plugin_manager=plugin_manager,
    )
    if args.format == "json":
        rendered = json.dumps(
            report.to_dict(),
            indent=2,
            sort_keys=True,
        )
    elif args.format == "text":
        rendered = cli._render_text_report(
            report,
            verbose=args.verbose,
        )
    else:
        rendered = cli.render_export(
            args.format,
            [
                cli.ExportPackage(
                    report=report,
                    source=cli.SourceLocation(report.package_url),
                    artifacts=expected_artifacts,
                )
            ],
            source_name=f"{report.project} {report.version}",
            plugin_manager=plugin_manager,
        )
    cli._emit_output(rendered, args.output_file)
    if not evaluation.passed:
        return int(cli.EXIT_POLICY_FAILURE)
    return int(cli.EXIT_OK)
