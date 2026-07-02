from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from ..cli_models import EXIT_OK, ScanTarget
from ..diff import (
    TrustDiffReport,
    build_dependency_diff,
    changed_package_names,
    enrich_dependency_diff,
    merge_manifest_exception_changes,
    old_changed_package_names,
    render_trust_diff_markdown,
    render_trust_diff_sarif,
    render_trust_diff_text,
    should_fail_diff,
)
from ..lockfiles import is_supported_lockfile
from ..manifest import load_manifest
from ..models import TrustReport
from ..pypi import PypiClient, PypiClientError
from .context import CommandContext

GIT_EXECUTABLE = shutil.which("git") or "git"
GH_EXECUTABLE = shutil.which("gh") or "gh"


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    has_positional = args.old_file is not None or args.new_file is not None
    if has_positional and (args.old_file is None or args.new_file is None):
        parser.error("diff requires both OLD_FILE and NEW_FILE")
    if has_positional and (args.base or args.head or args.github_pr):
        parser.error("OLD_FILE/NEW_FILE cannot be combined with --base/--head")
    if not has_positional and (not args.base or not args.head):
        parser.error("diff requires OLD_FILE NEW_FILE or --base and --head")
    if args.github_pr and (not args.base or not args.head):
        parser.error("--github-pr requires --base and --head")
    if args.comment and not args.github_pr:
        parser.error("--comment requires --github-pr")


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

    with tempfile.TemporaryDirectory(prefix="trustcheck-diff-") as tempdir:
        pairs = _diff_file_pairs(args, Path(tempdir))
        all_changes = []
        old_targets: list[ScanTarget] = []
        new_targets: list[ScanTarget] = []
        failures: list[dict[str, str]] = []
        for old_path, new_path, old_label, new_label in pairs:
            loaded_old = cli._load_scan_targets(
                str(old_path),
                client,
                resolver=resolver,
                constraints=args.constraint,
                extras=args.extra,
                groups=args.group,
                target_environment=cli._target_environment_from_args(args),
                offline=client.offline,
            )
            loaded_new = cli._load_scan_targets(
                str(new_path),
                client,
                resolver=resolver,
                constraints=args.constraint,
                extras=args.extra,
                groups=args.group,
                target_environment=cli._target_environment_from_args(args),
                offline=client.offline,
            )
            _rewrite_source_labels(loaded_old, old_label)
            _rewrite_source_labels(loaded_new, new_label)
            old_targets.extend(loaded_old)
            new_targets.extend(loaded_new)
            all_changes.extend(build_dependency_diff(loaded_old, loaded_new))
            failures.extend(_target_failures(loaded_old, loaded_new))

        manifest = _load_manifest_for_diff(args, Path(tempdir)) if args.manifest else None
        if manifest is not None and args.base and args.head:
            all_changes = merge_manifest_exception_changes(
                all_changes,
                old_manifest=_load_base_manifest_for_diff(args, Path(tempdir)),
                new_manifest=manifest,
                source=args.manifest,
            )
        old_names = old_changed_package_names(all_changes)
        new_names = changed_package_names(all_changes)
        old_reports, old_failures = _inspect_targets(
            args,
            cli=cli,
            targets=old_targets,
            selected_names=old_names,
            client=client,
            resolver=resolver,
            plugin_manager=plugin_manager,
            vulnerability_client=vulnerability_client,
        )
        new_reports, new_failures = _inspect_targets(
            args,
            cli=cli,
            targets=new_targets,
            selected_names=new_names,
            client=client,
            resolver=resolver,
            plugin_manager=plugin_manager,
            vulnerability_client=vulnerability_client,
        )
        failures.extend(old_failures)
        failures.extend(new_failures)
        if vulnerability_client is not None:
            vulnerability_client.flush_snapshots()
        changes = enrich_dependency_diff(
            all_changes,
            old_reports=old_reports,
            new_reports=new_reports,
            manifest=manifest,
            new_targets=new_targets,
        )
        report = TrustDiffReport(
            old_source=", ".join(pair[2] for pair in pairs),
            new_source=", ".join(pair[3] for pair in pairs),
            changes=changes,
            failures=failures,
        )
        rendered = _render_report(args.format, report)
        if args.comment:
            _post_github_comment(render_trust_diff_markdown(report))
        cli._emit_output(rendered, args.output_file)
        return (
            cli.EXIT_POLICY_FAILURE
            if should_fail_diff(report, fail_on=args.fail_on)
            else EXIT_OK
        )


def _diff_file_pairs(
    args: argparse.Namespace,
    tempdir: Path,
) -> list[tuple[Path, Path, str, str]]:
    if args.old_file and args.new_file:
        return [
            (
                Path(args.old_file),
                Path(args.new_file),
                args.old_file,
                args.new_file,
            )
        ]
    paths = _changed_dependency_paths(
        args.base,
        args.head,
        restricted_paths=args.dependency_file,
    )
    pairs: list[tuple[Path, Path, str, str]] = []
    for index, path in enumerate(paths, 1):
        old_path = tempdir / f"base-{index}-{Path(path).name}"
        new_path = tempdir / f"head-{index}-{Path(path).name}"
        old_payload = _git_show(args.base, path)
        new_payload = _git_show(args.head, path)
        old_path.write_bytes(old_payload)
        new_path.write_bytes(new_payload)
        pairs.append(
            (
                old_path,
                new_path,
                f"{args.base}:{path}",
                f"{args.head}:{path}",
            )
        )
    if not pairs:
        raise ValueError("no changed dependency files found between base and head")
    return pairs


def _changed_dependency_paths(
    base: str,
    head: str,
    *,
    restricted_paths: Sequence[str],
) -> list[str]:
    if restricted_paths:
        return list(dict.fromkeys(restricted_paths))
    completed = subprocess.run(  # nosec B603
        [GIT_EXECUTABLE, "diff", "--name-only", "--diff-filter=ACMR", base, head],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "git diff failed")
    return [
        path
        for path in completed.stdout.splitlines()
        if _is_dependency_file(path)
    ]


def _git_show(ref: str, path: str) -> bytes:
    completed = subprocess.run(  # nosec B603
        [GIT_EXECUTABLE, "show", f"{ref}:{path}"],
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise ValueError(
            completed.stderr.decode("utf-8", errors="replace").strip()
            or f"unable to read {path!r} from {ref!r}"
        )
    return completed.stdout


def _load_manifest_for_diff(
    args: argparse.Namespace,
    tempdir: Path,
) -> dict[str, Any]:
    if not args.base or not args.head:
        return load_manifest(args.manifest)
    try:
        payload = _git_show(args.head, args.manifest)
    except ValueError:
        return load_manifest(args.manifest)
    path = tempdir / "head-trustcheck-manifest.json"
    path.write_bytes(payload)
    return load_manifest(path)


def _load_base_manifest_for_diff(
    args: argparse.Namespace,
    tempdir: Path,
) -> dict[str, Any] | None:
    try:
        payload = _git_show(args.base, args.manifest)
    except ValueError:
        return None
    path = tempdir / "base-trustcheck-manifest.json"
    path.write_bytes(payload)
    return load_manifest(path)


def _is_dependency_file(path: str) -> bool:
    candidate = Path(path)
    name = candidate.name.lower()
    if is_supported_lockfile(Path(path)):
        return True
    return (
        candidate.suffix.lower() == ".lock"
        or name.endswith(".txt")
        or name in {"pyproject.toml", "requirements.txt"}
    )


def _rewrite_source_labels(targets: Sequence[ScanTarget], label: str) -> None:
    for target in targets:
        target.source_file = label


def _target_failures(
    old_targets: Sequence[ScanTarget],
    new_targets: Sequence[ScanTarget],
) -> list[dict[str, str]]:
    return [
        {
            "requirement": target.requirement,
            "message": target.failure_message,
        }
        for target in (*old_targets, *new_targets)
        if target.failure_message is not None
    ]


def _inspect_targets(
    args: argparse.Namespace,
    *,
    cli: Any,
    targets: Sequence[ScanTarget],
    selected_names: set[str],
    client: PypiClient,
    resolver: Any,
    plugin_manager: Any,
    vulnerability_client: Any,
) -> tuple[dict[str, TrustReport], list[dict[str, str]]]:
    reports: dict[str, TrustReport] = {}
    failures: list[dict[str, str]] = []
    for target in targets:
        name = canonicalize_name(target.project)
        if name not in selected_names or target.failure_message is not None:
            continue
        try:
            target_client = cli._client_for_target(
                cli._clone_pypi_client(client),
                target,
                keyring_provider=args.keyring_provider,
                plugin_manager=plugin_manager,
            )
            reports[name] = cli.inspect_package(
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
                artifact_scope=args.diff_artifact_scope,
                max_workers=args.max_workers,
            )
        except PypiClientError as exc:
            failures.append(
                {
                    "requirement": target.requirement,
                    "message": cli._format_upstream_error(exc),
                }
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
    return reports, failures


def _render_report(output_format: str, report: TrustDiffReport) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if output_format == "markdown":
        return render_trust_diff_markdown(report)
    if output_format == "sarif":
        return render_trust_diff_sarif(report)
    return render_trust_diff_text(report)


def _post_github_comment(markdown: str) -> None:
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        suffix=".md",
    ) as body_file:
        body_file.write(markdown)
        body_path = body_file.name
    try:
        completed = subprocess.run(  # nosec B603
            [GH_EXECUTABLE, "pr", "comment", "--body-file", body_path],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        if completed.returncode != 0:
            raise ValueError(completed.stderr.strip() or "gh pr comment failed")
    finally:
        try:
            os.unlink(body_path)
        except OSError:
            pass
