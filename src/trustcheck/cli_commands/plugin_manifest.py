from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..cli_models import EXIT_OK
from ..plugin_manifest import (
    PluginManifestSummary,
    build_plugin_manifest_draft,
    fingerprint_public_key_file,
    sign_plugin_wheel,
    verify_plugin_manifest,
)
from .context import CommandContext


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.plugin_manifest_action == "sign" and args.output is not None:
        output = Path(args.output)
        if output.exists() and output.is_dir():
            parser.error("--output must be a wheel path, not a directory")


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    if args.plugin_manifest_action == "fingerprint":
        rendered = _render_fingerprint(args, fingerprint_public_key_file(args.public_key))
    elif args.plugin_manifest_action == "init":
        draft = build_plugin_manifest_draft(
            args.distribution,
            configuration_schema=args.configuration_schema,
        )
        rendered = json.dumps(draft, indent=2, sort_keys=True)
    elif args.plugin_manifest_action == "sign":
        summary = sign_plugin_wheel(
            args.distribution,
            key=args.key,
            output=args.output,
            configuration_schema=args.configuration_schema,
        )
        rendered = _render_summary(args, "signed", summary)
    elif args.plugin_manifest_action == "verify":
        summary = verify_plugin_manifest(args.distribution)
        rendered = _render_summary(args, "verified", summary)
    else:
        context.parser.error("unknown plugin-manifest action")
        return int(EXIT_OK)
    cli._emit_output(rendered, args.output_file)
    return int(EXIT_OK)


def _render_fingerprint(args: argparse.Namespace, fingerprint: str) -> str:
    if args.format == "json":
        return json.dumps({"fingerprint_sha256": fingerprint}, indent=2, sort_keys=True)
    return fingerprint


def _render_summary(
    args: argparse.Namespace,
    action: str,
    summary: PluginManifestSummary,
) -> str:
    payload = {
        "action": action,
        "path": str(summary.path),
        "plugin": f"{summary.kind}:{summary.name}",
        "entry_point": summary.entry_point,
        "distribution": summary.distribution,
        "distribution_version": summary.distribution_version,
        "signer_sha256": summary.signer_sha256,
        "wheel_sha256": summary.wheel_sha256,
        "record_sha256": summary.record_sha256,
    }
    if args.format == "json":
        return json.dumps(payload, indent=2, sort_keys=True)
    lines = [
        f"plugin manifest {action}: {summary.path}",
        f"plugin: {summary.kind}:{summary.name}",
        f"entry point: {summary.entry_point}",
        f"distribution: {summary.distribution} {summary.distribution_version}",
        f"wheel_sha256: {summary.wheel_sha256}",
        f"record_sha256: {summary.record_sha256}",
    ]
    if summary.signer_sha256 is not None:
        lines.append(f"signer_sha256: {summary.signer_sha256}")
    return "\n".join(lines)
