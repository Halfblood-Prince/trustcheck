from __future__ import annotations

import argparse
from typing import Any

from trustcheck.doctor import (
    collect_doctor_report,
    render_doctor_json,
    render_doctor_text,
)

from .context import CommandContext


def run(args: argparse.Namespace, context: CommandContext) -> int:
    cli: Any = context.facade
    report = collect_doctor_report(
        cache_dir=args.cache_dir,
        index_urls=(args.index_url, *args.extra_index_url),
        keyring_provider=args.keyring_provider,
        sandbox_mode=args.sandbox,
    )
    rendered = (
        render_doctor_json(report)
        if args.format == "json"
        else render_doctor_text(report)
    )
    cli._emit_output(rendered, args.output_file)
    if args.strict and not report.passed:
        return int(cli.EXIT_POLICY_FAILURE)
    return int(cli.EXIT_OK)
