from __future__ import annotations

from collections.abc import Mapping, Sequence

from .export_models import ExportPackage


def render_markdown_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
) -> str:
    from .exports import _markdown_document

    return _markdown_document(packages, source_name, failures)
