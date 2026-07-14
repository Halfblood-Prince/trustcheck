from __future__ import annotations

from collections.abc import Sequence

from .export_models import ExportPackage


def render_openvex_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    timestamp: str,
) -> str:
    from .exports import _json_text, _openvex_document

    return _json_text(_openvex_document(packages, source_name, timestamp))
