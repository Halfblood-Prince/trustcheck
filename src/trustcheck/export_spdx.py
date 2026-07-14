from __future__ import annotations

from collections.abc import Mapping, Sequence

from .export_models import ExportPackage


def render_spdx_json_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
) -> str:
    from .exports import _json_text, _spdx_document

    return _json_text(_spdx_document(packages, source_name, failures, timestamp))


def render_spdx3_json_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
) -> str:
    from .exports import _json_text, _spdx3_document

    return _json_text(_spdx3_document(packages, source_name, failures, timestamp))
