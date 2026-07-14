from __future__ import annotations

from collections.abc import Mapping, Sequence

from .export_models import ExportPackage


def render_cyclonedx_json_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
    *,
    spec_version: str = "1.6",
) -> str:
    from .exports import _cyclonedx_document, _json_text

    return _json_text(
        _cyclonedx_document(
            packages,
            source_name,
            failures,
            timestamp,
            spec_version=spec_version,
        )
    )


def render_cyclonedx_xml_export(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
    *,
    spec_version: str = "1.6",
) -> str:
    from .exports import _cyclonedx_xml

    return _cyclonedx_xml(
        packages,
        source_name,
        failures,
        timestamp,
        spec_version=spec_version,
    )
