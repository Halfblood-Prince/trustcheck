from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from urllib import parse

from packaging.utils import canonicalize_name

from .models import TrustReport
from .resolver import ArtifactReference

OUTPUT_FORMATS: Final = (
    "text",
    "json",
    "sarif",
    "cyclonedx-json",
    "cyclonedx-xml",
    "spdx-json",
    "openvex",
    "markdown",
)
INDUSTRY_OUTPUT_FORMATS: Final = OUTPUT_FORMATS[2:]
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)
CYCLONEDX_NAMESPACE = "http://cyclonedx.org/schema/bom/1.6"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    uri: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ExportPackage:
    report: TrustReport
    source: SourceLocation | None = None
    artifacts: tuple[ArtifactReference, ...] = ()

    @property
    def purl(self) -> str:
        return package_purl(self.report.project, self.report.version)


def package_purl(project: str, version: str) -> str:
    name = parse.quote(canonicalize_name(project), safe=".-_~")
    encoded_version = parse.quote(version, safe=".-_~+")
    return f"pkg:pypi/{name}@{encoded_version}"


def recommended_extension(output_format: str) -> str:
    extensions = {
        "text": ".txt",
        "json": ".json",
        "sarif": ".sarif",
        "cyclonedx-json": ".cdx.json",
        "cyclonedx-xml": ".cdx.xml",
        "spdx-json": ".spdx.json",
        "openvex": ".openvex.json",
        "markdown": ".md",
    }
    try:
        return extensions[output_format]
    except KeyError as exc:
        raise ValueError(f"unsupported output format: {output_format}") from exc
