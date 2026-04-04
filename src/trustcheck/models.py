from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RiskFlag:
    code: str
    severity: str
    message: str


@dataclass(slots=True)
class VulnerabilityRecord:
    id: str
    summary: str
    aliases: list[str] = field(default_factory=list)
    source: str | None = None
    fixed_in: list[str] = field(default_factory=list)
    link: str | None = None


@dataclass(slots=True)
class PublisherIdentity:
    kind: str
    repository: str | None
    workflow: str | None
    environment: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FileProvenance:
    filename: str
    url: str
    sha256: str | None
    has_provenance: bool
    verified: bool = False
    attestation_count: int = 0
    verified_attestation_count: int = 0
    observed_sha256: str | None = None
    publisher_identities: list[PublisherIdentity] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class TrustReport:
    project: str
    version: str
    summary: str | None
    package_url: str
    repository_urls: list[str] = field(default_factory=list)
    expected_repository: str | None = None
    ownership: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    files: list[FileProvenance] = field(default_factory=list)
    risk_flags: list[RiskFlag] = field(default_factory=list)
    recommendation: str = "review"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
