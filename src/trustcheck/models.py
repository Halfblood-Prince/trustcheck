from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

JSON_SCHEMA_VERSION = "1"


@dataclass(slots=True)
class RiskFlag:
    code: str
    severity: str
    message: str
    why: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


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
class CoverageSummary:
    total_files: int = 0
    files_with_provenance: int = 0
    verified_files: int = 0
    status: str = "none"


@dataclass(slots=True)
class PublisherTrustSummary:
    depth_score: int = 0
    depth_label: str = "none"
    verified_publishers: list[str] = field(default_factory=list)
    unique_verified_repositories: list[str] = field(default_factory=list)
    unique_verified_workflows: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProvenanceConsistency:
    has_sdist: bool = False
    has_wheel: bool = False
    sdist_wheel_consistent: bool | None = None
    consistent_repositories: list[str] = field(default_factory=list)
    consistent_workflows: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReleaseDriftSummary:
    compared_to_version: str | None = None
    publisher_repository_drift: bool | None = None
    publisher_workflow_drift: bool | None = None
    previous_repositories: list[str] = field(default_factory=list)
    previous_workflows: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TrustReport:
    project: str
    version: str
    summary: str | None
    package_url: str
    declared_repository_urls: list[str] = field(default_factory=list)
    repository_urls: list[str] = field(default_factory=list)
    expected_repository: str | None = None
    ownership: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    files: list[FileProvenance] = field(default_factory=list)
    coverage: CoverageSummary = field(default_factory=CoverageSummary)
    publisher_trust: PublisherTrustSummary = field(default_factory=PublisherTrustSummary)
    provenance_consistency: ProvenanceConsistency = field(default_factory=ProvenanceConsistency)
    release_drift: ReleaseDriftSummary = field(default_factory=ReleaseDriftSummary)
    risk_flags: list[RiskFlag] = field(default_factory=list)
    recommendation: str = "metadata-only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": JSON_SCHEMA_VERSION,
            "report": asdict(self),
        }
