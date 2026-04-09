from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
class PolicyViolation:
    code: str
    severity: str
    message: str


@dataclass(slots=True)
class PolicyEvaluation:
    profile: str = "default"
    passed: bool = True
    enforced: bool = False
    fail_on_severity: str = "none"
    require_verified_provenance: str = "none"
    require_expected_repository_match: bool = False
    allow_metadata_only: bool = True
    vulnerability_mode: str = "ignore"
    violations: list[PolicyViolation] = field(default_factory=list)


@dataclass(slots=True)
class RequestFailureDiagnostic:
    url: str
    attempt: int
    code: str
    subcode: str
    message: str
    transient: bool
    status_code: int | None = None


@dataclass(slots=True)
class ArtifactDiagnostic:
    filename: str
    stage: str
    code: str
    subcode: str
    message: str


@dataclass(slots=True)
class ReportDiagnostics:
    timeout: float = 10.0
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    cache_dir: str | None = None
    request_count: int = 0
    retry_count: int = 0
    cache_hit_count: int = 0
    request_failures: list[RequestFailureDiagnostic] = field(default_factory=list)
    artifact_failures: list[ArtifactDiagnostic] = field(default_factory=list)


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
    policy: PolicyEvaluation = field(default_factory=PolicyEvaluation)
    diagnostics: ReportDiagnostics = field(default_factory=ReportDiagnostics)

    def to_dict(self) -> dict[str, Any]:
        from .contract import serialize_report

        return serialize_report(self)
