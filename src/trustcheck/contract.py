from __future__ import annotations

from dataclasses import asdict
from typing import Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from .models import TrustReport

JSON_SCHEMA_VERSION: Final = "1.2.0"
JSON_SCHEMA_ID = f"urn:trustcheck:report:{JSON_SCHEMA_VERSION}"
SchemaVersion: TypeAlias = Literal["1.2.0"]
DEFAULT_SCHEMA_VERSION: Final[SchemaVersion] = "1.2.0"


class RiskFlagPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: str
    message: str
    why: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class VulnerabilityRecordPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)
    source: str | None = None
    fixed_in: list[str] = Field(default_factory=list)
    link: str | None = None


class PublisherIdentityPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    repository: str | None = None
    workflow: str | None = None
    environment: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class FileProvenancePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    url: str
    sha256: str | None = None
    has_provenance: bool
    verified: bool = False
    attestation_count: int = 0
    verified_attestation_count: int = 0
    observed_sha256: str | None = None
    publisher_identities: list[PublisherIdentityPayload] = Field(default_factory=list)
    error: str | None = None


class CoverageSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_files: int = 0
    files_with_provenance: int = 0
    verified_files: int = 0
    status: str = "none"


class PublisherTrustSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depth_score: int = 0
    depth_label: str = "none"
    verified_publishers: list[str] = Field(default_factory=list)
    unique_verified_repositories: list[str] = Field(default_factory=list)
    unique_verified_workflows: list[str] = Field(default_factory=list)


class ProvenanceConsistencyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    has_sdist: bool = False
    has_wheel: bool = False
    sdist_wheel_consistent: bool | None = None
    consistent_repositories: list[str] = Field(default_factory=list)
    consistent_workflows: list[str] = Field(default_factory=list)


class ReleaseDriftSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compared_to_version: str | None = None
    publisher_repository_drift: bool | None = None
    publisher_workflow_drift: bool | None = None
    previous_repositories: list[str] = Field(default_factory=list)
    previous_workflows: list[str] = Field(default_factory=list)


class PolicyViolationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: str
    message: str


class PolicyEvaluationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str = "default"
    passed: bool = True
    enforced: bool = False
    fail_on_severity: str = "none"
    require_verified_provenance: str = "none"
    require_expected_repository_match: bool = False
    allow_metadata_only: bool = True
    vulnerability_mode: str = "ignore"
    violations: list[PolicyViolationPayload] = Field(default_factory=list)


class RequestFailureDiagnosticPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    attempt: int
    code: str
    subcode: str
    message: str
    transient: bool
    status_code: int | None = None


class ArtifactDiagnosticPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    stage: str
    code: str
    subcode: str
    message: str


class ReportDiagnosticsPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeout: float = 10.0
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    cache_dir: str | None = None
    request_count: int = 0
    retry_count: int = 0
    cache_hit_count: int = 0
    request_failures: list[RequestFailureDiagnosticPayload] = Field(default_factory=list)
    artifact_failures: list[ArtifactDiagnosticPayload] = Field(default_factory=list)


class OwnershipRolePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str | None = None
    user: str | None = None


class OwnershipPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    organization: str | None = None
    roles: list[OwnershipRolePayload] = Field(default_factory=list)


class TrustReportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str
    version: str
    summary: str | None = None
    package_url: str
    declared_repository_urls: list[str] = Field(default_factory=list)
    repository_urls: list[str] = Field(default_factory=list)
    expected_repository: str | None = None
    ownership: OwnershipPayload = Field(default_factory=OwnershipPayload)
    vulnerabilities: list[VulnerabilityRecordPayload] = Field(default_factory=list)
    files: list[FileProvenancePayload] = Field(default_factory=list)
    coverage: CoverageSummaryPayload = Field(default_factory=CoverageSummaryPayload)
    publisher_trust: PublisherTrustSummaryPayload = Field(
        default_factory=PublisherTrustSummaryPayload
    )
    provenance_consistency: ProvenanceConsistencyPayload = Field(
        default_factory=ProvenanceConsistencyPayload
    )
    release_drift: ReleaseDriftSummaryPayload = Field(default_factory=ReleaseDriftSummaryPayload)
    risk_flags: list[RiskFlagPayload] = Field(default_factory=list)
    recommendation: str = "metadata-only"
    policy: PolicyEvaluationPayload = Field(default_factory=PolicyEvaluationPayload)
    diagnostics: ReportDiagnosticsPayload = Field(default_factory=ReportDiagnosticsPayload)


class TrustReportEnvelopePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: SchemaVersion = DEFAULT_SCHEMA_VERSION
    report: TrustReportPayload


def serialize_report(report: TrustReport) -> dict[str, Any]:
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "report": asdict(report),
    }
    return TrustReportEnvelopePayload.model_validate(payload).model_dump(mode="json")


def get_json_schema() -> dict[str, Any]:
    schema = TrustReportEnvelopePayload.model_json_schema()
    schema["$id"] = JSON_SCHEMA_ID
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "trustcheck report envelope"
    return schema
