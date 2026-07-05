from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from typing import Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    ArtifactDiagnostic,
    ArtifactInspection,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    DynamicAnalysisResult,
    FileProvenance,
    HeuristicFinding,
    MaliciousPackageAssessment,
    NativeBinaryInspection,
    PolicyEvaluation,
    PolicyViolation,
    ProvenanceConsistency,
    ProvenanceIssue,
    ProvenanceMaterial,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    RemediationSummary,
    ReportDiagnostics,
    RequestFailureDiagnostic,
    RiskFlag,
    SlsaProvenance,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)

JSON_SCHEMA_VERSION: Final = "1.11.0"
JSON_SCHEMA_ID = f"urn:trustcheck:report:{JSON_SCHEMA_VERSION}"
SchemaVersion: TypeAlias = Literal["1.11.0"]
DEFAULT_SCHEMA_VERSION: Final[SchemaVersion] = "1.11.0"


class RiskFlagPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: str
    message: str
    why: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class VulnerabilitySuppressionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    owner: str
    justification: str
    expires: str
    status: str = "configured"


class VulnerabilityRecordPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)
    source: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwes: list[str] = Field(default_factory=list)
    fixed_in: list[str] = Field(default_factory=list)
    link: str | None = None
    withdrawn: bool = False
    withdrawn_at: str | None = None
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    kev_known_ransomware_campaign_use: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    suppression: VulnerabilitySuppressionPayload | None = None


class PublisherIdentityPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    repository: str | None = None
    workflow: str | None = None
    environment: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ProvenanceIssuePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: str
    message: str
    evidence: list[str] = Field(default_factory=list)


class ProvenanceMaterialPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uri: str
    digests: dict[str, str] = Field(default_factory=dict)
    name: str | None = None
    source: bool = False


class SlsaProvenancePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    predicate_type: str = "https://slsa.dev/provenance/v1"
    valid: bool = False
    signer_identity: str | None = None
    source_uri: str | None = None
    source_repository: str | None = None
    source_commit: str | None = None
    builder_id: str | None = None
    build_type: str | None = None
    workflow_uri: str | None = None
    workflow_path: str | None = None
    workflow_ref: str | None = None
    workflow_ref_immutable: bool | None = None
    invocation_id: str | None = None
    materials: list[ProvenanceMaterialPayload] = Field(default_factory=list)
    action_references: list[str] = Field(default_factory=list)
    unpinned_actions: list[str] = Field(default_factory=list)
    issues: list[ProvenanceIssuePayload] = Field(default_factory=list)


class HeuristicFindingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    category: str
    severity: str
    confidence: str = Field(
        description=(
            "Rule-author-assigned confidence label. This is not yet calibrated "
            "against a published malicious-package evaluation corpus."
        )
    )
    score: int
    message: str
    evidence: list[str] = Field(default_factory=list)
    location: str | None = None
    artifact: str | None = None
    heuristic: bool = True
    rule_version: str = "1.0"
    false_positive_rate: float | None = Field(
        default=None,
        description=(
            "Estimated false-positive prior from rule metadata. This field is "
            "not an empirically measured false-positive rate until a matching "
            "calibration corpus and benchmark metrics are published."
        ),
    )
    score_threshold: int = 1


class NativeBinaryInspectionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    format: str = "unknown"
    architecture: str | None = None
    imports: list[str] = Field(default_factory=list)
    signature_present: bool | None = None
    signature_status: str = "not-applicable"
    entropy: float | None = None
    embedded_payloads: list[str] = Field(default_factory=list)
    parse_error: str | None = None


class ArtifactInspectionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inspected: bool = False
    kind: str = "unknown"
    archive_valid: bool | None = None
    file_count: int = 0
    total_uncompressed_size: int = 0
    record_valid: bool | None = None
    record_errors: list[str] = Field(default_factory=list)
    console_scripts: list[str] = Field(default_factory=list)
    suspicious_entry_points: list[str] = Field(default_factory=list)
    native_files: list[str] = Field(default_factory=list)
    unexpected_top_level_files: list[str] = Field(default_factory=list)
    suspicious_files: list[str] = Field(default_factory=list)
    oversized_files: list[str] = Field(default_factory=list)
    unusual_files: list[str] = Field(default_factory=list)
    metadata_name: str | None = None
    metadata_version: str | None = None
    metadata_requires_dist: list[str] = Field(default_factory=list)
    wheel_version: str | None = None
    wheel_root_is_purelib: bool | None = None
    wheel_tags: list[str] = Field(default_factory=list)
    metadata_mismatches: list[str] = Field(default_factory=list)
    source_files_analyzed: int = 0
    source_parse_errors: list[str] = Field(default_factory=list)
    native_binaries: list[NativeBinaryInspectionPayload] = Field(default_factory=list)
    heuristic_findings: list[HeuristicFindingPayload] = Field(default_factory=list)
    error: str | None = None


class DynamicAnalysisResultPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    executed: bool = False
    sandbox: str = "docker"
    warning: str = (
        "Dynamic analysis executes untrusted package code in a disposable "
        "container; it is never enabled by default."
    )
    network: str = "none"
    user: str = "non-root"
    cpu_limit: str = "1 CPU, 10 CPU seconds"
    memory_limit: str = "512 MiB"
    timeout_seconds: float = 30.0
    image: str | None = None
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: list[str] = Field(default_factory=list)
    stderr: list[str] = Field(default_factory=list)
    error: str | None = None


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
    slsa_provenance: list[SlsaProvenancePayload] = Field(default_factory=list)
    error: str | None = None
    artifact: ArtifactInspectionPayload = Field(default_factory=ArtifactInspectionPayload)
    dynamic_analysis: DynamicAnalysisResultPayload = Field(
        default_factory=DynamicAnalysisResultPayload
    )


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
    builder_consistent: bool | None = None
    source_commit_consistent: bool | None = None
    build_type_consistent: bool | None = None
    consistent_builders: list[str] = Field(default_factory=list)
    consistent_source_commits: list[str] = Field(default_factory=list)
    consistent_build_types: list[str] = Field(default_factory=list)


class ReleaseDriftSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compared_to_version: str | None = None
    publisher_repository_drift: bool | None = None
    publisher_workflow_drift: bool | None = None
    signer_drift: bool | None = None
    builder_drift: bool | None = None
    source_commit_drift: bool | None = None
    build_type_drift: bool | None = None
    previous_signers: list[str] = Field(default_factory=list)
    previous_repositories: list[str] = Field(default_factory=list)
    previous_workflows: list[str] = Field(default_factory=list)
    previous_builders: list[str] = Field(default_factory=list)
    previous_source_commits: list[str] = Field(default_factory=list)
    previous_build_types: list[str] = Field(default_factory=list)


class MaliciousPackageAssessmentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = 0
    level: str = "none"
    artifact_analysis: bool = False
    trusted_name_count: int = 0
    findings: list[HeuristicFindingPayload] = Field(default_factory=list)
    score_thresholds: dict[str, int] = Field(
        default_factory=lambda: {
            "low": 1,
            "elevated": 25,
            "high": 50,
            "critical": 75,
        }
    )
    rule_thresholds: dict[str, int] = Field(default_factory=dict)
    disclaimer: str = (
        "These findings are heuristic indicators for review, not proof that "
        "the package is malicious."
    )


class DependencyInspectionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement: str
    project: str
    version: str
    depth: int
    parent_project: str | None = None
    parent_version: str | None = None
    package_url: str | None = None
    recommendation: str = "metadata-only"
    risk_flags: list[RiskFlagPayload] = Field(default_factory=list)
    declared_dependencies: list[str] = Field(default_factory=list)
    error: str | None = None


class DependencySummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested: bool = False
    total_declared: int = 0
    total_inspected: int = 0
    unique_dependencies: int = 0
    max_depth: int = 0
    highest_risk_recommendation: str = "metadata-only"
    highest_risk_projects: list[str] = Field(default_factory=list)
    high_risk_projects: list[str] = Field(default_factory=list)
    review_required_projects: list[str] = Field(default_factory=list)
    metadata_only_projects: list[str] = Field(default_factory=list)
    verified_projects: list[str] = Field(default_factory=list)


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
    allowed_publisher_organizations: list[str] = Field(default_factory=list)
    allow_metadata_only: bool = True
    vulnerability_mode: str = "ignore"
    malicious_package_thresholds: dict[str, int] = Field(
        default_factory=lambda: {
            "low": 1,
            "elevated": 25,
            "high": 50,
            "critical": 75,
        }
    )
    malicious_rule_thresholds: dict[str, int] = Field(default_factory=dict)
    suppressions_applied: int = 0
    suppressions_expired: int = 0
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
    plugin_executions: list[dict[str, Any]] = Field(default_factory=list)


class RemediationSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = "not-requested"
    minimal: bool = False
    attempts: int = 0
    upgrades_planned: int = 0
    blocked_fixes: int = 0
    patch_files: list[str] = Field(default_factory=list)
    pull_request_url: str | None = None
    confidence: str | None = None
    breaking_change_warnings: list[str] = Field(default_factory=list)
    minimal_secure_upgrade_proven: bool = False


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
    declared_dependencies: list[str] = Field(default_factory=list)
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
    malicious_package: MaliciousPackageAssessmentPayload = Field(
        default_factory=MaliciousPackageAssessmentPayload
    )
    dependencies: list[DependencyInspectionPayload] = Field(default_factory=list)
    dependency_summary: DependencySummaryPayload = Field(default_factory=DependencySummaryPayload)
    risk_flags: list[RiskFlagPayload] = Field(default_factory=list)
    recommendation: str = "metadata-only"
    policy: PolicyEvaluationPayload = Field(default_factory=PolicyEvaluationPayload)
    diagnostics: ReportDiagnosticsPayload = Field(default_factory=ReportDiagnosticsPayload)
    remediation: RemediationSummaryPayload = Field(default_factory=RemediationSummaryPayload)


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


def deserialize_report(payload: Mapping[str, object]) -> TrustReport:
    data = TrustReportPayload.model_validate(payload).model_dump(mode="python")
    vulnerabilities_data = data.pop("vulnerabilities")
    files = [
        FileProvenance(
            **{
                **item,
                "publisher_identities": [
                    PublisherIdentity(**identity)
                    for identity in item["publisher_identities"]
                ],
                "slsa_provenance": [
                    SlsaProvenance(
                        **{
                            **assessment,
                            "materials": [
                                ProvenanceMaterial(**material)
                                for material in assessment["materials"]
                            ],
                            "issues": [
                                ProvenanceIssue(**issue)
                                for issue in assessment["issues"]
                            ],
                        }
                    )
                    for assessment in item["slsa_provenance"]
                ],
                "artifact": ArtifactInspection(
                    **{
                        **item["artifact"],
                        "native_binaries": [
                            NativeBinaryInspection(**native)
                            for native in item["artifact"]["native_binaries"]
                        ],
                        "heuristic_findings": [
                            HeuristicFinding(**finding)
                            for finding in item["artifact"]["heuristic_findings"]
                        ],
                    }
                ),
                "dynamic_analysis": DynamicAnalysisResult(
                    **item["dynamic_analysis"]
                ),
            }
        )
        for item in data.pop("files")
    ]
    coverage_data = data.pop("coverage")
    publisher_trust_data = data.pop("publisher_trust")
    consistency_data = data.pop("provenance_consistency")
    release_drift_data = data.pop("release_drift")
    malicious_package_data = data.pop("malicious_package")
    dependencies = [
        DependencyInspection(
            **{
                **item,
                "risk_flags": [
                    RiskFlag(**risk_flag)
                    for risk_flag in item["risk_flags"]
                ],
            }
        )
        for item in data.pop("dependencies")
    ]
    dependency_summary_data = data.pop("dependency_summary")
    risk_flags_data = data.pop("risk_flags")
    policy_data = data.pop("policy")
    diagnostics_data = data.pop("diagnostics")
    remediation_data = data.pop("remediation")
    return TrustReport(
        **data,
        vulnerabilities=[
            VulnerabilityRecord(
                **{
                    **item,
                    "suppression": (
                        VulnerabilitySuppression(**item["suppression"])
                        if item["suppression"] is not None
                        else None
                    ),
                }
            )
            for item in vulnerabilities_data
        ],
        files=files,
        coverage=CoverageSummary(**coverage_data),
        publisher_trust=PublisherTrustSummary(**publisher_trust_data),
        provenance_consistency=ProvenanceConsistency(**consistency_data),
        release_drift=ReleaseDriftSummary(**release_drift_data),
        malicious_package=MaliciousPackageAssessment(
            **{
                **malicious_package_data,
                "findings": [
                    HeuristicFinding(**item)
                    for item in malicious_package_data["findings"]
                ],
            }
        ),
        dependencies=dependencies,
        dependency_summary=DependencySummary(**dependency_summary_data),
        risk_flags=[
            RiskFlag(**item) for item in risk_flags_data
        ],
        policy=PolicyEvaluation(
            **{
                **policy_data,
                "violations": [
                    PolicyViolation(**item)
                    for item in policy_data["violations"]
                ],
            }
        ),
        diagnostics=ReportDiagnostics(
            **{
                **diagnostics_data,
                "request_failures": [
                    RequestFailureDiagnostic(**item)
                    for item in diagnostics_data["request_failures"]
                ],
                "artifact_failures": [
                    ArtifactDiagnostic(**item)
                    for item in diagnostics_data["artifact_failures"]
                ],
            }
        ),
        remediation=RemediationSummary(**remediation_data),
    )


def get_json_schema() -> dict[str, Any]:
    schema = TrustReportEnvelopePayload.model_json_schema()
    schema["$id"] = JSON_SCHEMA_ID
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "trustcheck report envelope"
    return schema
