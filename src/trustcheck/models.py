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
class VulnerabilitySuppression:
    vulnerability_id: str
    owner: str
    justification: str
    expires: str
    status: str = "configured"


@dataclass(slots=True)
class VulnerabilityRecord:
    id: str
    summary: str
    aliases: list[str] = field(default_factory=list)
    source: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwes: list[str] = field(default_factory=list)
    fixed_in: list[str] = field(default_factory=list)
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
    suppression: VulnerabilitySuppression | None = None


@dataclass(slots=True)
class PublisherIdentity:
    kind: str
    repository: str | None
    workflow: str | None
    environment: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProvenanceIssue:
    code: str
    severity: str
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProvenanceMaterial:
    uri: str
    digests: dict[str, str] = field(default_factory=dict)
    name: str | None = None
    source: bool = False


@dataclass(slots=True)
class SlsaProvenance:
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
    materials: list[ProvenanceMaterial] = field(default_factory=list)
    action_references: list[str] = field(default_factory=list)
    unpinned_actions: list[str] = field(default_factory=list)
    issues: list[ProvenanceIssue] = field(default_factory=list)


@dataclass(slots=True)
class HeuristicFinding:
    code: str
    category: str
    severity: str
    confidence: str
    score: int
    message: str
    evidence: list[str] = field(default_factory=list)
    location: str | None = None
    artifact: str | None = None
    heuristic: bool = True
    rule_version: str = "1.0"
    false_positive_rate: float | None = None
    score_threshold: int = 1


@dataclass(slots=True)
class NativeBinaryInspection:
    path: str
    format: str = "unknown"
    architecture: str | None = None
    imports: list[str] = field(default_factory=list)
    signature_present: bool | None = None
    signature_status: str = "not-applicable"
    entropy: float | None = None
    embedded_payloads: list[str] = field(default_factory=list)
    parse_error: str | None = None


@dataclass(slots=True)
class ArtifactInspection:
    inspected: bool = False
    kind: str = "unknown"
    archive_valid: bool | None = None
    file_count: int = 0
    total_uncompressed_size: int = 0
    record_valid: bool | None = None
    record_errors: list[str] = field(default_factory=list)
    console_scripts: list[str] = field(default_factory=list)
    suspicious_entry_points: list[str] = field(default_factory=list)
    native_files: list[str] = field(default_factory=list)
    unexpected_top_level_files: list[str] = field(default_factory=list)
    suspicious_files: list[str] = field(default_factory=list)
    oversized_files: list[str] = field(default_factory=list)
    unusual_files: list[str] = field(default_factory=list)
    metadata_name: str | None = None
    metadata_version: str | None = None
    metadata_requires_dist: list[str] = field(default_factory=list)
    wheel_version: str | None = None
    wheel_root_is_purelib: bool | None = None
    wheel_tags: list[str] = field(default_factory=list)
    metadata_mismatches: list[str] = field(default_factory=list)
    source_files_analyzed: int = 0
    source_parse_errors: list[str] = field(default_factory=list)
    native_binaries: list[NativeBinaryInspection] = field(default_factory=list)
    heuristic_findings: list[HeuristicFinding] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class DynamicAnalysisResult:
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
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    error: str | None = None


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
    slsa_provenance: list[SlsaProvenance] = field(default_factory=list)
    error: str | None = None
    artifact: ArtifactInspection = field(default_factory=ArtifactInspection)
    dynamic_analysis: DynamicAnalysisResult = field(default_factory=DynamicAnalysisResult)


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
    builder_consistent: bool | None = None
    source_commit_consistent: bool | None = None
    build_type_consistent: bool | None = None
    consistent_builders: list[str] = field(default_factory=list)
    consistent_source_commits: list[str] = field(default_factory=list)
    consistent_build_types: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReleaseDriftSummary:
    compared_to_version: str | None = None
    publisher_repository_drift: bool | None = None
    publisher_workflow_drift: bool | None = None
    signer_drift: bool | None = None
    builder_drift: bool | None = None
    source_commit_drift: bool | None = None
    build_type_drift: bool | None = None
    previous_signers: list[str] = field(default_factory=list)
    previous_repositories: list[str] = field(default_factory=list)
    previous_workflows: list[str] = field(default_factory=list)
    previous_builders: list[str] = field(default_factory=list)
    previous_source_commits: list[str] = field(default_factory=list)
    previous_build_types: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MaliciousPackageAssessment:
    score: int = 0
    level: str = "none"
    artifact_analysis: bool = False
    trusted_name_count: int = 0
    findings: list[HeuristicFinding] = field(default_factory=list)
    score_thresholds: dict[str, int] = field(
        default_factory=lambda: {
            "low": 1,
            "elevated": 25,
            "high": 50,
            "critical": 75,
        }
    )
    rule_thresholds: dict[str, int] = field(default_factory=dict)
    disclaimer: str = (
        "These findings are heuristic indicators for review, not proof that "
        "the package is malicious."
    )


@dataclass(slots=True)
class DependencyInspection:
    requirement: str
    project: str
    version: str
    depth: int
    parent_project: str | None = None
    parent_version: str | None = None
    package_url: str | None = None
    recommendation: str = "metadata-only"
    risk_flags: list[RiskFlag] = field(default_factory=list)
    declared_dependencies: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class DependencySummary:
    requested: bool = False
    total_declared: int = 0
    total_inspected: int = 0
    unique_dependencies: int = 0
    max_depth: int = 0
    highest_risk_recommendation: str = "metadata-only"
    highest_risk_projects: list[str] = field(default_factory=list)
    high_risk_projects: list[str] = field(default_factory=list)
    review_required_projects: list[str] = field(default_factory=list)
    metadata_only_projects: list[str] = field(default_factory=list)
    verified_projects: list[str] = field(default_factory=list)


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
    allowed_publisher_organizations: list[str] = field(default_factory=list)
    allow_metadata_only: bool = True
    vulnerability_mode: str = "ignore"
    malicious_package_thresholds: dict[str, int] = field(
        default_factory=lambda: {
            "low": 1,
            "elevated": 25,
            "high": 50,
            "critical": 75,
        }
    )
    malicious_rule_thresholds: dict[str, int] = field(default_factory=dict)
    suppressions_applied: int = 0
    suppressions_expired: int = 0
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
    plugin_executions: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class RemediationSummary:
    status: str = "not-requested"
    minimal: bool = False
    attempts: int = 0
    upgrades_planned: int = 0
    blocked_fixes: int = 0
    patch_files: list[str] = field(default_factory=list)
    pull_request_url: str | None = None
    confidence: str | None = None
    breaking_change_warnings: list[str] = field(default_factory=list)
    minimal_secure_upgrade_proven: bool = False


@dataclass(slots=True)
class TrustReport:
    project: str
    version: str
    summary: str | None
    package_url: str
    declared_dependencies: list[str] = field(default_factory=list)
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
    malicious_package: MaliciousPackageAssessment = field(
        default_factory=MaliciousPackageAssessment
    )
    dependencies: list[DependencyInspection] = field(default_factory=list)
    dependency_summary: DependencySummary = field(default_factory=DependencySummary)
    risk_flags: list[RiskFlag] = field(default_factory=list)
    recommendation: str = "metadata-only"
    policy: PolicyEvaluation = field(default_factory=PolicyEvaluation)
    diagnostics: ReportDiagnostics = field(default_factory=ReportDiagnostics)
    remediation: RemediationSummary = field(default_factory=RemediationSummary)

    def to_dict(self) -> dict[str, Any]:
        from .contract import serialize_report

        return serialize_report(self)
