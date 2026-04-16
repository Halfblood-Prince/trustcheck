from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pypi_attestations import Distribution as AttestedDistribution
from pypi_attestations import Provenance, VerificationError

from .models import (
    ArtifactDiagnostic,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    ProvenanceConsistency,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    ReportDiagnostics,
    RequestFailureDiagnostic,
    RiskFlag,
    TrustReport,
    VulnerabilityRecord,
)
from .policy import advisory_evaluation_for
from .pypi import PypiClient, PypiClientError

GITHUB_RESERVED_SEGMENTS = {
    "about",
    "account",
    "apps",
    "blog",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "gist",
    "git-guides",
    "github",
    "images",
    "issues",
    "join",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "organizations",
    "pricing",
    "pulls",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "team",
    "teams",
    "topics",
    "trending",
    "users",
}
GITHUB_REPO_SUBPATHS = {
    "actions",
    "blob",
    "commit",
    "commits",
    "compare",
    "discussions",
    "issues",
    "packages",
    "projects",
    "pull",
    "pulls",
    "releases",
    "security",
    "tags",
    "tree",
    "wiki",
}

ProgressCallback = Callable[[str, int, int], None]
DependencyProgressCallback = Callable[[str, int, int, bool], None]

_RECOMMENDATION_ORDER = {
    "verified": 0,
    "metadata-only": 1,
    "review-required": 2,
    "high-risk": 3,
}


@dataclass(slots=True)
class DependencyTraversalContext:
    seen: set[str] = field(default_factory=set)


class DiagnosticsCollector:
    def __init__(self) -> None:
        self.request_count = 0
        self.retry_count = 0
        self.cache_hit_count = 0
        self.request_failures: list[RequestFailureDiagnostic] = []
        self.artifact_failures: list[ArtifactDiagnostic] = []

    def on_request_event(self, event: str, payload: dict[str, Any]) -> None:
        if event == "request":
            self.request_count += 1
        elif event == "retry":
            self.retry_count += 1
        elif event == "cache_hit":
            self.cache_hit_count += 1
        elif event == "failure":
            self.request_failures.append(
                RequestFailureDiagnostic(
                    url=str(payload.get("url") or ""),
                    attempt=int(payload.get("attempt") or 0),
                    code=str(payload.get("code") or "upstream"),
                    subcode=str(payload.get("subcode") or "unknown"),
                    message=str(payload.get("message") or ""),
                    transient=bool(payload.get("transient")),
                    status_code=(
                        int(payload["status_code"])
                        if payload.get("status_code") is not None
                        else None
                    ),
                )
            )

    def add_artifact_failure(
        self,
        *,
        filename: str,
        stage: str,
        code: str,
        subcode: str,
        message: str,
    ) -> None:
        self.artifact_failures.append(
            ArtifactDiagnostic(
                filename=filename,
                stage=stage,
                code=code,
                subcode=subcode,
                message=message,
            )
        )

    def to_report_diagnostics(self, client: PypiClient) -> ReportDiagnostics:
        return ReportDiagnostics(
            timeout=float(getattr(client, "timeout", 10.0)),
            max_retries=int(getattr(client, "max_retries", 2)),
            backoff_factor=float(getattr(client, "backoff_factor", 0.25)),
            offline=bool(getattr(client, "offline", False)),
            cache_dir=getattr(client, "cache_dir", None),
            request_count=self.request_count,
            retry_count=self.retry_count,
            cache_hit_count=self.cache_hit_count,
            request_failures=self.request_failures,
            artifact_failures=self.artifact_failures,
        )


def inspect_package(
    project: str,
    *,
    version: str | None = None,
    expected_repository: str | None = None,
    client: PypiClient | None = None,
    progress_callback: ProgressCallback | None = None,
    dependency_progress_callback: DependencyProgressCallback | None = None,
    include_dependencies: bool = False,
    include_transitive_dependencies: bool = False,
    _dependency_context: DependencyTraversalContext | None = None,
) -> TrustReport:
    client = client or PypiClient()
    diagnostics = DiagnosticsCollector()
    dependency_context = _dependency_context or DependencyTraversalContext()
    dependency_context.seen.add(canonicalize_name(project))

    with _instrument_client(client, diagnostics.on_request_event):
        payload = client.get_release(project, version) if version else client.get_project(project)
        info = payload.get("info", {})
        selected_version = payload.get("info", {}).get("version") or version or "unknown"
        declared_dependencies = _extract_declared_dependencies(info.get("requires_dist"))
        declared_repository_urls = _extract_repository_urls(info.get("project_urls") or {})
        vulnerabilities = _parse_vulnerabilities(payload.get("vulnerabilities") or [])
        ownership = info.get("ownership") or {}
        files = _collect_files(
            project,
            selected_version,
            payload,
            client,
            progress_callback=progress_callback,
            diagnostics=diagnostics,
        )

        report = TrustReport(
            project=project,
            version=selected_version,
            summary=info.get("summary"),
            package_url=f"https://pypi.org/project/{project}/{selected_version}/",
            declared_dependencies=declared_dependencies,
            declared_repository_urls=declared_repository_urls,
            repository_urls=declared_repository_urls,
            expected_repository=expected_repository,
            ownership=ownership,
            vulnerabilities=vulnerabilities,
            files=files,
            coverage=_build_coverage_summary(files),
            publisher_trust=_build_publisher_trust_summary(files),
            provenance_consistency=_build_provenance_consistency(files),
            release_drift=_build_release_drift_summary(
                project,
                selected_version,
                client,
                current_files=files,
            ),
            diagnostics=diagnostics.to_report_diagnostics(client),
        )
        dependency_inspection_requested = include_dependencies or include_transitive_dependencies
        if dependency_inspection_requested:
            report.dependencies = _inspect_dependencies(
                report,
                client,
                dependency_context=dependency_context,
                dependency_progress_callback=dependency_progress_callback,
                recursive=include_transitive_dependencies,
            )
        report.dependency_summary = _build_dependency_summary(
            declared_dependencies,
            report.dependencies,
            requested=dependency_inspection_requested,
        )
        report.risk_flags = _build_risk_flags(report)
        advisory_evaluation_for(report)
        report.diagnostics = diagnostics.to_report_diagnostics(client)
        return report


def _collect_files(
    project: str,
    version: str,
    payload: dict[str, Any],
    client: PypiClient,
    *,
    progress_callback: ProgressCallback | None = None,
    diagnostics: DiagnosticsCollector | None = None,
) -> list[FileProvenance]:
    urls = payload.get("urls") or []
    results: list[FileProvenance] = []

    total_files = len(urls)
    for index, item in enumerate(urls, start=1):
        filename = item.get("filename") or ""
        if progress_callback is not None:
            progress_callback(filename, index, total_files)
        provenance = FileProvenance(
            filename=filename,
            url=item.get("url") or "",
            sha256=(item.get("digests") or {}).get("sha256"),
            has_provenance=False,
        )
        try:
            prov_payload = client.get_provenance(project, version, filename)
            attestation_provenance = Provenance.model_validate(prov_payload)
            bundles = attestation_provenance.attestation_bundles
            provenance.has_provenance = bool(bundles)
            provenance.attestation_count = sum(len(bundle.attestations) for bundle in bundles)
            provenance.publisher_identities = _parse_publisher_identities(bundles)

            artifact_bytes = client.download_distribution(provenance.url)
            provenance.observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            if provenance.sha256 and provenance.observed_sha256 != provenance.sha256:
                raise VerificationError("downloaded artifact digest does not match PyPI metadata")

            dist = AttestedDistribution(name=filename, digest=provenance.observed_sha256)
            for bundle in bundles:
                for attestation in bundle.attestations:
                    attestation.verify(bundle.publisher, dist)
                    provenance.verified_attestation_count += 1

            provenance.verified = provenance.has_provenance and (
                provenance.verified_attestation_count == provenance.attestation_count
            )
            if provenance.has_provenance and not provenance.verified:
                raise VerificationError("no attestations were successfully verified")
        except PypiClientError as exc:
            provenance.error = str(exc)
            if diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="provenance-fetch",
                    code=exc.code,
                    subcode=exc.subcode,
                    message=str(exc),
                )
        except VerificationError as exc:
            provenance.error = str(exc)
            if diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="verification",
                    code="verification",
                    subcode="attestation_verification_failed",
                    message=str(exc),
                )
        except Exception as exc:
            provenance.error = f"attestation verification failed: {exc}"
            if diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="verification",
                    code="verification",
                    subcode="unexpected_verification_error",
                    message=str(exc),
                )
        results.append(provenance)
    return results


@contextmanager
def _instrument_client(
    client: PypiClient,
    hook: Callable[[str, dict[str, Any]], None],
) -> Any:
    previous_hook = getattr(client, "request_hook", None)

    def combined(event: str, payload: dict[str, Any]) -> None:
        hook(event, payload)
        if previous_hook is not None:
            previous_hook(event, payload)

    client.request_hook = combined
    try:
        yield
    finally:
        client.request_hook = previous_hook


def _parse_vulnerabilities(items: list[dict[str, Any]]) -> list[VulnerabilityRecord]:
    vulnerabilities: list[VulnerabilityRecord] = []
    for item in items:
        vulnerabilities.append(
            VulnerabilityRecord(
                id=item.get("id") or "unknown",
                summary=item.get("summary") or item.get("details") or "No summary provided.",
                aliases=list(item.get("aliases") or []),
                source=item.get("source"),
                fixed_in=list(item.get("fixed_in") or []),
                link=item.get("link"),
            )
        )
    return vulnerabilities


def _extract_declared_dependencies(requires_dist: object) -> list[str]:
    if not isinstance(requires_dist, list):
        return []
    return [str(item) for item in requires_dist if isinstance(item, str) and item.strip()]


def _inspect_dependencies(
    report: TrustReport,
    client: PypiClient,
    *,
    dependency_context: DependencyTraversalContext,
    dependency_progress_callback: DependencyProgressCallback | None = None,
    recursive: bool,
) -> list[DependencyInspection]:
    inspections: list[DependencyInspection] = []
    environment: dict[str, str] = {
        key: str(value) for key, value in default_environment().items()
    }
    environment.setdefault("extra", "")
    pending: deque[tuple[str, tuple[str, str], int]] = deque(
        (requirement_text, (report.project, report.version), 1)
        for requirement_text in report.declared_dependencies
    )

    while pending:
        requirement_text, dependency_parent, depth = pending.popleft()
        inspection, nested_requirements = _inspect_dependency_requirement(
            requirement_text,
            client,
            dependency_context=dependency_context,
            parent=dependency_parent,
            depth=depth,
            environment=environment,
            dependency_progress_callback=dependency_progress_callback,
        )
        if inspection is None:
            continue
        inspections.append(inspection)
        if recursive:
            for nested_requirement in nested_requirements:
                pending.append(
                    (
                        nested_requirement,
                        (inspection.project, inspection.version),
                        depth + 1,
                    )
                )
    return inspections


def _inspect_dependency_requirement(
    requirement_text: str,
    client: PypiClient,
    *,
    dependency_context: DependencyTraversalContext,
    parent: tuple[str, str],
    depth: int,
    environment: dict[str, str],
    dependency_progress_callback: DependencyProgressCallback | None = None,
) -> tuple[DependencyInspection | None, list[str]]:
    try:
        requirement = Requirement(requirement_text)
    except InvalidRequirement as exc:
        return (
            DependencyInspection(
                requirement=requirement_text,
                project=requirement_text,
                version="unknown",
                depth=depth,
                parent_project=parent[0],
                parent_version=parent[1],
                recommendation="high-risk",
                error=f"invalid dependency requirement: {exc}",
            ),
            [],
        )

    if requirement.marker is not None and not requirement.marker.evaluate(environment):
        return None, []

    project_name = requirement.name
    dependency_key = canonicalize_name(project_name)
    if dependency_key in dependency_context.seen:
        return None, []
    dependency_context.seen.add(dependency_key)
    if dependency_progress_callback is not None:
        dependency_progress_callback(project_name, depth, 0, False)

    try:
        payload = client.get_project(project_name)
        selected_version = _select_dependency_version(payload, requirement)

        def emit_dependency_artifact_progress(
            filename: str,
            current: int,
            total: int,
        ) -> None:
            del filename
            if dependency_progress_callback is None:
                return
            percent = int((current / total) * 100) if total > 0 else 100
            dependency_progress_callback(
                project_name,
                depth,
                percent,
                current == total,
            )

        nested_report = inspect_package(
            project_name,
            version=selected_version,
            client=client,
            progress_callback=emit_dependency_artifact_progress,
            include_dependencies=False,
            _dependency_context=dependency_context,
        )
        if dependency_progress_callback is not None and not nested_report.files:
            dependency_progress_callback(project_name, depth, 100, True)
        inspection = DependencyInspection(
            requirement=requirement_text,
            project=nested_report.project,
            version=nested_report.version,
            depth=depth,
            parent_project=parent[0],
            parent_version=parent[1],
            package_url=nested_report.package_url,
            recommendation=nested_report.recommendation,
            risk_flags=nested_report.risk_flags,
            declared_dependencies=nested_report.declared_dependencies,
        )
        return inspection, nested_report.declared_dependencies
    except PypiClientError as exc:
        return (
            DependencyInspection(
                requirement=requirement_text,
                project=project_name,
                version="unknown",
                depth=depth,
                parent_project=parent[0],
                parent_version=parent[1],
                recommendation="high-risk",
                error=str(exc),
            ),
            [],
        )


def _select_dependency_version(payload: dict[str, Any], requirement: Requirement) -> str:
    info = payload.get("info") or {}
    releases = payload.get("releases") or {}
    versions: list[Version] = []
    version_map: dict[Version, str] = {}

    if isinstance(releases, dict):
        for raw_version in releases:
            try:
                parsed = Version(str(raw_version))
            except InvalidVersion:
                continue
            if requirement.specifier and not requirement.specifier.contains(
                parsed,
                prereleases=None,
            ):
                continue
            versions.append(parsed)
            version_map[parsed] = str(raw_version)

    if versions:
        return version_map[max(versions)]

    fallback = info.get("version")
    if isinstance(fallback, str) and fallback:
        try:
            parsed_fallback = Version(fallback)
        except InvalidVersion:
            parsed_fallback = None
        if parsed_fallback is not None and (
            not requirement.specifier
            or requirement.specifier.contains(parsed_fallback, prereleases=None)
        ):
            return fallback
    raise PypiClientError(
        f"unable to resolve a compatible version for dependency {requirement.name!r}",
        transient=False,
        code="dependency",
        subcode="version_resolution_failed",
    )


def _build_dependency_summary(
    declared_dependencies: list[str],
    dependencies: list[DependencyInspection],
    *,
    requested: bool,
) -> DependencySummary:
    highest_recommendation = "verified"
    highest_projects: list[str] = []
    projects_by_recommendation: dict[str, list[str]] = {
        "high-risk": [],
        "review-required": [],
        "metadata-only": [],
        "verified": [],
    }

    for dependency in dependencies:
        dependency_recommendation = dependency.recommendation or "metadata-only"
        if dependency.project not in projects_by_recommendation.setdefault(
            dependency_recommendation,
            [],
        ):
            projects_by_recommendation[dependency_recommendation].append(dependency.project)
        if (
            _RECOMMENDATION_ORDER.get(dependency_recommendation, 1)
            > _RECOMMENDATION_ORDER.get(highest_recommendation, 0)
        ):
            highest_recommendation = dependency_recommendation
            highest_projects = [dependency.project]
        elif dependency_recommendation == highest_recommendation:
            if dependency.project not in highest_projects:
                highest_projects.append(dependency.project)

    if not dependencies:
        highest_recommendation = "metadata-only"

    return DependencySummary(
        requested=requested,
        total_declared=len(declared_dependencies),
        total_inspected=len(dependencies),
        unique_dependencies=len({canonicalize_name(item.project) for item in dependencies}),
        max_depth=max((item.depth for item in dependencies), default=0),
        highest_risk_recommendation=highest_recommendation,
        highest_risk_projects=sorted(highest_projects),
        high_risk_projects=sorted(projects_by_recommendation["high-risk"]),
        review_required_projects=sorted(projects_by_recommendation["review-required"]),
        metadata_only_projects=sorted(projects_by_recommendation["metadata-only"]),
        verified_projects=sorted(projects_by_recommendation["verified"]),
    )


def _extract_repository_urls(project_urls: dict[str, str]) -> list[str]:
    explicit_repo_urls: list[str] = []
    fallback_repo_urls: list[str] = []

    for label, url in project_urls.items():
        normalized = _normalize_repo_url(url)
        if not normalized:
            continue

        if _is_explicit_repository_label(label):
            explicit_repo_urls.append(normalized)
        else:
            fallback_repo_urls.append(normalized)

    repo_urls = explicit_repo_urls or fallback_repo_urls

    deduped: list[str] = []
    seen: set[str] = set()
    for url in repo_urls:
        if url not in seen:
            deduped.append(url)
            seen.add(url)
    return deduped


def _parse_publisher_identities(bundles: list[Any]) -> list[PublisherIdentity]:
    identities: list[PublisherIdentity] = []

    for bundle in bundles:
        publisher = getattr(bundle, "publisher", None)
        if publisher is None:
            continue

        raw = publisher.model_dump() if hasattr(publisher, "model_dump") else {}
        kind = str(getattr(publisher, "kind", None) or raw.get("issuer") or "unknown")
        repository = _publisher_repository_url(kind, getattr(publisher, "repository", None))
        workflow = getattr(publisher, "workflow", None) or getattr(
            publisher,
            "workflow_filepath",
            None,
        )
        environment = getattr(publisher, "environment", None)
        identities.append(
            PublisherIdentity(
                kind=kind,
                repository=repository,
                workflow=workflow,
                environment=environment,
                raw=raw,
            )
        )
    return identities


def _build_risk_flags(report: TrustReport) -> list[RiskFlag]:
    flags: list[RiskFlag] = []
    total_files = report.coverage.total_files
    verified_files = report.coverage.verified_files
    files_with_errors = [file.filename for file in report.files if file.error]
    files_without_provenance = [file.filename for file in report.files if not file.has_provenance]
    unverified_files = [file.filename for file in report.files if not file.verified]
    artifact_failure_by_filename = {
        failure.filename: failure for failure in report.diagnostics.artifact_failures
    }

    if report.vulnerabilities:
        flags.append(
            RiskFlag(
                code="known_vulnerabilities",
                severity="high",
                message=(
                    f"PyPI reports {len(report.vulnerabilities)} known "
                    "vulnerability record(s) for this release."
                ),
                why=[
                    "PyPI returned "
                    f"{len(report.vulnerabilities)} vulnerability record(s) "
                    "for this version.",
                    *[
                        f"{vuln.id}: {vuln.summary}"
                        for vuln in report.vulnerabilities[:3]
                    ],
                ],
                remediation=[
                    "Review the linked advisories before installation.",
                    "Prefer a fixed release if one is available.",
                    "Isolate or block this package until the vulnerability status is understood.",
                ],
            )
        )

    if report.dependency_summary.requested and report.dependencies:
        top_dependency_projects = ", ".join(report.dependency_summary.highest_risk_projects[:3])
        if report.dependency_summary.highest_risk_recommendation == "high-risk":
            flags.append(
                RiskFlag(
                    code="dependency_high_risk",
                    severity="high",
                    message="One or more inspected dependencies are high-risk.",
                    why=[
                        "Dependency inspection was requested and at least one dependency "
                        "evaluated to high-risk.",
                        *(
                            [f"Highest-risk dependencies: {top_dependency_projects}"]
                            if top_dependency_projects
                            else []
                        ),
                    ],
                    remediation=[
                        "Review and pin the flagged dependencies before promoting this package.",
                        (
                            "Block or isolate the dependency set until the high-risk "
                            "findings are understood."
                        ),
                    ],
                )
            )
        elif report.dependency_summary.highest_risk_recommendation == "review-required":
            flags.append(
                RiskFlag(
                    code="dependency_review_required",
                    severity="medium",
                    message="One or more inspected dependencies require manual review.",
                    why=[
                        "Dependency inspection was requested and at least one dependency "
                        "evaluated to review-required.",
                        *(
                            [f"Dependencies needing review: {top_dependency_projects}"]
                            if top_dependency_projects
                            else []
                        ),
                    ],
                    remediation=[
                        "Review the dependency findings before approving the package.",
                        (
                            "Consider pinning or replacing dependencies with cleaner "
                            "provenance coverage."
                        ),
                    ],
                )
            )

    if not report.repository_urls:
        flags.append(
            RiskFlag(
                code="missing_repository_url",
                severity="medium",
                message=(
                    "The package does not expose an obvious repository URL "
                    "in project metadata. It may not be open source or may "
                    "omit a public repository."
                ),
                why=[
                    "No supported source repository URL was found in the package metadata.",
                    "That makes it harder to compare project metadata with "
                    "publisher identity evidence.",
                ],
                remediation=[
                    "Look for an official source repository outside PyPI "
                    "before trusting the release.",
                    "Prefer packages that publish a clear repository URL in project metadata.",
                ],
            )
        )

    if report.expected_repository:
        expected = _normalize_repo_url(report.expected_repository)
        if not expected:
            flags.append(
                RiskFlag(
                    code="expected_repository_invalid",
                    severity="high",
                    message=(
                        "The expected repository could not be normalized to a "
                        "supported GitHub or GitLab repository URL."
                    ),
                    why=[
                        f"Original expected repository input: {report.expected_repository}",
                        "Repository matching only supports canonical GitHub "
                        "and GitLab repository URLs or equivalent git remotes.",
                    ],
                    remediation=[
                        "Provide a repository root URL such as "
                        "https://github.com/owner/repo.",
                        "Avoid issue pages, profile pages, documentation "
                        "sites, and unsupported forge URLs.",
                    ],
                )
            )
        else:
            repo_matches = any(url == expected for url in report.declared_repository_urls)
            publisher_matches = any(
                _normalize_repo_url(identity.repository) == expected
                for file in report.files
                for identity in file.publisher_identities
                if identity.repository
            )
            verified_publisher_matches = any(
                _normalize_repo_url(identity.repository) == expected
                for file in report.files
                if file.verified
                for identity in file.publisher_identities
                if identity.repository
            )
            if not repo_matches and not publisher_matches:
                flags.append(
                    RiskFlag(
                        code="expected_repository_mismatch",
                        severity="high",
                        message=(
                            "The expected repository does not match declared "
                            "project metadata or observed publisher identity hints."
                        ),
                        why=[
                            f"Expected repository: {expected}",
                            "No declared repository URL or publisher identity "
                            "matched that expectation.",
                        ],
                        remediation=[
                            "Stop and confirm the package name and expected repository.",
                            "Check whether the project moved to a new "
                            "repository before proceeding.",
                        ],
                    )
                )
            elif report.files and not verified_publisher_matches:
                flags.append(
                    RiskFlag(
                        code="expected_repository_unverified",
                        severity="high",
                        message=(
                            "No verified attestation binds the release artifact "
                            "to the expected repository."
                        ),
                        why=[
                            f"Expected repository: {expected}",
                            "Matching repository hints may exist, but none were "
                            "backed by a verified attestation.",
                        ],
                        remediation=[
                            "Treat the release as unverified until a matching "
                            "verified attestation exists.",
                            "Confirm the release was produced from the expected "
                            "repository and workflow.",
                        ],
                    )
                )

    if report.files and all(not file.has_provenance for file in report.files):
        flags.append(
            RiskFlag(
                code="no_provenance",
                severity="medium",
                message=(
                    "No provenance bundles were found for the release files "
                    "on PyPI, so the artifacts cannot be verified."
                ),
                why=[
                    f"Discovered {total_files} release artifact(s), and none "
                    "exposed provenance bundles.",
                    "Without provenance, cryptographic verification cannot be performed.",
                ],
                remediation=[
                    "Prefer a release that publishes Trusted Publishing provenance.",
                    "If you must proceed, pin exact hashes and perform manual "
                    "review outside this tool.",
                ],
            )
        )

    if report.coverage.status == "partial":
        flags.append(
            RiskFlag(
                code="partial_provenance_coverage",
                severity="high",
                message=(
                    "Only some release artifacts have provenance or successful "
                    "verification coverage."
                ),
                why=[
                    f"Verified {verified_files} of {total_files} discovered artifact(s).",
                    *(
                        [f"Missing provenance: {', '.join(files_without_provenance[:3])}"]
                        if files_without_provenance
                        else []
                    ),
                ],
                remediation=[
                    "Install only artifacts that verified successfully.",
                    "Ask the maintainer to publish provenance for every release artifact.",
                ],
            )
        )

    if any(
        file.error
        and not _is_missing_provenance_failure(
            artifact_failure_by_filename.get(file.filename)
        )
        for file in report.files
    ):
        flags.append(
            RiskFlag(
                code="provenance_verification_failed",
                severity="high",
                message="One or more release files have invalid or unverifiable provenance.",
                why=[
                    f"Verification failed for {len(files_with_errors)} artifact(s).",
                    *[
                        f"{file.filename}: {file.error}"
                        for file in report.files
                        if file.error
                    ][:3],
                ],
                remediation=[
                    "Review the file-level errors to determine whether this "
                    "is tampering, bad metadata, or a transient upstream problem.",
                    "Do not treat the affected artifacts as verified.",
                ],
            )
        )

    if (
        report.files
        and not all(file.verified for file in report.files)
        and not all(not file.has_provenance for file in report.files)
    ):
        flags.append(
            RiskFlag(
                code="unverified_provenance",
                severity="high",
                message=(
                    "Every release artifact must have a valid attestation "
                    "bound to its exact digest and publisher identity."
                ),
                why=[
                    f"{len(unverified_files)} artifact(s) were not fully verified.",
                    f"Coverage status: {report.coverage.status}.",
                ],
                remediation=[
                    "Require cryptographic verification for every artifact "
                    "before promotion or deployment.",
                    "Use `--strict` in automation so missing verification fails the run.",
                ],
            )
        )

    if (
        report.files
        and any(file.has_provenance for file in report.files)
        and not any(file.publisher_identities for file in report.files)
    ):
        flags.append(
            RiskFlag(
                code="missing_publisher_identity",
                severity="high",
                message=(
                    "No Trusted Publisher identity information was recovered "
                    "from the provenance bundles."
                ),
                why=[
                    "Provenance was present, but it did not yield repository "
                    "or workflow identity details.",
                    "That prevents source-to-artifact attribution.",
                ],
                remediation=[
                    "Prefer releases whose provenance exposes publisher "
                    "repository and workflow identity.",
                    "Review maintainer publishing configuration before trusting the artifacts.",
                ],
            )
        )

    if report.provenance_consistency.sdist_wheel_consistent is False:
        flags.append(
            RiskFlag(
                code="sdist_wheel_provenance_mismatch",
                severity="high",
                message=(
                    "Verified sdist and wheel provenance do not agree on the "
                    "publisher repository or workflow."
                ),
                why=[
                    "The verified sdist and wheel do not overlap on "
                    "repository or workflow identity.",
                ],
                remediation=[
                    "Inspect both artifacts separately before installation.",
                    "Ask the maintainer why different build sources or "
                    "workflows produced the release files.",
                ],
            )
        )

    if report.release_drift.publisher_repository_drift:
        flags.append(
            RiskFlag(
                code="publisher_repository_drift",
                severity="high",
                message=(
                    "Verified publisher repository differs from the previous "
                    "release, which may warrant review."
                ),
                why=[
                    f"Current release was compared to {report.release_drift.compared_to_version}.",
                    "Previous verified repositories: "
                    f"{', '.join(report.release_drift.previous_repositories) or 'unknown'}",
                ],
                remediation=[
                    "Confirm that a repository transfer, rename, or fork was intentional.",
                    "Review release notes and maintainer communications before upgrading.",
                ],
            )
        )

    if report.release_drift.publisher_workflow_drift:
        flags.append(
            RiskFlag(
                code="publisher_workflow_drift",
                severity="medium",
                message=(
                    "Verified publisher workflow differs from the previous "
                    "release."
                ),
                why=[
                    f"Current release was compared to {report.release_drift.compared_to_version}.",
                    "Previous verified workflows: "
                    f"{', '.join(report.release_drift.previous_workflows) or 'unknown'}",
                ],
                remediation=[
                    "Review the workflow change to confirm it is an expected "
                    "release pipeline update.",
                    "Require an explicit approval step for packages with publisher workflow drift.",
                ],
            )
        )

    return flags


def _is_missing_provenance_failure(diagnostic: ArtifactDiagnostic | None) -> bool:
    return (
        diagnostic is not None
        and diagnostic.stage == "provenance-fetch"
        and (
            diagnostic.subcode == "http_not_found"
            or "not found" in diagnostic.message.lower()
        )
    )


def _normalize_repo_url(url: str | None) -> str:
    if not url:
        return ""

    ssh_match = re.fullmatch(r"git@(?P<host>github\.com|gitlab\.com):(?P<path>.+)", url.strip())
    if ssh_match:
        host = ssh_match.group("host")
        path = ssh_match.group("path")
        return _normalize_supported_forge_url(host, path)

    parsed = urlparse(url.strip())
    if not parsed.scheme and not parsed.netloc:
        if url.count("/") == 1:
            return _normalize_supported_forge_url("github.com", url)
        return ""

    host = parsed.hostname.lower() if parsed.hostname else ""
    path = parsed.path or ""

    if parsed.scheme.lower() == "ssh" and parsed.username == "git" and host:
        return _normalize_supported_forge_url(host, path)

    if parsed.scheme.lower().startswith("git+"):
        nested = urlparse(url[len("git+"):])
        host = nested.hostname.lower() if nested.hostname else ""
        path = nested.path or ""

    return _normalize_supported_forge_url(host, path)


def _publisher_repository_url(kind: str, repository: str | None) -> str | None:
    if not repository:
        return repository
    if repository.startswith(("http://", "https://")):
        return _normalize_repo_url(repository) or repository
    kind_normalized = kind.lower()
    if "github" in kind_normalized:
        return _normalize_repo_url(f"https://github.com/{repository}") or repository
    if "gitlab" in kind_normalized:
        return _normalize_repo_url(f"https://gitlab.com/{repository}") or repository
    return repository


def _is_explicit_repository_label(label: str) -> bool:
    label_norm = label.strip().lower()
    explicit_labels = {
        "source",
        "source code",
        "repository",
        "repo",
        "code",
        "source repository",
    }
    return label_norm in explicit_labels


def _normalize_supported_forge_url(host: str, path: str) -> str:
    host_normalized = host.lower().removesuffix(":")
    cleaned_path = path.strip().lstrip("/").rstrip("/")
    cleaned_path = cleaned_path.removesuffix(".git")

    if host_normalized == "github.com":
        segments = [segment for segment in cleaned_path.split("/") if segment]
        if len(segments) < 2:
            return ""
        if segments[0].lower() in GITHUB_RESERVED_SEGMENTS:
            return ""
        if len(segments) > 2 and segments[2].lower() not in GITHUB_REPO_SUBPATHS:
            return ""
        owner, repo = segments[0].lower(), segments[1].lower()
        return f"https://github.com/{owner}/{repo}"

    if host_normalized == "gitlab.com":
        had_gitlab_subpath = "/-/" in cleaned_path
        if had_gitlab_subpath:
            cleaned_path = cleaned_path.split("/-/", maxsplit=1)[0]
        segments = [segment for segment in cleaned_path.split("/") if segment]
        if len(segments) < 2:
            return ""
        if not had_gitlab_subpath and len(segments) > 3:
            return ""
        namespace = "/".join(segment.lower() for segment in segments)
        return f"https://gitlab.com/{namespace}"

    return ""


def _build_coverage_summary(files: list[FileProvenance]) -> CoverageSummary:
    total_files = len(files)
    files_with_provenance = sum(1 for file in files if file.has_provenance)
    verified_files = sum(1 for file in files if file.verified)

    if total_files == 0:
        status = "none"
    elif verified_files == total_files:
        status = "all-verified"
    elif files_with_provenance == total_files:
        status = "all-attested"
    elif files_with_provenance > 0 or verified_files > 0:
        status = "partial"
    else:
        status = "none"

    return CoverageSummary(
        total_files=total_files,
        files_with_provenance=files_with_provenance,
        verified_files=verified_files,
        status=status,
    )


def _build_publisher_trust_summary(files: list[FileProvenance]) -> PublisherTrustSummary:
    verified_publishers: set[str] = set()
    repositories: set[str] = set()
    workflows: set[str] = set()

    for file in files:
        if not file.verified:
            continue
        for identity in file.publisher_identities:
            publisher_key = ":".join(
                [
                    identity.kind or "unknown",
                    identity.repository or "-",
                    identity.workflow or "-",
                ]
            )
            verified_publishers.add(publisher_key)
            if identity.repository:
                repositories.add(identity.repository)
            if identity.workflow:
                workflows.add(identity.workflow)

    depth_score = 0
    if any(file.has_provenance for file in files):
        depth_score += 1
    if any(file.verified for file in files):
        depth_score += 2
    if repositories:
        depth_score += 1
    if workflows:
        depth_score += 1

    if depth_score >= 5:
        depth_label = "strong"
    elif depth_score >= 3:
        depth_label = "moderate"
    elif depth_score >= 1:
        depth_label = "weak"
    else:
        depth_label = "none"

    return PublisherTrustSummary(
        depth_score=depth_score,
        depth_label=depth_label,
        verified_publishers=sorted(verified_publishers),
        unique_verified_repositories=sorted(repositories),
        unique_verified_workflows=sorted(workflows),
    )


def _build_provenance_consistency(files: list[FileProvenance]) -> ProvenanceConsistency:
    sdist_files = [file for file in files if _is_sdist(file.filename) and file.verified]
    wheel_files = [file for file in files if _is_wheel(file.filename) and file.verified]

    if not sdist_files or not wheel_files:
        return ProvenanceConsistency(
            has_sdist=bool([file for file in files if _is_sdist(file.filename)]),
            has_wheel=bool([file for file in files if _is_wheel(file.filename)]),
            sdist_wheel_consistent=None,
        )

    sdist_repositories = _collect_verified_identity_values(sdist_files, "repository")
    wheel_repositories = _collect_verified_identity_values(wheel_files, "repository")
    sdist_workflows = _collect_verified_identity_values(sdist_files, "workflow")
    wheel_workflows = _collect_verified_identity_values(wheel_files, "workflow")

    repository_overlap = sorted(sdist_repositories & wheel_repositories)
    workflow_overlap = sorted(sdist_workflows & wheel_workflows)
    consistent = bool(repository_overlap) and (
        not sdist_workflows and not wheel_workflows or bool(workflow_overlap)
    )

    return ProvenanceConsistency(
        has_sdist=True,
        has_wheel=True,
        sdist_wheel_consistent=consistent,
        consistent_repositories=repository_overlap,
        consistent_workflows=workflow_overlap,
    )


def _build_release_drift_summary(
    project: str,
    version: str,
    client: PypiClient,
    *,
    current_files: list[FileProvenance],
) -> ReleaseDriftSummary:
    previous_version = _previous_release_version(project, version, client)
    if not previous_version:
        return ReleaseDriftSummary()

    try:
        previous_payload = client.get_release(project, previous_version)
        previous_files = _collect_files(project, previous_version, previous_payload, client)
    except PypiClientError:
        return ReleaseDriftSummary(compared_to_version=previous_version)

    current_repositories = _collect_verified_identity_values(current_files, "repository")
    current_workflows = _collect_verified_identity_values(current_files, "workflow")
    previous_repositories = _collect_verified_identity_values(previous_files, "repository")
    previous_workflows = _collect_verified_identity_values(previous_files, "workflow")

    repository_drift = None
    workflow_drift = None
    if current_repositories and previous_repositories:
        repository_drift = current_repositories != previous_repositories
    if current_workflows and previous_workflows:
        workflow_drift = current_workflows != previous_workflows

    return ReleaseDriftSummary(
        compared_to_version=previous_version,
        publisher_repository_drift=repository_drift,
        publisher_workflow_drift=workflow_drift,
        previous_repositories=sorted(previous_repositories),
        previous_workflows=sorted(previous_workflows),
    )


def _previous_release_version(project: str, version: str, client: PypiClient) -> str | None:
    try:
        project_payload = client.get_project(project)
    except PypiClientError:
        return None

    releases = project_payload.get("releases") or {}
    if not isinstance(releases, dict):
        return None

    try:
        current_version = Version(version)
    except InvalidVersion:
        return None

    candidates: list[Version] = []
    version_map: dict[Version, str] = {}
    for release_version in releases:
        try:
            parsed = Version(str(release_version))
        except InvalidVersion:
            continue
        if parsed < current_version:
            candidates.append(parsed)
            version_map[parsed] = str(release_version)

    if not candidates:
        return None
    previous = max(candidates)
    return version_map[previous]


def _collect_verified_identity_values(
    files: list[FileProvenance],
    attribute: str,
) -> set[str]:
    values: set[str] = set()
    for file in files:
        if not file.verified:
            continue
        for identity in file.publisher_identities:
            value = getattr(identity, attribute, None)
            if value:
                values.add(str(value))
    return values


def _is_sdist(filename: str) -> bool:
    return filename.endswith((".tar.gz", ".zip"))


def _is_wheel(filename: str) -> bool:
    return filename.endswith(".whl")
