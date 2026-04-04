from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from packaging.version import InvalidVersion, Version
from pypi_attestations import Distribution as AttestedDistribution
from pypi_attestations import Provenance, VerificationError

from .models import (
    CoverageSummary,
    FileProvenance,
    ProvenanceConsistency,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    RiskFlag,
    TrustReport,
    VulnerabilityRecord,
)
from .pypi import PypiClient, PypiClientError


def inspect_package(
    project: str,
    *,
    version: str | None = None,
    expected_repository: str | None = None,
    client: PypiClient | None = None,
) -> TrustReport:
    client = client or PypiClient()

    payload = client.get_release(project, version) if version else client.get_project(project)
    info = payload.get("info", {})
    selected_version = payload.get("info", {}).get("version") or version or "unknown"
    declared_repository_urls = _extract_repository_urls(info.get("project_urls") or {})
    vulnerabilities = _parse_vulnerabilities(payload.get("vulnerabilities") or [])
    ownership = info.get("ownership") or {}
    files = _collect_files(project, selected_version, payload, client)

    report = TrustReport(
        project=project,
        version=selected_version,
        summary=info.get("summary"),
        package_url=f"https://pypi.org/project/{project}/{selected_version}/",
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
    )
    report.risk_flags = _build_risk_flags(report)
    report.recommendation = _recommendation_for(report)
    return report


def _collect_files(
    project: str,
    version: str,
    payload: dict[str, Any],
    client: PypiClient,
) -> list[FileProvenance]:
    urls = payload.get("urls") or []
    results: list[FileProvenance] = []

    for item in urls:
        filename = item.get("filename") or ""
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
        except VerificationError as exc:
            provenance.error = str(exc)
        except Exception as exc:
            provenance.error = f"attestation verification failed: {exc}"
        results.append(provenance)
    return results


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

    if report.vulnerabilities:
        flags.append(
            RiskFlag(
                code="known_vulnerabilities",
                severity="high",
                message=(
                    f"PyPI reports {len(report.vulnerabilities)} known "
                    "vulnerability record(s) for this release."
                ),
            )
        )

    if not report.repository_urls:
        flags.append(
            RiskFlag(
                code="missing_repository_url",
                severity="medium",
                message=(
                    "The package does not expose an obvious repository URL "
                    "in project metadata."
                ),
            )
        )

    if report.expected_repository:
        expected = _normalize_repo_url(report.expected_repository)
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
                )
            )

    if report.files and all(not file.has_provenance for file in report.files):
        flags.append(
            RiskFlag(
                code="no_provenance",
                severity="high",
                message=(
                    "No provenance bundles were found for the release files "
                    "on PyPI, so the artifacts cannot be verified."
                ),
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
            )
        )

    if any(file.error for file in report.files):
        flags.append(
            RiskFlag(
                code="provenance_verification_failed",
                severity="high",
                message="One or more release files have invalid or unverifiable provenance.",
            )
        )

    if report.files and not all(file.verified for file in report.files):
        flags.append(
            RiskFlag(
                code="unverified_provenance",
                severity="high",
                message=(
                    "Every release artifact must have a valid attestation "
                    "bound to its exact digest and publisher identity."
                ),
            )
        )

    if report.files and not any(file.publisher_identities for file in report.files):
        flags.append(
            RiskFlag(
                code="missing_publisher_identity",
                severity="high",
                message=(
                    "No Trusted Publisher identity information was recovered "
                    "from the provenance bundles."
                ),
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
            )
        )

    return flags


def _recommendation_for(report: TrustReport) -> str:
    if any(flag.severity == "high" for flag in report.risk_flags):
        return "high-risk"
    if report.files and all(file.verified for file in report.files):
        return "verified"
    if any(flag.severity == "medium" for flag in report.risk_flags):
        return "review-required"
    return "metadata-only"


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
        owner, repo = segments[0].lower(), segments[1].lower()
        return f"https://github.com/{owner}/{repo}"

    if host_normalized == "gitlab.com":
        if "/-/" in cleaned_path:
            cleaned_path = cleaned_path.split("/-/", maxsplit=1)[0]
        segments = [segment for segment in cleaned_path.split("/") if segment]
        if len(segments) < 2:
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
