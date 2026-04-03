from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .models import FileProvenance, PublisherIdentity, RiskFlag, TrustReport, VulnerabilityRecord
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
    project_urls = _extract_repository_urls(info.get("project_urls") or {})
    vulnerabilities = _parse_vulnerabilities(payload.get("vulnerabilities") or [])
    ownership = info.get("ownership") or {}
    files = _collect_files(project, selected_version, payload, client)

    report = TrustReport(
        project=project,
        version=selected_version,
        summary=info.get("summary"),
        package_url=f"https://pypi.org/project/{project}/{selected_version}/",
        repository_urls=project_urls,
        expected_repository=expected_repository,
        ownership=ownership,
        vulnerabilities=vulnerabilities,
        files=files,
    )
    report.risk_flags = _build_risk_flags(report)
    report.recommendation = _recommendation_for(report.risk_flags)
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
            bundles = prov_payload.get("attestation_bundles") or []
            provenance.has_provenance = bool(bundles)
            provenance.attestation_count = sum(
                len(bundle.get("attestations") or [])
                for bundle in bundles
                if isinstance(bundle, dict)
            )
            provenance.publisher_identities = _parse_publisher_identities(bundles)
        except PypiClientError as exc:
            provenance.error = str(exc)
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
    repo_urls: list[str] = []
    preferred_labels = ("source", "source code", "repository", "repo", "homepage", "home")

    for label, url in project_urls.items():
        label_norm = label.strip().lower()
        if any(token in label_norm for token in preferred_labels):
            repo_urls.append(url)

    if not repo_urls:
        repo_urls.extend(project_urls.values())

    deduped: list[str] = []
    seen: set[str] = set()
    for url in repo_urls:
        normalized = _normalize_repo_url(url)
        if normalized not in seen:
            deduped.append(url)
            seen.add(normalized)
    return deduped


def _parse_publisher_identities(bundles: list[dict[str, Any]]) -> list[PublisherIdentity]:
    identities: list[PublisherIdentity] = []

    for bundle in bundles:
        publisher = bundle.get("publisher") or bundle.get("verification_material", {}).get("publisher")
        if not isinstance(publisher, dict):
            continue

        kind = str(publisher.get("kind") or publisher.get("issuer") or "unknown")
        repository = (
            publisher.get("repository")
            or publisher.get("repository_url")
            or publisher.get("repo")
            or publisher.get("sub")
        )
        workflow = (
            publisher.get("workflow")
            or publisher.get("workflow_ref")
            or publisher.get("job_workflow_ref")
        )
        environment = publisher.get("environment")
        identities.append(
            PublisherIdentity(
                kind=kind,
                repository=repository,
                workflow=workflow,
                environment=environment,
                raw=publisher,
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
                message=f"PyPI reports {len(report.vulnerabilities)} known vulnerability record(s) for this release.",
            )
        )

    if not report.repository_urls:
        flags.append(
            RiskFlag(
                code="missing_repository_url",
                severity="medium",
                message="The package does not expose an obvious repository URL in project metadata.",
            )
        )

    if report.expected_repository:
        expected = _normalize_repo_url(report.expected_repository)
        repo_matches = any(_normalize_repo_url(url) == expected for url in report.repository_urls)
        publisher_matches = any(
            _normalize_repo_url(identity.repository) == expected
            for file in report.files
            for identity in file.publisher_identities
            if identity.repository
        )
        if not repo_matches and not publisher_matches:
            flags.append(
                RiskFlag(
                    code="expected_repository_mismatch",
                    severity="high",
                    message="The expected repository does not match declared project metadata or observed publisher identity hints.",
                )
            )

    if report.files and all(not file.has_provenance for file in report.files):
        flags.append(
            RiskFlag(
                code="no_provenance",
                severity="medium",
                message="No provenance bundles were found for the release files on PyPI.",
            )
        )

    if any(file.error for file in report.files) and not any(file.has_provenance for file in report.files):
        flags.append(
            RiskFlag(
                code="provenance_lookup_failed",
                severity="low",
                message="PyPI provenance lookups failed for one or more files, so attestation coverage may be incomplete.",
            )
        )

    if report.files and not any(file.publisher_identities for file in report.files):
        flags.append(
            RiskFlag(
                code="missing_publisher_identity",
                severity="medium",
                message="No Trusted Publisher identity hints were recovered from the provenance bundles.",
            )
        )

    return flags


def _recommendation_for(flags: list[RiskFlag]) -> str:
    if any(flag.severity == "high" for flag in flags):
        return "do-not-trust-without-review"
    if any(flag.severity == "medium" for flag in flags):
        return "review"
    return "looks-good"


def _normalize_repo_url(url: str | None) -> str:
    if not url:
        return ""

    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    if netloc.endswith("github.com") or netloc.endswith("gitlab.com"):
        path = path.removesuffix(".git")
        segments = [segment for segment in path.split("/") if segment]
        path = "/" + "/".join(segments[:2])

    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, params="", query="", fragment="")
    return normalized.geturl()
