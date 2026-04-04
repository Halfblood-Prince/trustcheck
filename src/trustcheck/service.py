from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

from pypi_attestations import Provenance, VerificationError
from pypi_attestations import Distribution as AttestedDistribution

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


def _parse_publisher_identities(bundles: list[Any]) -> list[PublisherIdentity]:
    identities: list[PublisherIdentity] = []

    for bundle in bundles:
        publisher = getattr(bundle, "publisher", None)
        if publisher is None:
            continue

        raw = publisher.model_dump() if hasattr(publisher, "model_dump") else {}
        kind = str(getattr(publisher, "kind", None) or raw.get("issuer") or "unknown")
        repository = _publisher_repository_url(kind, getattr(publisher, "repository", None))
        workflow = getattr(publisher, "workflow", None) or getattr(publisher, "workflow_filepath", None)
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
                    message="The expected repository does not match declared project metadata or observed publisher identity hints.",
                )
            )
        elif report.files and not verified_publisher_matches:
            flags.append(
                RiskFlag(
                    code="expected_repository_unverified",
                    severity="high",
                    message="No verified attestation binds the release artifact to the expected repository.",
                )
            )

    if report.files and all(not file.has_provenance for file in report.files):
        flags.append(
            RiskFlag(
                code="no_provenance",
                severity="high",
                message="No provenance bundles were found for the release files on PyPI, so the artifacts cannot be verified.",
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
                message="Every release artifact must have a valid attestation bound to its exact digest and publisher identity.",
            )
        )

    if report.files and not any(file.publisher_identities for file in report.files):
        flags.append(
            RiskFlag(
                code="missing_publisher_identity",
                severity="high",
                message="No Trusted Publisher identity information was recovered from the provenance bundles.",
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
    if not parsed.scheme and not parsed.netloc:
        if url.count("/") == 1:
            return _normalize_repo_url(f"https://github.com/{url}")
        return url.rstrip("/")
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    if netloc.endswith("github.com") or netloc.endswith("gitlab.com"):
        path = path.removesuffix(".git")
        segments = [segment for segment in path.split("/") if segment]
        path = "/" + "/".join(segments[:2])

    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path, params="", query="", fragment="")
    return normalized.geturl()


def _publisher_repository_url(kind: str, repository: str | None) -> str | None:
    if not repository:
        return repository
    if repository.startswith(("http://", "https://")):
        return repository
    kind_normalized = kind.lower()
    if "github" in kind_normalized:
        return f"https://github.com/{repository}"
    if "gitlab" in kind_normalized:
        return f"https://gitlab.com/{repository}"
    return repository
