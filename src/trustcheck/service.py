from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .advisories import (
    OSV_SOURCE,
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
    parse_pypi_vulnerabilities,
)
from .artifacts import compare_artifact_metadata, inspect_artifact
from .attestations import Distribution as AttestedDistribution
from .attestations import Provenance, VerificationError
from .malicious import assess_package, finding_for_artifact
from .models import (
    ArtifactDiagnostic,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    MaliciousPackageAssessment,
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
from .provenance import SLSA_PROVENANCE_V1, analyze_slsa_provenance
from .pypi import PackageClient, PypiClient, PypiClientError
from .resolver import ArtifactReference, PipResolver, ResolutionError, TargetEnvironment

if TYPE_CHECKING:
    from .plugins import PluginManager

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

SCAN_PROFILE_NAMES = ("fast", "standard", "full")


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    collect_provenance: bool
    selected_artifacts_only: bool
    inspect_artifacts: bool
    release_history: bool
    heuristics: bool


SCAN_PROFILES = {
    "fast": ScanProfile(
        name="fast",
        collect_provenance=False,
        selected_artifacts_only=True,
        inspect_artifacts=False,
        release_history=False,
        heuristics=False,
    ),
    "standard": ScanProfile(
        name="standard",
        collect_provenance=True,
        selected_artifacts_only=True,
        inspect_artifacts=False,
        release_history=False,
        heuristics=False,
    ),
    "full": ScanProfile(
        name="full",
        collect_provenance=True,
        selected_artifacts_only=False,
        inspect_artifacts=True,
        release_history=True,
        heuristics=True,
    ),
}


class ArtifactDigestCache:
    """Share downloaded artifacts by digest and coalesce concurrent fetches."""

    def __init__(self) -> None:
        self._payloads: dict[str, bytes] = {}
        self._pending: dict[str, Future[bytes]] = {}
        self._lock = Lock()

    def fetch(
        self,
        url: str,
        expected_sha256: str | None,
        loader: Callable[[str], bytes],
    ) -> bytes:
        key = (
            f"sha256:{expected_sha256.lower()}"
            if expected_sha256
            else f"url:{url}"
        )
        with self._lock:
            cached = self._payloads.get(key)
            if cached is not None:
                return cached
            pending = self._pending.get(key)
            owner = pending is None
            if pending is None:
                pending = Future()
                self._pending[key] = pending
        if not owner:
            return pending.result()

        try:
            payload = loader(url)
            observed_digest = hashlib.new("sha256", payload).hexdigest()
            observed_key = f"sha256:{observed_digest}"
            with self._lock:
                self._payloads[observed_key] = payload
                if not expected_sha256 or expected_sha256.lower() == observed_digest:
                    self._payloads[key] = payload
            pending.set_result(payload)
            return payload
        except BaseException as exc:
            pending.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(key, None)


@dataclass(slots=True)
class DependencyTraversalContext:
    seen: set[str] = field(default_factory=set)


@dataclass(slots=True)
class PackageHistoryContext:
    project_payload: Mapping[str, object] | None = None
    previous_version: str | None = None
    previous_payload: Mapping[str, object] | None = None


class DiagnosticsCollector:
    def __init__(self) -> None:
        self._lock = Lock()
        self.request_count = 0
        self.retry_count = 0
        self.cache_hit_count = 0
        self.request_failures: list[RequestFailureDiagnostic] = []
        self.artifact_failures: list[ArtifactDiagnostic] = []

    def on_request_event(self, event: str, payload: dict[str, Any]) -> None:
        with self._lock:
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
        with self._lock:
            self.artifact_failures.append(
                ArtifactDiagnostic(
                    filename=filename,
                    stage=stage,
                    code=code,
                    subcode=subcode,
                    message=message,
                )
            )

    def to_report_diagnostics(self, client: PackageClient) -> ReportDiagnostics:
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


def _resolve_scan_profile(name: str | None) -> ScanProfile | None:
    if name is None:
        return None
    try:
        return SCAN_PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            "scan_profile must be fast, standard, or full"
        ) from exc


def inspect_package(
    project: str,
    *,
    version: str | None = None,
    expected_repository: str | None = None,
    client: PackageClient | None = None,
    progress_callback: ProgressCallback | None = None,
    dependency_progress_callback: DependencyProgressCallback | None = None,
    include_dependencies: bool = False,
    include_transitive_dependencies: bool = False,
    include_vulnerabilities: bool = True,
    include_osv: bool = False,
    vulnerability_only: bool = False,
    inspect_artifacts: bool = False,
    osv_client: OsvClient | None = None,
    vulnerability_client: VulnerabilityIntelligenceClient | None = None,
    locked_versions: Mapping[str, str] | None = None,
    resolver: PipResolver | None = None,
    target_environment: TargetEnvironment | None = None,
    complete_locked_versions: bool = False,
    expected_artifacts: Sequence[ArtifactReference] = (),
    dependency_confusion_indexes: Sequence[str] = (),
    trusted_projects: Sequence[str] = (),
    plugin_manager: PluginManager | None = None,
    scan_profile: str | None = None,
    max_workers: int = 1,
    artifact_cache: ArtifactDigestCache | None = None,
    artifact_executor: Executor | None = None,
    _dependency_context: DependencyTraversalContext | None = None,
) -> TrustReport:
    profile = _resolve_scan_profile(scan_profile)
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")
    if profile is not None:
        vulnerability_only = not profile.collect_provenance
        inspect_artifacts = profile.inspect_artifacts
    client = client or PypiClient()
    diagnostics = DiagnosticsCollector()
    dependency_context = _dependency_context or DependencyTraversalContext()
    dependency_context.seen.add(canonicalize_name(project))
    dependency_inspection_requested = include_dependencies or include_transitive_dependencies
    normalized_locked_versions: dict[str, str] = {
        str(canonicalize_name(name)): str(locked_version)
        for name, locked_version in (locked_versions or {}).items()
    }

    if dependency_inspection_requested and not normalized_locked_versions:
        root_requirement = f"{project}=={version}" if version else project
        try:
            resolution = (resolver or PipResolver()).resolve_requirements(
                [root_requirement],
                target=target_environment,
                offline=bool(getattr(client, "offline", False)),
            )
        except ResolutionError as exc:
            raise PypiClientError(
                f"unable to resolve dependencies for {root_requirement!r}: {exc}",
                transient=False,
                code="dependency",
                subcode="resolution_failed",
            ) from exc
        normalized_locked_versions = resolution.versions
        selected_root_version = normalized_locked_versions.get(canonicalize_name(project))
        if selected_root_version is None:
            raise PypiClientError(
                f"dependency resolver did not return the root package {project!r}",
                transient=False,
                code="dependency",
                subcode="root_missing",
            )
        version = selected_root_version
        complete_locked_versions = True

    with _instrument_client(client, diagnostics.on_request_event):
        payload = client.get_release(project, version) if version else client.get_project(project)
        info = payload.get("info", {})
        selected_version = payload.get("info", {}).get("version") or version or "unknown"
        declared_dependencies = _extract_declared_dependencies(info.get("requires_dist"))
        declared_repository_urls = _extract_repository_urls(info.get("project_urls") or {})
        vulnerabilities: list[VulnerabilityRecord] = []
        if include_vulnerabilities:
            vulnerabilities = _parse_vulnerabilities(
                payload.get("vulnerabilities") or []
            )
            if include_osv and vulnerability_client is None:
                osv_client = osv_client or OsvClient(
                    timeout=float(getattr(client, "timeout", 10.0)),
                    max_retries=int(getattr(client, "max_retries", 2)),
                    backoff_factor=float(getattr(client, "backoff_factor", 0.25)),
                    offline=bool(getattr(client, "offline", False)),
                )
                vulnerability_client = VulnerabilityIntelligenceClient(
                    providers=(
                        OsvProvider(
                            name=OSV_SOURCE,
                            client=osv_client,
                        ),
                    )
                )
            if vulnerability_client is not None:
                with _instrument_client(
                    vulnerability_client,
                    diagnostics.on_request_event,
                ):
                    vulnerabilities = vulnerability_client.query(
                        project,
                        selected_version,
                        vulnerabilities,
                    )
        ownership = info.get("ownership") or {}
        package_url = (
            client.package_url(project, selected_version)
            if hasattr(client, "package_url")
            else f"https://pypi.org/project/{project}/{selected_version}/"
        )
        if vulnerability_only:
            report = TrustReport(
                project=project,
                version=selected_version,
                summary=info.get("summary"),
                package_url=package_url,
                declared_dependencies=declared_dependencies,
                declared_repository_urls=declared_repository_urls,
                repository_urls=declared_repository_urls,
                ownership=ownership,
                vulnerabilities=vulnerabilities,
                diagnostics=diagnostics.to_report_diagnostics(client),
            )
            report.risk_flags = _build_risk_flags(report)
            advisory_evaluation_for(report)
            report.diagnostics = diagnostics.to_report_diagnostics(client)
            return report

        files = _collect_files(
            project,
            selected_version,
            payload,
            client,
            progress_callback=progress_callback,
            diagnostics=diagnostics,
            inspect_artifacts=inspect_artifacts,
            expected_requires_dist=declared_dependencies,
            expected_artifacts=expected_artifacts,
            plugin_manager=plugin_manager,
            selected_artifacts_only=(
                profile.selected_artifacts_only if profile is not None else False
            ),
            max_workers=max_workers,
            artifact_cache=artifact_cache,
            artifact_executor=artifact_executor,
        )
        if inspect_artifacts:
            compare_artifact_metadata(file.artifact for file in files)
        history = (
            _load_package_history(project, selected_version, client)
            if profile is None or profile.release_history
            else PackageHistoryContext()
        )
        artifact_findings = [
            finding_for_artifact(finding, file.filename)
            for file in files
            for finding in file.artifact.heuristic_findings
        ]

        report = TrustReport(
            project=project,
            version=selected_version,
            summary=info.get("summary"),
            package_url=package_url,
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
                history=history,
                max_workers=max_workers,
                artifact_cache=artifact_cache,
                artifact_executor=artifact_executor,
            ),
            malicious_package=(
                assess_package(
                    project,
                    current_info=info,
                    current_ownership=ownership,
                    current_repositories=declared_repository_urls,
                    project_payload=history.project_payload,
                    previous_payload=history.previous_payload,
                    dependency_confusion_indexes=dependency_confusion_indexes,
                    artifact_findings=artifact_findings,
                    artifact_analysis=inspect_artifacts,
                    trusted_projects=trusted_projects,
                )
                if profile is None or profile.heuristics
                else MaliciousPackageAssessment()
            ),
            diagnostics=diagnostics.to_report_diagnostics(client),
        )
        if dependency_inspection_requested:
            report.dependencies = _inspect_dependencies(
                report,
                client,
                dependency_context=dependency_context,
                dependency_progress_callback=dependency_progress_callback,
                recursive=include_transitive_dependencies,
                include_vulnerabilities=include_vulnerabilities,
                include_osv=include_osv,
                inspect_artifacts=inspect_artifacts,
                osv_client=osv_client,
                vulnerability_client=vulnerability_client,
                locked_versions=normalized_locked_versions,
                complete_locked_versions=complete_locked_versions,
                trusted_projects=trusted_projects,
                plugin_manager=plugin_manager,
                max_workers=max_workers,
                artifact_cache=artifact_cache,
                artifact_executor=artifact_executor,
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
    client: PackageClient,
    *,
    progress_callback: ProgressCallback | None = None,
    diagnostics: DiagnosticsCollector | None = None,
    inspect_artifacts: bool = False,
    expected_requires_dist: list[str] | None = None,
    expected_artifacts: Sequence[ArtifactReference] = (),
    plugin_manager: PluginManager | None = None,
    selected_artifacts_only: bool = False,
    max_workers: int = 1,
    artifact_cache: ArtifactDigestCache | None = None,
    artifact_executor: Executor | None = None,
) -> list[FileProvenance]:
    urls = payload.get("urls") or []
    selected_urls = _select_expected_artifacts(
        urls,
        expected_artifacts,
        selected_only=selected_artifacts_only,
    )
    cache = artifact_cache or ArtifactDigestCache()
    total_files = len(selected_urls)
    for index, (item, matched_artifacts) in enumerate(selected_urls, start=1):
        if progress_callback is not None:
            progress_callback(item.get("filename") or "", index, total_files)

    def submit(executor: Executor) -> list[Future[FileProvenance]]:
        return [
            executor.submit(
                _collect_file,
                project,
                version,
                item,
                matched_artifacts,
                client,
                diagnostics=diagnostics,
                inspect_artifacts=inspect_artifacts,
                expected_requires_dist=expected_requires_dist,
                plugin_manager=plugin_manager,
                artifact_cache=cache,
            )
            for item, matched_artifacts in selected_urls
        ]

    if artifact_executor is not None:
        return [future.result() for future in submit(artifact_executor)]
    workers = min(max_workers, max(1, total_files))
    if workers == 1:
        return [
            _collect_file(
                project,
                version,
                item,
                matched_artifacts,
                client,
                diagnostics=diagnostics,
                inspect_artifacts=inspect_artifacts,
                expected_requires_dist=expected_requires_dist,
                plugin_manager=plugin_manager,
                artifact_cache=cache,
            )
            for item, matched_artifacts in selected_urls
        ]
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="trustcheck-artifact",
    ) as executor:
        return [future.result() for future in submit(executor)]


def _collect_file(
    project: str,
    version: str,
    item: Mapping[str, Any],
    matched_artifacts: Sequence[ArtifactReference],
    client: PackageClient,
    *,
    diagnostics: DiagnosticsCollector | None,
    inspect_artifacts: bool,
    expected_requires_dist: list[str] | None,
    plugin_manager: PluginManager | None,
    artifact_cache: ArtifactDigestCache,
) -> FileProvenance:
    filename = str(item.get("filename") or "")
    provenance = FileProvenance(
        filename=filename,
        url=str(item.get("url") or ""),
        sha256=_expected_sha256(item, matched_artifacts),
        has_provenance=False,
    )

    def download() -> bytes:
        return artifact_cache.fetch(
            provenance.url,
            provenance.sha256,
            client.download_distribution,
        )

    artifact_bytes: bytes | None = None
    download_error: PypiClientError | None = None
    if any(
        artifact.hashes or artifact.size is not None
        for artifact in matched_artifacts
    ):
        try:
            artifact_bytes = download()
            _verify_locked_artifact(
                provenance,
                artifact_bytes,
                matched_artifacts,
            )
        except (PypiClientError, VerificationError) as exc:
            provenance.error = str(exc)
            if diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="lockfile-hash",
                    code=(
                        exc.code
                        if isinstance(exc, PypiClientError)
                        else "verification"
                    ),
                    subcode=(
                        exc.subcode
                        if isinstance(exc, PypiClientError)
                        else "lockfile_hash_mismatch"
                    ),
                    message=str(exc),
                )
    if inspect_artifacts:
        try:
            if artifact_bytes is None:
                artifact_bytes = download()
            provenance.observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            provenance.artifact = inspect_artifact(
                filename,
                artifact_bytes,
                expected_project=project,
                expected_version=version,
                expected_requires_dist=expected_requires_dist,
            )
            if plugin_manager is not None:
                provenance.artifact.heuristic_findings.extend(
                    plugin_manager.analyze_artifact(
                        filename=filename,
                        payload=artifact_bytes,
                        project=project,
                        version=version,
                        inspection=provenance.artifact,
                    )
                )
            if provenance.artifact.error and diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="artifact-inspection",
                    code="artifact",
                    subcode="archive_invalid",
                    message=provenance.artifact.error,
                )
        except PypiClientError as exc:
            download_error = exc
            provenance.artifact.inspected = True
            if _is_wheel(filename):
                provenance.artifact.kind = "wheel"
            elif _is_sdist(filename):
                provenance.artifact.kind = "sdist"
            provenance.artifact.error = str(exc)
            if diagnostics is not None:
                diagnostics.add_artifact_failure(
                    filename=filename,
                    stage="artifact-download",
                    code=exc.code,
                    subcode=exc.subcode,
                    message=str(exc),
                )
    try:
        prov_payload = client.get_provenance(project, version, filename)
        attestation_provenance = Provenance.model_validate(prov_payload)
        bundles = attestation_provenance.attestation_bundles
        provenance.has_provenance = bool(bundles)
        provenance.attestation_count = sum(len(bundle.attestations) for bundle in bundles)
        provenance.publisher_identities = _parse_publisher_identities(bundles)

        if bundles:
            if artifact_bytes is None:
                if download_error is not None:
                    raise download_error
                artifact_bytes = download()
            provenance.observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            if provenance.sha256 and provenance.observed_sha256 != provenance.sha256:
                raise VerificationError(
                    "downloaded artifact digest does not match PyPI metadata"
                )

            dist = AttestedDistribution(
                name=filename,
                digest=provenance.observed_sha256,
            )
            for bundle in bundles:
                for attestation in bundle.attestations:
                    predicate_type, predicate = attestation.verify(
                        bundle.publisher,
                        dist,
                    )
                    if (
                        predicate_type == SLSA_PROVENANCE_V1
                        and predicate is not None
                    ):
                        provenance.slsa_provenance.append(
                            analyze_slsa_provenance(
                                predicate,
                                publisher_kind=bundle.publisher.kind,
                                publisher_repository=getattr(
                                    bundle.publisher,
                                    "repository",
                                    None,
                                ),
                                publisher_workflow=(
                                    getattr(bundle.publisher, "workflow", None)
                                    or getattr(
                                        bundle.publisher,
                                        "workflow_filepath",
                                        None,
                                    )
                                ),
                            )
                        )
                    provenance.verified_attestation_count += 1

        provenance.verified = (
            provenance.has_provenance
            and provenance.attestation_count > 0
            and provenance.verified_attestation_count
            == provenance.attestation_count
        )
        if provenance.has_provenance and not provenance.verified:
            raise VerificationError("no attestations were successfully verified")
    except PypiClientError as exc:
        if provenance.error is None:
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
        if provenance.error is None:
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
        if provenance.error is None:
            provenance.error = f"attestation verification failed: {exc}"
        if diagnostics is not None:
            diagnostics.add_artifact_failure(
                filename=filename,
                stage="verification",
                code="verification",
                subcode="unexpected_verification_error",
                message=str(exc),
            )
    return provenance


def _select_expected_artifacts(
    urls: Sequence[dict[str, Any]],
    expected_artifacts: Sequence[ArtifactReference],
    *,
    selected_only: bool = False,
) -> list[tuple[dict[str, Any], tuple[ArtifactReference, ...]]]:
    if not expected_artifacts:
        available: list[
            tuple[dict[str, Any], tuple[ArtifactReference, ...]]
        ] = [(item, ()) for item in urls]
        if not selected_only or not available:
            return available
        return [min(available, key=lambda candidate: _artifact_preference(candidate[0]))]
    selected: list[tuple[dict[str, Any], tuple[ArtifactReference, ...]]] = []
    for item in urls:
        filename = item.get("filename")
        url = item.get("url")
        digests = item.get("digests")
        release_hashes = (
            {
                str(algorithm).lower(): str(digest).lower()
                for algorithm, digest in digests.items()
                if digest is not None
            }
            if isinstance(digests, dict)
            else {}
        )
        matches = tuple(
            artifact
            for artifact in expected_artifacts
            if _artifact_matches_release_file(
                artifact,
                filename=filename,
                url=url,
                release_hashes=release_hashes,
            )
        )
        if matches:
            selected.append((item, matches))
    if not selected:
        raise ValueError(
            "none of the release artifacts match the filenames, URLs, or hashes "
            "recorded by the lockfile"
        )
    return selected


def _artifact_preference(item: Mapping[str, Any]) -> tuple[bool, int, str]:
    filename = str(item.get("filename") or "")
    package_type = str(item.get("packagetype") or "")
    if package_type == "bdist_wheel" or filename.endswith(".whl"):
        kind = 0
    elif package_type == "sdist" or _is_sdist(filename):
        kind = 1
    else:
        kind = 2
    return bool(item.get("yanked")), kind, filename


def _artifact_matches_release_file(
    artifact: ArtifactReference,
    *,
    filename: object,
    url: object,
    release_hashes: Mapping[str, str],
) -> bool:
    if artifact.filename and artifact.filename == filename:
        return True
    if artifact.url and artifact.url == url:
        return True
    if artifact.filename or artifact.url:
        return False
    return any(
        release_hashes.get(algorithm.lower()) == digest.lower()
        for algorithm, digest in artifact.hashes
    )


def _expected_hash_mapping(
    artifacts: Sequence[ArtifactReference],
) -> dict[str, list[str]]:
    expected: dict[str, list[str]] = {}
    for artifact in artifacts:
        for algorithm, digest in artifact.hashes:
            values = expected.setdefault(algorithm.lower(), [])
            if digest.lower() not in values:
                values.append(digest.lower())
    return expected


def _expected_sha256(
    item: Mapping[str, Any],
    artifacts: Sequence[ArtifactReference],
) -> str | None:
    expected = _expected_hash_mapping(artifacts).get("sha256", [])
    if len(expected) == 1:
        return expected[0]
    digests = item.get("digests")
    if isinstance(digests, dict):
        digest = digests.get("sha256")
        return str(digest) if digest is not None else None
    return None


def _verify_locked_artifact(
    provenance: FileProvenance,
    artifact_bytes: bytes,
    artifacts: Sequence[ArtifactReference],
) -> None:
    expected_size = next(
        (
            artifact.size
            for artifact in artifacts
            if artifact.size is not None
        ),
        None,
    )
    if expected_size is not None and len(artifact_bytes) != expected_size:
        raise VerificationError(
            f"locked artifact size mismatch: expected {expected_size}, "
            f"observed {len(artifact_bytes)}"
        )
    expected_hashes = _expected_hash_mapping(artifacts)
    for algorithm, allowed_digests in expected_hashes.items():
        try:
            observed = hashlib.new(algorithm, artifact_bytes).hexdigest()
        except ValueError as exc:
            raise VerificationError(
                f"lockfile uses unsupported hash algorithm {algorithm!r}"
            ) from exc
        if observed not in allowed_digests:
            raise VerificationError(
                f"locked artifact {algorithm} digest mismatch"
            )
    provenance.observed_sha256 = hashlib.sha256(artifact_bytes).hexdigest()


@contextmanager
def _instrument_client(
    client: Any,
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
    return parse_pypi_vulnerabilities(items)


def _extract_declared_dependencies(requires_dist: object) -> list[str]:
    if not isinstance(requires_dist, list):
        return []
    return [str(item) for item in requires_dist if isinstance(item, str) and item.strip()]


def _inspect_dependencies(
    report: TrustReport,
    client: PackageClient,
    *,
    dependency_context: DependencyTraversalContext,
    dependency_progress_callback: DependencyProgressCallback | None = None,
    recursive: bool,
    include_vulnerabilities: bool,
    include_osv: bool,
    inspect_artifacts: bool,
    osv_client: OsvClient | None,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    locked_versions: Mapping[str, str],
    complete_locked_versions: bool,
    trusted_projects: Sequence[str],
    plugin_manager: PluginManager | None,
    max_workers: int,
    artifact_cache: ArtifactDigestCache | None,
    artifact_executor: Executor | None,
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
            include_vulnerabilities=include_vulnerabilities,
            include_osv=include_osv,
            inspect_artifacts=inspect_artifacts,
            osv_client=osv_client,
            vulnerability_client=vulnerability_client,
            locked_versions=locked_versions,
            complete_locked_versions=complete_locked_versions,
            trusted_projects=trusted_projects,
            plugin_manager=plugin_manager,
            max_workers=max_workers,
            artifact_cache=artifact_cache,
            artifact_executor=artifact_executor,
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
    client: PackageClient,
    *,
    dependency_context: DependencyTraversalContext,
    parent: tuple[str, str],
    depth: int,
    environment: dict[str, str],
    dependency_progress_callback: DependencyProgressCallback | None = None,
    include_vulnerabilities: bool,
    include_osv: bool,
    inspect_artifacts: bool,
    osv_client: OsvClient | None,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    locked_versions: Mapping[str, str],
    complete_locked_versions: bool,
    trusted_projects: Sequence[str],
    plugin_manager: PluginManager | None,
    max_workers: int,
    artifact_cache: ArtifactDigestCache | None,
    artifact_executor: Executor | None,
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

    project_name = requirement.name
    dependency_key = canonicalize_name(project_name)
    locked_version = locked_versions.get(dependency_key)
    if complete_locked_versions:
        if locked_version is None:
            return None, []
    elif requirement.marker is not None and not requirement.marker.evaluate(environment):
        return None, []

    if dependency_key in dependency_context.seen:
        return None, []
    dependency_context.seen.add(dependency_key)
    if dependency_progress_callback is not None:
        dependency_progress_callback(project_name, depth, 0, False)

    try:
        if locked_version is not None:
            selected_version = _validate_locked_dependency_version(
                requirement,
                locked_version,
            )
        else:
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
            include_vulnerabilities=include_vulnerabilities,
            include_osv=include_osv,
            inspect_artifacts=inspect_artifacts,
            osv_client=osv_client,
            vulnerability_client=vulnerability_client,
            _dependency_context=dependency_context,
            locked_versions=locked_versions,
            complete_locked_versions=complete_locked_versions,
            trusted_projects=trusted_projects,
            plugin_manager=plugin_manager,
            max_workers=max_workers,
            artifact_cache=artifact_cache,
            artifact_executor=artifact_executor,
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


def _validate_locked_dependency_version(requirement: Requirement, locked_version: str) -> str:
    try:
        parsed = Version(locked_version)
    except InvalidVersion as exc:
        raise PypiClientError(
            f"locked version {locked_version!r} for dependency "
            f"{requirement.name!r} is invalid",
            transient=False,
            code="dependency",
            subcode="locked_version_invalid",
        ) from exc
    if requirement.specifier and not requirement.specifier.contains(
        parsed,
        prereleases=True,
    ):
        raise PypiClientError(
            f"locked version {locked_version!r} for dependency "
            f"{requirement.name!r} does not satisfy {requirement.specifier}",
            transient=False,
            code="dependency",
            subcode="locked_version_conflict",
        )
    return locked_version


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
    invalid_records = [
        file
        for file in report.files
        if file.artifact.inspected
        and file.artifact.kind == "wheel"
        and file.artifact.record_valid is False
    ]
    native_artifacts = [
        file for file in report.files if file.artifact.native_files
    ]
    metadata_mismatches = [
        file for file in report.files if file.artifact.metadata_mismatches
    ]
    suspicious_artifacts = [
        file
        for file in report.files
        if file.artifact.suspicious_entry_points or file.artifact.suspicious_files
    ]
    invalid_lock_hashes = [
        failure
        for failure in report.diagnostics.artifact_failures
        if failure.stage == "lockfile-hash"
    ]

    if report.malicious_package.score >= 25:
        severity = "high" if report.malicious_package.score >= 50 else "medium"
        flags.append(
            RiskFlag(
                code="malicious_package_heuristics",
                severity=severity,
                message=(
                    "Static analysis found malicious-package heuristic indicators; "
                    "this is not proof of malware."
                ),
                why=[
                    (
                        f"{finding.code}"
                        f"{f' at {finding.location}' if finding.location else ''}: "
                        f"{finding.message}"
                    )
                    for finding in report.malicious_package.findings[:5]
                ],
                remediation=[
                    "Review the cited source, metadata, index, and native-code evidence.",
                    "Confirm package ownership and repository history through an "
                    "independent trusted channel.",
                    "Analyze high-scoring artifacts in an isolated sandbox before use.",
                ],
            )
        )

    if invalid_lock_hashes:
        flags.append(
            RiskFlag(
                code="lockfile_hash_mismatch",
                severity="high",
                message="One or more artifacts failed lockfile integrity verification.",
                why=[
                    *[
                        f"{failure.filename}: {failure.message}"
                        for failure in invalid_lock_hashes
                    ][:5],
                ],
                remediation=[
                    "Do not install an artifact that does not match the lockfile.",
                    "Regenerate the lockfile only after confirming the intended source.",
                ],
            )
        )

    if invalid_records:
        flags.append(
            RiskFlag(
                code="wheel_record_invalid",
                severity="high",
                message="One or more wheels failed RECORD integrity validation.",
                why=[
                    *[
                        f"{file.filename}: {error}"
                        for file in invalid_records
                        for error in file.artifact.record_errors[:3]
                    ][:5],
                ],
                remediation=[
                    "Do not install a wheel whose RECORD hashes or file list are invalid.",
                    "Download the artifact again and compare it with the publisher's release.",
                ],
            )
        )

    if native_artifacts:
        flags.append(
            RiskFlag(
                code="artifact_contains_native_code",
                severity="medium",
                message="One or more release artifacts contain native code.",
                why=[
                    *[
                        f"{file.filename}: {native_file}"
                        for file in native_artifacts
                        for native_file in file.artifact.native_files[:3]
                    ][:5],
                    "Native extensions require platform-specific review and cannot "
                    "be assessed as Python source alone.",
                ],
                remediation=[
                    "Confirm the native extension is expected for this package and platform.",
                    "Prefer artifacts built by a trusted workflow with verified provenance.",
                ],
            )
        )

    if metadata_mismatches:
        flags.append(
            RiskFlag(
                code="metadata_mismatch",
                severity="high",
                message="Artifact package metadata does not match the selected release.",
                why=[
                    *[
                        f"{file.filename}: {mismatch}"
                        for file in metadata_mismatches
                        for mismatch in file.artifact.metadata_mismatches[:3]
                    ][:5],
                ],
                remediation=[
                    "Do not install artifacts whose Name, Version, or dependency metadata "
                    "does not match the release.",
                    "Confirm that the wheel and sdist were built from the same source release.",
                ],
            )
        )

    if suspicious_artifacts:
        flags.append(
            RiskFlag(
                code="suspicious_entry_point",
                severity="medium",
                message="Artifact inspection found a suspicious executable entry point or script.",
                why=[
                    *[
                        f"{file.filename}: {finding}"
                        for file in suspicious_artifacts
                        for finding in (
                            file.artifact.suspicious_entry_points
                            + file.artifact.suspicious_files
                        )[:3]
                    ][:5],
                ],
                remediation=[
                    "Review the referenced entry point or script without executing it.",
                    "Confirm that install-time or command execution behavior is expected.",
                ],
            )
        )

    active_vulnerabilities = [
        vulnerability
        for vulnerability in report.vulnerabilities
        if not vulnerability.withdrawn
    ]
    if active_vulnerabilities:
        flags.append(
            RiskFlag(
                code="known_vulnerabilities",
                severity="high",
                message=(
                    f"Advisory sources report {len(active_vulnerabilities)} active "
                    "vulnerability record(s) for this release."
                ),
                why=[
                    "Configured advisory sources returned "
                    f"{len(active_vulnerabilities)} active vulnerability record(s) "
                    "for this version.",
                    *[
                        f"{vuln.id}: {vuln.summary}"
                        for vuln in active_vulnerabilities[:3]
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
        mismatches = [
            label
            for label, consistent in (
                (
                    "builder identity",
                    report.provenance_consistency.builder_consistent,
                ),
                (
                    "source commit",
                    report.provenance_consistency.source_commit_consistent,
                ),
                (
                    "build type",
                    report.provenance_consistency.build_type_consistent,
                ),
            )
            if consistent is False
        ]
        if not mismatches:
            mismatches.append("publisher repository or workflow identity")
        flags.append(
            RiskFlag(
                code="sdist_wheel_provenance_mismatch",
                severity="high",
                message=(
                    "Verified sdist and wheel provenance do not agree on their "
                    "source or build identity."
                ),
                why=[
                    "Mismatched fields: " + ", ".join(mismatches) + ".",
                ],
                remediation=[
                    "Inspect both artifacts separately before installation.",
                    "Ask the maintainer why different build sources or "
                    "workflows produced the release files.",
                ],
            )
        )

    deep_issues: dict[tuple[str, str], list[str]] = {}
    for file in report.files:
        if not file.verified:
            continue
        for assessment in file.slsa_provenance:
            for issue in assessment.issues:
                key = (issue.code, issue.severity)
                evidence = deep_issues.setdefault(key, [])
                details = ", ".join(issue.evidence)
                evidence.append(
                    f"{file.filename}: {issue.message}"
                    + (f" ({details})" if details else "")
                )
    for (code, severity), evidence in sorted(deep_issues.items()):
        messages = {
            "mutable_workflow_reference": (
                "Verified SLSA provenance uses a mutable workflow reference."
            ),
            "missing_workflow_reference": (
                "Verified SLSA provenance does not identify the workflow revision."
            ),
            "unpinned_build_actions": (
                "Verified SLSA provenance contains build actions that are not "
                "pinned to immutable commits."
            ),
            "weak_material_digest": (
                "Verified SLSA provenance contains build materials without a "
                "strong digest."
            ),
        }
        flags.append(
            RiskFlag(
                code=code,
                severity=severity,
                message=messages.get(code, "SLSA provenance requires review."),
                why=evidence[:5],
                remediation=[
                    "Pin workflows and build actions to full commit digests.",
                    "Require strong digests for every resolved build material.",
                ],
            )
        )

    deep_values = {
        "source repository": _collect_verified_slsa_values(
            report.files,
            "source_repository",
        ),
        "source commit": _collect_verified_slsa_values(
            report.files,
            "source_commit",
        ),
    }
    inconsistent_sources = [
        f"{label}: {', '.join(sorted(values))}"
        for label, values in deep_values.items()
        if len(values) > 1
    ]
    if inconsistent_sources:
        flags.append(
            RiskFlag(
                code="release_slsa_source_inconsistency",
                severity="high",
                message=(
                    "Verified artifacts in the same release were attributed to "
                    "different SLSA source repositories or commits."
                ),
                why=inconsistent_sources,
                remediation=[
                    "Do not treat the release as a single reproducible artifact set.",
                    "Confirm every artifact was built from the intended release commit.",
                ],
            )
        )

    build_values = {
        "builder": _collect_verified_slsa_values(report.files, "builder_id"),
        "build type": _collect_verified_slsa_values(report.files, "build_type"),
        "workflow": _collect_verified_slsa_values(report.files, "workflow_path"),
    }
    inconsistent_builds = [
        f"{label}: {', '.join(sorted(values))}"
        for label, values in build_values.items()
        if len(values) > 1
    ]
    if inconsistent_builds:
        flags.append(
            RiskFlag(
                code="release_slsa_build_inconsistency",
                severity="medium",
                message=(
                    "Verified artifacts in the same release use different SLSA "
                    "builders, build types, or workflows."
                ),
                why=inconsistent_builds,
                remediation=[
                    "Confirm the release intentionally uses multiple build paths.",
                    "Review each builder and workflow trust boundary independently.",
                ],
            )
        )

    slsa_sources = {
        assessment.source_repository
        for file in report.files
        if file.verified
        for assessment in file.slsa_provenance
        if assessment.source_repository
    }
    declared_sources = {
        normalized
        for url in report.declared_repository_urls
        if (normalized := _normalize_repo_url(url))
    }
    if slsa_sources and declared_sources and not slsa_sources <= declared_sources:
        flags.append(
            RiskFlag(
                code="slsa_source_repository_mismatch",
                severity="high",
                message=(
                    "The verified SLSA source repository conflicts with package "
                    "metadata."
                ),
                why=[
                    "Verified SLSA sources: " + ", ".join(sorted(slsa_sources)),
                    "Declared repositories: " + ", ".join(sorted(declared_sources)),
                ],
                remediation=[
                    "Confirm the release was built from the declared source repository.",
                    "Treat unexplained source-to-metadata inconsistencies as a "
                    "supply-chain warning.",
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

    if report.release_drift.signer_drift:
        flags.append(
            RiskFlag(
                code="provenance_signer_drift",
                severity="high",
                message="Verified provenance signer identity changed since the prior release.",
                why=[
                    f"Compared with {report.release_drift.compared_to_version}.",
                    "Previous signers: "
                    f"{', '.join(report.release_drift.previous_signers) or 'unknown'}",
                ],
                remediation=[
                    "Confirm the publisher identity or ownership transfer independently.",
                    "Review the release workflow and repository permissions.",
                ],
            )
        )

    if report.release_drift.builder_drift:
        flags.append(
            RiskFlag(
                code="provenance_builder_drift",
                severity="medium",
                message="The verified SLSA builder identity changed since the prior release.",
                why=[
                    "Previous builders: "
                    f"{', '.join(report.release_drift.previous_builders) or 'unknown'}",
                ],
                remediation=[
                    "Review the builder migration and its trust configuration.",
                ],
            )
        )

    if report.release_drift.build_type_drift:
        flags.append(
            RiskFlag(
                code="provenance_build_type_drift",
                severity="medium",
                message="The verified SLSA build type changed since the prior release.",
                why=[
                    "Previous build types: "
                    f"{', '.join(report.release_drift.previous_build_types) or 'unknown'}",
                ],
                remediation=[
                    "Review whether the release process intentionally changed.",
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
    sdist_builders = _collect_verified_slsa_values(sdist_files, "builder_id")
    wheel_builders = _collect_verified_slsa_values(wheel_files, "builder_id")
    sdist_source_commits = _collect_verified_slsa_values(
        sdist_files,
        "source_commit",
    )
    wheel_source_commits = _collect_verified_slsa_values(
        wheel_files,
        "source_commit",
    )
    sdist_build_types = _collect_verified_slsa_values(sdist_files, "build_type")
    wheel_build_types = _collect_verified_slsa_values(wheel_files, "build_type")

    repository_overlap = sorted(sdist_repositories & wheel_repositories)
    workflow_overlap = sorted(sdist_workflows & wheel_workflows)
    builder_overlap = sorted(sdist_builders & wheel_builders)
    source_commit_overlap = sorted(sdist_source_commits & wheel_source_commits)
    build_type_overlap = sorted(sdist_build_types & wheel_build_types)
    builder_consistent = _optional_set_overlap(sdist_builders, wheel_builders)
    source_commit_consistent = _optional_set_overlap(
        sdist_source_commits,
        wheel_source_commits,
    )
    build_type_consistent = _optional_set_overlap(
        sdist_build_types,
        wheel_build_types,
    )
    identity_consistent = bool(repository_overlap) and (
        not sdist_workflows and not wheel_workflows or bool(workflow_overlap)
    )
    consistent = identity_consistent and all(
        value is not False
        for value in (
            builder_consistent,
            source_commit_consistent,
            build_type_consistent,
        )
    )

    return ProvenanceConsistency(
        has_sdist=True,
        has_wheel=True,
        sdist_wheel_consistent=consistent,
        consistent_repositories=repository_overlap,
        consistent_workflows=workflow_overlap,
        builder_consistent=builder_consistent,
        source_commit_consistent=source_commit_consistent,
        build_type_consistent=build_type_consistent,
        consistent_builders=builder_overlap,
        consistent_source_commits=source_commit_overlap,
        consistent_build_types=build_type_overlap,
    )


def _build_release_drift_summary(
    project: str,
    version: str,
    client: PackageClient,
    *,
    current_files: list[FileProvenance],
    history: PackageHistoryContext,
    max_workers: int = 1,
    artifact_cache: ArtifactDigestCache | None = None,
    artifact_executor: Executor | None = None,
) -> ReleaseDriftSummary:
    previous_version = history.previous_version
    if not previous_version:
        return ReleaseDriftSummary()

    try:
        if history.previous_payload is None:
            return ReleaseDriftSummary(compared_to_version=previous_version)
        previous_files = _collect_files(
            project,
            previous_version,
            dict(history.previous_payload),
            client,
            max_workers=max_workers,
            artifact_cache=artifact_cache,
            artifact_executor=artifact_executor,
        )
    except PypiClientError:
        return ReleaseDriftSummary(compared_to_version=previous_version)

    current_repositories = _collect_verified_identity_values(current_files, "repository")
    current_workflows = _collect_verified_identity_values(current_files, "workflow")
    previous_repositories = _collect_verified_identity_values(previous_files, "repository")
    previous_workflows = _collect_verified_identity_values(previous_files, "workflow")
    current_signers = _collect_verified_signers(current_files)
    previous_signers = _collect_verified_signers(previous_files)
    current_builders = _collect_verified_slsa_values(current_files, "builder_id")
    previous_builders = _collect_verified_slsa_values(previous_files, "builder_id")
    current_source_commits = _collect_verified_slsa_values(
        current_files,
        "source_commit",
    )
    previous_source_commits = _collect_verified_slsa_values(
        previous_files,
        "source_commit",
    )
    current_build_types = _collect_verified_slsa_values(current_files, "build_type")
    previous_build_types = _collect_verified_slsa_values(previous_files, "build_type")

    repository_drift = _optional_set_difference(
        current_repositories,
        previous_repositories,
    )
    workflow_drift = _optional_set_difference(current_workflows, previous_workflows)

    return ReleaseDriftSummary(
        compared_to_version=previous_version,
        publisher_repository_drift=repository_drift,
        publisher_workflow_drift=workflow_drift,
        signer_drift=_optional_set_difference(current_signers, previous_signers),
        builder_drift=_optional_set_difference(current_builders, previous_builders),
        source_commit_drift=_optional_set_difference(
            current_source_commits,
            previous_source_commits,
        ),
        build_type_drift=_optional_set_difference(
            current_build_types,
            previous_build_types,
        ),
        previous_signers=sorted(previous_signers),
        previous_repositories=sorted(previous_repositories),
        previous_workflows=sorted(previous_workflows),
        previous_builders=sorted(previous_builders),
        previous_source_commits=sorted(previous_source_commits),
        previous_build_types=sorted(previous_build_types),
    )


def _load_package_history(
    project: str,
    version: str,
    client: PackageClient,
) -> PackageHistoryContext:
    try:
        project_payload = client.get_project(project)
    except PypiClientError:
        return PackageHistoryContext()
    previous_version = _previous_release_version_from_payload(
        project_payload,
        version,
    )
    if previous_version is None:
        return PackageHistoryContext(project_payload=project_payload)
    try:
        previous_payload = client.get_release(project, previous_version)
    except PypiClientError:
        previous_payload = None
    return PackageHistoryContext(
        project_payload=project_payload,
        previous_version=previous_version,
        previous_payload=previous_payload,
    )


def _previous_release_version(
    project: str,
    version: str,
    client: PackageClient,
) -> str | None:
    try:
        project_payload = client.get_project(project)
    except PypiClientError:
        return None

    return _previous_release_version_from_payload(project_payload, version)


def _previous_release_version_from_payload(
    project_payload: Mapping[str, object],
    version: str,
) -> str | None:
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


def _collect_verified_slsa_values(
    files: list[FileProvenance],
    attribute: str,
) -> set[str]:
    values: set[str] = set()
    for file in files:
        if not file.verified:
            continue
        for provenance in file.slsa_provenance:
            value = getattr(provenance, attribute, None)
            if value:
                values.add(str(value))
    return values


def _optional_set_overlap(left: set[str], right: set[str]) -> bool | None:
    if not left and not right:
        return None
    return bool(left & right)


def _optional_set_difference(left: set[str], right: set[str]) -> bool | None:
    if not left and not right:
        return None
    return left != right


def _collect_verified_signers(files: list[FileProvenance]) -> set[str]:
    return {
        ":".join(
            (
                identity.kind or "unknown",
                identity.repository or "-",
                identity.workflow or "-",
            )
        )
        for file in files
        if file.verified
        for identity in file.publisher_identities
    }


def _is_sdist(filename: str) -> bool:
    return filename.endswith((".tar.gz", ".zip"))


def _is_wheel(filename: str) -> bool:
    return filename.endswith(".whl")
