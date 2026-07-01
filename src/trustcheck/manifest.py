from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import parse

from packaging.utils import canonicalize_name

from .cli_models import ScanTarget
from .indexes import DEFAULT_INDEX_URL, normalize_index_url, redact_url_credentials
from .models import PublisherIdentity, SlsaProvenance, TrustReport
from .provenance import normalize_publisher_repository, normalize_repository_uri

TRUST_MANIFEST_SCHEMA = "urn:trustcheck:manifest:1.0"
DEFAULT_TRUST_MANIFEST_PATH = "trustcheck.manifest.json"
DEFAULT_MAX_MALICIOUS_SCORE = 15


@dataclass(slots=True)
class ManifestIssue:
    package: str
    code: str
    severity: str
    message: str
    expected: str | None = None
    observed: str | None = None
    suppressed_by: str | None = None
    exception_expires: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "package": self.package,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.expected is not None:
            payload["expected"] = self.expected
        if self.observed is not None:
            payload["observed"] = self.observed
        if self.suppressed_by is not None:
            payload["suppressed_by"] = self.suppressed_by
        if self.exception_expires is not None:
            payload["exception_expires"] = self.exception_expires
        return payload


@dataclass(slots=True)
class ManifestVerificationResult:
    checked_packages: int
    violations: list[ManifestIssue]
    suppressed: list[ManifestIssue]
    warnings: list[ManifestIssue]

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": TRUST_MANIFEST_SCHEMA,
            "passed": self.passed,
            "checked_packages": self.checked_packages,
            "violations": [issue.to_dict() for issue in self.violations],
            "suppressed": [issue.to_dict() for issue in self.suppressed],
            "warnings": [issue.to_dict() for issue in self.warnings],
        }


def load_manifest(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return normalize_manifest(payload)


def write_manifest(path: str | Path, manifest: Mapping[str, object]) -> None:
    normalized = normalize_manifest(manifest)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_manifest(payload: object) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("trust manifest must contain a top-level JSON object")
    schema = payload.get("schema")
    if schema != TRUST_MANIFEST_SCHEMA:
        raise ValueError(
            "unsupported trust manifest schema: "
            f"{schema!r}; expected {TRUST_MANIFEST_SCHEMA!r}"
        )
    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, Mapping):
        raise ValueError("trust manifest field 'packages' must be an object")

    packages: dict[str, dict[str, Any]] = {}
    for raw_name, raw_package in raw_packages.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("trust manifest package names must be non-empty strings")
        if not isinstance(raw_package, Mapping):
            raise ValueError(
                f"trust manifest package {raw_name!r} must contain an object"
            )
        name = canonicalize_name(raw_name)
        if name in packages:
            raise ValueError(f"duplicate trust manifest package entry: {name}")
        package = dict(raw_package)
        package["exceptions"] = _normalize_exceptions(
            package.get("exceptions", []),
            package=name,
        )
        packages[name] = package

    normalized = dict(payload)
    normalized["schema"] = TRUST_MANIFEST_SCHEMA
    normalized["packages"] = packages
    return normalized


def build_manifest(
    reports: Sequence[TrustReport],
    targets: Sequence[ScanTarget] = (),
    *,
    existing_manifest: Mapping[str, object] | None = None,
    default_max_malicious_score: int = DEFAULT_MAX_MALICIOUS_SCORE,
) -> dict[str, Any]:
    existing_packages: Mapping[str, object] = {}
    if existing_manifest is not None:
        existing_packages = normalize_manifest(existing_manifest)["packages"]

    targets_by_name = _targets_by_name(targets)
    packages: dict[str, dict[str, Any]] = {}
    for report in sorted(reports, key=lambda item: canonicalize_name(item.project)):
        name = canonicalize_name(report.project)
        raw_existing = existing_packages.get(name)
        existing = raw_existing if isinstance(raw_existing, Mapping) else None
        packages[name] = build_package_baseline(
            report,
            targets_by_name.get(name),
            existing_package=existing,
            default_max_malicious_score=default_max_malicious_score,
        )

    return {
        "schema": TRUST_MANIFEST_SCHEMA,
        "packages": packages,
    }


def build_package_baseline(
    report: TrustReport,
    target: ScanTarget | None = None,
    *,
    existing_package: Mapping[str, object] | None = None,
    default_max_malicious_score: int = DEFAULT_MAX_MALICIOUS_SCORE,
) -> dict[str, Any]:
    origin = _target_origin(target)
    malicious_score = max(default_max_malicious_score, report.malicious_package.score)
    if existing_package is not None:
        existing_score = _optional_int(existing_package.get("max_malicious_score"))
        if existing_score is not None:
            malicious_score = max(existing_score, report.malicious_package.score)

    baseline: dict[str, Any] = {
        "approved_version": report.version,
        "require_provenance": report.coverage.files_with_provenance > 0,
        "require_verified_provenance": _verified_provenance_requirement(report),
        "min_verified_attestations": _verified_attestation_count(report),
        "permitted_indexes": [origin],
        "allow_private_indexes": _is_private_origin(origin),
        "allow_dependency_confusion": False,
        "source_type": target.source_type if target is not None else "index",
        "max_malicious_score": malicious_score,
        "allow_native_binaries": bool(_native_files(report)),
        "allow_dynamic_execution": _dynamic_execution_observed(report),
        "exceptions": [],
    }

    repository = _selected_repository(report)
    if repository is not None:
        baseline["repository"] = repository
        owner = _repository_owner(repository)
        if owner is not None:
            baseline["owner"] = owner

    publisher = _selected_publisher(report)
    if publisher:
        baseline["trusted_publisher"] = publisher

    slsa = _selected_slsa(report)
    if slsa:
        baseline["slsa"] = slsa

    if existing_package is not None:
        baseline["exceptions"] = _normalize_exceptions(
            existing_package.get("exceptions", []),
            package=report.project,
        )

    return baseline


def verify_manifest(
    manifest: Mapping[str, object],
    reports: Sequence[TrustReport],
    targets: Sequence[ScanTarget] = (),
    *,
    now: datetime | None = None,
) -> ManifestVerificationResult:
    normalized = normalize_manifest(manifest)
    manifest_packages = normalized["packages"]
    reports_by_name = {
        canonicalize_name(report.project): report
        for report in reports
    }
    targets_by_name = _targets_by_name(targets)
    current = now or datetime.now(timezone.utc)

    violations: list[ManifestIssue] = []
    suppressed: list[ManifestIssue] = []
    warnings: list[ManifestIssue] = []

    for name in sorted(reports_by_name):
        report = reports_by_name[name]
        raw_package = manifest_packages.get(name)
        if not isinstance(raw_package, Mapping):
            violations.append(
                ManifestIssue(
                    package=name,
                    code="manifest_missing_package",
                    severity="high",
                    message="Package is not present in the trust manifest.",
                    observed=f"{report.project} {report.version}",
                )
            )
            continue
        issues = _verify_package(
            name,
            raw_package,
            report,
            targets_by_name.get(name),
        )
        for issue in issues:
            exception = _active_exception(raw_package, issue.code, now=current)
            if exception is None:
                violations.append(issue)
                continue
            issue.suppressed_by = exception["owner"]
            issue.exception_expires = exception["expires"]
            suppressed.append(issue)

    for name in sorted(set(manifest_packages) - set(reports_by_name)):
        warnings.append(
            ManifestIssue(
                package=name,
                code="manifest_package_not_present",
                severity="medium",
                message="Manifest package is not present in the current dependency file.",
            )
        )

    return ManifestVerificationResult(
        checked_packages=len(reports_by_name),
        violations=violations,
        suppressed=suppressed,
        warnings=warnings,
    )


def render_manifest_verification_text(result: ManifestVerificationResult) -> str:
    lines = [
        f"trust manifest verification: {'pass' if result.passed else 'fail'}",
        f"checked packages: {result.checked_packages}",
    ]
    if not result.violations and not result.suppressed and not result.warnings:
        lines.append("No trust regressions detected.")
        return "\n".join(lines)

    if result.violations:
        lines.append("violations:")
        lines.extend(_format_issue(issue) for issue in result.violations)
    if result.suppressed:
        lines.append("suppressed:")
        lines.extend(_format_issue(issue) for issue in result.suppressed)
    if result.warnings:
        lines.append("warnings:")
        lines.extend(_format_issue(issue) for issue in result.warnings)
    return "\n".join(lines)


def _verify_package(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
    target: ScanTarget | None,
) -> list[ManifestIssue]:
    issues: list[ManifestIssue] = []
    issues.extend(_verify_repository(name, package, report))
    issues.extend(_verify_publisher(name, package, report))
    issues.extend(_verify_slsa(name, package, report))
    issues.extend(_verify_provenance(name, package, report))
    issues.extend(_verify_index_origin(name, package, target))
    issues.extend(_verify_malicious_score(name, package, report))
    issues.extend(_verify_native_binaries(name, package, report))
    issues.extend(_verify_dynamic_execution(name, package, report))
    return issues


def _verify_repository(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    issues: list[ManifestIssue] = []
    expected_repository = _optional_text(package.get("repository"))
    observed_repositories = _observed_repositories(report)
    if (
        expected_repository is not None
        and _normalize_repository(expected_repository) not in observed_repositories
    ):
        issues.append(
            ManifestIssue(
                package=name,
                code="repository_changed",
                severity="high",
                message="Approved source repository changed or disappeared.",
                expected=_normalize_repository(expected_repository),
                observed=_join_observed(observed_repositories),
            )
        )

    expected_owner = _optional_text(package.get("owner"))
    if expected_owner is None:
        return issues
    observed_owners = _observed_repository_owners(report)
    if expected_owner.lower() not in observed_owners:
        issues.append(
            ManifestIssue(
                package=name,
                code="repository_owner_changed",
                severity="high",
                message="Approved source repository owner changed or disappeared.",
                expected=expected_owner.lower(),
                observed=_join_observed(observed_owners),
            )
        )
    return issues


def _verify_publisher(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    raw_expected = package.get("trusted_publisher")
    if not isinstance(raw_expected, Mapping):
        return []

    observed = _observed_publishers(report)
    if not observed:
        return [
            ManifestIssue(
                package=name,
                code="trusted_publisher_missing",
                severity="high",
                message="Approved Trusted Publisher identity is no longer verified.",
                expected=json.dumps(dict(raw_expected), sort_keys=True),
                observed="none",
            )
        ]

    issues: list[ManifestIssue] = []
    expected_provider = _optional_text(raw_expected.get("provider"))
    if expected_provider is not None:
        providers = {item.get("provider", "") for item in observed}
        if expected_provider.lower() not in providers:
            issues.append(
                ManifestIssue(
                    package=name,
                    code="trusted_publisher_provider_changed",
                    severity="high",
                    message="Approved Trusted Publisher provider changed.",
                    expected=expected_provider.lower(),
                    observed=_join_observed(providers),
                )
            )

    expected_organization = _optional_text(raw_expected.get("organization"))
    if expected_organization is not None:
        organizations = {item.get("organization", "") for item in observed}
        if expected_organization.lower() not in organizations:
            issues.append(
                ManifestIssue(
                    package=name,
                    code="trusted_publisher_organization_changed",
                    severity="high",
                    message="Approved Trusted Publisher organization changed.",
                    expected=expected_organization.lower(),
                    observed=_join_observed(organizations),
                )
            )

    expected_workflow = _optional_text(raw_expected.get("workflow"))
    if expected_workflow is not None:
        workflows = {
            workflow
            for item in observed
            if (workflow := item.get("workflow"))
        }
        if not any(_workflow_matches(expected_workflow, workflow) for workflow in workflows):
            issues.append(
                ManifestIssue(
                    package=name,
                    code="trusted_publisher_workflow_changed",
                    severity="high",
                    message="Approved Trusted Publisher workflow changed.",
                    expected=expected_workflow,
                    observed=_join_observed(workflows),
                )
            )

    return issues


def _verify_slsa(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    raw_expected = package.get("slsa")
    if not isinstance(raw_expected, Mapping):
        return []
    observed = _observed_slsa(report)
    if not observed:
        return [
            ManifestIssue(
                package=name,
                code="slsa_provenance_missing",
                severity="high",
                message="Approved SLSA provenance is no longer verified.",
                expected=json.dumps(dict(raw_expected), sort_keys=True),
                observed="none",
            )
        ]

    issues: list[ManifestIssue] = []
    for field, code, message in (
        ("builder", "slsa_builder_changed", "Approved SLSA builder changed."),
        ("build_type", "slsa_build_type_changed", "Approved SLSA build type changed."),
    ):
        expected = _optional_text(raw_expected.get(field))
        if expected is None:
            continue
        observed_values = {
            value
            for item in observed
            if (value := item.get(field))
        }
        if expected not in observed_values:
            issues.append(
                ManifestIssue(
                    package=name,
                    code=code,
                    severity="high",
                    message=message,
                    expected=expected,
                    observed=_join_observed(observed_values),
                )
            )
    return issues


def _verify_provenance(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    issues: list[ManifestIssue] = []
    if bool(package.get("require_provenance", False)) and (
        report.coverage.files_with_provenance == 0
    ):
        issues.append(
            ManifestIssue(
                package=name,
                code="provenance_missing",
                severity="high",
                message="Required provenance disappeared.",
                expected="provenance present",
                observed=report.coverage.status,
            )
        )

    requirement = _optional_text(package.get("require_verified_provenance")) or "none"
    if requirement == "all":
        if report.coverage.total_files == 0 or (
            report.coverage.verified_files < report.coverage.total_files
        ):
            issues.append(
                ManifestIssue(
                    package=name,
                    code="provenance_coverage_regressed",
                    severity="high",
                    message="Verified provenance no longer covers every artifact.",
                    expected="all artifacts verified",
                    observed=(
                        f"{report.coverage.verified_files}/"
                        f"{report.coverage.total_files} verified"
                    ),
                )
            )
    elif requirement == "any" and report.coverage.verified_files == 0:
        issues.append(
            ManifestIssue(
                package=name,
                code="verified_provenance_missing",
                severity="high",
                message="Required verified provenance disappeared.",
                expected="at least one verified artifact",
                observed=report.coverage.status,
            )
        )

    expected_attestations = _optional_int(package.get("min_verified_attestations"))
    if expected_attestations is not None:
        observed_attestations = _verified_attestation_count(report)
        if observed_attestations < expected_attestations:
            issues.append(
                ManifestIssue(
                    package=name,
                    code="attestation_coverage_regressed",
                    severity="high",
                    message="Verified attestation coverage decreased.",
                    expected=str(expected_attestations),
                    observed=str(observed_attestations),
                )
            )
    return issues


def _verify_index_origin(
    name: str,
    package: Mapping[str, object],
    target: ScanTarget | None,
) -> list[ManifestIssue]:
    observed_origin = _target_origin(target)
    permitted = _permitted_origins(package)
    issues: list[ManifestIssue] = []
    if permitted and observed_origin not in permitted:
        issues.append(
            ManifestIssue(
                package=name,
                code="index_origin_changed",
                severity="high",
                message="Package index or artifact origin changed.",
                expected=", ".join(permitted),
                observed=observed_origin,
            )
        )

    if _is_private_origin(observed_origin) and not bool(
        package.get("allow_private_indexes", False)
    ):
        issues.append(
            ManifestIssue(
                package=name,
                code="private_index_not_allowed",
                severity="high",
                message="Package resolved from a private or non-PyPI origin.",
                expected="public PyPI origin",
                observed=observed_origin,
            )
        )

    expected_source_type = _optional_text(package.get("source_type"))
    observed_source_type = target.source_type if target is not None else "index"
    if (
        expected_source_type is not None
        and observed_source_type != expected_source_type
    ):
        issues.append(
            ManifestIssue(
                package=name,
                code="source_type_changed",
                severity="high",
                message="Package source type changed.",
                expected=expected_source_type,
                observed=observed_source_type,
            )
        )

    if (
        target is not None
        and target.dependency_confusion
        and not bool(package.get("allow_dependency_confusion", False))
    ):
        issues.append(
            ManifestIssue(
                package=name,
                code="dependency_confusion_detected",
                severity="high",
                message="Package name exists on more than one configured index.",
                expected="single approved origin",
                observed=", ".join(target.dependency_confusion),
            )
        )
    return issues


def _verify_malicious_score(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    maximum = _optional_int(package.get("max_malicious_score"))
    if maximum is None or report.malicious_package.score <= maximum:
        return []
    return [
        ManifestIssue(
            package=name,
            code="malicious_score_exceeded",
            severity="high",
            message="Malicious-package heuristic score exceeded the approved maximum.",
            expected=str(maximum),
            observed=str(report.malicious_package.score),
        )
    ]


def _verify_native_binaries(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    native_files = _native_files(report)
    if bool(package.get("allow_native_binaries", False)) or not native_files:
        return []
    return [
        ManifestIssue(
            package=name,
            code="native_binaries_introduced",
            severity="high",
            message="Native binaries appeared but are not allowed by the manifest.",
            expected="no native binaries",
            observed=", ".join(native_files[:5]),
        )
    ]


def _verify_dynamic_execution(
    name: str,
    package: Mapping[str, object],
    report: TrustReport,
) -> list[ManifestIssue]:
    if bool(package.get("allow_dynamic_execution", False)):
        return []
    if not _dynamic_execution_observed(report):
        return []
    return [
        ManifestIssue(
            package=name,
            code="dynamic_execution_introduced",
            severity="high",
            message="Dynamic artifact execution occurred but is not allowed.",
            expected="dynamic execution disabled",
            observed="dynamic analysis executed package code",
        )
    ]


def _targets_by_name(targets: Sequence[ScanTarget]) -> dict[str, ScanTarget]:
    return {
        canonicalize_name(target.project): target
        for target in targets
        if target.failure_message is None
    }


def _selected_repository(report: TrustReport) -> str | None:
    for repository in _observed_repositories(report):
        return repository
    return None


def _observed_repositories(report: TrustReport) -> set[str]:
    repositories: set[str] = set()
    for value in (*report.repository_urls, *report.declared_repository_urls):
        normalized = _normalize_repository(value)
        if normalized:
            repositories.add(normalized)
    for file in report.files:
        if not file.verified:
            continue
        for identity in file.publisher_identities:
            normalized = normalize_publisher_repository(
                identity.kind,
                identity.repository,
            )
            if normalized is not None:
                repositories.add(normalized)
        for provenance in file.slsa_provenance:
            normalized = _normalize_repository(provenance.source_repository)
            if normalized:
                repositories.add(normalized)
    return repositories


def _observed_repository_owners(report: TrustReport) -> set[str]:
    owners = {
        owner
        for repository in _observed_repositories(report)
        if (owner := _repository_owner(repository)) is not None
    }
    organization = report.ownership.get("organization")
    if isinstance(organization, str) and organization.strip():
        owners.add(organization.strip().lower())
    return owners


def _selected_publisher(report: TrustReport) -> dict[str, str]:
    for file in report.files:
        if not file.verified:
            continue
        for identity in file.publisher_identities:
            return _publisher_to_manifest(identity)
    return {}


def _observed_publishers(report: TrustReport) -> list[dict[str, str]]:
    return [
        _publisher_to_manifest(identity)
        for file in report.files
        if file.verified
        for identity in file.publisher_identities
    ]


def _publisher_to_manifest(identity: PublisherIdentity) -> dict[str, str]:
    provider = _publisher_provider(identity.kind)
    repository = normalize_publisher_repository(identity.kind, identity.repository)
    payload: dict[str, str] = {"provider": provider}
    owner = _repository_owner(repository)
    if owner is not None:
        payload["organization"] = owner
    if repository is not None:
        payload["repository"] = repository
    if identity.workflow:
        payload["workflow"] = identity.workflow
    if identity.environment:
        payload["environment"] = identity.environment
    return payload


def _publisher_provider(kind: str) -> str:
    lowered = kind.lower()
    if "github" in lowered:
        return "github"
    if "gitlab" in lowered:
        return "gitlab"
    if "circleci" in lowered:
        return "circleci"
    if "google" in lowered:
        return "google"
    return lowered or "unknown"


def _selected_slsa(report: TrustReport) -> dict[str, str]:
    for provenance in _verified_slsa_provenance(report):
        return _slsa_to_manifest(provenance)
    return {}


def _observed_slsa(report: TrustReport) -> list[dict[str, str]]:
    return [
        _slsa_to_manifest(provenance)
        for provenance in _verified_slsa_provenance(report)
    ]


def _verified_slsa_provenance(report: TrustReport) -> list[SlsaProvenance]:
    return [
        provenance
        for file in report.files
        if file.verified
        for provenance in file.slsa_provenance
        if provenance.valid
    ]


def _slsa_to_manifest(provenance: SlsaProvenance) -> dict[str, str]:
    payload: dict[str, str] = {}
    if provenance.builder_id:
        payload["builder"] = provenance.builder_id
    if provenance.build_type:
        payload["build_type"] = provenance.build_type
    if provenance.workflow_path:
        payload["workflow"] = provenance.workflow_path
    if provenance.source_repository:
        payload["source_repository"] = provenance.source_repository
    return payload


def _verified_provenance_requirement(report: TrustReport) -> str:
    if report.coverage.total_files > 0 and (
        report.coverage.verified_files == report.coverage.total_files
    ):
        return "all"
    if report.coverage.verified_files > 0:
        return "any"
    return "none"


def _verified_attestation_count(report: TrustReport) -> int:
    return sum(file.verified_attestation_count for file in report.files)


def _target_origin(target: ScanTarget | None) -> str:
    if target is None:
        return _normalize_origin(DEFAULT_INDEX_URL)
    if target.index_url:
        return _normalize_origin(target.index_url)
    for url in _target_artifact_urls(target):
        if _is_pypi_artifact_url(url):
            return _normalize_origin(DEFAULT_INDEX_URL)
        origin = _url_origin(url)
        if origin is not None:
            return _normalize_origin(origin)
    return _normalize_origin(DEFAULT_INDEX_URL)


def _target_artifact_urls(target: ScanTarget) -> list[str]:
    urls = [artifact.url for artifact in target.artifacts if artifact.url]
    if target.source_url:
        urls.append(target.source_url)
    return urls


def _url_origin(url: str) -> str | None:
    parsed = parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _normalize_origin(value: str) -> str:
    return redact_url_credentials(normalize_index_url(value))


def _is_pypi_artifact_url(url: str) -> bool:
    hostname = (parse.urlsplit(url).hostname or "").lower()
    return hostname in {"files.pythonhosted.org", "pypi.org"}


def _is_private_origin(origin: str) -> bool:
    return _normalize_origin(origin) != _normalize_origin(DEFAULT_INDEX_URL)


def _permitted_origins(package: Mapping[str, object]) -> list[str]:
    raw = package.get("permitted_indexes", [])
    if raw is None:
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("permitted_indexes must be a list of package index URLs")
    return [_normalize_origin(str(item)) for item in raw if str(item).strip()]


def _native_files(report: TrustReport) -> list[str]:
    native: set[str] = set()
    for file in report.files:
        native.update(file.artifact.native_files)
        native.update(item.path for item in file.artifact.native_binaries)
    return sorted(native)


def _dynamic_execution_observed(report: TrustReport) -> bool:
    return any(file.dynamic_analysis.executed for file in report.files)


def _normalize_repository(value: str | None) -> str:
    normalized = normalize_repository_uri(value)
    return normalized or (value.strip().lower() if value else "")


def _repository_owner(repository: str | None) -> str | None:
    normalized = normalize_repository_uri(repository) if repository else None
    if normalized is None:
        return None
    parsed = parse.urlsplit(normalized)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.hostname == "github.com" and len(parts) >= 2:
        return parts[0].lower()
    if parsed.hostname == "gitlab.com" and len(parts) >= 2:
        return "/".join(parts[:-1]).lower()
    return None


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _normalize_exceptions(value: object, *, package: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"trust manifest exceptions for {package!r} must be a list")
    exceptions: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(
                f"trust manifest exception {package}[{index}] must be an object"
            )
        code = _optional_text(item.get("code"))
        owner = _optional_text(item.get("owner"))
        reason = _optional_text(item.get("reason"))
        expires = _optional_text(item.get("expires"))
        if code is None:
            raise ValueError(f"trust manifest exception {package}[{index}].code is required")
        if owner is None:
            raise ValueError(f"trust manifest exception {package}[{index}].owner is required")
        if reason is None:
            raise ValueError(
                f"trust manifest exception {package}[{index}].reason is required"
            )
        if expires is None:
            raise ValueError(
                f"trust manifest exception {package}[{index}].expires is required"
            )
        _exception_expiry(expires)
        exceptions.append(
            {
                "code": code,
                "owner": owner,
                "reason": reason,
                "expires": expires,
            }
        )
    return exceptions


def _active_exception(
    package: Mapping[str, object],
    code: str,
    *,
    now: datetime,
) -> dict[str, str] | None:
    exceptions = _normalize_exceptions(package.get("exceptions", []), package="package")
    for exception in exceptions:
        if exception["code"] not in {code, "*"}:
            continue
        if _normalize_datetime(now) < _exception_expiry(exception["expires"]):
            return exception
    return None


def _exception_expiry(value: str) -> datetime:
    normalized = value.strip()
    if "T" not in normalized and " " not in normalized:
        try:
            parsed_date = date.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(
                f"manifest exception expiration must be an ISO date or datetime: {value!r}"
            ) from exc
        return datetime.combine(
            parsed_date + timedelta(days=1),
            time.min,
            tzinfo=timezone.utc,
        )
    try:
        parsed_datetime = datetime.fromisoformat(
            normalized.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"manifest exception expiration must be an ISO date or datetime: {value!r}"
        ) from exc
    return _normalize_datetime(parsed_datetime)


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _workflow_matches(expected: str, observed: str) -> bool:
    expected_path = expected.replace("\\", "/").strip("/")
    observed_path = observed.replace("\\", "/").strip("/")
    return (
        observed_path == expected_path
        or observed_path.endswith(f"/{expected_path}")
        or observed_path.rsplit("/", 1)[-1] == expected_path.rsplit("/", 1)[-1]
    )


def _join_observed(values: Sequence[str] | set[str]) -> str:
    cleaned = sorted(value for value in values if value)
    return ", ".join(cleaned) if cleaned else "none"


def _format_issue(issue: ManifestIssue) -> str:
    detail = f"  - {issue.package}: {issue.message} ({issue.code})"
    if issue.expected is not None:
        detail += f" expected={issue.expected}"
    if issue.observed is not None:
        detail += f" observed={issue.observed}"
    if issue.suppressed_by is not None:
        detail += (
            f" suppressed_by={issue.suppressed_by}"
            f" expires={issue.exception_expires}"
        )
    return detail
