from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from .malicious import (
    DEFAULT_SCORE_THRESHOLDS,
    _score_level,
    heuristic_score,
    normalize_rule_thresholds,
    normalize_score_thresholds,
)
from .models import (
    PolicyEvaluation,
    PolicyViolation,
    RiskFlag,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from .provenance import (
    publisher_matches_organization_allowlist,
    validate_publisher_organization_allowlist,
)

if TYPE_CHECKING:
    from .plugins import PluginManager

SeverityLevel = Literal["none", "medium", "high"]
ProvenanceRequirement = Literal["none", "all"]
VulnerabilityMode = Literal["ignore", "any", "critical", "kev", "fixable"]

_SEVERITY_ORDER = {"medium": 1, "high": 2}


@dataclass(slots=True)
class PolicySettings:
    profile: str = "default"
    require_verified_provenance: ProvenanceRequirement = "none"
    allow_metadata_only: bool = True
    require_expected_repository_match: bool = False
    allowed_publisher_organizations: list[str] = field(default_factory=list)
    vulnerability_mode: VulnerabilityMode = "ignore"
    fail_on_severity: SeverityLevel = "none"
    malicious_package_thresholds: dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_SCORE_THRESHOLDS)
    )
    malicious_rule_thresholds: dict[str, int] = field(default_factory=dict)
    suppressions: list[VulnerabilitySuppression] = field(default_factory=list)


BUILTIN_POLICIES: dict[str, PolicySettings] = {
    "default": PolicySettings(profile="default"),
    "strict": PolicySettings(
        profile="strict",
        require_verified_provenance="all",
        allow_metadata_only=False,
        vulnerability_mode="any",
        fail_on_severity="high",
    ),
    "internal-metadata": PolicySettings(
        profile="internal-metadata",
        allow_metadata_only=True,
        vulnerability_mode="ignore",
        fail_on_severity="none",
    ),
    "startup": PolicySettings(
        profile="startup",
        allow_metadata_only=True,
        vulnerability_mode="fixable",
        fail_on_severity="high",
    ),
    "regulated": PolicySettings(
        profile="regulated",
        require_verified_provenance="all",
        allow_metadata_only=False,
        vulnerability_mode="any",
        fail_on_severity="medium",
    ),
    "enterprise-private-index": PolicySettings(
        profile="enterprise-private-index",
        allow_metadata_only=True,
        require_expected_repository_match=True,
        vulnerability_mode="kev",
        fail_on_severity="high",
    ),
    "release-gate": PolicySettings(
        profile="release-gate",
        require_verified_provenance="all",
        allow_metadata_only=False,
        require_expected_repository_match=True,
        vulnerability_mode="fixable",
        fail_on_severity="medium",
    ),
    "open-source-maintainer": PolicySettings(
        profile="open-source-maintainer",
        allow_metadata_only=True,
        vulnerability_mode="critical",
        fail_on_severity="high",
    ),
}


def advisory_evaluation_for(report: TrustReport) -> PolicyEvaluation:
    violations: list[PolicyViolation] = []
    recommendation = "metadata-only"

    if any(flag.severity == "high" for flag in report.risk_flags):
        recommendation = "high-risk"
        violations = _violations_from_flags(report.risk_flags, minimum="high")
    elif any(flag.severity == "medium" for flag in report.risk_flags):
        recommendation = "review-required"
        violations = _violations_from_flags(report.risk_flags, minimum="medium")
    elif report.files and all(file.verified for file in report.files):
        recommendation = "verified"

    report.recommendation = recommendation
    report.policy = PolicyEvaluation(
        profile="default",
        passed=True,
        enforced=False,
        fail_on_severity="none",
        require_verified_provenance="none",
        require_expected_repository_match=False,
        allowed_publisher_organizations=[],
        allow_metadata_only=True,
        vulnerability_mode="ignore",
        suppressions_applied=0,
        suppressions_expired=0,
        violations=violations,
    )
    return report.policy


def evaluate_policy(
    report: TrustReport,
    settings: PolicySettings,
    *,
    now: datetime | None = None,
    plugin_manager: PluginManager | None = None,
) -> PolicyEvaluation:
    violations: list[PolicyViolation] = []
    settings.malicious_package_thresholds = normalize_score_thresholds(
        settings.malicious_package_thresholds
    )
    settings.malicious_rule_thresholds = normalize_rule_thresholds(
        settings.malicious_rule_thresholds
    )
    suppressions_applied, suppressions_expired = _apply_suppressions(
        report.vulnerabilities,
        settings.suppressions,
        now=now,
    )
    _apply_malicious_thresholds(report, settings)

    if settings.require_verified_provenance == "all":
        if not report.files:
            violations.append(
                PolicyViolation(
                    code="verified_provenance_required",
                    severity="high",
                    message=(
                        "Policy requires verified provenance for every artifact, "
                        "but no release files were discovered."
                    ),
                )
            )
        elif not all(file.verified for file in report.files):
            violations.append(
                PolicyViolation(
                    code="verified_provenance_required",
                    severity="high",
                    message=(
                        "Policy requires verified provenance for every artifact, "
                        "but only "
                        f"{report.coverage.verified_files}/{report.coverage.total_files} "
                        "verified."
                    ),
                )
            )

    if settings.require_expected_repository_match:
        matching_codes = {
            "expected_repository_invalid",
            "expected_repository_mismatch",
            "expected_repository_unverified",
        }
        if not report.expected_repository:
            violations.append(
                PolicyViolation(
                    code="expected_repository_required",
                    severity="high",
                    message="Policy requires an expected repository, but none was provided.",
                )
            )
        else:
            violations.extend(
                PolicyViolation(code=flag.code, severity=flag.severity, message=flag.message)
                for flag in report.risk_flags
                if flag.code in matching_codes
            )

    if settings.allowed_publisher_organizations:
        verified_identities = [
            identity
            for file in report.files
            if file.verified
            for identity in file.publisher_identities
        ]
        disallowed = [
            identity
            for identity in verified_identities
            if not publisher_matches_organization_allowlist(
                identity,
                settings.allowed_publisher_organizations,
            )
        ]
        if not verified_identities:
            violations.append(
                PolicyViolation(
                    code="publisher_organization_unverified",
                    severity="high",
                    message=(
                        "Policy requires an organization-owned verified publisher, "
                        "but no verified publisher identity was available."
                    ),
                )
            )
        elif disallowed:
            observed = sorted(
                {
                    ":".join(
                        (
                            identity.kind or "unknown",
                            identity.repository or "-",
                            identity.workflow or "-",
                        )
                    )
                    for identity in disallowed
                }
            )
            violations.append(
                PolicyViolation(
                    code="publisher_organization_not_allowed",
                    severity="high",
                    message=(
                        "Verified publisher identity is outside the allowed "
                        "organization set: "
                        + ", ".join(observed[:5])
                        + "."
                    ),
                )
            )

    blocked_vulnerabilities = [
        vulnerability
        for vulnerability in report.vulnerabilities
        if _vulnerability_is_blocked(
            vulnerability,
            mode=settings.vulnerability_mode,
        )
    ]
    if blocked_vulnerabilities:
        codes = {
            "any": "vulnerabilities_blocked",
            "critical": "critical_vulnerabilities_blocked",
            "kev": "kev_vulnerabilities_blocked",
            "fixable": "fixable_vulnerabilities_blocked",
        }
        violations.append(
            PolicyViolation(
                code=codes[settings.vulnerability_mode],
                severity="high",
                message=(
                    f"Policy vulnerability mode {settings.vulnerability_mode!r} "
                    f"blocks {len(blocked_vulnerabilities)} active, unsuppressed "
                    "vulnerability record(s): "
                    + ", ".join(
                        vulnerability.id
                        for vulnerability in blocked_vulnerabilities[:5]
                    )
                    + ("." if len(blocked_vulnerabilities) <= 5 else ", ...")
                ),
            )
        )

    if settings.fail_on_severity != "none":
        violations.extend(
            _violations_from_flags(
                [
                    flag
                    for flag in report.risk_flags
                    if flag.code != "known_vulnerabilities"
                ],
                minimum=settings.fail_on_severity,
            )
        )

    if not settings.allow_metadata_only and report.recommendation == "metadata-only":
        violations.append(
            PolicyViolation(
                code="metadata_only_not_allowed",
                severity="medium",
                message="Policy does not allow metadata-only trust decisions.",
            )
        )

    if plugin_manager is not None:
        violations.extend(plugin_manager.evaluate_policy(report))

    evaluation = PolicyEvaluation(
        profile=settings.profile,
        passed=not violations,
        enforced=True,
        fail_on_severity=settings.fail_on_severity,
        require_verified_provenance=settings.require_verified_provenance,
        require_expected_repository_match=settings.require_expected_repository_match,
        allowed_publisher_organizations=list(
            settings.allowed_publisher_organizations
        ),
        allow_metadata_only=settings.allow_metadata_only,
        vulnerability_mode=settings.vulnerability_mode,
        malicious_package_thresholds=dict(settings.malicious_package_thresholds),
        malicious_rule_thresholds=dict(settings.malicious_rule_thresholds),
        suppressions_applied=suppressions_applied,
        suppressions_expired=suppressions_expired,
        violations=_dedupe_violations(violations),
    )
    report.policy = evaluation
    if plugin_manager is not None:
        plugin_manager.attach_executions(report)
    return evaluation


def load_policy_file(path: str | Path) -> PolicySettings:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("policy file must contain a top-level JSON object")
    return policy_from_mapping(payload, profile=payload.get("profile", "file"))


def policy_from_mapping(mapping: dict[str, Any], *, profile: str | None = None) -> PolicySettings:
    allowed_fields = {field.name for field in fields(PolicySettings)}
    unknown = sorted(key for key in mapping if key not in allowed_fields)
    if unknown:
        raise ValueError(f"unknown policy setting(s): {', '.join(unknown)}")

    data = dict(mapping)
    raw_suppressions = data.get("suppressions")
    if raw_suppressions is not None:
        data["suppressions"] = _parse_suppressions(raw_suppressions)
    if profile is not None:
        data["profile"] = profile

    settings = PolicySettings(**data)
    _validate_policy_settings(settings)
    return settings


def resolve_policy(
    *,
    builtin_name: str,
    config_path: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> PolicySettings:
    if builtin_name not in BUILTIN_POLICIES:
        raise ValueError(f"unknown built-in policy: {builtin_name}")

    settings = replace(BUILTIN_POLICIES[builtin_name])
    if config_path:
        file_settings = load_policy_file(config_path)
        settings = replace(settings, **_policy_data(file_settings))
    if cli_overrides:
        overrides = {key: value for key, value in cli_overrides.items() if value is not None}
        if overrides:
            settings = replace(settings, **overrides)
    _validate_policy_settings(settings)
    return settings


def _policy_data(settings: PolicySettings) -> dict[str, Any]:
    return {field.name: getattr(settings, field.name) for field in fields(PolicySettings)}


def _validate_policy_settings(settings: PolicySettings) -> None:
    if settings.require_verified_provenance not in {"none", "all"}:
        raise ValueError("require_verified_provenance must be 'none' or 'all'")
    if settings.vulnerability_mode not in {
        "ignore",
        "any",
        "critical",
        "kev",
        "fixable",
    }:
        raise ValueError(
            "vulnerability_mode must be 'ignore', 'any', 'critical', "
            "'kev', or 'fixable'"
        )
    if settings.fail_on_severity not in {"none", "medium", "high"}:
        raise ValueError("fail_on_severity must be 'none', 'medium', or 'high'")
    settings.allowed_publisher_organizations = list(
        validate_publisher_organization_allowlist(
            settings.allowed_publisher_organizations
        )
    )
    settings.malicious_package_thresholds = normalize_score_thresholds(
        settings.malicious_package_thresholds
    )
    settings.malicious_rule_thresholds = normalize_rule_thresholds(
        settings.malicious_rule_thresholds
    )
    _validate_suppressions(settings.suppressions)


def _apply_malicious_thresholds(
    report: TrustReport,
    settings: PolicySettings,
) -> None:
    if not report.malicious_package.findings:
        report.malicious_package.score_thresholds = dict(
            settings.malicious_package_thresholds
        )
        report.malicious_package.rule_thresholds = dict(
            settings.malicious_rule_thresholds
        )
        report.malicious_package.level = _score_level(
            report.malicious_package.score,
            thresholds=settings.malicious_package_thresholds,
        )
        return

    score = heuristic_score(
        report.malicious_package.findings,
        rule_thresholds=settings.malicious_rule_thresholds,
    )
    report.malicious_package.score = score
    report.malicious_package.score_thresholds = dict(
        settings.malicious_package_thresholds
    )
    report.malicious_package.rule_thresholds = dict(
        settings.malicious_rule_thresholds
    )
    report.malicious_package.level = _score_level(
        score,
        thresholds=settings.malicious_package_thresholds,
    )
    report.risk_flags = [
        flag
        for flag in report.risk_flags
        if flag.code != "malicious_package_heuristics"
    ]
    if score < settings.malicious_package_thresholds["elevated"]:
        return
    severity = (
        "high"
        if score >= settings.malicious_package_thresholds["high"]
        else "medium"
    )
    report.risk_flags.append(
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
                    f"{finding.message} "
                    f"(rule {finding.rule_version}, "
                    f"estimated false-positive prior {finding.false_positive_rate})"
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


def _parse_suppressions(value: object) -> list[VulnerabilitySuppression]:
    if not isinstance(value, list):
        raise ValueError("suppressions must be a list")
    suppressions: list[VulnerabilitySuppression] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"suppressions[{index}] must be an object")
        allowed = {"id", "vulnerability_id", "owner", "justification", "expires"}
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ValueError(
                f"unknown suppression setting(s) at index {index}: "
                + ", ".join(unknown)
            )
        vulnerability_id = item.get("vulnerability_id") or item.get("id")
        suppressions.append(
            VulnerabilitySuppression(
                vulnerability_id=str(vulnerability_id or ""),
                owner=str(item.get("owner") or ""),
                justification=str(item.get("justification") or ""),
                expires=str(item.get("expires") or ""),
            )
        )
    return suppressions


def _validate_suppressions(
    suppressions: list[VulnerabilitySuppression],
) -> None:
    seen: set[str] = set()
    for index, suppression in enumerate(suppressions):
        identifier = suppression.vulnerability_id.strip().upper()
        if not identifier:
            raise ValueError(f"suppressions[{index}].id is required")
        if identifier in seen:
            raise ValueError(f"duplicate suppression identifier: {identifier}")
        seen.add(identifier)
        if not suppression.owner.strip():
            raise ValueError(f"suppressions[{index}].owner is required")
        if not suppression.justification.strip():
            raise ValueError(
                f"suppressions[{index}].justification is required"
            )
        if not suppression.expires.strip():
            raise ValueError(f"suppressions[{index}].expires is required")
        _suppression_expiry(suppression.expires)


def _apply_suppressions(
    vulnerabilities: list[VulnerabilityRecord],
    suppressions: list[VulnerabilitySuppression],
    *,
    now: datetime | None,
) -> tuple[int, int]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    applied = 0
    expired = 0
    for vulnerability in vulnerabilities:
        vulnerability.suppression = None
        identifiers = {
            identifier.strip().upper()
            for identifier in [vulnerability.id, *vulnerability.aliases]
            if identifier.strip()
        }
        matching = [
            suppression
            for suppression in suppressions
            if suppression.vulnerability_id.strip().upper() in identifiers
        ]
        if not matching:
            continue
        active = [
            suppression
            for suppression in matching
            if current < _suppression_expiry(suppression.expires)
        ]
        if active:
            selected = min(active, key=lambda item: _suppression_expiry(item.expires))
            vulnerability.suppression = replace(selected, status="active")
            applied += 1
            continue
        selected = max(
            matching,
            key=lambda item: _suppression_expiry(item.expires),
        )
        vulnerability.suppression = replace(selected, status="expired")
        expired += 1
    return applied, expired


def _suppression_expiry(value: str) -> datetime:
    normalized = value.strip()
    if "T" not in normalized and " " not in normalized:
        try:
            parsed_date = date.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(
                f"suppression expiration must be an ISO date or datetime: {value!r}"
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
            f"suppression expiration must be an ISO date or datetime: {value!r}"
        ) from exc
    if parsed_datetime.tzinfo is None:
        parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
    return parsed_datetime.astimezone(timezone.utc)


def _vulnerability_is_blocked(
    vulnerability: VulnerabilityRecord,
    *,
    mode: VulnerabilityMode,
) -> bool:
    if (
        mode == "ignore"
        or vulnerability.withdrawn
        or (
            vulnerability.suppression is not None
            and vulnerability.suppression.status == "active"
        )
    ):
        return False
    if mode == "any":
        return True
    if mode == "critical":
        return (
            (vulnerability.severity or "").upper() == "CRITICAL"
            or (
                vulnerability.cvss_score is not None
                and vulnerability.cvss_score >= 9.0
            )
        )
    if mode == "kev":
        return vulnerability.kev
    if mode == "fixable":
        return bool(vulnerability.fixed_in)
    return False


def _violations_from_flags(
    flags: list[RiskFlag],
    *,
    minimum: SeverityLevel,
) -> list[PolicyViolation]:
    threshold = _SEVERITY_ORDER.get(minimum, 99)
    return [
        PolicyViolation(code=flag.code, severity=flag.severity, message=flag.message)
        for flag in flags
        if _SEVERITY_ORDER.get(flag.severity, 0) >= threshold
    ]


def _dedupe_violations(violations: list[PolicyViolation]) -> list[PolicyViolation]:
    unique: list[PolicyViolation] = []
    seen: set[tuple[str, str, str]] = set()
    for violation in violations:
        key = (violation.code, violation.severity, violation.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(violation)
    return unique
