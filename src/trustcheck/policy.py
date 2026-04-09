from __future__ import annotations

import json
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any, Literal

from .models import PolicyEvaluation, PolicyViolation, RiskFlag, TrustReport

SeverityLevel = Literal["none", "medium", "high"]
ProvenanceRequirement = Literal["none", "all"]
VulnerabilityMode = Literal["ignore", "any"]

_SEVERITY_ORDER = {"medium": 1, "high": 2}


@dataclass(slots=True)
class PolicySettings:
    profile: str = "default"
    require_verified_provenance: ProvenanceRequirement = "none"
    allow_metadata_only: bool = True
    require_expected_repository_match: bool = False
    vulnerability_mode: VulnerabilityMode = "ignore"
    fail_on_severity: SeverityLevel = "none"


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
}


def advisory_evaluation_for(report: TrustReport) -> PolicyEvaluation:
    violations: list[PolicyViolation] = []
    recommendation = "metadata-only"

    if any(flag.severity == "high" for flag in report.risk_flags):
        recommendation = "high-risk"
        violations = _violations_from_flags(report.risk_flags, minimum="high")
    elif report.files and all(file.verified for file in report.files):
        recommendation = "verified"
    elif any(flag.severity == "medium" for flag in report.risk_flags):
        recommendation = "review-required"
        violations = _violations_from_flags(report.risk_flags, minimum="medium")

    report.recommendation = recommendation
    report.policy = PolicyEvaluation(
        profile="default",
        passed=True,
        enforced=False,
        fail_on_severity="none",
        require_verified_provenance="none",
        require_expected_repository_match=False,
        allow_metadata_only=True,
        vulnerability_mode="ignore",
        violations=violations,
    )
    return report.policy


def evaluate_policy(report: TrustReport, settings: PolicySettings) -> PolicyEvaluation:
    violations: list[PolicyViolation] = []

    if settings.require_verified_provenance == "all":
        if not report.files:
            violations.append(
                PolicyViolation(
                    code="verified_provenance_required",
                    severity="high",
                    message="Policy requires verified provenance for every artifact, but no release files were discovered.",
                )
            )
        elif not all(file.verified for file in report.files):
            violations.append(
                PolicyViolation(
                    code="verified_provenance_required",
                    severity="high",
                    message=(
                        "Policy requires verified provenance for every artifact, "
                        f"but only {report.coverage.verified_files}/{report.coverage.total_files} verified."
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

    if settings.vulnerability_mode == "any" and report.vulnerabilities:
        violations.append(
            PolicyViolation(
                code="vulnerabilities_blocked",
                severity="high",
                message=(
                    "Policy blocks releases with any known vulnerabilities; "
                    f"PyPI reported {len(report.vulnerabilities)} vulnerability record(s)."
                ),
            )
        )

    if settings.fail_on_severity != "none":
        violations.extend(_violations_from_flags(report.risk_flags, minimum=settings.fail_on_severity))

    if not settings.allow_metadata_only and report.recommendation == "metadata-only":
        violations.append(
            PolicyViolation(
                code="metadata_only_not_allowed",
                severity="medium",
                message="Policy does not allow metadata-only trust decisions.",
            )
        )

    evaluation = PolicyEvaluation(
        profile=settings.profile,
        passed=not violations,
        enforced=True,
        fail_on_severity=settings.fail_on_severity,
        require_verified_provenance=settings.require_verified_provenance,
        require_expected_repository_match=settings.require_expected_repository_match,
        allow_metadata_only=settings.allow_metadata_only,
        vulnerability_mode=settings.vulnerability_mode,
        violations=_dedupe_violations(violations),
    )
    report.policy = evaluation
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
    if settings.vulnerability_mode not in {"ignore", "any"}:
        raise ValueError("vulnerability_mode must be 'ignore' or 'any'")
    if settings.fail_on_severity not in {"none", "medium", "high"}:
        raise ValueError("fail_on_severity must be 'none', 'medium', or 'high'")


def _violations_from_flags(flags: list[RiskFlag], *, minimum: SeverityLevel) -> list[PolicyViolation]:
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
