from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

from .cli_models import ScanTarget
from .export_models import SARIF_SCHEMA, package_purl
from .manifest import (
    ManifestVerificationResult,
    _native_files,
    _observed_publishers,
    _observed_repositories,
    _observed_slsa,
    _target_origin,
    normalize_manifest,
    verify_manifest,
)
from .models import TrustReport, VulnerabilityRecord

TRUST_DIFF_SCHEMA = "urn:trustcheck:diff:1.0"
SEVERITY_ORDER = {"LOW": 1, "MED": 2, "HIGH": 3}
SARIF_LEVELS = {"LOW": "note", "MED": "warning", "HIGH": "error"}


@dataclass(slots=True)
class TrustDiffFinding:
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(slots=True)
class TrustDiffChange:
    project: str
    change_type: str
    old_version: str | None
    new_version: str | None
    requested: bool = False
    source: str | None = None
    line: int | None = None
    old_index_origin: str | None = None
    new_index_origin: str | None = None
    old_source_type: str | None = None
    new_source_type: str | None = None
    findings: list[TrustDiffFinding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if not self.findings:
            return "LOW"
        return max(
            (finding.severity for finding in self.findings),
            key=lambda severity: SEVERITY_ORDER.get(severity, 0),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "change_type": self.change_type,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "requested": self.requested,
            "source": self.source,
            "line": self.line,
            "old_index_origin": self.old_index_origin,
            "new_index_origin": self.new_index_origin,
            "old_source_type": self.old_source_type,
            "new_source_type": self.new_source_type,
            "severity": self.severity,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class TrustDiffReport:
    old_source: str
    new_source: str
    changes: list[TrustDiffChange]
    failures: list[dict[str, str]] = field(default_factory=list)

    @property
    def package_count(self) -> int:
        return len(self.changes)

    @property
    def max_severity(self) -> str:
        if self.failures:
            return "HIGH"
        if not self.changes:
            return "LOW"
        return max(
            (change.severity for change in self.changes),
            key=lambda severity: SEVERITY_ORDER.get(severity, 0),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": TRUST_DIFF_SCHEMA,
            "old_source": self.old_source,
            "new_source": self.new_source,
            "package_count": self.package_count,
            "max_severity": self.max_severity,
            "changes": [change.to_dict() for change in self.changes],
            "failures": list(self.failures),
        }


def build_dependency_diff(
    old_targets: Sequence[ScanTarget],
    new_targets: Sequence[ScanTarget],
) -> list[TrustDiffChange]:
    old_by_name = _targets_by_name(old_targets)
    new_by_name = _targets_by_name(new_targets)
    changes: list[TrustDiffChange] = []
    for name in sorted(set(old_by_name) | set(new_by_name)):
        old = old_by_name.get(name)
        new = new_by_name.get(name)
        if old is None and new is not None:
            changes.append(_change_for_added(new))
            continue
        if new is None and old is not None:
            changes.append(_change_for_removed(old))
            continue
        if old is None or new is None:
            continue
        old_origin = _target_origin(old)
        new_origin = _target_origin(new)
        if (
            old.version != new.version
            or old_origin != new_origin
            or old.source_type != new.source_type
        ):
            changes.append(
                TrustDiffChange(
                    project=new.project,
                    change_type=(
                        "updated" if old.version != new.version else "source-changed"
                    ),
                    old_version=old.version,
                    new_version=new.version,
                    requested=old.requested or new.requested,
                    source=new.source_file,
                    line=new.source_line,
                    old_index_origin=old_origin,
                    new_index_origin=new_origin,
                    old_source_type=old.source_type,
                    new_source_type=new.source_type,
                )
            )
    return changes


def enrich_dependency_diff(
    changes: Sequence[TrustDiffChange],
    *,
    old_reports: Mapping[str, TrustReport],
    new_reports: Mapping[str, TrustReport],
    manifest: Mapping[str, object] | None = None,
    new_targets: Sequence[ScanTarget] = (),
) -> list[TrustDiffChange]:
    manifest_result = (
        verify_manifest(
            manifest,
            list(new_reports.values()),
            [
                target
                for target in new_targets
                if canonicalize_name(target.project) in new_reports
            ],
        )
        if manifest is not None
        else ManifestVerificationResult(0, [], [], [])
    )
    manifest_findings = _manifest_findings_by_package(manifest_result)
    enriched: list[TrustDiffChange] = []
    for change in changes:
        old_report = old_reports.get(canonicalize_name(change.project))
        new_report = new_reports.get(canonicalize_name(change.project))
        findings = [
            *change.findings,
            *_graph_findings(change),
            *_report_findings(change, old_report, new_report),
            *manifest_findings.get(canonicalize_name(change.project), []),
        ]
        if not findings and change.change_type != "removed":
            findings.append(
                TrustDiffFinding(
                    code="no_trust_regression",
                    severity="LOW",
                    message="no vulnerability or trust regression detected",
                )
            )
        enriched.append(
            TrustDiffChange(
                project=change.project,
                change_type=change.change_type,
                old_version=change.old_version,
                new_version=change.new_version,
                requested=change.requested,
                source=change.source,
                line=change.line,
                old_index_origin=change.old_index_origin,
                new_index_origin=change.new_index_origin,
                old_source_type=change.old_source_type,
                new_source_type=change.new_source_type,
                findings=findings,
            )
        )
    return sorted(
        enriched,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.severity, 0),
            canonicalize_name(item.project),
        ),
    )


def render_trust_diff_text(report: TrustDiffReport) -> str:
    lines = [_summary_line(report)]
    if report.failures:
        lines.append("")
        lines.append("failures:")
        lines.extend(
            f"  - {failure.get('requirement', 'unknown')}: {failure.get('message', '')}"
            for failure in report.failures
        )
    for change in report.changes:
        lines.append("")
        lines.append(_change_heading(change))
        for finding in change.findings:
            lines.append(f"      * {finding.message}")
    return "\n".join(lines)


def render_trust_diff_markdown(report: TrustDiffReport) -> str:
    lines = [
        "# trustcheck dependency trust diff",
        "",
        _summary_line(report),
    ]
    if report.failures:
        lines.extend(["", "## Failures"])
        lines.extend(
            f"- `{failure.get('requirement', 'unknown')}`: {failure.get('message', '')}"
            for failure in report.failures
        )
    if report.changes:
        lines.extend(["", "## Changed Packages"])
        for change in report.changes:
            lines.extend(
                [
                    "",
                    f"### {change.severity} `{change.project}` "
                    f"{_version_range(change)}",
                ]
            )
            lines.extend(f"- {finding.message}" for finding in change.findings)
    return "\n".join(lines)


def render_trust_diff_sarif(report: TrustDiffReport) -> str:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for change in report.changes:
        findings = change.findings or [
            TrustDiffFinding(
                code="package_changed",
                severity=change.severity,
                message=f"{change.project} changed.",
            )
        ]
        for finding in findings:
            rule_id = f"TC-DIFF-{_rule_token(finding.code)}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": _rule_token(finding.code),
                    "shortDescription": {"text": finding.message},
                    "fullDescription": {
                        "text": "trustcheck dependency trust diff finding"
                    },
                    "properties": {"tags": ["trustcheck", "dependency-diff"]},
                },
            )
            results.append(_sarif_result(change, finding, rule_id))
    for failure in report.failures:
        rule_id = "TC-DIFF-SCAN-FAILURE"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": "scan_failure",
                "shortDescription": {"text": "Diff evidence collection failed"},
                "fullDescription": {
                    "text": "trustcheck could not inspect a changed dependency"
                },
                "properties": {"tags": ["trustcheck", "dependency-diff"]},
            },
        )
        identity = failure.get("requirement", "unknown")
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": failure.get("message", "unknown failure")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(report.new_source)}
                        }
                    }
                ],
                "partialFingerprints": {
                    "trustcheck/v1": _stable_digest(
                        "diff-failure",
                        report.new_source,
                        identity,
                    )
                },
                "properties": {
                    "category": "dependency-diff",
                    "requirement": identity,
                },
            }
        )
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trustcheck",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "automationDetails": {
                    "id": f"trustcheck-diff/{_stable_digest(report.new_source)[:16]}"
                },
                "results": sorted(
                    results,
                    key=lambda item: (
                        str(item["ruleId"]),
                        str(item["partialFingerprints"]["trustcheck/v1"]),
                    ),
                ),
                "properties": {
                    "trustcheck.schema": TRUST_DIFF_SCHEMA,
                    "trustcheck.oldSource": report.old_source,
                    "trustcheck.newSource": report.new_source,
                    "trustcheck.packageCount": report.package_count,
                    "trustcheck.maxSeverity": report.max_severity,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def merge_manifest_exception_changes(
    changes: Sequence[TrustDiffChange],
    *,
    old_manifest: Mapping[str, object] | None,
    new_manifest: Mapping[str, object],
    source: str | None = None,
) -> list[TrustDiffChange]:
    result = list(changes)
    by_name = {
        canonicalize_name(change.project): change
        for change in result
    }
    for exception_change in manifest_exception_changes(
        old_manifest,
        new_manifest,
        source=source,
    ):
        existing = by_name.get(canonicalize_name(exception_change.project))
        if existing is None:
            result.append(exception_change)
            by_name[canonicalize_name(exception_change.project)] = exception_change
            continue
        existing.findings.extend(exception_change.findings)
    return result


def manifest_exception_changes(
    old_manifest: Mapping[str, object] | None,
    new_manifest: Mapping[str, object],
    *,
    source: str | None = None,
) -> list[TrustDiffChange]:
    new_packages = normalize_manifest(new_manifest)["packages"]
    old_packages = (
        normalize_manifest(old_manifest)["packages"]
        if old_manifest is not None
        else {}
    )
    changes: list[TrustDiffChange] = []
    for name in sorted(new_packages):
        new_package = new_packages[name]
        old_package = old_packages.get(name, {})
        if not isinstance(new_package, Mapping):
            continue
        old_exceptions = (
            _manifest_exception_set(old_package)
            if isinstance(old_package, Mapping)
            else set()
        )
        added = sorted(_manifest_exception_set(new_package) - old_exceptions)
        if not added:
            continue
        findings = [
            TrustDiffFinding(
                code="manifest_exception_added",
                severity="MED",
                message=(
                    "trust manifest exception added for "
                    f"{code} until {expires}"
                ),
            )
            for code, _owner, _reason, expires in added
        ]
        changes.append(
            TrustDiffChange(
                project=name,
                change_type="manifest-exception-added",
                old_version=_manifest_version(old_package),
                new_version=_manifest_version(new_package),
                source=source,
                findings=findings,
            )
        )
    return changes


def should_fail_diff(report: TrustDiffReport, *, fail_on: str) -> bool:
    if report.failures:
        return True
    if fail_on == "none":
        return False
    return SEVERITY_ORDER[report.max_severity] >= SEVERITY_ORDER[fail_on.upper()]


def changed_package_names(changes: Iterable[TrustDiffChange]) -> set[str]:
    return {
        canonicalize_name(change.project)
        for change in changes
        if change.change_type != "removed"
    }


def old_changed_package_names(changes: Iterable[TrustDiffChange]) -> set[str]:
    return {
        canonicalize_name(change.project)
        for change in changes
        if change.change_type in {"updated", "source-changed"}
    }


def _targets_by_name(targets: Sequence[ScanTarget]) -> dict[str, ScanTarget]:
    return {
        canonicalize_name(target.project): target
        for target in targets
        if target.failure_message is None
    }


def _change_for_added(target: ScanTarget) -> TrustDiffChange:
    return TrustDiffChange(
        project=target.project,
        change_type="added",
        old_version=None,
        new_version=target.version,
        requested=target.requested,
        source=target.source_file,
        line=target.source_line,
        new_index_origin=_target_origin(target),
        new_source_type=target.source_type,
    )


def _change_for_removed(target: ScanTarget) -> TrustDiffChange:
    return TrustDiffChange(
        project=target.project,
        change_type="removed",
        old_version=target.version,
        new_version=None,
        requested=target.requested,
        source=target.source_file,
        line=target.source_line,
        old_index_origin=_target_origin(target),
        old_source_type=target.source_type,
        findings=[
            TrustDiffFinding(
                code="package_removed",
                severity="LOW",
                message="package removed from the dependency graph",
            )
        ],
    )


def _graph_findings(change: TrustDiffChange) -> list[TrustDiffFinding]:
    findings: list[TrustDiffFinding] = []
    if change.change_type == "added":
        findings.append(
            TrustDiffFinding(
                code=(
                    "new_direct_dependency"
                    if change.requested
                    else "new_transitive_dependency"
                ),
                severity="MED" if change.requested else "HIGH",
                message=(
                    "new direct dependency introduced"
                    if change.requested
                    else "new transitive dependency introduced"
                ),
            )
        )
    if change.old_index_origin and change.new_index_origin and (
        change.old_index_origin != change.new_index_origin
    ):
        findings.append(
            TrustDiffFinding(
                code="index_origin_changed",
                severity="HIGH",
                message="private-index or package index origin changed",
            )
        )
    if change.old_source_type and change.new_source_type and (
        change.old_source_type != change.new_source_type
    ):
        findings.append(
            TrustDiffFinding(
                code="source_type_changed",
                severity="HIGH",
                message="dependency source type changed",
            )
        )
    return findings


def _report_findings(
    change: TrustDiffChange,
    old_report: TrustReport | None,
    new_report: TrustReport | None,
) -> list[TrustDiffFinding]:
    if new_report is None:
        return []
    findings: list[TrustDiffFinding] = []
    findings.extend(_vulnerability_findings(old_report, new_report))
    findings.extend(_malicious_findings(old_report, new_report))
    findings.extend(_provenance_findings(old_report, new_report))
    findings.extend(_identity_findings(old_report, new_report))
    findings.extend(_artifact_findings(old_report, new_report))
    if change.change_type == "added" and _native_files(new_report):
        findings.append(
            TrustDiffFinding(
                code="new_native_binary",
                severity="HIGH",
                message="artifact contains a native binary",
            )
        )
    return _dedupe_findings(findings)


def _vulnerability_findings(
    old_report: TrustReport | None,
    new_report: TrustReport,
) -> list[TrustDiffFinding]:
    old_ids = _vulnerability_ids(old_report.vulnerabilities if old_report else [])
    new_ids = _vulnerability_ids(new_report.vulnerabilities)
    introduced = sorted(new_ids - old_ids)
    if not introduced:
        return []
    return [
        TrustDiffFinding(
            code="new_vulnerability_signal",
            severity="HIGH",
            message=(
                "new vulnerability signal introduced: "
                + ", ".join(introduced[:5])
            ),
        )
    ]


def _malicious_findings(
    old_report: TrustReport | None,
    new_report: TrustReport,
) -> list[TrustDiffFinding]:
    old_score = old_report.malicious_package.score if old_report else 0
    new_score = new_report.malicious_package.score
    if new_score <= old_score or new_score < 25:
        return []
    return [
        TrustDiffFinding(
            code="malicious_score_increased",
            severity="HIGH" if new_score >= 50 else "MED",
            message=(
                "malicious-package heuristic score increased "
                f"from {old_score} to {new_score}"
            ),
        )
    ]


def _provenance_findings(
    old_report: TrustReport | None,
    new_report: TrustReport,
) -> list[TrustDiffFinding]:
    if new_report.coverage.files_with_provenance == 0:
        return [
            TrustDiffFinding(
                code="provenance_unavailable",
                severity="HIGH",
                message="release provenance unavailable",
            )
        ]
    if old_report and old_report.coverage.verified_files > 0 and (
        new_report.coverage.verified_files == 0
    ):
        return [
            TrustDiffFinding(
                code="verified_provenance_disappeared",
                severity="HIGH",
                message="verified provenance disappeared",
            )
        ]
    return []


def _identity_findings(
    old_report: TrustReport | None,
    new_report: TrustReport,
) -> list[TrustDiffFinding]:
    if old_report is None:
        return []
    findings: list[TrustDiffFinding] = []
    if _observed_repositories(old_report) != _observed_repositories(new_report):
        findings.append(
            TrustDiffFinding(
                code="repository_changed",
                severity="HIGH",
                message="publisher repository changed",
            )
        )
    if _observed_publishers(old_report) != _observed_publishers(new_report):
        findings.append(
            TrustDiffFinding(
                code="trusted_publisher_changed",
                severity="MED",
                message="PyPI publisher/workflow identity changed",
            )
        )
    if _observed_slsa(old_report) != _observed_slsa(new_report):
        findings.append(
            TrustDiffFinding(
                code="slsa_identity_changed",
                severity="MED",
                message="Sigstore/SLSA builder or build type changed",
            )
        )
    if old_report.ownership != new_report.ownership:
        findings.append(
            TrustDiffFinding(
                code="maintainer_metadata_changed",
                severity="MED",
                message="maintainer or ownership metadata changed",
            )
        )
    old_license = _license_value(old_report)
    new_license = _license_value(new_report)
    if old_license != new_license:
        findings.append(
            TrustDiffFinding(
                code="license_changed",
                severity="MED",
                message="declared license metadata changed",
            )
        )
    return findings


def _artifact_findings(
    old_report: TrustReport | None,
    new_report: TrustReport,
) -> list[TrustDiffFinding]:
    if old_report is None:
        return []
    findings: list[TrustDiffFinding] = []
    old_artifacts = _artifact_kinds(old_report)
    new_artifacts = _artifact_kinds(new_report)
    if old_artifacts and new_artifacts and old_artifacts != new_artifacts:
        findings.append(
            TrustDiffFinding(
                code="artifact_distribution_changed",
                severity="MED",
                message=(
                    "wheel or sdist distribution set changed "
                    f"from {_join_tokens(old_artifacts)} to "
                    f"{_join_tokens(new_artifacts)}"
                ),
            )
        )
    old_native = set(_native_files(old_report))
    new_native = set(_native_files(new_report))
    if new_native and not old_native:
        findings.append(
            TrustDiffFinding(
                code="native_binary_introduced",
                severity="HIGH",
                message="artifact now contains a native binary",
            )
        )
    return findings


def _artifact_kinds(report: TrustReport) -> set[str]:
    result: set[str] = set()
    for file in report.files:
        kind = file.artifact.kind
        if kind and kind != "unknown":
            result.add(kind)
            continue
        filename = file.filename.lower()
        if filename.endswith(".whl"):
            result.add("wheel")
        elif filename.endswith((".tar.gz", ".zip", ".tar.bz2", ".tar.xz")):
            result.add("sdist")
    return result


def _manifest_findings_by_package(
    result: ManifestVerificationResult,
) -> dict[str, list[TrustDiffFinding]]:
    by_package: dict[str, list[TrustDiffFinding]] = {}
    for issue in result.violations:
        by_package.setdefault(canonicalize_name(issue.package), []).append(
            TrustDiffFinding(
                code=f"manifest_{issue.code}",
                severity="HIGH" if issue.severity == "high" else "MED",
                message=f"trust manifest violation: {issue.message}",
            )
        )
    return by_package


def _vulnerability_ids(vulnerabilities: Iterable[VulnerabilityRecord]) -> set[str]:
    return {
        identifier.upper()
        for vulnerability in vulnerabilities
        if not vulnerability.withdrawn
        for identifier in (vulnerability.id, *vulnerability.aliases)
        if identifier
    }


def _license_value(report: TrustReport) -> str | None:
    value = report.ownership.get("license")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _dedupe_findings(findings: Sequence[TrustDiffFinding]) -> list[TrustDiffFinding]:
    result: list[TrustDiffFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.code, finding.severity, finding.message)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _manifest_exception_set(
    package: Mapping[str, object],
) -> set[tuple[str, str, str, str]]:
    raw_exceptions = package.get("exceptions", [])
    if not isinstance(raw_exceptions, list):
        return set()
    result: set[tuple[str, str, str, str]] = set()
    for item in raw_exceptions:
        if not isinstance(item, Mapping):
            continue
        result.add(
            (
                str(item.get("code", "")),
                str(item.get("owner", "")),
                str(item.get("reason", "")),
                str(item.get("expires", "")),
            )
        )
    return result


def _manifest_version(package: object) -> str | None:
    if not isinstance(package, Mapping):
        return None
    version = package.get("approved_version")
    return version if isinstance(version, str) and version else None


def _join_tokens(values: Iterable[str]) -> str:
    return ", ".join(sorted(values))


def _summary_line(report: TrustDiffReport) -> str:
    return f"{report.package_count} package{'s' if report.package_count != 1 else ''} changed"


def _change_heading(change: TrustDiffChange) -> str:
    return (
        f"{change.severity:<4} {change.project} "
        f"{_version_range(change)}"
    ).rstrip()


def _version_range(change: TrustDiffChange) -> str:
    if change.old_version and change.new_version:
        return f"{change.old_version} -> {change.new_version}"
    if change.new_version:
        return f"new {change.new_version}"
    if change.old_version:
        return f"removed {change.old_version}"
    return change.change_type


def _sarif_result(
    change: TrustDiffChange,
    finding: TrustDiffFinding,
    rule_id: str,
) -> dict[str, object]:
    uri = change.source or change.project
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": _sarif_uri(uri)}
    }
    if change.line is not None:
        physical_location["region"] = {"startLine": change.line}
    purl = (
        package_purl(change.project, change.new_version)
        if change.new_version
        else None
    )
    return {
        "ruleId": rule_id,
        "level": SARIF_LEVELS.get(finding.severity, "warning"),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": physical_location,
                "logicalLocations": [
                    {
                        "name": change.project,
                        "fullyQualifiedName": purl or change.project,
                        "kind": "package",
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "trustcheck/v1": _stable_digest(
                "diff-v1",
                finding.code,
                change.project,
                change.old_version or "",
                change.new_version or "",
                uri,
                str(change.line or ""),
            )
        },
        "properties": {
            "category": "dependency-diff",
            "project": change.project,
            "oldVersion": change.old_version,
            "newVersion": change.new_version,
            "changeType": change.change_type,
            "severity": finding.severity,
            "purl": purl,
        },
    }


def _stable_digest(*parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rule_token(value: str) -> str:
    return "".join(
        character.lower() if character.isalnum() else "_"
        for character in value.strip()
    ).strip("_") or "finding"


def _sarif_uri(value: str) -> str:
    return value.replace("\\", "/")
