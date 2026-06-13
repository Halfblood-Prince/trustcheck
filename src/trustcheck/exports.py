from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path, PureWindowsPath
from typing import Any, Final
from urllib import parse
from xml.etree import ElementTree  # nosec B405

from packaging.utils import canonicalize_name

from .contract import deserialize_report
from .models import HeuristicFinding, TrustReport, VulnerabilityRecord
from .resolver import ArtifactReference

OUTPUT_FORMATS: Final = (
    "text",
    "json",
    "sarif",
    "cyclonedx-json",
    "cyclonedx-xml",
    "spdx-json",
    "openvex",
    "markdown",
)
INDUSTRY_OUTPUT_FORMATS: Final = OUTPUT_FORMATS[2:]
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)
CYCLONEDX_NAMESPACE = "http://cyclonedx.org/schema/bom/1.6"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    uri: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ExportPackage:
    report: TrustReport
    source: SourceLocation | None = None
    artifacts: tuple[ArtifactReference, ...] = ()

    @property
    def purl(self) -> str:
        return package_purl(self.report.project, self.report.version)


def package_purl(project: str, version: str) -> str:
    name = parse.quote(canonicalize_name(project), safe=".-_~")
    encoded_version = parse.quote(version, safe=".-_~+")
    return f"pkg:pypi/{name}@{encoded_version}"


def recommended_extension(output_format: str) -> str:
    extensions = {
        "text": ".txt",
        "json": ".json",
        "sarif": ".sarif",
        "cyclonedx-json": ".cdx.json",
        "cyclonedx-xml": ".cdx.xml",
        "spdx-json": ".spdx.json",
        "openvex": ".openvex.json",
        "markdown": ".md",
    }
    try:
        return extensions[output_format]
    except KeyError as exc:
        raise ValueError(f"unsupported output format: {output_format}") from exc


def render_export(
    output_format: str,
    packages: Sequence[ExportPackage],
    *,
    source_name: str,
    failures: Sequence[Mapping[str, str]] = (),
    generated_at: datetime | None = None,
) -> str:
    timestamp = _timestamp(generated_at)
    if output_format == "sarif":
        payload = _sarif_document(packages, source_name, failures)
        return _json_text(payload)
    if output_format == "cyclonedx-json":
        payload = _cyclonedx_document(packages, source_name, failures, timestamp)
        return _json_text(payload)
    if output_format == "cyclonedx-xml":
        return _cyclonedx_xml(packages, source_name, failures, timestamp)
    if output_format == "spdx-json":
        payload = _spdx_document(packages, source_name, failures, timestamp)
        return _json_text(payload)
    if output_format == "openvex":
        payload = _openvex_document(packages, source_name, timestamp)
        return _json_text(payload)
    if output_format == "markdown":
        return _markdown_document(packages, source_name, failures)
    raise ValueError(f"unsupported industry output format: {output_format}")


def render_payload_export(
    output_format: str,
    payload: Mapping[str, object],
    *,
    generated_at: datetime | None = None,
) -> str:
    packages, source_name, failures = export_packages_from_payload(payload)
    return render_export(
        output_format,
        packages,
        source_name=source_name,
        failures=failures,
        generated_at=generated_at,
    )


def export_packages_from_payload(
    payload: Mapping[str, object],
) -> tuple[list[ExportPackage], str, list[dict[str, str]]]:
    report_payload = payload.get("report")
    if isinstance(report_payload, Mapping):
        report = deserialize_report(report_payload)
        return [
            ExportPackage(
                report=report,
                source=SourceLocation(report.package_url),
            )
        ], f"{report.project} {report.version}", []

    raw_reports = payload.get("reports")
    if not isinstance(raw_reports, list):
        raise ValueError("trustcheck payload has no report or reports collection")
    source_name = str(payload.get("file") or "trustcheck scan")
    resolved = _resolved_export_metadata(payload.get("resolved"))
    packages: list[ExportPackage] = []
    for raw_report in raw_reports:
        if not isinstance(raw_report, Mapping):
            continue
        report = deserialize_report(raw_report)
        metadata = resolved.get(
            (canonicalize_name(report.project), report.version),
            {},
        )
        source_uri = metadata.get("source_file")
        source_line = metadata.get("source_line")
        raw_artifacts = metadata.get("artifacts")
        artifacts = (
            tuple(raw_artifacts)
            if isinstance(raw_artifacts, list)
            and all(
                isinstance(item, ArtifactReference)
                for item in raw_artifacts
            )
            else ()
        )
        packages.append(
            ExportPackage(
                report=report,
                source=SourceLocation(
                    str(source_uri or source_name),
                    int(source_line) if isinstance(source_line, int) else None,
                ),
                artifacts=artifacts,
            )
        )
    raw_failures = payload.get("failures")
    failures = [
        {
            "requirement": str(item.get("requirement") or "unknown"),
            "message": str(item.get("message") or "unknown failure"),
        }
        for item in raw_failures
        if isinstance(item, Mapping)
    ] if isinstance(raw_failures, list) else []
    return packages, source_name, failures


def _resolved_export_metadata(
    value: object,
) -> dict[tuple[str, str], dict[str, object]]:
    if not isinstance(value, list):
        return {}
    metadata: dict[tuple[str, str], dict[str, object]] = {}
    for item in value:
        if not isinstance(item, Mapping):
            continue
        project = item.get("project")
        version = item.get("version")
        if not isinstance(project, str) or not isinstance(version, str):
            continue
        artifacts: list[ArtifactReference] = []
        raw_artifacts = item.get("artifacts")
        if isinstance(raw_artifacts, list):
            for raw_artifact in raw_artifacts:
                if not isinstance(raw_artifact, Mapping):
                    continue
                raw_hashes = raw_artifact.get("hashes")
                hashes = (
                    tuple(
                        sorted(
                            (str(algorithm), str(digest))
                            for algorithm, digest in raw_hashes.items()
                        )
                    )
                    if isinstance(raw_hashes, Mapping)
                    else ()
                )
                artifacts.append(
                    ArtifactReference(
                        filename=_optional_str(raw_artifact.get("filename")),
                        url=_optional_str(raw_artifact.get("url")),
                        path=_optional_str(raw_artifact.get("path")),
                        hashes=hashes,
                        size=(
                            int(raw_artifact["size"])
                            if isinstance(raw_artifact.get("size"), int)
                            else None
                        ),
                        kind=str(raw_artifact.get("kind") or "archive"),
                    )
                )
        metadata[(canonicalize_name(project), version)] = {
            "artifacts": artifacts,
            "source_file": item.get("source_file"),
            "source_line": item.get("source_line"),
        }
    return metadata


def _sarif_document(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, object]] = {}
    for package in packages:
        report = package.report
        for vulnerability in report.vulnerabilities:
            rule_id = "TC-VULNERABILITY"
            _add_sarif_rule(
                rules,
                rule_id,
                "Known vulnerability",
                "A configured advisory source reported a vulnerability.",
                ("security", "vulnerability"),
            )
            results.append(
                _sarif_result(
                    package,
                    rule_id=rule_id,
                    category="vulnerability",
                    identity=vulnerability.id,
                    level=_sarif_level(vulnerability.severity),
                    message=f"{vulnerability.id}: {vulnerability.summary}",
                    properties={
                        "vulnerabilityId": vulnerability.id,
                        "aliases": vulnerability.aliases,
                        "source": vulnerability.source,
                        "severity": vulnerability.severity,
                        "cvssScore": vulnerability.cvss_score,
                        "cvssVector": vulnerability.cvss_vector,
                        "cvssVersion": vulnerability.cvss_version,
                        "cwes": vulnerability.cwes,
                        "fixedIn": vulnerability.fixed_in,
                        "advisory": vulnerability.link,
                        "withdrawn": vulnerability.withdrawn,
                        "withdrawnAt": vulnerability.withdrawn_at,
                        "cisaKev": vulnerability.kev,
                        "kevDateAdded": vulnerability.kev_date_added,
                        "kevDueDate": vulnerability.kev_due_date,
                        "kevRequiredAction": vulnerability.kev_required_action,
                        "epssScore": vulnerability.epss_score,
                        "epssPercentile": vulnerability.epss_percentile,
                        "epssDate": vulnerability.epss_date,
                        "suppression": (
                            {
                                "owner": vulnerability.suppression.owner,
                                "justification": (
                                    vulnerability.suppression.justification
                                ),
                                "expires": vulnerability.suppression.expires,
                                "status": vulnerability.suppression.status,
                            }
                            if vulnerability.suppression is not None
                            else None
                        ),
                    },
                )
            )
        for finding in report.malicious_package.findings:
            rule_id = f"TC-HEURISTIC-{_rule_token(finding.code)}"
            _add_sarif_rule(
                rules,
                rule_id,
                finding.code,
                finding.message,
                ("security", "supply-chain", "heuristic", finding.category),
            )
            location = _heuristic_source_location(package, finding)
            results.append(
                _sarif_result_for_location(
                    location,
                    purl=package.purl,
                    project=report.project,
                    version=report.version,
                    rule_id=rule_id,
                    category="malicious-package-heuristic",
                    identity=(
                        f"{finding.code}:{finding.artifact or ''}:"
                        f"{finding.location or ''}"
                    ),
                    level=_sarif_level(finding.severity),
                    message=f"{finding.message} This is a heuristic, not proof of malware.",
                    properties={
                        "heuristic": True,
                        "confidence": finding.confidence,
                        "score": finding.score,
                        "category": finding.category,
                        "evidence": finding.evidence,
                        "artifact": finding.artifact,
                        "assessmentScore": report.malicious_package.score,
                        "assessmentLevel": report.malicious_package.level,
                        "disclaimer": report.malicious_package.disclaimer,
                    },
                )
            )
        for risk_flag in report.risk_flags:
            rule_id = f"TC-RISK-{_rule_token(risk_flag.code)}"
            _add_sarif_rule(
                rules,
                rule_id,
                risk_flag.code,
                risk_flag.message,
                ("security", "supply-chain", "risk"),
            )
            results.append(
                _sarif_result(
                    package,
                    rule_id=rule_id,
                    category="risk",
                    identity=risk_flag.code,
                    level=_sarif_level(risk_flag.severity),
                    message=risk_flag.message,
                    properties={
                        "severity": risk_flag.severity,
                        "why": risk_flag.why,
                        "remediation": risk_flag.remediation,
                    },
                )
            )
        for violation in report.policy.violations:
            rule_id = f"TC-POLICY-{_rule_token(violation.code)}"
            _add_sarif_rule(
                rules,
                rule_id,
                violation.code,
                violation.message,
                ("policy",),
            )
            results.append(
                _sarif_result(
                    package,
                    rule_id=rule_id,
                    category="policy",
                    identity=violation.code,
                    level=_sarif_level(violation.severity),
                    message=violation.message,
                    properties={
                        "severity": violation.severity,
                        "profile": report.policy.profile,
                    },
                )
            )
        for artifact_failure in report.diagnostics.artifact_failures:
            rule_id = (
                f"TC-ARTIFACT-{_rule_token(artifact_failure.subcode)}"
            )
            _add_sarif_rule(
                rules,
                rule_id,
                artifact_failure.subcode,
                artifact_failure.message,
                ("artifact", "integrity"),
            )
            results.append(
                _sarif_result(
                    package,
                    rule_id=rule_id,
                    category="artifact",
                    identity=(
                        f"{artifact_failure.subcode}:"
                        f"{artifact_failure.filename}"
                    ),
                    level="error",
                    message=(
                        f"{artifact_failure.filename}: "
                        f"{artifact_failure.message}"
                    ),
                    properties={
                        "filename": artifact_failure.filename,
                        "stage": artifact_failure.stage,
                        "code": artifact_failure.code,
                        "subcode": artifact_failure.subcode,
                        "hashes": _artifact_hashes_for_filename(
                            package,
                            artifact_failure.filename,
                        ),
                    },
                )
            )
        for file in report.files:
            if file.verified:
                continue
            rule_id = "TC-PROVENANCE-UNVERIFIED"
            _add_sarif_rule(
                rules,
                rule_id,
                "Artifact provenance is not verified",
                "The release artifact did not have fully verified provenance.",
                ("provenance", "supply-chain"),
            )
            results.append(
                _sarif_result(
                    package,
                    rule_id=rule_id,
                    category="provenance",
                    identity=file.filename,
                    level="warning" if file.has_provenance else "note",
                    message=(
                        f"{file.filename} provenance was not fully verified"
                        + (f": {file.error}" if file.error else "")
                    ),
                    properties={
                        "filename": file.filename,
                        "hasProvenance": file.has_provenance,
                        "verified": file.verified,
                        "attestationCount": file.attestation_count,
                        "verifiedAttestationCount": (
                            file.verified_attestation_count
                        ),
                        "sha256": file.observed_sha256 or file.sha256,
                    },
                )
            )

    if failures:
        rule_id = "TC-SCAN-FAILURE"
        _add_sarif_rule(
            rules,
            rule_id,
            "Dependency scan failure",
            "Trustcheck could not complete inspection for a dependency.",
            ("operational",),
        )
        for scan_failure in failures:
            identity = str(
                scan_failure.get("requirement") or "unknown"
            )
            message = str(
                scan_failure.get("message") or "unknown scan failure"
            )
            location = SourceLocation(source_name)
            results.append(
                _sarif_result_for_location(
                    location,
                    purl=None,
                    project=identity,
                    version=None,
                    rule_id=rule_id,
                    category="scan",
                    identity=identity,
                    level="error",
                    message=message,
                    properties={"requirement": identity},
                )
            )

    run_properties = {
        "trustcheck.source": source_name,
        "trustcheck.packageCount": len(packages),
        "trustcheck.failureCount": len(failures),
        "trustcheck.policyPassed": all(
            package.report.policy.passed for package in packages
        ) and not failures,
        "trustcheck.recommendation": _worst_recommendation(packages),
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trustcheck",
                        "semanticVersion": _tool_version(),
                        "informationUri": (
                            "https://github.com/Halfblood-Prince/trustcheck"
                        ),
                        "rules": [
                            rules[rule_id] for rule_id in sorted(rules)
                        ],
                    }
                },
                "automationDetails": {
                    "id": f"trustcheck/{_stable_digest(source_name)[:16]}"
                },
                "results": sorted(
                    results,
                    key=lambda item: (
                        str(item["ruleId"]),
                        str(item["partialFingerprints"]["trustcheck/v1"]),
                    ),
                ),
                "properties": run_properties,
            }
        ],
    }


def _add_sarif_rule(
    rules: dict[str, dict[str, object]],
    rule_id: str,
    name: str,
    description: str,
    tags: Sequence[str],
) -> None:
    rules.setdefault(
        rule_id,
        {
            "id": rule_id,
            "name": _rule_token(name),
            "shortDescription": {"text": name},
            "fullDescription": {"text": description},
            "helpUri": (
                "https://halfblood-prince.github.io/trustcheck/"
                "reference/recommendations/"
            ),
            "properties": {"tags": list(tags)},
        },
    )


def _sarif_result(
    package: ExportPackage,
    *,
    rule_id: str,
    category: str,
    identity: str,
    level: str,
    message: str,
    properties: Mapping[str, object],
) -> dict[str, Any]:
    return _sarif_result_for_location(
        package.source or SourceLocation(package.report.package_url),
        purl=package.purl,
        project=package.report.project,
        version=package.report.version,
        rule_id=rule_id,
        category=category,
        identity=identity,
        level=level,
        message=message,
        properties=properties,
    )


def _heuristic_source_location(
    package: ExportPackage,
    finding: HeuristicFinding,
) -> SourceLocation:
    internal_path = finding.location
    line: int | None = None
    if internal_path:
        path_part, separator, line_part = internal_path.rpartition(":")
        if separator and line_part.isdigit():
            internal_path = path_part
            line = int(line_part)
    if finding.artifact and internal_path:
        return SourceLocation(
            f"{finding.artifact}!/{internal_path.lstrip('/')}",
            line,
        )
    if finding.artifact:
        return SourceLocation(finding.artifact, line)
    if internal_path:
        return SourceLocation(internal_path, line)
    return package.source or SourceLocation(package.report.package_url)


def _sarif_result_for_location(
    location: SourceLocation,
    *,
    purl: str | None,
    project: str,
    version: str | None,
    rule_id: str,
    category: str,
    identity: str,
    level: str,
    message: str,
    properties: Mapping[str, object],
) -> dict[str, Any]:
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": _sarif_uri(location.uri)}
    }
    if location.line is not None:
        physical_location["region"] = {"startLine": location.line}
    fingerprint = _stable_digest(
        "sarif-v1",
        category,
        purl or project,
        identity,
        _fingerprint_location(location.uri),
        str(location.line or ""),
    )
    result_properties = {
        "category": category,
        "project": project,
        "version": version,
        "purl": purl,
        **properties,
    }
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": physical_location,
                "logicalLocations": [
                    {
                        "name": project,
                        "fullyQualifiedName": purl or project,
                        "kind": "package",
                    }
                ],
            }
        ],
        "partialFingerprints": {"trustcheck/v1": fingerprint},
        "properties": _without_none(result_properties),
    }


def _cyclonedx_document(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
) -> dict[str, Any]:
    components = _cyclonedx_components(packages)
    properties = [
        {"name": "trustcheck:source", "value": source_name},
        {
            "name": "trustcheck:policy:passed",
            "value": _bool_text(
                all(package.report.policy.passed for package in packages)
                and not failures
            ),
        },
        {
            "name": "trustcheck:recommendation",
            "value": _worst_recommendation(packages),
        },
    ]
    properties.extend(
        {
            "name": "trustcheck:scan-failure",
            "value": (
                f"{failure.get('requirement') or 'unknown'}: "
                f"{failure.get('message') or 'unknown failure'}"
            ),
        }
        for failure in failures
    )
    identity = _stable_digest(
        source_name,
        *(package.purl for package in packages),
        *(
            vulnerability.id
            for package in packages
            for vulnerability in package.report.vulnerabilities
        ),
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "trustcheck",
                        "version": _tool_version(),
                    }
                ]
            },
            "properties": properties,
        },
        "components": components,
        "dependencies": _cyclonedx_dependencies(packages, components),
        "vulnerabilities": _cyclonedx_vulnerabilities(packages),
    }


def _cyclonedx_components(
    packages: Sequence[ExportPackage],
) -> list[dict[str, object]]:
    components: dict[str, dict[str, object]] = {}
    for package in packages:
        report = package.report
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": package.purl,
            "name": report.project,
            "version": report.version,
            "purl": package.purl,
            "description": report.summary,
            "externalReferences": _cyclonedx_external_references(report),
            "properties": _cyclonedx_properties(package),
        }
        hashes = _component_hashes(package)
        if hashes:
            component["hashes"] = [
                {"alg": _cyclonedx_hash_name(algorithm), "content": digest}
                for algorithm, digest in hashes
                if _cyclonedx_hash_name(algorithm) is not None
            ]
        components[package.purl] = _without_empty(component)
        for dependency in report.dependencies:
            purl = package_purl(dependency.project, dependency.version)
            components.setdefault(
                purl,
                _without_empty(
                    {
                        "type": "library",
                        "bom-ref": purl,
                        "name": dependency.project,
                        "version": dependency.version,
                        "purl": purl,
                        "externalReferences": (
                            [
                                {
                                    "type": "distribution",
                                    "url": dependency.package_url,
                                }
                            ]
                            if dependency.package_url
                            else []
                        ),
                        "properties": [
                            {
                                "name": "trustcheck:recommendation",
                                "value": dependency.recommendation,
                            },
                            {
                                "name": "trustcheck:dependency:depth",
                                "value": str(dependency.depth),
                            },
                        ],
                    }
                ),
            )
    return [components[key] for key in sorted(components)]


def _cyclonedx_external_references(
    report: TrustReport,
) -> list[dict[str, str]]:
    references = [
        {"type": "distribution", "url": report.package_url},
    ]
    references.extend(
        {"type": "vcs", "url": url}
        for url in report.repository_urls
    )
    return references


def _cyclonedx_properties(
    package: ExportPackage,
) -> list[dict[str, str]]:
    report = package.report
    properties = [
        {"name": "trustcheck:recommendation", "value": report.recommendation},
        {
            "name": "trustcheck:policy:profile",
            "value": report.policy.profile,
        },
        {
            "name": "trustcheck:policy:passed",
            "value": _bool_text(report.policy.passed),
        },
        {
            "name": "trustcheck:provenance:status",
            "value": report.coverage.status,
        },
        {
            "name": "trustcheck:provenance:verified-artifacts",
            "value": str(report.coverage.verified_files),
        },
        {
            "name": "trustcheck:provenance:total-artifacts",
            "value": str(report.coverage.total_files),
        },
        {
            "name": "trustcheck:malicious-package:score",
            "value": str(report.malicious_package.score),
        },
        {
            "name": "trustcheck:malicious-package:level",
            "value": report.malicious_package.level,
        },
        {
            "name": "trustcheck:malicious-package:disclaimer",
            "value": report.malicious_package.disclaimer,
        },
    ]
    for artifact in _all_artifacts(package):
        filename = artifact.filename or artifact.url or artifact.path or "artifact"
        for algorithm, digest in artifact.hashes:
            properties.append(
                {
                    "name": (
                        "trustcheck:artifact:"
                        f"{_property_token(filename)}:{algorithm.lower()}"
                    ),
                    "value": digest,
                }
            )
    properties.extend(
        {
            "name": (
                "trustcheck:malicious-package:heuristic:"
                f"{_property_token(finding.code)}"
            ),
            "value": json.dumps(
                {
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "score": finding.score,
                    "message": finding.message,
                    "evidence": finding.evidence,
                    "location": finding.location,
                    "artifact": finding.artifact,
                    "heuristic": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
        for finding in report.malicious_package.findings
    )
    properties.extend(
        {
            "name": f"trustcheck:vulnerability:{vulnerability.id}",
            "value": json.dumps(
                _without_none(
                    {
                        "severity": vulnerability.severity,
                        "cvss_score": vulnerability.cvss_score,
                        "cvss_vector": vulnerability.cvss_vector,
                        "cwes": vulnerability.cwes,
                        "fixed_in": vulnerability.fixed_in,
                        "source": vulnerability.source,
                        "withdrawn": vulnerability.withdrawn,
                        "kev": vulnerability.kev,
                        "epss_score": vulnerability.epss_score,
                        "epss_percentile": vulnerability.epss_percentile,
                        "suppression": (
                            {
                                "owner": vulnerability.suppression.owner,
                                "justification": (
                                    vulnerability.suppression.justification
                                ),
                                "expires": vulnerability.suppression.expires,
                                "status": vulnerability.suppression.status,
                            }
                            if vulnerability.suppression is not None
                            else None
                        ),
                    }
                ),
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
        for vulnerability in report.vulnerabilities
    )
    properties.extend(
        {
            "name": f"trustcheck:policy-violation:{violation.code}",
            "value": f"{violation.severity}:{violation.message}",
        }
        for violation in report.policy.violations
    )
    return properties


def _cyclonedx_dependencies(
    packages: Sequence[ExportPackage],
    components: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    relationships: dict[str, set[str]] = {
        str(component["bom-ref"]): set()
        for component in components
    }
    for package in packages:
        relationships.setdefault(package.purl, set()).update(
            package_purl(dependency.project, dependency.version)
            for dependency in package.report.dependencies
        )
    return [
        {"ref": ref, "dependsOn": sorted(dependencies)}
        for ref, dependencies in sorted(relationships.items())
    ]


def _cyclonedx_vulnerabilities(
    packages: Sequence[ExportPackage],
) -> list[dict[str, object]]:
    vulnerabilities: dict[tuple[str, str], dict[str, object]] = {}
    for package in packages:
        for vulnerability in package.report.vulnerabilities:
            key = (vulnerability.id, package.purl)
            severity = _cyclonedx_severity(vulnerability.severity)
            item: dict[str, object] = {
                "bom-ref": f"trustcheck-vulnerability-{_stable_digest(*key)[:20]}",
                "id": vulnerability.id,
                "source": _without_none(
                    {
                        "name": vulnerability.source or "trustcheck",
                        "url": vulnerability.link,
                    }
                ),
                "description": vulnerability.summary,
                "affects": [{"ref": package.purl}],
                "properties": [
                    {
                        "name": "trustcheck:vulnerability:aliases",
                        "value": ",".join(vulnerability.aliases),
                    },
                    {
                        "name": "trustcheck:vulnerability:fixed-in",
                        "value": ",".join(vulnerability.fixed_in),
                    },
                    {
                        "name": "trustcheck:vulnerability:cwes",
                        "value": ",".join(vulnerability.cwes),
                    },
                    {
                        "name": "trustcheck:vulnerability:withdrawn",
                        "value": _bool_text(vulnerability.withdrawn),
                    },
                    {
                        "name": "trustcheck:vulnerability:cisa-kev",
                        "value": _bool_text(vulnerability.kev),
                    },
                    {
                        "name": "trustcheck:vulnerability:epss",
                        "value": (
                            str(vulnerability.epss_score)
                            if vulnerability.epss_score is not None
                            else ""
                        ),
                    },
                    {
                        "name": "trustcheck:vulnerability:suppression",
                        "value": (
                            json.dumps(
                                {
                                    "owner": vulnerability.suppression.owner,
                                    "justification": (
                                        vulnerability.suppression.justification
                                    ),
                                    "expires": (
                                        vulnerability.suppression.expires
                                    ),
                                    "status": (
                                        vulnerability.suppression.status
                                    ),
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            if vulnerability.suppression is not None
                            else ""
                        ),
                    },
                ],
            }
            if severity is not None:
                rating: dict[str, object] = {"severity": severity}
                if vulnerability.cvss_score is not None:
                    rating["score"] = vulnerability.cvss_score
                method = _cyclonedx_score_method(vulnerability.cvss_version)
                if method is not None:
                    rating["method"] = method
                if vulnerability.cvss_vector:
                    rating["vector"] = vulnerability.cvss_vector
                item["ratings"] = [rating]
            cwes = _cyclonedx_cwe_numbers(vulnerability.cwes)
            if cwes:
                item["cwes"] = cwes
            if vulnerability.link:
                item["advisories"] = [{"url": vulnerability.link}]
            vulnerabilities[key] = _without_empty(item)
    return [
        vulnerabilities[key] for key in sorted(vulnerabilities)
    ]


def _cyclonedx_xml(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
) -> str:
    document = _cyclonedx_document(packages, source_name, failures, timestamp)
    ElementTree.register_namespace("", CYCLONEDX_NAMESPACE)
    root = ElementTree.Element(
        _xml_tag("bom"),
        {
            "serialNumber": str(document["serialNumber"]),
            "version": "1",
        },
    )
    metadata = ElementTree.SubElement(root, _xml_tag("metadata"))
    _xml_text(metadata, "timestamp", timestamp)
    tools = ElementTree.SubElement(metadata, _xml_tag("tools"))
    tool_components = ElementTree.SubElement(tools, _xml_tag("components"))
    tool = ElementTree.SubElement(
        tool_components,
        _xml_tag("component"),
        {"type": "application"},
    )
    _xml_text(tool, "name", "trustcheck")
    _xml_text(tool, "version", _tool_version())
    _xml_properties(
        metadata,
        document["metadata"]["properties"],
    )

    components_element = ElementTree.SubElement(root, _xml_tag("components"))
    for component in document["components"]:
        component_element = ElementTree.SubElement(
            components_element,
            _xml_tag("component"),
            {
                "type": str(component["type"]),
                "bom-ref": str(component["bom-ref"]),
            },
        )
        _xml_text(component_element, "name", str(component["name"]))
        _xml_text(component_element, "version", str(component["version"]))
        if component.get("description"):
            _xml_text(
                component_element,
                "description",
                str(component["description"]),
            )
        if component.get("hashes"):
            hashes = ElementTree.SubElement(
                component_element,
                _xml_tag("hashes"),
            )
            for item in component["hashes"]:
                hash_element = ElementTree.SubElement(
                    hashes,
                    _xml_tag("hash"),
                    {"alg": str(item["alg"])},
                )
                hash_element.text = str(item["content"])
        _xml_text(component_element, "purl", str(component["purl"]))
        if component.get("externalReferences"):
            references = ElementTree.SubElement(
                component_element,
                _xml_tag("externalReferences"),
            )
            for reference in component["externalReferences"]:
                reference_element = ElementTree.SubElement(
                    references,
                    _xml_tag("reference"),
                    {"type": str(reference["type"])},
                )
                _xml_text(reference_element, "url", str(reference["url"]))
        _xml_properties(component_element, component.get("properties", []))

    dependencies_element = ElementTree.SubElement(
        root,
        _xml_tag("dependencies"),
    )
    for relationship in document["dependencies"]:
        dependency = ElementTree.SubElement(
            dependencies_element,
            _xml_tag("dependency"),
            {"ref": str(relationship["ref"])},
        )
        for child_ref in relationship["dependsOn"]:
            ElementTree.SubElement(
                dependency,
                _xml_tag("dependency"),
                {"ref": str(child_ref)},
            )

    vulnerabilities = document["vulnerabilities"]
    if vulnerabilities:
        vulnerabilities_element = ElementTree.SubElement(
            root,
            _xml_tag("vulnerabilities"),
        )
        for vulnerability in vulnerabilities:
            vulnerability_element = ElementTree.SubElement(
                vulnerabilities_element,
                _xml_tag("vulnerability"),
                {"bom-ref": str(vulnerability["bom-ref"])},
            )
            _xml_text(vulnerability_element, "id", str(vulnerability["id"]))
            source = vulnerability.get("source")
            if isinstance(source, Mapping):
                source_element = ElementTree.SubElement(
                    vulnerability_element,
                    _xml_tag("source"),
                )
                if source.get("name"):
                    _xml_text(source_element, "name", str(source["name"]))
                if source.get("url"):
                    _xml_text(source_element, "url", str(source["url"]))
            ratings = vulnerability.get("ratings")
            if isinstance(ratings, list) and ratings:
                ratings_element = ElementTree.SubElement(
                    vulnerability_element,
                    _xml_tag("ratings"),
                )
                for rating in ratings:
                    rating_element = ElementTree.SubElement(
                        ratings_element,
                        _xml_tag("rating"),
                    )
                    if rating.get("score") is not None:
                        _xml_text(
                            rating_element,
                            "score",
                            str(rating["score"]),
                        )
                    _xml_text(
                        rating_element,
                        "severity",
                        str(rating["severity"]),
                    )
                    if rating.get("method"):
                        _xml_text(
                            rating_element,
                            "method",
                            str(rating["method"]),
                        )
                    if rating.get("vector"):
                        _xml_text(
                            rating_element,
                            "vector",
                            str(rating["vector"]),
                        )
            cwes = vulnerability.get("cwes")
            if isinstance(cwes, list) and cwes:
                cwes_element = ElementTree.SubElement(
                    vulnerability_element,
                    _xml_tag("cwes"),
                )
                for cwe in cwes:
                    _xml_text(cwes_element, "cwe", str(cwe))
            _xml_text(
                vulnerability_element,
                "description",
                str(vulnerability["description"]),
            )
            affects_element = ElementTree.SubElement(
                vulnerability_element,
                _xml_tag("affects"),
            )
            for affected in vulnerability["affects"]:
                target_element = ElementTree.SubElement(
                    affects_element,
                    _xml_tag("target"),
                )
                _xml_text(target_element, "ref", str(affected["ref"]))
            _xml_properties(
                vulnerability_element,
                vulnerability.get("properties", []),
            )
    ElementTree.indent(root, space="  ")
    return ElementTree.tostring(
        root,
        encoding="unicode",
        xml_declaration=True,
    )


def _spdx_document(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
    timestamp: str,
) -> dict[str, object]:
    package_items: dict[str, dict[str, object]] = {}
    relationships: list[dict[str, str]] = []
    annotations: list[dict[str, str]] = []
    for package in packages:
        spdx_id = _spdx_id(package.report.project, package.report.version)
        package_items[package.purl] = _spdx_package(package, spdx_id)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            }
        )
        for dependency in package.report.dependencies:
            dependency_purl = package_purl(
                dependency.project,
                dependency.version,
            )
            dependency_id = _spdx_id(
                dependency.project,
                dependency.version,
            )
            package_items.setdefault(
                dependency_purl,
                _spdx_dependency_package(dependency, dependency_id),
            )
            relationships.append(
                {
                    "spdxElementId": spdx_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dependency_id,
                }
            )
        annotations.extend(_spdx_annotations(package, spdx_id, timestamp))
    annotations.extend(
        {
            "annotationDate": timestamp,
            "annotationType": "OTHER",
            "annotator": f"Tool: trustcheck-{_tool_version()}",
            "comment": (
                "trustcheck:scan-failure:"
                f"{failure.get('requirement') or 'unknown'}="
                f"{failure.get('message') or 'unknown failure'}"
            ),
        }
        for failure in failures
    )
    identity = _stable_digest(
        source_name,
        *(sorted(package_items)),
        *(
            str(annotation["comment"])
            for annotation in annotations
        ),
    )
    policy_passed = (
        all(package.report.policy.passed for package in packages)
        and not failures
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"trustcheck-{_filename_token(source_name)}",
        "documentNamespace": (
            f"https://trustcheck.dev/spdx/{identity}"
        ),
        "creationInfo": {
            "created": timestamp,
            "creators": [f"Tool: trustcheck-{_tool_version()}"],
        },
        "documentDescribes": [
            relationship["relatedSpdxElement"]
            for relationship in relationships
            if relationship["relationshipType"] == "DESCRIBES"
        ],
        "packages": [
            package_items[key] for key in sorted(package_items)
        ],
        "relationships": _dedupe_dicts(relationships),
        "annotations": annotations,
        "comment": (
            f"trustcheck:source={source_name}\n"
            f"trustcheck:policy:passed="
            f"{_bool_text(policy_passed)}"
            "\n"
            f"trustcheck:recommendation={_worst_recommendation(packages)}"
        ),
    }


def _spdx_package(
    package: ExportPackage,
    spdx_id: str,
) -> dict[str, object]:
    report = package.report
    checksums = [
        {"algorithm": algorithm, "checksumValue": digest}
        for algorithm, digest in _spdx_checksums(package)
    ]
    external_refs = [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": package.purl,
        }
    ]
    external_refs.extend(
        {
            "referenceCategory": "SECURITY",
            "referenceType": "advisory",
            "referenceLocator": (
                vulnerability.link or vulnerability.id
            ),
            "comment": vulnerability.summary,
        }
        for vulnerability in report.vulnerabilities
    )
    return _without_empty(
        {
            "name": report.project,
            "SPDXID": spdx_id,
            "versionInfo": report.version,
            "downloadLocation": report.package_url or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "summary": report.summary,
            "homepage": (
                report.repository_urls[0]
                if report.repository_urls
                else report.package_url
            ),
            "checksums": checksums,
            "externalRefs": external_refs,
            "comment": _spdx_trust_comment(package),
            "primaryPackagePurpose": "LIBRARY",
        }
    )


def _spdx_dependency_package(
    dependency: Any,
    spdx_id: str,
) -> dict[str, object]:
    purl = package_purl(dependency.project, dependency.version)
    return {
        "name": dependency.project,
        "SPDXID": spdx_id,
        "versionInfo": dependency.version,
        "downloadLocation": dependency.package_url or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        "comment": (
            f"trustcheck:recommendation={dependency.recommendation}\n"
            f"trustcheck:dependency:depth={dependency.depth}"
        ),
        "primaryPackagePurpose": "LIBRARY",
    }


def _spdx_annotations(
    package: ExportPackage,
    spdx_id: str,
    timestamp: str,
) -> list[dict[str, str]]:
    report = package.report
    comments: list[str] = []
    comments.extend(
        (
            f"{spdx_id}:trustcheck:malicious-package-heuristic:{finding.code}:"
            f"{finding.severity}:{finding.confidence}:{finding.score}:"
            f"{finding.message}:not-proof-of-malware"
        )
        for finding in report.malicious_package.findings
    )
    comments.extend(
        (
            f"{spdx_id}:trustcheck:vulnerability:{vulnerability.id}:"
            f"{vulnerability.severity or 'unknown'}:{vulnerability.summary}"
        )
        for vulnerability in report.vulnerabilities
    )
    comments.extend(
        (
            f"{spdx_id}:trustcheck:policy-violation:{violation.code}:"
            f"{violation.severity}:{violation.message}"
        )
        for violation in report.policy.violations
    )
    comments.extend(
        (
            f"{spdx_id}:trustcheck:artifact:{artifact.filename or 'artifact'}:"
            f"{algorithm}={digest}"
        )
        for artifact in _all_artifacts(package)
        for algorithm, digest in artifact.hashes
    )
    return [
        {
            "annotationDate": timestamp,
            "annotationType": "OTHER",
            "annotator": f"Tool: trustcheck-{_tool_version()}",
            "comment": comment,
        }
        for comment in comments
    ]


def _spdx_trust_comment(package: ExportPackage) -> str:
    report = package.report
    lines = [
        f"trustcheck:recommendation={report.recommendation}",
        f"trustcheck:policy:profile={report.policy.profile}",
        f"trustcheck:policy:passed={_bool_text(report.policy.passed)}",
        f"trustcheck:provenance:status={report.coverage.status}",
        (
            "trustcheck:provenance:verified-artifacts="
            f"{report.coverage.verified_files}/{report.coverage.total_files}"
        ),
        (
            "trustcheck:malicious-package="
            f"{report.malicious_package.level};score={report.malicious_package.score};"
            "heuristic=true;not-proof-of-malware"
        ),
    ]
    lines.extend(
        (
            f"trustcheck:malicious-package-heuristic:{finding.code}="
            f"{finding.severity};confidence={finding.confidence};"
            f"score={finding.score};message={finding.message}"
        )
        for finding in report.malicious_package.findings
    )
    lines.extend(
        (
            f"trustcheck:vulnerability:{vulnerability.id}="
            f"{vulnerability.severity or 'unknown'}"
            f";cvss={vulnerability.cvss_score}"
            f";cwes={','.join(vulnerability.cwes)}"
            f";withdrawn={_bool_text(vulnerability.withdrawn)}"
            f";kev={_bool_text(vulnerability.kev)}"
            f";epss={vulnerability.epss_score}"
        )
        for vulnerability in report.vulnerabilities
    )
    lines.extend(
        (
            f"trustcheck:policy-violation:{violation.code}="
            f"{violation.severity}:{violation.message}"
        )
        for violation in report.policy.violations
    )
    lines.extend(
        (
            f"trustcheck:artifact:{artifact.filename or 'artifact'}:"
            f"{algorithm}={digest}"
        )
        for artifact in _all_artifacts(package)
        for algorithm, digest in artifact.hashes
    )
    return "\n".join(lines)


def _openvex_document(
    packages: Sequence[ExportPackage],
    source_name: str,
    timestamp: str,
) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    for package in packages:
        hashes = {
            _openvex_hash_name(algorithm): digest
            for algorithm, digest in _component_hashes(package)
            if _openvex_hash_name(algorithm) is not None
        }
        product: dict[str, object] = {
            "@id": package.purl,
            "identifiers": {"purl": package.purl},
        }
        if hashes:
            product["hashes"] = hashes
        for vulnerability in package.report.vulnerabilities:
            action = (
                "Upgrade to " + ", ".join(vulnerability.fixed_in)
                if vulnerability.fixed_in
                else "Review the advisory and apply the vendor-recommended mitigation."
            )
            status_notes = vulnerability.summary
            if vulnerability.kev:
                status_notes += " Listed in the CISA KEV catalog."
            if vulnerability.epss_score is not None:
                status_notes += (
                    f" EPSS probability {vulnerability.epss_score:.4f}"
                    + (
                        f", percentile {vulnerability.epss_percentile:.4f}."
                        if vulnerability.epss_percentile is not None
                        else "."
                    )
                )
            if vulnerability.suppression is not None:
                status_notes += (
                    " Trustcheck suppression "
                    f"{vulnerability.suppression.status} until "
                    f"{vulnerability.suppression.expires}, owned by "
                    f"{vulnerability.suppression.owner}."
                )
            statements.append(
                {
                    "@id": (
                        "https://trustcheck.dev/openvex/statements/"
                        f"{_stable_digest(package.purl, vulnerability.id)[:32]}"
                    ),
                    "vulnerability": {
                        "name": vulnerability.id,
                        "aliases": vulnerability.aliases,
                    },
                    "products": [product],
                    "status": "affected",
                    "status_notes": status_notes,
                    "action_statement": action,
                    "action_statement_timestamp": timestamp,
                }
            )
    if not statements:
        raise ValueError(
            "OpenVEX requires at least one vulnerability statement; "
            "no vulnerabilities were reported"
        )
    identity = _stable_digest(
        source_name,
        *(
            f"{statement['products'][0]['@id']}:{statement['vulnerability']['name']}"
            for statement in statements
        ),
    )
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://trustcheck.dev/openvex/{identity}",
        "author": "https://github.com/Halfblood-Prince/trustcheck",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"trustcheck/{_tool_version()}",
        "statements": statements,
    }


def _markdown_document(
    packages: Sequence[ExportPackage],
    source_name: str,
    failures: Sequence[Mapping[str, str]],
) -> str:
    policy_passed = (
        all(package.report.policy.passed for package in packages)
        and not failures
    )
    lines = [
        "# Trustcheck Report",
        "",
        f"- Source: `{_markdown_escape(source_name)}`",
        f"- Packages: {len(packages)}",
        f"- Recommendation: `{_worst_recommendation(packages)}`",
        f"- Policy: **{'passed' if policy_passed else 'failed'}**",
    ]
    for package in packages:
        report = package.report
        lines.extend(
            [
                "",
                f"## {_markdown_escape(report.project)} {report.version}",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Package URL | `{_markdown_escape(package.purl)}` |",
                (
                    "| Summary | "
                    f"{_markdown_escape(report.summary or '-')} |"
                ),
                (
                    "| Recommendation | "
                    f"`{_markdown_escape(report.recommendation)}` |"
                ),
                (
                    "| Provenance | "
                    f"{report.coverage.verified_files}/"
                    f"{report.coverage.total_files} verified "
                    f"(`{_markdown_escape(report.coverage.status)}`) |"
                ),
                (
                    "| Policy | "
                    f"{'passed' if report.policy.passed else 'failed'} "
                    f"(`{_markdown_escape(report.policy.profile)}`) |"
                ),
                (
                    "| Malicious-package heuristics | "
                    f"`{_markdown_escape(report.malicious_package.level)}` "
                    f"(score {report.malicious_package.score}) |"
                ),
            ]
        )
        if report.malicious_package.findings:
            lines.extend(
                [
                    "",
                    "### Malicious-Package Heuristics",
                    "",
                    f"> {_markdown_escape(report.malicious_package.disclaimer)}",
                    "",
                    "| Finding | Severity | Confidence | Score | Location |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for finding in report.malicious_package.findings:
                location = " / ".join(
                    value
                    for value in (finding.artifact, finding.location)
                    if value
                ) or "-"
                lines.append(
                    "| "
                    f"`{_markdown_escape(finding.code)}`: "
                    f"{_markdown_escape(finding.message)} | "
                    f"{_markdown_escape(finding.severity)} | "
                    f"{_markdown_escape(finding.confidence)} | "
                    f"{finding.score} | "
                    f"{_markdown_escape(location)} |"
                )
        artifacts = _all_artifacts(package)
        if artifacts:
            lines.extend(
                [
                    "",
                    "### Artifacts",
                    "",
                    "| Artifact | Hashes | Provenance |",
                    "| --- | --- | --- |",
                ]
            )
            file_lookup = {file.filename: file for file in report.files}
            for artifact in artifacts:
                filename = artifact.filename or artifact.url or artifact.path or "artifact"
                hashes = "<br>".join(
                    f"`{algorithm}:{digest}`"
                    for algorithm, digest in artifact.hashes
                ) or "-"
                file = file_lookup.get(artifact.filename or "")
                provenance = (
                    "verified"
                    if file is not None and file.verified
                    else "unverified"
                )
                lines.append(
                    f"| {_markdown_escape(filename)} | {hashes} | {provenance} |"
                )
        if report.vulnerabilities:
            lines.extend(
                [
                    "",
                    "### Vulnerabilities",
                    "",
                    "| ID | Severity | CVSS | KEV | EPSS | Summary | Fixed In | Suppression |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for vulnerability in report.vulnerabilities:
                lines.append(
                    "| "
                    f"{_markdown_escape(vulnerability.id)} | "
                    f"{_markdown_escape(vulnerability.severity or 'unknown')} | "
                    f"{_optional_number(vulnerability.cvss_score)} | "
                    f"{'yes' if vulnerability.kev else 'no'} | "
                    f"{_optional_number(vulnerability.epss_score)} | "
                    f"{_markdown_escape(vulnerability.summary)} | "
                    f"{_markdown_escape(', '.join(vulnerability.fixed_in) or '-')} | "
                    f"{_markdown_escape(_suppression_summary(vulnerability))} |"
                )
        if report.policy.violations:
            lines.extend(["", "### Policy Violations", ""])
            lines.extend(
                (
                    f"- **{_markdown_escape(violation.severity)}** "
                    f"`{_markdown_escape(violation.code)}`: "
                    f"{_markdown_escape(violation.message)}"
                )
                for violation in report.policy.violations
            )
        if report.risk_flags:
            lines.extend(["", "### Risk Flags", ""])
            lines.extend(
                (
                    f"- **{_markdown_escape(flag.severity)}** "
                    f"`{_markdown_escape(flag.code)}`: "
                    f"{_markdown_escape(flag.message)}"
                )
                for flag in report.risk_flags
            )
    if failures:
        lines.extend(["", "## Scan Failures", ""])
        lines.extend(
            (
                f"- `{_markdown_escape(str(failure.get('requirement') or 'unknown'))}`: "
                f"{_markdown_escape(str(failure.get('message') or 'unknown failure'))}"
            )
            for failure in failures
        )
    return "\n".join(lines)


def _all_artifacts(package: ExportPackage) -> tuple[ArtifactReference, ...]:
    artifacts: dict[
        tuple[str | None, str | None, str | None],
        ArtifactReference,
    ] = {}

    def merge(artifact: ArtifactReference) -> None:
        key = (artifact.filename, artifact.url, artifact.path)
        existing = artifacts.get(key)
        if existing is None:
            artifacts[key] = artifact
            return
        artifacts[key] = ArtifactReference(
            filename=existing.filename or artifact.filename,
            url=existing.url or artifact.url,
            path=existing.path or artifact.path,
            hashes=tuple(
                sorted({*existing.hashes, *artifact.hashes})
            ),
            size=existing.size if existing.size is not None else artifact.size,
            kind=(
                existing.kind
                if existing.kind != "archive"
                else artifact.kind
            ),
        )

    for artifact in package.artifacts:
        merge(artifact)
    for file in package.report.files:
        digest = file.observed_sha256 or file.sha256
        merge(
            ArtifactReference(
                filename=file.filename,
                url=file.url,
                hashes=(("sha256", digest),) if digest else (),
            )
        )
    return tuple(artifacts.values())


def _component_hashes(
    package: ExportPackage,
) -> tuple[tuple[str, str], ...]:
    by_algorithm: dict[str, set[str]] = {}
    for artifact in _all_artifacts(package):
        for algorithm, digest in artifact.hashes:
            by_algorithm.setdefault(algorithm.lower(), set()).add(digest.lower())
    return tuple(
        (algorithm, next(iter(digests)))
        for algorithm, digests in sorted(by_algorithm.items())
        if len(digests) == 1
    )


def _artifact_hashes_for_filename(
    package: ExportPackage,
    filename: str,
) -> dict[str, str]:
    return {
        algorithm: digest
        for artifact in _all_artifacts(package)
        if artifact.filename == filename
        for algorithm, digest in artifact.hashes
    }


def _spdx_checksums(
    package: ExportPackage,
) -> tuple[tuple[str, str], ...]:
    names = {
        "sha1": "SHA1",
        "sha224": "SHA224",
        "sha256": "SHA256",
        "sha384": "SHA384",
        "sha512": "SHA512",
        "sha3-256": "SHA3-256",
        "sha3-384": "SHA3-384",
        "sha3-512": "SHA3-512",
        "md5": "MD5",
        "blake2b-256": "BLAKE2b-256",
        "blake2b-384": "BLAKE2b-384",
        "blake2b-512": "BLAKE2b-512",
        "blake3": "BLAKE3",
    }
    return tuple(
        (names[algorithm], digest)
        for algorithm, digest in _component_hashes(package)
        if algorithm in names
    )


def _cyclonedx_hash_name(algorithm: str) -> str | None:
    names = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "sha3-256": "SHA3-256",
        "sha3-384": "SHA3-384",
        "sha3-512": "SHA3-512",
        "blake2b-256": "BLAKE2b-256",
        "blake2b-384": "BLAKE2b-384",
        "blake2b-512": "BLAKE2b-512",
        "blake3": "BLAKE3",
    }
    return names.get(algorithm.lower())


def _openvex_hash_name(algorithm: str) -> str | None:
    names = {
        "md5": "md5",
        "sha1": "sha-1",
        "sha256": "sha-256",
        "sha384": "sha-384",
        "sha512": "sha-512",
    }
    return names.get(algorithm.lower())


def _cyclonedx_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    aliases = {
        "moderate": "medium",
        "important": "high",
    }
    normalized = aliases.get(normalized, normalized)
    return (
        normalized
        if normalized in {"unknown", "info", "low", "medium", "high", "critical"}
        else None
    )


def _cyclonedx_score_method(value: str | None) -> str | None:
    methods = {
        "2.0": "CVSSv2",
        "3.0": "CVSSv3",
        "3.1": "CVSSv31",
        "4.0": "CVSSv4",
    }
    return methods.get((value or "").upper())


def _cyclonedx_cwe_numbers(values: Sequence[str]) -> list[int]:
    cwes: set[int] = set()
    for value in values:
        match = re.fullmatch(r"CWE-(\d+)", value.strip(), re.IGNORECASE)
        if match:
            cwes.add(int(match.group(1)))
    return sorted(cwes)


def _sarif_level(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"critical", "high", "error"}:
        return "error"
    if normalized in {"medium", "moderate", "warning"}:
        return "warning"
    return "note"


def _worst_recommendation(packages: Sequence[ExportPackage]) -> str:
    order = {
        "verified": 0,
        "metadata-only": 1,
        "review-required": 2,
        "high-risk": 3,
        "error": 4,
    }
    if not packages:
        return "error"
    return max(
        (package.report.recommendation for package in packages),
        key=lambda item: order.get(item, order["error"]),
    )


def _timestamp(value: datetime | None) -> str:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _tool_version() -> str:
    try:
        return package_version("trustcheck")
    except PackageNotFoundError:
        return "0+unknown"


def _stable_digest(*parts: str) -> str:
    payload = "\0".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rule_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return token.upper() or "TRUSTCHECK"


def _property_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "artifact"


def _filename_token(value: str) -> str:
    return _property_token(Path(value).name or value).lower()


def _spdx_id(project: str, version: str) -> str:
    token = re.sub(
        r"[^A-Za-z0-9.-]+",
        "-",
        f"{canonicalize_name(project)}-{version}",
    ).strip("-")
    return f"SPDXRef-Package-{token}-{_stable_digest(project, version)[:10]}"


def _sarif_uri(value: str) -> str:
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return value.replace("\\", "/")
    parsed = parse.urlsplit(value)
    if parsed.scheme:
        return value
    return value.replace("\\", "/")


def _fingerprint_location(value: str) -> str:
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return PureWindowsPath(value).name
    parsed = parse.urlsplit(value)
    if parsed.scheme:
        return value
    path = Path(value)
    return path.name if path.is_absolute() else path.as_posix()


def _markdown_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _suppression_summary(vulnerability: VulnerabilityRecord) -> str:
    if vulnerability.suppression is None:
        return "-"
    return (
        f"{vulnerability.suppression.status}; "
        f"{vulnerability.suppression.owner}; "
        f"expires {vulnerability.suppression.expires}"
    )


def _optional_number(value: float | None) -> str:
    return str(value) if value is not None else "-"


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _optional_str(value: object) -> str | None:
    return str(value) if value is not None else None


def _without_none(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if item is not None}


def _without_empty(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: item
        for key, item in value.items()
        if item is not None and item != [] and item != {}
    }


def _dedupe_dicts(
    values: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    result: list[dict[str, str]] = []
    for value in values:
        key = tuple(sorted(value.items()))
        if key not in seen:
            seen.add(key)
            result.append(dict(value))
    return result


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _xml_tag(name: str) -> str:
    return f"{{{CYCLONEDX_NAMESPACE}}}{name}"


def _xml_text(parent: ElementTree.Element, name: str, value: str) -> None:
    element = ElementTree.SubElement(parent, _xml_tag(name))
    element.text = value


def _xml_properties(
    parent: ElementTree.Element,
    properties: object,
) -> None:
    if not isinstance(properties, list) or not properties:
        return
    properties_element = ElementTree.SubElement(
        parent,
        _xml_tag("properties"),
    )
    for item in properties:
        if not isinstance(item, Mapping):
            continue
        property_element = ElementTree.SubElement(
            properties_element,
            _xml_tag("property"),
            {"name": str(item.get("name") or "trustcheck:property")},
        )
        property_element.text = str(item.get("value") or "")
