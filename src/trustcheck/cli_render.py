from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict

from .cli_models import ScanTarget
from .contract import JSON_SCHEMA_VERSION
from .indexes import redact_url_credentials
from .models import TrustReport


def _render_text_report(report: TrustReport, *, verbose: bool = False) -> str:
    lines: list[str] = [
        f"trustcheck report for {report.project} {report.version}",
        "",
        "summary:",
        f"  recommendation: {report.recommendation}",
        f"  package: {report.package_url}",
    ]

    if report.summary:
        lines.append(f"  package summary: {report.summary}")

    lines.append(
        "  verification: "
        f"{report.coverage.verified_files}/{report.coverage.total_files} artifact(s) verified "
        f"({report.coverage.status})"
    )
    lines.append(
        "  publisher trust: "
        f"{report.publisher_trust.depth_label} "
        f"(score={report.publisher_trust.depth_score})"
    )
    lines.append(
        f"  policy: {report.policy.profile} ({'pass' if report.policy.passed else 'fail'})"
    )
    lines.append(
        "  diagnostics: "
        f"requests={report.diagnostics.request_count} "
        f"retries={report.diagnostics.retry_count} "
        f"failures={len(report.diagnostics.request_failures)} "
        f"cache_hits={report.diagnostics.cache_hit_count}"
    )
    lines.append(
        "  malicious-package heuristics: "
        f"{report.malicious_package.level} "
        f"(score={report.malicious_package.score}, "
        f"findings={len(report.malicious_package.findings)})"
    )
    lines.append(f"  why this result: {_evidence_summary(report)}")

    reasons = _recommendation_reasons(report)
    if reasons:
        lines.append("  why this result details:")
        lines.extend(f"    - {reason}" for reason in reasons)

    if report.declared_repository_urls:
        lines.append("")
        lines.append("declared repository urls:")
        lines.extend(f"  - {url}" for url in report.declared_repository_urls)

    if report.dependency_summary.requested:
        lines.append("")
        lines.append("dependencies:")
        lines.append(
            "  summary: "
            f"declared={report.dependency_summary.total_declared} "
            f"inspected={report.dependency_summary.total_inspected} "
            f"unique={report.dependency_summary.unique_dependencies} "
            f"max_depth={report.dependency_summary.max_depth} "
            f"highest_risk={report.dependency_summary.highest_risk_recommendation}"
        )
        if report.dependency_summary.high_risk_projects:
            lines.append(
                "  high-risk dependencies: "
                + ", ".join(report.dependency_summary.high_risk_projects)
            )
        if report.dependency_summary.review_required_projects:
            lines.append(
                "  review-required dependencies: "
                + ", ".join(report.dependency_summary.review_required_projects)
            )
        if report.dependency_summary.metadata_only_projects:
            lines.append(
                "  metadata-only dependencies: "
                + ", ".join(report.dependency_summary.metadata_only_projects)
            )
        if report.dependency_summary.verified_projects:
            lines.append(
                "  verified dependencies: " + ", ".join(report.dependency_summary.verified_projects)
            )
        if verbose and report.dependencies:
            for dependency in report.dependencies:
                lines.append(
                    "  - "
                    f"{dependency.project} {dependency.version} "
                    f"(depth={dependency.depth}, recommendation={dependency.recommendation})"
                )
                lines.append(f"    requirement: {dependency.requirement}")
                if dependency.parent_project:
                    lines.append(
                        "    parent: "
                        f"{dependency.parent_project} {dependency.parent_version or 'unknown'}"
                    )
                if dependency.error:
                    lines.append(f"    note: {dependency.error}")
                elif dependency.risk_flags:
                    lines.append("    risk flags:")
                    lines.extend(
                        f"      - [{flag.severity}] {flag.code}: {flag.message}"
                        for flag in dependency.risk_flags[:3]
                    )

    if report.expected_repository:
        lines.append(f"expected repository: {report.expected_repository}")
    if report.provenance_consistency.sdist_wheel_consistent is not None:
        consistency_label = (
            "consistent" if report.provenance_consistency.sdist_wheel_consistent else "mismatch"
        )
        lines.append("")
        lines.append(f"sdist/wheel provenance consistency: {consistency_label}")
    if report.release_drift.compared_to_version:
        lines.append(f"release drift baseline: {report.release_drift.compared_to_version}")
        drift_fields = [
            name
            for name, changed in (
                ("signer", report.release_drift.signer_drift),
                ("repository", report.release_drift.publisher_repository_drift),
                ("workflow", report.release_drift.publisher_workflow_drift),
                ("builder", report.release_drift.builder_drift),
                ("source commit", report.release_drift.source_commit_drift),
                ("build type", report.release_drift.build_type_drift),
            )
            if changed
        ]
        if drift_fields:
            lines.append("release provenance changes: " + ", ".join(drift_fields))

    if report.malicious_package.findings:
        lines.append("")
        lines.append("malicious-package heuristic indicators:")
        lines.append(f"  disclaimer: {report.malicious_package.disclaimer}")
        for finding in report.malicious_package.findings:
            location = (
                f" location={finding.location}" if finding.location else ""
            )
            artifact = (
                f" artifact={finding.artifact}" if finding.artifact else ""
            )
            lines.append(
                "  - "
                f"[{finding.severity}/{finding.confidence}] {finding.code}: "
                f"{finding.message} score={finding.score}{artifact}{location}"
            )
            if verbose:
                lines.extend(
                    f"    evidence: {evidence}"
                    for evidence in finding.evidence
                )

    ownership = report.ownership or {}
    roles = ownership.get("roles") or []
    organization = ownership.get("organization")
    if organization or roles:
        lines.append("")
        lines.append("ownership:")
        if organization:
            lines.append(f"  - organization: {organization}")
        for role in roles:
            lines.append(f"  - {role.get('role')}: {role.get('user')}")

    if report.vulnerabilities:
        lines.append("")
        lines.append("vulnerabilities:")
        for vuln in report.vulnerabilities:
            lines.append(f"  - {vuln.id}: {vuln.summary}")
            details = [
                f"source={vuln.source or 'unknown'}",
                f"severity={vuln.severity or 'unknown'}",
            ]
            if vuln.cvss_score is not None:
                details.append(f"cvss={vuln.cvss_score:.1f}")
            if vuln.cwes:
                details.append(f"cwes={','.join(vuln.cwes)}")
            if vuln.fixed_in:
                details.append(f"fixed_in={','.join(vuln.fixed_in)}")
            if vuln.withdrawn:
                details.append(
                    f"withdrawn={vuln.withdrawn_at or 'yes'}"
                )
            if vuln.kev:
                details.append("kev=yes")
                if vuln.kev_due_date:
                    details.append(f"kev_due={vuln.kev_due_date}")
            if vuln.epss_score is not None:
                details.append(f"epss={vuln.epss_score:.4f}")
            if vuln.epss_percentile is not None:
                details.append(
                    f"epss_percentile={vuln.epss_percentile:.4f}"
                )
            if vuln.suppression is not None:
                details.append(
                    "suppression="
                    f"{vuln.suppression.status}:"
                    f"{vuln.suppression.owner}:"
                    f"{vuln.suppression.expires}"
                )
            if vuln.link:
                details.append(f"advisory={vuln.link}")
            lines.append(f"    {' '.join(details)}")

    if verbose:
        lines.append("")
        lines.append("files:")
        for file in report.files:
            lines.append(f"  - {file.filename}")
            lines.append(f"    provenance: {'yes' if file.has_provenance else 'no'}")
            lines.append(f"    verified: {'yes' if file.verified else 'no'}")
            lines.append(
                "    attestations: "
                f"{file.verified_attestation_count}/{file.attestation_count} verified"
            )
            if file.sha256:
                lines.append(f"    sha256: {file.sha256}")
            if file.observed_sha256:
                lines.append(f"    observed sha256: {file.observed_sha256}")
            if file.publisher_identities:
                for identity in file.publisher_identities:
                    lines.append(
                        "    publisher: "
                        f"kind={identity.kind} "
                        f"repository={identity.repository or '-'} "
                        f"workflow={identity.workflow or '-'}"
                    )
            for assessment in file.slsa_provenance:
                lines.append("    SLSA provenance:")
                lines.append(
                    f"      source: {assessment.source_repository or '-'}"
                    f"@{assessment.source_commit or '-'}"
                )
                lines.append(f"      builder: {assessment.builder_id or '-'}")
                lines.append(f"      build type: {assessment.build_type or '-'}")
                lines.append(
                    "      workflow: "
                    f"{assessment.workflow_path or '-'}"
                    f"@{assessment.workflow_ref or '-'}"
                )
                lines.append(f"      materials: {len(assessment.materials)}")
                if assessment.action_references:
                    lines.append(
                        "      actions: "
                        + ", ".join(assessment.action_references)
                    )
                for issue in assessment.issues:
                    lines.append(
                        f"      issue: [{issue.severity}] "
                        f"{issue.code}: {issue.message}"
                    )
            if file.error:
                lines.append(f"    note: {file.error}")
            if file.artifact.inspected:
                lines.append("    artifact inspection:")
                lines.append(f"      kind: {file.artifact.kind}")
                lines.append(
                    "      archive valid: "
                    + (
                        "unknown"
                        if file.artifact.archive_valid is None
                        else "yes"
                        if file.artifact.archive_valid
                        else "no"
                    )
                )
                lines.append(f"      files: {file.artifact.file_count}")
                lines.append(
                    f"      uncompressed size: {file.artifact.total_uncompressed_size} bytes"
                )
                if file.artifact.record_valid is not None:
                    lines.append(
                        "      wheel RECORD: "
                        f"{'valid' if file.artifact.record_valid else 'invalid'}"
                    )
                if file.artifact.metadata_name or file.artifact.metadata_version:
                    lines.append(
                        "      metadata: "
                        f"name={file.artifact.metadata_name or '-'} "
                        f"version={file.artifact.metadata_version or '-'}"
                    )
                if file.artifact.wheel_version:
                    lines.append(
                        "      wheel metadata: "
                        f"version={file.artifact.wheel_version} "
                        "root_is_purelib="
                        f"{file.artifact.wheel_root_is_purelib} "
                        f"tags={','.join(file.artifact.wheel_tags) or '-'}"
                    )
                _append_artifact_findings(
                    lines,
                    "console scripts",
                    file.artifact.console_scripts,
                )
                _append_artifact_findings(
                    lines,
                    "native files",
                    file.artifact.native_files,
                )
                _append_artifact_findings(
                    lines,
                    "unexpected top-level files",
                    file.artifact.unexpected_top_level_files,
                )
                _append_artifact_findings(
                    lines,
                    "suspicious entry points",
                    file.artifact.suspicious_entry_points,
                )
                _append_artifact_findings(
                    lines,
                    "suspicious files",
                    file.artifact.suspicious_files,
                )
                _append_artifact_findings(
                    lines,
                    "oversized files",
                    file.artifact.oversized_files,
                )
                _append_artifact_findings(
                    lines,
                    "unusual files",
                    file.artifact.unusual_files,
                )
                _append_artifact_findings(
                    lines,
                    "RECORD errors",
                    file.artifact.record_errors,
                )
                _append_artifact_findings(
                    lines,
                    "metadata mismatches",
                    file.artifact.metadata_mismatches,
                )
                lines.append(
                    "      Python source files analyzed: "
                    f"{file.artifact.source_files_analyzed}"
                )
                _append_artifact_findings(
                    lines,
                    "source analysis errors",
                    file.artifact.source_parse_errors,
                )
                if file.artifact.native_binaries:
                    lines.append("      native binary analysis:")
                    for native in file.artifact.native_binaries:
                        lines.append(
                            "        - "
                            f"{native.path}: format={native.format} "
                            f"architecture={native.architecture or '-'} "
                            f"signature={native.signature_status} "
                            f"entropy={native.entropy if native.entropy is not None else '-'}"
                        )
                        if native.imports:
                            lines.append(
                                "          imports: " + ", ".join(native.imports)
                            )
                        if native.embedded_payloads:
                            lines.append(
                                "          embedded payloads: "
                                + ", ".join(native.embedded_payloads)
                            )
                        if native.parse_error:
                            lines.append(f"          parse note: {native.parse_error}")
                if file.artifact.error:
                    lines.append(f"      error: {file.artifact.error}")
            if file.dynamic_analysis.enabled:
                dynamic = file.dynamic_analysis
                lines.append("    bounded install analysis:")
                lines.append(f"      warning: {dynamic.warning}")
                lines.append(
                    "      mode: "
                    f"{dynamic.mode} ({dynamic.mode_label}) "
                    f"python={dynamic.python_version} "
                    f"classification={dynamic.classification}"
                )
                lines.append(
                    "      sandbox: "
                    f"{dynamic.sandbox} image={dynamic.image or '-'} "
                    f"network={dynamic.network} user={dynamic.user}"
                )
                lines.append(
                    "      limits: "
                    f"cpu={dynamic.cpu_limit} memory={dynamic.memory_limit} "
                    f"pids={dynamic.pids_limit} timeout={dynamic.timeout_seconds:g}s"
                )
                lines.append(
                    "      mounts: "
                    f"root={dynamic.root_filesystem} "
                    f"artifact={dynamic.artifact_mount} "
                    f"tmp={dynamic.temp_filesystem}"
                )
                lines.append(
                    "      result: "
                    f"executed={'yes' if dynamic.executed else 'no'} "
                    f"exit_code={dynamic.exit_code if dynamic.exit_code is not None else '-'}"
                )
                if dynamic.failure_type:
                    lines.append(f"      failure type: {dynamic.failure_type}")
                if dynamic.phases:
                    lines.append("      phases:")
                    for phase in dynamic.phases:
                        detail = (
                            f"        {phase.name}: {phase.status} "
                            f"classification={phase.classification}"
                        )
                        if phase.failure_type:
                            detail += f" failure={phase.failure_type}"
                        if phase.exit_code is not None:
                            detail += f" exit_code={phase.exit_code}"
                        lines.append(detail)
                evidence = dynamic.evidence
                evidence_counts = {
                    "children": len(evidence.child_processes),
                    "writes": len(evidence.files_modified),
                    "outside_writes": len(evidence.writes_outside_expected_locations),
                    "network": len(evidence.attempted_network_connections),
                    "credentials": len(evidence.credential_path_accesses),
                    "persistence": len(evidence.persistence_attempts),
                }
                if any(evidence_counts.values()):
                    lines.append(
                        "      evidence: "
                        + " ".join(
                            f"{name}={count}"
                            for name, count in evidence_counts.items()
                        )
                    )
                if dynamic.error:
                    lines.append(f"      error: {dynamic.error}")

    lines.append("")
    lines.append("diagnostics:")
    lines.append(
        "  network: "
        f"timeout={report.diagnostics.timeout} "
        f"retries={report.diagnostics.max_retries} "
        f"backoff={report.diagnostics.backoff_factor} "
        f"offline={report.diagnostics.offline} "
        f"cache_dir={report.diagnostics.cache_dir or '-'}"
    )
    if report.diagnostics.request_failures:
        lines.append("  request failures:")
        lines.extend(
            "    - "
            f"[{failure.subcode}] attempt={failure.attempt} "
            f"status={failure.status_code if failure.status_code is not None else '-'} "
            f"url={failure.url}"
            for failure in report.diagnostics.request_failures
        )
    else:
        lines.append("  request failures: none")
    if report.diagnostics.artifact_failures:
        lines.append("  artifact failures:")
        lines.extend(
            f"    - {item.filename} stage={item.stage} [{item.subcode}] {item.message}"
            for item in report.diagnostics.artifact_failures
        )
    else:
        lines.append("  artifact failures: none")

    lines.append("")
    lines.append("policy evaluation:")
    lines.append(
        "  settings: "
        f"verified_provenance={report.policy.require_verified_provenance} "
        f"expected_repo={report.policy.require_expected_repository_match} "
        "publisher_orgs="
        f"{','.join(report.policy.allowed_publisher_organizations) or 'any'} "
        f"metadata_only={report.policy.allow_metadata_only} "
        f"vulnerabilities={report.policy.vulnerability_mode} "
        f"suppressions={report.policy.suppressions_applied}/"
        f"{report.policy.suppressions_expired} "
        f"risk_severity={report.policy.fail_on_severity}"
    )
    if report.policy.violations:
        lines.append("  violations:")
        lines.extend(
            f"    - [{violation.severity}] {violation.code}: {violation.message}"
            for violation in report.policy.violations
        )
    else:
        lines.append("  violations: none")

    lines.append("")
    if report.risk_flags:
        lines.append("risk flags:")
        for flag in report.risk_flags:
            lines.append(f"  - [{flag.severity}] {flag.code}: {flag.message}")
            if flag.why:
                lines.append("    why:")
                lines.extend(f"      - {reason}" for reason in flag.why)
            if flag.remediation:
                lines.append("    remediation:")
                lines.extend(f"      - {step}" for step in flag.remediation)
    else:
        lines.append("risk flags: none")
    return "\n".join(lines)


def _append_artifact_findings(
    lines: list[str],
    label: str,
    findings: list[str],
) -> None:
    if not findings:
        return
    lines.append(f"      {label}:")
    lines.extend(f"        - {finding}" for finding in findings)


def _render_cve_json(report: TrustReport) -> dict[str, object]:
    payload: dict[str, object] = {
        "project": report.project,
        "version": report.version,
        "package_url": report.package_url,
        "vulnerabilities": [
            {
                "id": vuln.id,
                "summary": vuln.summary,
                "aliases": vuln.aliases,
                "source": vuln.source,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "cvss_version": vuln.cvss_version,
                "cwes": vuln.cwes,
                "fixed_in": vuln.fixed_in,
                "link": vuln.link,
                "withdrawn": vuln.withdrawn,
                "withdrawn_at": vuln.withdrawn_at,
                "kev": vuln.kev,
                "kev_date_added": vuln.kev_date_added,
                "kev_due_date": vuln.kev_due_date,
                "kev_required_action": vuln.kev_required_action,
                "kev_known_ransomware_campaign_use": (
                    vuln.kev_known_ransomware_campaign_use
                ),
                "epss_score": vuln.epss_score,
                "epss_percentile": vuln.epss_percentile,
                "epss_date": vuln.epss_date,
                "suppression": (
                    {
                        "vulnerability_id": (
                            vuln.suppression.vulnerability_id
                        ),
                        "owner": vuln.suppression.owner,
                        "justification": vuln.suppression.justification,
                        "expires": vuln.suppression.expires,
                        "status": vuln.suppression.status,
                    }
                    if vuln.suppression is not None
                    else None
                ),
            }
            for vuln in report.vulnerabilities
        ],
    }
    if report.remediation.status != "not-requested":
        payload["remediation"] = asdict(report.remediation)
    return payload


def _render_cve_report(report: TrustReport) -> str:
    lines = [
        f"known vulnerabilities for {report.project} {report.version}",
        f"package: {report.package_url}",
    ]
    if not report.vulnerabilities:
        lines.append("")
        lines.append("No known vulnerability records reported by configured sources.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"count: {len(report.vulnerabilities)}")
    lines.append("")
    for vuln in report.vulnerabilities:
        lines.append(f"- {vuln.id}: {vuln.summary}")
        if vuln.aliases:
            lines.append(f"  aliases: {', '.join(vuln.aliases)}")
        lines.append(f"  source: {vuln.source or 'unknown'}")
        lines.append(f"  severity: {vuln.severity or 'unknown'}")
        if vuln.cvss_score is not None:
            cvss = f"{vuln.cvss_score:.1f}"
            if vuln.cvss_vector:
                cvss += f" ({vuln.cvss_vector})"
            lines.append(f"  cvss: {cvss}")
        if vuln.cwes:
            lines.append(f"  cwes: {', '.join(vuln.cwes)}")
        if vuln.fixed_in:
            lines.append(f"  fixed in: {', '.join(vuln.fixed_in)}")
        if vuln.withdrawn:
            lines.append(f"  withdrawn: {vuln.withdrawn_at or 'yes'}")
        if vuln.kev:
            lines.append(
                "  CISA KEV: yes"
                + (
                    f" (due {vuln.kev_due_date})"
                    if vuln.kev_due_date
                    else ""
                )
            )
        if vuln.epss_score is not None:
            lines.append(
                f"  EPSS: {vuln.epss_score:.4f}"
                + (
                    f" (percentile {vuln.epss_percentile:.4f})"
                    if vuln.epss_percentile is not None
                    else ""
                )
            )
        if vuln.suppression is not None:
            lines.append(
                "  suppression: "
                f"{vuln.suppression.status}; "
                f"owner={vuln.suppression.owner}; "
                f"expires={vuln.suppression.expires}; "
                f"justification={vuln.suppression.justification}"
            )
        if vuln.link:
            lines.append(f"  link: {vuln.link}")
    return "\n".join(lines)


def _render_scan_text(
    filename: str,
    reports: list[TrustReport],
    *,
    failures: list[dict[str, str]],
    verbose: bool,
    vulnerability_only: bool,
) -> str:
    sections = [
        f"trustcheck scan results for {filename}",
        f"packages: {len(reports) + len(failures)}",
        f"successful: {len(reports)}",
        f"failed: {len(failures)}",
    ]

    rendered_reports = [
        (
            _render_cve_report(report)
            if vulnerability_only
            else _render_text_report(report, verbose=verbose)
        )
        for report in reports
    ]
    if rendered_reports:
        sections.append("")
        sections.extend(rendered_reports)

    if failures:
        sections.append("")
        sections.append("scan failures:")
        sections.extend(
            f"  - {failure['requirement']}: {failure['message']}" for failure in failures
        )
    return "\n\n".join(section for section in sections if section != "")


def _render_decision_report(report: TrustReport) -> str:
    lines = [
        f"decision: {'pass' if report.policy.passed else 'fail'}",
        f"affected package: {report.project} {report.version}",
        f"blocking reason: {_blocking_reason(report)}",
        f"recommended action: {_recommended_action(report)}",
        "evidence links:",
    ]
    links = _evidence_links(report)
    lines.extend(f"  - {link}" for link in links)
    if not links:
        lines.append("  - none")
    return "\n".join(lines)


def _render_decision_scan(
    filename: str,
    reports: list[TrustReport],
    *,
    failures: list[dict[str, str]],
) -> str:
    failing_reports = [report for report in reports if not report.policy.passed]
    selected_reports = failing_reports or reports[:1]
    decision = "fail" if failures or failing_reports else "pass"
    sections = [f"decision: {decision}"]
    if failures:
        for failure in failures:
            sections.append(
                "\n".join(
                    [
                        f"affected package: {failure['requirement']}",
                        f"blocking reason: {failure['message']}",
                        (
                            "recommended action: Fix the target or rerun after "
                            "the upstream/index error is resolved."
                        ),
                        "evidence links:",
                        f"  - {filename}",
                    ]
                )
            )
    for report in selected_reports:
        sections.append(_render_decision_report(report))
    if not failures and not selected_reports:
        sections.append(
            "\n".join(
                [
                    "affected package: none",
                    "blocking reason: no packages were inspected",
                    "recommended action: Provide a package or dependency file target.",
                    "evidence links:",
                    f"  - {filename}",
                ]
            )
        )
    return "\n\n".join(sections)


def _render_scan_json(
    filename: str,
    reports: list[TrustReport],
    *,
    failures: list[dict[str, str]],
    vulnerability_only: bool,
    targets: Sequence[ScanTarget] = (),
) -> dict[str, object]:
    return {
        "file": filename,
        "schema_version": JSON_SCHEMA_VERSION,
        "resolved": [
            {
                "requirement": target.requirement,
                "project": target.project,
                "version": target.version,
                "requested": target.requested,
                "source_url": target.source_url,
                "editable": target.editable,
                "vcs": target.vcs,
                "vcs_commit": target.vcs_commit,
                "index_url": (
                    redact_url_credentials(target.index_url)
                    if target.index_url
                    else None
                ),
                "artifacts": [
                    artifact.to_dict() for artifact in target.artifacts
                ],
                "dependency_confusion": list(target.dependency_confusion),
                "source_file": target.source_file,
                "source_line": target.source_line,
            }
            for target in targets
        ],
        "reports": [
            (
                _render_cve_json(report)
                if vulnerability_only
                else report.to_dict()["report"]
            )
            for report in reports
        ],
        "failures": failures,
    }


def _evidence_summary(report: TrustReport) -> str:
    if report.files and all(file.verified for file in report.files):
        return "cryptographic verification succeeded for all discovered release artifacts"
    if any(file.verified for file in report.files):
        return "mixed evidence; some release artifacts verified cryptographically, others did not"
    return (
        "heuristic metadata and provenance signals only; no cryptographically verified artifact set"
    )


def _recommendation_reasons(report: TrustReport) -> list[str]:
    reasons: list[str] = []
    if report.risk_flags:
        reasons.extend(flag.message for flag in report.risk_flags[:3])
    if report.files and not all(file.verified for file in report.files):
        reasons.append(
            "Only "
            f"{report.coverage.verified_files} of "
            f"{report.coverage.total_files} discovered artifact(s) "
            "verified successfully."
        )
    elif report.files:
        reasons.append("Every discovered release artifact verified successfully.")
    if report.expected_repository and not any(
        flag.code.startswith("expected_repository") for flag in report.risk_flags
    ):
        reasons.append("The expected repository matched available package and publisher evidence.")
    return reasons[:4]


def _blocking_reason(report: TrustReport) -> str:
    if report.policy.violations:
        violation = report.policy.violations[0]
        return f"{violation.code}: {violation.message}"
    high_flags = [flag for flag in report.risk_flags if flag.severity == "high"]
    if high_flags:
        flag = high_flags[0]
        return f"{flag.code}: {flag.message}"
    if report.vulnerabilities:
        vulnerability = report.vulnerabilities[0]
        return f"{vulnerability.id}: {vulnerability.summary}"
    if report.recommendation in {"high-risk", "review-required", "metadata-only"}:
        return f"recommendation={report.recommendation}: {_evidence_summary(report)}"
    return "none"


def _recommended_action(report: TrustReport) -> str:
    reason = _blocking_reason(report)
    if reason == "none":
        return "Proceed with the selected package version."
    if "vulnerab" in reason or report.vulnerabilities:
        return "Upgrade to a fixed version or apply a reviewed expiring suppression."
    if "source_release_" in reason or "expected_repository" in reason:
        return "Verify the publisher source and rebuild from the intended immutable commit."
    if "provenance" in reason or "attestation" in reason:
        return "Require verified provenance or approve a documented release exception."
    return "Block promotion until the cited evidence is reviewed."


def _evidence_links(report: TrustReport) -> list[str]:
    links: list[str] = []
    for candidate in (
        report.package_url,
        report.expected_repository,
        *report.declared_repository_urls,
        *report.repository_urls,
        *(vulnerability.link for vulnerability in report.vulnerabilities),
        *(file.url for file in report.files),
        *(
            provenance.invocation_id
            for file in report.files
            for provenance in file.slsa_provenance
        ),
    ):
        if candidate and candidate not in links:
            links.append(candidate)
    return links[:8]

