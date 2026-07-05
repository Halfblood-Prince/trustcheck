from __future__ import annotations

import importlib
import io
import json
import runpy
import sys
import types
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

import trustcheck
from trustcheck.cli import (
    _build_client,
    _build_debug_request_hook,
    _load_config_file,
    _render_text_report,
)
from trustcheck.models import (
    ArtifactDiagnostic,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    HeuristicFinding,
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
from trustcheck.policy import (
    PolicySettings,
    _suppression_expiry,
    _vulnerability_is_blocked,
    evaluate_policy,
    load_policy_file,
    policy_from_mapping,
    resolve_policy,
)
from trustcheck.pypi import PypiClient, PypiClientError

SCRATCH_ROOT = Path(__file__).parent / "_tmp"


def make_report() -> TrustReport:
    return TrustReport(
        project="gridoptim",
        version="2.2.0",
        summary="gridoptim package",
        package_url="https://pypi.org/project/gridoptim/2.2.0/",
        declared_dependencies=["depalpha>=1.0"],
        declared_repository_urls=["https://github.com/halfblood-prince/gridoptim"],
        repository_urls=["https://github.com/halfblood-prince/gridoptim"],
        expected_repository="https://github.com/halfblood-prince/gridoptim",
        ownership={
            "organization": "Halfblood-Prince",
            "roles": [{"role": "Owner", "user": "Halfblood-Prince"}],
        },
        files=[
            FileProvenance(
                filename="gridoptim-2.2.0-py3-none-any.whl",
                url="https://files.pythonhosted.org/packages/gridoptim.whl",
                sha256="abc123",
                observed_sha256="abc123",
                has_provenance=True,
                verified=True,
                attestation_count=1,
                verified_attestation_count=1,
                publisher_identities=[
                    PublisherIdentity(
                        kind="GitHub",
                        repository="https://github.com/halfblood-prince/gridoptim",
                        workflow="release.yml",
                        environment=None,
                    )
                ],
            )
        ],
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1,
            verified_files=1,
            status="all-verified",
        ),
        publisher_trust=PublisherTrustSummary(
            depth_score=5,
            depth_label="strong",
            verified_publishers=[
                "GitHub:https://github.com/halfblood-prince/gridoptim:release.yml"
            ],
            unique_verified_repositories=["https://github.com/halfblood-prince/gridoptim"],
            unique_verified_workflows=["release.yml"],
        ),
        provenance_consistency=ProvenanceConsistency(
            has_sdist=False,
            has_wheel=True,
            sdist_wheel_consistent=True,
            consistent_repositories=["https://github.com/halfblood-prince/gridoptim"],
            consistent_workflows=["release.yml"],
        ),
        release_drift=ReleaseDriftSummary(
            compared_to_version="2.1.0",
            publisher_repository_drift=False,
            publisher_workflow_drift=True,
            previous_repositories=["https://github.com/halfblood-prince/gridoptim"],
            previous_workflows=["old-release.yml"],
        ),
        dependencies=[
            DependencyInspection(
                requirement="depalpha>=1.0",
                project="depalpha",
                version="1.4.0",
                depth=1,
                parent_project="gridoptim",
                parent_version="2.2.0",
                package_url="https://pypi.org/project/depalpha/1.4.0/",
                recommendation="review-required",
            )
        ],
        dependency_summary=DependencySummary(
            requested=True,
            total_declared=1,
            total_inspected=1,
            unique_dependencies=1,
            max_depth=1,
            highest_risk_recommendation="review-required",
            highest_risk_projects=["depalpha"],
            review_required_projects=["depalpha"],
        ),
        vulnerabilities=[
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="example vulnerability",
            )
        ],
        risk_flags=[
            RiskFlag(
                code="publisher_workflow_drift",
                severity="medium",
                message="Workflow changed between releases.",
                why=["The verified workflow name differs from the previous release."],
                remediation=["Review the workflow update before promotion."],
            )
        ],
        diagnostics=ReportDiagnostics(
            timeout=1.5,
            max_retries=3,
            backoff_factor=0.25,
            offline=True,
            cache_dir=".cache/trustcheck",
            request_count=4,
            retry_count=1,
            cache_hit_count=2,
            request_failures=[
                RequestFailureDiagnostic(
                    url="https://pypi.org/pypi/gridoptim/json",
                    attempt=1,
                    code="upstream",
                    subcode="http_transient",
                    message="PyPI returned HTTP 503",
                    transient=True,
                    status_code=503,
                )
            ],
            artifact_failures=[
                ArtifactDiagnostic(
                    filename="gridoptim-2.2.0.tar.gz",
                    stage="provenance-fetch",
                    code="upstream",
                    subcode="http_not_found",
                    message="resource not found",
                )
            ],
        ),
    )


class PackageEntryPointTests(unittest.TestCase):
    def test_main_module_exits_with_cli_status(self) -> None:
        with patch("trustcheck.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_module("trustcheck.__main__", run_name="__main__")

        self.assertEqual(ctx.exception.code, 7)

    def test_package_version_falls_back_when_metadata_missing(self) -> None:
        with patch.dict(sys.modules, {"trustcheck._version": None}):
            with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
                reloaded = importlib.reload(trustcheck)
                self.assertEqual(reloaded.__version__, "0+unknown")

        importlib.reload(trustcheck)

    def test_package_version_uses_generated_version_module_without_metadata(self) -> None:
        version_module = types.ModuleType("trustcheck._version")
        version_module.version = "1.2.3"

        with patch.dict(sys.modules, {"trustcheck._version": version_module}):
            with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
                reloaded = importlib.reload(trustcheck)
                self.assertEqual(reloaded.__version__, "1.2.3")

        importlib.reload(trustcheck)


class CliHelperCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(exist_ok=True)

    def test_load_config_file_rejects_non_object_payload(self) -> None:
        path = SCRATCH_ROOT / "config_non_object.json"
        path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "top-level JSON object"):
            _load_config_file(str(path))

    def test_build_client_rejects_non_object_network_config(self) -> None:
        args = Namespace(
            timeout=None,
            retries=None,
            backoff=None,
            cache_dir=None,
            offline=False,
        )

        with self.assertRaisesRegex(ValueError, "field 'network' must be an object"):
            _build_client(args, config_payload={"network": []}, request_hook=None)

    def test_build_client_uses_cli_values_over_env_and_config(self) -> None:
        args = Namespace(
            timeout=9.0,
            retries=8,
            backoff=0.9,
            cache_dir=".cli-cache",
            offline=True,
        )

        with patch.dict(
            "os.environ",
            {
                "TRUSTCHECK_TIMEOUT": "1.0",
                "TRUSTCHECK_RETRIES": "1",
                "TRUSTCHECK_BACKOFF": "0.1",
                "TRUSTCHECK_CACHE_DIR": ".env-cache",
                "TRUSTCHECK_OFFLINE": "false",
            },
            clear=False,
        ):
            client = _build_client(
                args,
                config_payload={
                    "network": {
                        "timeout": 2.0,
                        "retries": 2,
                        "backoff_factor": 0.2,
                        "cache_dir": ".cfg-cache",
                        "offline": False,
                    }
                },
                request_hook=None,
            )

        self.assertEqual(client.timeout, 9.0)
        self.assertEqual(client.max_retries, 8)
        self.assertEqual(client.backoff_factor, 0.9)
        self.assertEqual(client.cache_dir, ".cli-cache")
        self.assertTrue(client.offline)

    def test_build_debug_request_hook_text_logs_are_key_sorted(self) -> None:
        stderr = io.StringIO()
        hook = _build_debug_request_hook(enabled=True, log_format="text")
        assert hook is not None

        with redirect_stderr(stderr):
            hook("retry", {"zeta": 2, "alpha": 1})

        self.assertEqual(
            stderr.getvalue().strip(),
            "[debug] event=retry alpha=1 zeta=2",
        )

    def test_render_text_report_includes_verbose_sections(self) -> None:
        report = make_report()
        report.diagnostics.request_failures = []
        rendered = _render_text_report(report, verbose=True)

        self.assertIn("expected repository:", rendered)
        self.assertIn("sdist/wheel provenance consistency: consistent", rendered)
        self.assertIn("release drift baseline: 2.1.0", rendered)
        self.assertIn("vulnerabilities:", rendered)
        self.assertIn("publisher: kind=GitHub", rendered)
        self.assertIn("request failures: none", rendered)
        self.assertIn("artifact failures:", rendered)
        self.assertIn("dependencies:", rendered)


class PolicyCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(exist_ok=True)

    def test_evaluate_policy_covers_missing_files_and_metadata_only(self) -> None:
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            expected_repository=None,
            recommendation="metadata-only",
        )
        settings = PolicySettings(
            profile="team",
            require_verified_provenance="all",
            allow_metadata_only=False,
            require_expected_repository_match=True,
            vulnerability_mode="any",
            fail_on_severity="medium",
        )

        evaluation = evaluate_policy(report, settings)
        self.assertFalse(evaluation.passed)
        self.assertEqual(
            {item.code for item in evaluation.violations},
            {
                "verified_provenance_required",
                "expected_repository_required",
                "metadata_only_not_allowed",
            },
        )

    def test_policy_file_and_mapping_validation_errors_are_explicit(self) -> None:
        path = SCRATCH_ROOT / "policy_non_object.json"
        path.write_text(json.dumps(["bad"]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "top-level JSON object"):
            load_policy_file(path)

        with self.assertRaisesRegex(ValueError, "unknown policy setting"):
            policy_from_mapping({"nope": True})

        with self.assertRaisesRegex(ValueError, "require_verified_provenance"):
            policy_from_mapping({"require_verified_provenance": "sometimes"})

        with self.assertRaisesRegex(ValueError, "vulnerability_mode"):
            policy_from_mapping({"vulnerability_mode": "sometimes"})

        with self.assertRaisesRegex(ValueError, "fail_on_severity"):
            policy_from_mapping({"fail_on_severity": "low"})

        with self.assertRaisesRegex(ValueError, "malicious-package score thresholds"):
            policy_from_mapping({"malicious_package_thresholds": {"high": 20}})

        with self.assertRaisesRegex(ValueError, "malicious-package rule thresholds"):
            policy_from_mapping({"malicious_rule_thresholds": {"ast_network_call": 101}})

        with self.assertRaisesRegex(ValueError, "organization allowlist"):
            policy_from_mapping(
                {
                    "allowed_publisher_organizations": [
                        "https://github.com/example"
                    ]
                }
            )

    def test_resolve_policy_rejects_unknown_builtin(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown built-in policy"):
            resolve_policy(builtin_name="missing")

    def test_evaluate_policy_dedupes_duplicate_risk_flags(self) -> None:
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            vulnerabilities=[
                VulnerabilityRecord(id="PYSEC-2026-1", summary="example vulnerability")
            ],
            risk_flags=[
                RiskFlag(
                    code="publisher_repository_drift",
                    severity="high",
                    message="Repository changed.",
                ),
                RiskFlag(
                    code="publisher_repository_drift",
                    severity="high",
                    message="Repository changed.",
                ),
            ],
        )
        settings = PolicySettings(
            profile="strict",
            vulnerability_mode="any",
            fail_on_severity="high",
        )

        evaluation = evaluate_policy(report, settings)
        self.assertEqual(
            [item.code for item in evaluation.violations],
            ["vulnerabilities_blocked", "publisher_repository_drift"],
        )

    def test_publisher_organization_policy_uses_verified_identities(self) -> None:
        report = make_report()
        allowed = evaluate_policy(
            report,
            PolicySettings(
                allowed_publisher_organizations=["github:halfblood-prince"]
            ),
        )
        self.assertTrue(allowed.passed)
        self.assertEqual(
            allowed.allowed_publisher_organizations,
            ["github:halfblood-prince"],
        )

        blocked = evaluate_policy(
            report,
            PolicySettings(
                allowed_publisher_organizations=["github:other-org"]
            ),
        )
        self.assertEqual(
            [violation.code for violation in blocked.violations],
            ["publisher_organization_not_allowed"],
        )

        report.files[0].verified = False
        unverified = evaluate_policy(
            report,
            PolicySettings(
                allowed_publisher_organizations=["halfblood-prince"]
            ),
        )
        self.assertEqual(
            [violation.code for violation in unverified.violations],
            ["publisher_organization_unverified"],
        )

    def test_malicious_package_thresholds_are_policy_configurable(self) -> None:
        report = make_report()
        report.malicious_package = MaliciousPackageAssessment(
            findings=[
                HeuristicFinding(
                    code="ast_credential_network_chain",
                    category="credential-access",
                    severity="critical",
                    confidence="medium",
                    score=75,
                    message="Credential access and network capability are combined.",
                )
            ]
        )
        strict_threshold = PolicySettings(
            fail_on_severity="high",
            malicious_package_thresholds={
                "low": 1,
                "elevated": 25,
                "high": 70,
                "critical": 90,
            },
        )
        relaxed_threshold = PolicySettings(fail_on_severity="high")

        strict = evaluate_policy(report, strict_threshold)
        self.assertTrue(strict.passed)
        self.assertEqual(report.malicious_package.level, "elevated")

        relaxed = evaluate_policy(report, relaxed_threshold)
        self.assertFalse(relaxed.passed)
        self.assertIn(
            "malicious_package_heuristics",
            {violation.code for violation in relaxed.violations},
        )
        self.assertTrue(
            any(
                "estimated false-positive prior" in reason
                for flag in report.risk_flags
                if flag.code == "malicious_package_heuristics"
                for reason in flag.why
            )
        )

    def test_vulnerability_modes_and_expiring_suppressions(self) -> None:
        vulnerability = VulnerabilityRecord(
            id="GHSA-demo",
            summary="Critical exploited vulnerability",
            aliases=["CVE-2026-1000"],
            severity="CRITICAL",
            cvss_score=9.8,
            fixed_in=["2.2.1"],
            kev=True,
        )
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            vulnerabilities=[vulnerability],
        )
        settings = policy_from_mapping({
            "vulnerability_mode": "kev",
            "suppressions": [
                {
                    "id": "CVE-2026-1000",
                    "owner": "security@example.com",
                    "justification": "Compensating control is deployed.",
                    "expires": "2026-06-30",
                }
            ],
        })

        active = evaluate_policy(
            report,
            settings,
            now=datetime(2026, 6, 13, tzinfo=timezone.utc),
        )
        self.assertTrue(active.passed)
        self.assertEqual(active.suppressions_applied, 1)
        self.assertEqual(vulnerability.suppression.status, "active")

        expired = evaluate_policy(
            report,
            settings,
            now=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        self.assertFalse(expired.passed)
        self.assertEqual(expired.suppressions_expired, 1)
        self.assertEqual(
            expired.violations[0].code,
            "kev_vulnerabilities_blocked",
        )
        self.assertEqual(vulnerability.suppression.status, "expired")

        for mode, code in (
            ("critical", "critical_vulnerabilities_blocked"),
            ("fixable", "fixable_vulnerabilities_blocked"),
        ):
            with self.subTest(mode=mode):
                evaluation = evaluate_policy(
                    report,
                    PolicySettings(vulnerability_mode=mode),
                )
                self.assertEqual(evaluation.violations[0].code, code)

    def test_suppression_validation_requires_accountability_and_expiry(self) -> None:
        cases = [
            ({}, "id is required"),
            ({"id": "CVE-1"}, "owner is required"),
            (
                {"id": "CVE-1", "owner": "team"},
                "justification is required",
            ),
            (
                {
                    "id": "CVE-1",
                    "owner": "team",
                    "justification": "temporary",
                },
                "expires is required",
            ),
            (
                {
                    "id": "CVE-1",
                    "owner": "team",
                    "justification": "temporary",
                    "expires": "forever",
                },
                "ISO date",
            ),
        ]
        for suppression, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    policy_from_mapping({"suppressions": [suppression]})

    def test_suppression_structure_duplicates_and_datetime_expiry(self) -> None:
        invalid = [
            ("not-a-list", "must be a list"),
            ([1], "must be an object"),
            (
                [
                    {
                        "id": "CVE-1",
                        "owner": "team",
                        "justification": "temporary",
                        "expires": "2026-07-01",
                        "unknown": True,
                    }
                ],
                "unknown suppression",
            ),
            (
                [
                    {
                        "id": "CVE-1",
                        "owner": "team",
                        "justification": "temporary",
                        "expires": "2026-07-01",
                    },
                    {
                        "vulnerability_id": "cve-1",
                        "owner": "team",
                        "justification": "duplicate",
                        "expires": "2026-08-01",
                    },
                ],
                "duplicate suppression",
            ),
            (
                [
                    {
                        "id": "CVE-1",
                        "owner": "team",
                        "justification": "temporary",
                        "expires": "2026-06-31T12:00:00Z",
                    }
                ],
                "ISO date",
            ),
        ]
        for suppressions, message in invalid:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    policy_from_mapping({"suppressions": suppressions})

        self.assertEqual(
            _suppression_expiry("2026-06-30T12:00:00"),
            datetime(2026, 6, 30, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(
            _suppression_expiry("2026-06-30 14:00:00+02:00"),
            datetime(2026, 6, 30, 12, tzinfo=timezone.utc),
        )

    def test_policy_repository_matching_naive_time_and_nonblocking_modes(self) -> None:
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            expected_repository="https://github.com/example/gridoptim",
            vulnerabilities=[
                VulnerabilityRecord(
                    id="CVE-2026-1",
                    summary="withdrawn",
                    withdrawn=True,
                ),
                VulnerabilityRecord(
                    id="CVE-2026-2",
                    summary="low",
                    severity="LOW",
                ),
            ],
            risk_flags=[
                RiskFlag(
                    code="expected_repository_mismatch",
                    severity="high",
                    message="Repository mismatch.",
                )
            ],
        )
        settings = policy_from_mapping(
            {
                "require_expected_repository_match": True,
                "vulnerability_mode": "critical",
                "suppressions": [
                    {
                        "id": "CVE-2026-2",
                        "owner": "security",
                        "justification": "temporary",
                        "expires": "2026-07-01T00:00:00Z",
                    }
                ],
            }
        )

        evaluation = evaluate_policy(
            report,
            settings,
            now=datetime(2026, 6, 13),
        )

        self.assertEqual(
            [violation.code for violation in evaluation.violations],
            ["expected_repository_mismatch"],
        )
        self.assertEqual(evaluation.suppressions_applied, 1)
        self.assertFalse(
            _vulnerability_is_blocked(
                report.vulnerabilities[0],
                mode="any",
            )
        )
        self.assertFalse(
            _vulnerability_is_blocked(
                report.vulnerabilities[1],
                mode="kev",
            )
        )
        self.assertFalse(
            _vulnerability_is_blocked(
                report.vulnerabilities[1],
                mode="fixable",
            )
        )
        self.assertFalse(
            _vulnerability_is_blocked(
                report.vulnerabilities[1],
                mode="ignore",
            )
        )
        self.assertFalse(
            _vulnerability_is_blocked(
                report.vulnerabilities[1],
                mode="invalid",  # type: ignore[arg-type]
            )
        )

    def test_resolve_policy_merges_file_and_cli_overrides(self) -> None:
        path = SCRATCH_ROOT / "policy_merge.json"
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(
            json.dumps(
                {
                    "profile": "file-policy",
                    "vulnerability_mode": "critical",
                    "allow_metadata_only": False,
                }
            ),
            encoding="utf-8",
        )

        settings = resolve_policy(
            builtin_name="default",
            config_path=str(path),
            cli_overrides={
                "vulnerability_mode": "kev",
                "fail_on_severity": None,
            },
        )

        self.assertEqual(settings.profile, "file-policy")
        self.assertEqual(settings.vulnerability_mode, "kev")
        self.assertFalse(settings.allow_metadata_only)

        unchanged = resolve_policy(
            builtin_name="default",
            cli_overrides={"vulnerability_mode": None},
        )
        self.assertEqual(unchanged.vulnerability_mode, "ignore")

    def test_policy_message_truncates_long_vulnerability_lists(self) -> None:
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            vulnerabilities=[
                VulnerabilityRecord(id=f"CVE-2026-{index}", summary="issue")
                for index in range(6)
            ],
        )

        evaluation = evaluate_policy(
            report,
            PolicySettings(vulnerability_mode="any"),
        )

        self.assertIn(", ...", evaluation.violations[0].message)

    def test_suppression_controls_vulnerability_policy_not_legacy_risk_flag(
        self,
    ) -> None:
        vulnerability = VulnerabilityRecord(
            id="CVE-2026-1000",
            summary="Known vulnerability",
            severity="critical",
        )
        report = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            vulnerabilities=[vulnerability],
            risk_flags=[
                RiskFlag(
                    code="known_vulnerabilities",
                    severity="high",
                    message="Known vulnerability.",
                )
            ],
        )
        settings = policy_from_mapping(
            {
                "vulnerability_mode": "critical",
                "fail_on_severity": "high",
                "suppressions": [
                    {
                        "id": "CVE-2026-1000",
                        "owner": "security",
                        "justification": "Compensating control.",
                        "expires": "2026-06-30",
                    }
                ],
            }
        )

        evaluation = evaluate_policy(
            report,
            settings,
            now=datetime(2026, 6, 13, tzinfo=timezone.utc),
        )

        self.assertTrue(evaluation.passed)
        self.assertEqual(evaluation.suppressions_applied, 1)


class PypiCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(exist_ok=True)

    def test_decode_json_payload_rejects_non_object(self) -> None:
        client = PypiClient()

        with self.assertRaises(PypiClientError) as ctx:
            client._decode_json_payload(b"[]", "https://pypi.org/pypi/gridoptim/json")

        self.assertEqual(ctx.exception.subcode, "json_non_object")

    def test_default_user_agent_uses_generated_version_module_without_metadata(self) -> None:
        version_module = types.ModuleType("trustcheck._version")
        version_module.version = "2.3.4"

        with patch.dict(sys.modules, {"trustcheck._version": version_module}):
            with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
                reloaded = importlib.reload(importlib.import_module("trustcheck.pypi"))

        self.assertEqual(reloaded.DEFAULT_USER_AGENT, "trustcheck/2.3.4")
        importlib.reload(reloaded)

    def test_write_and_read_disk_cache_emit_events(self) -> None:
        cache_dir = SCRATCH_ROOT / "cache"
        cache_dir.mkdir(exist_ok=True)
        events: list[tuple[str, dict[str, object]]] = []
        client = PypiClient(
            cache_dir=str(cache_dir),
            request_hook=lambda event, payload: events.append((event, payload)),
        )
        url = "https://pypi.org/pypi/gridoptim/json"
        payload = b'{"info":{"version":"1.0.0"}}'

        client._write_disk_cache(url, payload, accept="application/json")
        cached = client._read_disk_cache(url, accept="application/json")

        self.assertEqual(cached, payload)
        self.assertEqual([event for event, _ in events], ["cache_store", "cache_hit"])
