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
    FileProvenance,
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
