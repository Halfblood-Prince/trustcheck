from __future__ import annotations

import json
import runpy
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib import error

import trustcheck.cache as cache_module
import trustcheck.resume as resume_module
import trustcheck.snapshots as snapshots_module
from trustcheck.advisories import (
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
)
from trustcheck.cache import CacheIntegrityError, ContentAddressedCache
from trustcheck.cli import ScanTarget, _run_scan_targets, main
from trustcheck.github_action import (
    ActionInputError,
    ActionSettings,
    build_cli_arguments,
)
from trustcheck.indexes import IndexFile, IndexProject
from trustcheck.models import (
    ArtifactInspection,
    HeuristicFinding,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from trustcheck.plugins import PluginError, PluginManager
from trustcheck.policy import PolicySettings
from trustcheck.pypi import PypiClientError
from trustcheck.resume import ScanState, ScanStateError, scan_fingerprint, target_key
from trustcheck.schemas import VulnerabilityPayload
from trustcheck.service import inspect_package
from trustcheck.snapshots import (
    ADVISORY_SNAPSHOT_SCHEMA,
    AdvisorySnapshotError,
    AdvisorySnapshotStore,
)


class BenchmarkPublicationTests(unittest.TestCase):
    def test_committed_findings_normalize_to_complete_agreement(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_committed_findings_test",
        )
        published = json.loads(
            (root / "benchmarks" / "results" / "latest.json").read_text(
                encoding="utf-8"
            )
        )["findings"]

        def vulnerability(aliases: list[str]) -> dict[str, object]:
            return {"id": aliases[0], "aliases": aliases[1:]}

        trustcheck_payload = {
            "reports": [
                {
                    "project": item["project"],
                    "version": item["version"],
                    "vulnerabilities": [
                        vulnerability(aliases) for aliases in item["advisories"]
                    ],
                }
                for item in published["trustcheck"]
            ]
        }
        pip_audit_payload = {
            "dependencies": [
                {
                    "name": item["project"],
                    "version": item["version"],
                    "vulns": [
                        vulnerability(aliases) for aliases in item["advisories"]
                    ],
                }
                for item in published["pip_audit"]
            ]
        }
        comparison = namespace["_compare_findings"](
            namespace["_trustcheck_findings"](trustcheck_payload),
            namespace["_pip_audit_findings"](pip_audit_payload),
        )

        self.assertEqual(comparison["matched_advisories"], 263)
        self.assertEqual(comparison["trustcheck_only"], [])
        self.assertEqual(comparison["pip_audit_only"], [])
        self.assertEqual(comparison["alias_aware_agreement"], 1.0)

    def test_package_and_version_keys_are_canonicalized_across_tools(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_normalization_test",
        )
        trustcheck_payload = {
            "reports": [
                {
                    "project": "django",
                    "version": "2.2",
                    "vulnerabilities": [{"id": "CVE-2026-1"}],
                },
                {
                    "project": "jaraco.context",
                    "version": "5.3.0",
                    "vulnerabilities": [{"id": "CVE-2026-2"}],
                },
            ]
        }
        pip_audit_payload = {
            "dependencies": [
                {
                    "name": "Django",
                    "version": "2.2.0",
                    "vulns": [{"id": "CVE-2026-1"}],
                },
                {
                    "name": "jaraco-context",
                    "version": "5.3",
                    "vulns": [{"id": "CVE-2026-2"}],
                },
            ]
        }

        trustcheck = namespace["_trustcheck_findings"](trustcheck_payload)
        pip_audit = namespace["_pip_audit_findings"](pip_audit_payload)
        comparison = namespace["_compare_findings"](trustcheck, pip_audit)

        self.assertEqual(trustcheck, pip_audit)
        self.assertEqual(comparison["matched_advisories"], 2)
        self.assertEqual(comparison["trustcheck_only"], [])
        self.assertEqual(comparison["pip_audit_only"], [])
        self.assertEqual(comparison["alias_aware_agreement"], 1.0)
        self.assertTrue(
            namespace["_compare_resolutions"](
                trustcheck_payload, pip_audit_payload
            )["exact_match"]
        )

    def test_corpus_manifest_is_versioned_and_large_enough(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_test",
        )
        corpus = namespace["_load_corpus"](
            root / "benchmarks" / "corpus" / "corpus.json"
        )
        truth = namespace["_load_truth_corpus"](
            root / "benchmarks" / "corpus" / "truth.json"
        )
        comparable = namespace["_benchmark_cases"](corpus, [])

        self.assertEqual(corpus.version, "2026.06")
        self.assertGreaterEqual(corpus.package_count, 100)
        self.assertLessEqual(corpus.package_count, 500)
        self.assertGreaterEqual(sum(case.package_count for case in comparable), 100)
        self.assertIn(
            "mixed-clean-vulnerable-pins",
            {case.category for case in corpus.cases},
        )
        self.assertIn("lockfiles", {case.category for case in corpus.cases})
        self.assertIn("malformed", {case.category for case in corpus.cases})
        self.assertEqual(truth.version, "2026.06.1")
        self.assertTrue(any(case.withdrawn for case in truth.cases))
        self.assertTrue(any(case.extras for case in truth.cases))
        self.assertTrue(any(case.marker for case in truth.cases))
        self.assertTrue(any(case.private_index for case in truth.cases))

        trustcheck_command = namespace["_trustcheck_command"](
            comparable[0],
            max_workers=8,
        )
        pip_audit_command = namespace["_pip_audit_command"](comparable[0])
        self.assertEqual(
            trustcheck_command[:4],
            [sys.executable, "-m", "trustcheck", "scan"],
        )
        self.assertNotIn("inspect", trustcheck_command)
        self.assertIn("--fast", trustcheck_command)
        self.assertEqual(
            pip_audit_command[:3],
            [sys.executable, "-m", "pip_audit"],
        )
        self.assertIn("--no-deps", trustcheck_command)
        self.assertIn("--no-deps", pip_audit_command)
        self.assertIn("--disable-pip", pip_audit_command)
        resolution_case = namespace["_case_for_role"](corpus, "resolution")
        profiles_case = namespace["_case_for_role"](corpus, "profiles")
        self.assertIsNotNone(resolution_case)
        self.assertIsNotNone(profiles_case)
        resolution_command = namespace["_trustcheck_command"](
            resolution_case,
            max_workers=8,
            resolve_dependencies=True,
        )
        self.assertNotIn("--no-deps", resolution_command)

    def test_malicious_calibration_manifest_is_versioned_and_unmeasured(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads(
            (root / "benchmarks" / "corpus" / "malicious-calibration.json").read_text(
                encoding="utf-8"
            )
        )
        case_sets = {case["id"]: case for case in manifest["case_sets"]}

        self.assertEqual(
            manifest["schema"],
            "urn:trustcheck:malicious-calibration-corpus:0.1.0",
        )
        self.assertEqual(manifest["status"], "seed-unmeasured")
        self.assertFalse(manifest["measurement_state"]["published_metrics"])
        self.assertIsNone(manifest["results"])
        self.assertEqual(
            set(case_sets),
            {
                "known-malicious-pypi-releases",
                "typosquats",
                "benign-native-extensions",
                "benign-powerful-capabilities",
                "weird-harmless-academic-dev",
            },
        )
        self.assertIn("false_positive_rate", manifest["metric_contract"]["per_rule"])
        self.assertIn(
            "confidence_interval_95",
            manifest["metric_contract"]["score_band_metrics"],
        )
        self.assertTrue(
            manifest["publication_gate"][
                "forbids_measured_metric_claims_while_unmeasured"
            ]
        )

    def test_benchmark_reports_memory_requests_recall_and_resolver_correctness(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_metrics_test",
        )
        memory, stderr = namespace["_extract_memory_measurement"](
            "warning\n__trustcheck_max_rss_kib__=2048\n"
        )
        self.assertEqual(memory, 2 * 1024 * 1024)
        self.assertEqual(stderr, "warning")

        trust_payload = {
            "reports": [
                {
                    "project": "demo",
                    "version": "1.0",
                    "diagnostics": {"request_count": 4},
                    "files": [
                        {
                            "has_provenance": True,
                            "verified": True,
                            "artifact": {
                                "inspected": True,
                                "native_binaries": [{}],
                                "heuristic_findings": [{}, {}],
                            },
                        }
                    ],
                }
            ]
        }
        pip_payload = {"dependencies": [{"name": "demo", "version": "1.0"}]}
        self.assertEqual(namespace["_reported_request_count"](trust_payload), 4)
        self.assertTrue(
            namespace["_compare_resolutions"](trust_payload, pip_payload)["exact_match"]
        )
        work = namespace["_profile_work_summary"](trust_payload)
        self.assertEqual(work["inspected_artifacts"], 1)
        self.assertEqual(work["native_binaries"], 1)
        self.assertEqual(work["heuristic_findings"], 2)

        findings = {
            namespace["_package_key"]("demo", "1.0"): [
                {"GHSA-DEMO", "CVE-2026-1"}
            ]
        }
        truth_case = namespace["TruthCase"](
            case_id="test",
            project="demo",
            version="1.0",
            vulnerable=True,
            advisories=(frozenset({"GHSA-DEMO", "CVE-2026-1"}),),
            withdrawn=(),
            fixed_versions=("1.1",),
        )
        truth = namespace["TruthCorpus"](
            manifest=Path("truth.json"),
            version="test",
            cases=(truth_case,),
            min_recall=1.0,
            max_false_positives=0,
        )
        correctness = namespace["_compare_findings"](
            findings,
            {},
            truth=truth,
            selected_cases={"test"},
        )
        self.assertEqual(correctness["advisory_recall"]["trustcheck"], 1.0)
        self.assertEqual(correctness["advisory_recall"]["pip_audit"], 0.0)
        self.assertEqual(
            correctness["advisory_recall"]["reference"],
            "signed-curated-truth-corpus",
        )
        self.assertEqual(correctness["regressions"], [])

    def test_truth_corpus_signature_rejects_tampering(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_signature_test",
        )
        source = root / "benchmarks" / "corpus"
        with TemporaryDirectory() as directory:
            target = Path(directory)
            for name in ("truth.json", "truth.json.sig", "truth-public-key.pem"):
                (target / name).write_bytes((source / name).read_bytes())
            (target / "truth.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "signature is invalid"):
                namespace["_load_truth_corpus"](target / "truth.json")

    def test_benchmark_retries_empty_output_and_reports_stderr(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_test",
        )
        command = ["python", "-m", "trustcheck"]
        empty = subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="OSV temporarily unavailable",
        )
        success = subprocess.CompletedProcess(
            command,
            0,
            stdout='{"ok": true}',
            stderr="",
        )

        with patch("subprocess.run", side_effect=[empty, success]) as run, patch(
            "time.sleep"
        ) as sleep:
            result = namespace["_run"](
                command,
                timeout=1,
                accepted_exit_codes={0, 1},
                command_retries=1,
            )

        self.assertEqual(result.payload, {"ok": True})
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(1)

        with patch("subprocess.run", return_value=empty), self.assertRaisesRegex(
            RuntimeError,
            "OSV temporarily unavailable",
        ):
            namespace["_run"](
                command,
                timeout=1,
                accepted_exit_codes={0, 1},
                command_retries=0,
            )

    def test_redacts_local_paths(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "benchmarks" / "benchmark_against_pip_audit.py"),
            run_name="trustcheck_benchmark_test",
        )
        requirements = root / "benchmarks" / "corpus" / "requirements-main.txt"

        published = namespace["_published_command"](
            [
                r"C:\private\python.exe",
                "-m",
                "trustcheck",
                "scan",
                "-f",
                str(requirements),
            ],
            requirements=requirements,
        )

        self.assertEqual(published[0], "python")
        self.assertEqual(published[-1], "benchmarks/corpus/requirements-main.txt")
        self.assertIn("-f", published)
        self.assertNotIn(str(root), " ".join(published))
        external = root.parent / "private-requirements.txt"
        self.assertEqual(
            namespace["_published_path"](external),
            "<external>/private-requirements.txt",
        )

    def test_benchmark_table_is_inserted_before_installation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(
            str(root / "scripts" / "update_benchmark_table.py"),
            run_name="trustcheck_benchmark_table_test",
        )
        payload = {
            "generated_at": "2026-06-19T12:00:00+00:00",
            "environment": {
                "python": "3.12.0",
                "pip_audit": "pip-audit 2.10.1",
            },
            "corpus": {
                "version": "2026.06",
                "package_count": 133,
                "benchmark_package_count": 123,
            },
            "truth_corpus": {
                "case_count": 123,
                "complete_case_count": 123,
                "gates": {"min_recall": 1.0, "max_false_positives": 0},
            },
            "configuration": {"iterations": 5},
            "performance": {
                "trustcheck": {
                    "cold": {"p50_seconds": 2.0},
                    "samples_seconds": [1.1, 1.2, 1.3, 1.4, 1.5],
                    "p50_seconds": 1.234,
                    "p95_seconds": 2.345,
                    "peak_memory_bytes": 104857600,
                    "request_count_p50": 12,
                },
                "pip_audit": {
                    "cold": {"p50_seconds": 5.0},
                    "samples_seconds": [3.1, 3.2, 3.3, 3.4, 3.5],
                    "p50_seconds": 3.456,
                    "p95_seconds": 4.567,
                    "peak_memory_bytes": 209715200,
                    "request_count_p50": None,
                },
            },
            "correctness": {
                "trustcheck_vulnerable_packages": 7,
                "pip_audit_vulnerable_packages": 7,
                "alias_aware_agreement": 1.0,
                "packages_compared": 123,
                "matched_advisories": 9,
                "trustcheck_only": [],
                "pip_audit_only": [],
                "advisory_recall": {"trustcheck": 1.0, "pip_audit": 0.9},
                "regressions": [],
                "truth": {"case_count": 123},
            },
            "evidence": {
                "dependency_resolution": {
                    "resolver_correctness": {
                        "exact_match": True,
                        "trustcheck_package_count": 14,
                        "pip_audit_package_count": 14,
                    }
                }
            },
        }

        with TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            result = Path(directory) / "latest.json"
            readme.write_text("# Trustcheck\n\n## Installation\n\nInstall.\n", encoding="utf-8")
            result.write_text(json.dumps(payload), encoding="utf-8")

            exit_code = namespace["main"]([str(result), "--readme", str(readme)])
            updated = readme.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertLess(updated.index("## Latest benchmark"), updated.index("## Installation"))
        self.assertIn(
            "Corpus `2026.06` contains 133 entries; this fixed-input `--no-deps` "
            "comparison covers 123 comparable package entries.",
            updated,
        )
        self.assertIn("not a full dependency-resolution benchmark", updated)
        self.assertIn(
            "| trustcheck scan --fast | 2.00 s | 1.23 s | 2.35 s | "
            "100.0 MiB | 12 | 1 |",
            updated,
        )
        self.assertIn(
            "| pip-audit | 5.00 s | 3.46 s | 4.57 s | 200.0 MiB | "
            "unknown | 0.9 |",
            updated,
        )
        self.assertIn("Resolver exact match: `True`", updated)

        weak = json.loads(json.dumps(payload))
        weak["performance"]["trustcheck"]["samples_seconds"] = [1.0]
        with self.assertRaisesRegex(ValueError, "five warm trustcheck samples"):
            namespace["_validate_publishable"](weak)

    def test_benchmark_workflow_runs_on_demand_weekly_and_after_release(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "benchmarks.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn('cron: "23 4 * * 1"', workflow)
        self.assertIn("workflow_run:", workflow)
        self.assertIn('workflows: ["Release"]', workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("push:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertIn("group: benchmark-results-${{ github.ref }}", workflow)
        self.assertIn("uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("--output benchmarks/results/latest.json", workflow)
        self.assertIn("--requirement requirements/ci.lock", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn(
            "pip-audit==2.10.1",
            (root / "requirements" / "ci.lock").read_text(encoding="utf-8"),
        )
        self.assertIn("--iterations 5", workflow)
        self.assertIn("--evidence-iterations 5", workflow)
        self.assertIn("retention-days: 90", workflow)
        self.assertIn("python scripts/update_benchmark_table.py", workflow)
        self.assertIn("$GITHUB_STEP_SUMMARY", workflow)
        self.assertNotIn("git add", workflow)
        self.assertNotIn("git commit", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("gh pr", workflow)
        self.assertNotIn("trustcheck inspect", workflow)
        self.assertLess(
            workflow.index("name: Present benchmark results"),
            workflow.index(
                "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            ),
        )

def _report(project: str, version: str) -> TrustReport:
    return TrustReport(
        project=project,
        version=version,
        summary=None,
        package_url=f"https://example.test/{project}/{version}",
    )


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload).encode("utf-8")
        )
        self.status = 200

    def read(self) -> bytes:
        return self.payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class ContentAddressedCacheTests(unittest.TestCase):
    def test_deduplicates_objects_and_detects_corruption(self) -> None:
        with TemporaryDirectory() as directory:
            cache = ContentAddressedCache(directory)
            first = cache.put("http", "one", b"same", media_type="text/plain")
            second = cache.put("http", "two", b"same")

            self.assertEqual(first.digest, second.digest)
            self.assertEqual(cache.get("http", "one"), b"same")
            self.assertEqual(cache.get("http", "missing"), None)
            self.assertEqual(len(list((Path(directory) / "objects").rglob("*same*"))), 0)

            first.path.write_bytes(b"tampered")
            with self.assertRaisesRegex(CacheIntegrityError, "SHA-256"):
                cache.get("http", "two")

    def test_rejects_invalid_and_missing_references(self) -> None:
        with TemporaryDirectory() as directory:
            cache = ContentAddressedCache(directory)
            cache.put("space/name", "key", b"value")
            ref = next((Path(directory) / "refs").rglob("*.json"))
            ref.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(CacheIntegrityError, "invalid"):
                cache.get("space/name", "key")

            ref.write_text("{bad", encoding="utf-8")
            with self.assertRaisesRegex(CacheIntegrityError, "unreadable"):
                cache.get("space/name", "key")

            stored = cache.put("other", "key", b"value")
            stored.path.unlink()
            with self.assertRaisesRegex(CacheIntegrityError, "missing"):
                cache.get("other", "key")

    def test_rejects_bad_metadata_existing_objects_and_cleans_tempfiles(self) -> None:
        with TemporaryDirectory() as directory:
            cache = ContentAddressedCache(directory)
            cache.put("", "key", b"value")
            ref = next((Path(directory) / "refs" / "default").glob("*.json"))
            payload = json.loads(ref.read_text(encoding="utf-8"))
            payload["size"] = -1
            ref.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(CacheIntegrityError, "metadata"):
                cache.get("", "key")

            stored = cache.put("objects", "one", b"same")
            stored.path.write_bytes(b"wrong")
            with self.assertRaisesRegex(CacheIntegrityError, "existing"):
                cache.put("objects", "two", b"same")

            target = Path(directory) / "atomic"
            with patch("trustcheck.cache.os.replace", side_effect=OSError("no")):
                with self.assertRaises(OSError):
                    cache_module._atomic_write_bytes(target, b"value")
            self.assertEqual(list(Path(directory).glob(".atomic.*.tmp")), [])


class AdvisoryBatchAndSnapshotTests(unittest.TestCase):
    def test_osv_batch_fetches_each_advisory_once_and_caches(self) -> None:
        calls: list[str] = []

        def urlopen(request: object, timeout: float) -> FakeResponse:
            del timeout
            url = str(getattr(request, "full_url"))
            calls.append(url)
            if url.endswith("/v1/querybatch"):
                payload = json.loads(getattr(request, "data"))
                self.assertEqual(len(payload["queries"]), 2)
                return FakeResponse(
                    {
                        "results": [
                            {"vulns": [{"id": "GHSA-shared"}]},
                            {
                                "vulns": [
                                    {"id": "GHSA-shared"},
                                    {"id": "GHSA-second"},
                                ]
                            },
                        ]
                    }
                )
            identifier = url.rsplit("/", 1)[-1]
            return FakeResponse(
                {
                    "id": identifier,
                    "summary": identifier,
                    "affected": [],
                }
            )

        client = OsvClient(max_retries=0, max_workers=2)
        with patch("trustcheck.advisories.request.urlopen", side_effect=urlopen):
            first = client.query_batch([("Demo", "1"), ("Other", "2")])
            second = client.query_batch([("demo", "1"), ("other", "2")])

        self.assertEqual(first, second)
        self.assertEqual(len(calls), 3)
        self.assertEqual(
            [item["id"] for item in first[("other", "2")]],
            ["GHSA-shared", "GHSA-second"],
        )

    def test_osv_batch_paginates_and_rejects_bad_shapes(self) -> None:
        responses = [
            FakeResponse(
                {
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-one"}],
                            "next_page_token": "next",
                        }
                    ]
                }
            ),
            FakeResponse(
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-two"}]}
                    ]
                }
            ),
            FakeResponse({"id": "GHSA-one"}),
            FakeResponse({"id": "GHSA-two"}),
        ]
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=responses,
        ):
            result = OsvClient(max_retries=0).query_batch([("demo", "1")])
        self.assertEqual(
            [item["id"] for item in result[("demo", "1")]],
            ["GHSA-one", "GHSA-two"],
        )

        with patch(
            "trustcheck.advisories.request.urlopen",
            return_value=FakeResponse({"results": []}),
        ):
            with self.assertRaisesRegex(Exception, "unexpected response"):
                OsvClient(max_retries=0).query_batch([("demo", "1")])

    def test_osv_batch_offline_fallback_and_validation_paths(self) -> None:
        self.assertEqual(OsvClient().query_batch([]), {})
        with self.assertRaisesRegex(Exception, "offline"):
            OsvClient(offline=True).query_batch([("demo", "1")])

        fallback = OsvClient(max_workers=1)
        with patch.object(
            OsvClient,
            "_query_batch_identifiers",
            side_effect=PypiClientError(
                "missing",
                status_code=404,
            ),
        ), patch.object(
            OsvClient,
            "query",
            return_value=[{"id": "GHSA-fallback"}],
        ):
            result = fallback.query_batch([("demo", "1")])
        self.assertEqual(result[("demo", "1")][0]["id"], "GHSA-fallback")

        rejected = OsvClient()
        with patch.object(
            OsvClient,
            "_query_batch_identifiers",
            side_effect=PypiClientError(
                "bad",
                status_code=400,
            ),
        ):
            with self.assertRaises(PypiClientError):
                rejected.query_batch([("demo", "1")])

        invalid_results = (
            {"results": ["bad"]},
            {"results": [{"vulns": {}}]},
        )
        for payload in invalid_results:
            with self.subTest(payload=payload), patch.object(
                OsvClient,
                "_post_json",
                return_value=payload,
            ):
                with self.assertRaisesRegex(Exception, "unexpected response"):
                    OsvClient().query_batch([("demo", "1")])

        with patch.object(
            OsvClient,
            "_post_json",
            side_effect=[
                {"results": [{"next_page_token": "same"}]},
                {"results": [{"next_page_token": "same"}]},
            ],
        ):
            with self.assertRaisesRegex(Exception, "repeated"):
                OsvClient().query_batch([("demo", "1")])

    def test_osv_get_transport_retry_and_decode_errors(self) -> None:
        client = OsvClient(max_retries=1, backoff_factor=0, sleep=lambda _: None)
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=[TimeoutError("slow"), FakeResponse({"id": "GHSA-one"})],
        ):
            self.assertEqual(client._get_json("/v1/vulns/GHSA-one")["id"], "GHSA-one")

        failures = [
            error.HTTPError("url", 400, "bad", None, None),
            error.URLError("down"),
        ]
        for failure in failures:
            with self.subTest(failure=failure), patch(
                "trustcheck.advisories.request.urlopen",
                side_effect=failure,
            ):
                with self.assertRaises(Exception):
                    OsvClient(max_retries=0)._get_json("/v1/vulns/GHSA-one")

        for response in (FakeResponse(b"{bad"), FakeResponse([])):
            with self.subTest(response=response), patch(
                "trustcheck.advisories.request.urlopen",
                return_value=response,
            ):
                with self.assertRaises(Exception):
                    OsvClient(max_retries=0)._get_json("/v1/vulns/GHSA-one")

    def test_snapshot_round_trip_merge_and_validation(self) -> None:
        with TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.json"
            output_path = Path(directory) / "merged.json"
            first = AdvisorySnapshotStore(output=first_path, allow_unsigned=True)
            first.put(
                "Demo",
                "1",
                [VulnerabilityRecord(id="GHSA-one", summary="one")],
            )
            self.assertEqual(first.write(), first_path)

            merged = AdvisorySnapshotStore(
                inputs=[first_path],
                output=output_path,
                allow_unsigned=True,
            )
            self.assertTrue(merged.sources)
            self.assertEqual(merged.get("demo", "1")[0].id, "GHSA-one")  # type: ignore[index]
            merged.put(
                "demo",
                "2",
                [VulnerabilityRecord(id="GHSA-two", summary="two")],
            )
            merged.write()
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], ADVISORY_SNAPSHOT_SCHEMA)
            self.assertEqual(sorted(payload["records"]), ["demo==1", "demo==2"])

            bad = Path(directory) / "bad.json"
            bad.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                AdvisorySnapshotError,
                "unsupported",
            ):
                AdvisorySnapshotStore(inputs=[bad], allow_unsigned=True)

    def test_snapshot_rejects_invalid_records_and_preserves_suppressions(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"

            def write(records: object) -> None:
                path.write_text(
                    json.dumps(
                        {
                            "schema": "urn:trustcheck:advisory-snapshot:1.0.0",
                            "records": records,
                        }
                    ),
                    encoding="utf-8",
                )

            write([])
            with self.assertRaisesRegex(AdvisorySnapshotError, "records"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)
            write({"demo==1": {}})
            with self.assertRaisesRegex(AdvisorySnapshotError, "collection"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)
            write({"demo==1": ["bad"]})
            with self.assertRaisesRegex(AdvisorySnapshotError, "must be an object"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)
            write({"demo==1": [{"id": "X", "summary": "x", "suppression": "bad"}]})
            with self.assertRaisesRegex(AdvisorySnapshotError, "suppression"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)
            write({"demo==1": [{"id": "X", "summary": "x", "suppression": {}}]})
            with self.assertRaisesRegex(AdvisorySnapshotError, "invalid"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)
            write({"demo==1": [{"unknown": True}]})
            with self.assertRaisesRegex(AdvisorySnapshotError, "invalid"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)

            store = AdvisorySnapshotStore()
            self.assertIsNone(store.write())
            suppression = VulnerabilitySuppression(
                vulnerability_id="GHSA-one",
                owner="security",
                justification="reviewed",
                expires="2030-01-01",
            )
            store.put(
                "demo",
                "1",
                [
                    VulnerabilityRecord(
                        id="GHSA-one",
                        summary="one",
                        suppression=suppression,
                    )
                ],
            )
            copied = store.get("demo", "1")
            assert copied is not None
            self.assertIsNot(copied[0].suppression, suppression)

            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            duplicate = {
                "schema": "urn:trustcheck:advisory-snapshot:1.0.0",
                "records": {
                    "demo==1": [
                        {"id": "GHSA-one", "summary": "one", "aliases": []}
                    ]
                },
            }
            first.write_text(json.dumps(duplicate), encoding="utf-8")
            second.write_text(json.dumps(duplicate), encoding="utf-8")
            deduplicated = AdvisorySnapshotStore(
                inputs=[first, second],
                allow_unsigned=True,
            )
            self.assertEqual(len(deduplicated.get("demo", "1") or []), 1)

            path.write_text("{bad", encoding="utf-8")
            with self.assertRaisesRegex(AdvisorySnapshotError, "unable to read"):
                AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)

            output = Path(directory) / "atomic.json"
            with patch(
                "trustcheck.snapshots.os.replace",
                side_effect=OSError("no"),
            ):
                with self.assertRaises(OSError):
                    snapshots_module._atomic_write_json(output, {})
            self.assertEqual(list(Path(directory).glob(".atomic.json.*.tmp")), [])

    def test_snapshot_sigstore_metadata_digest_and_expiry(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)

        def signing_runner(command, **kwargs):
            del kwargs
            bundle = Path(command[command.index("--bundle") + 1])
            bundle.write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            store = AdvisorySnapshotStore(
                output=path,
                source_urls=("https://api.osv.dev",),
                sign_output=True,
                clock=lambda: now,
                runner=signing_runner,
            )
            store.put(
                "demo",
                "1",
                [VulnerabilityRecord(id="GHSA-one", summary="one")],
            )
            store.write()
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], ADVISORY_SNAPSHOT_SCHEMA)
            self.assertEqual(payload["generated_at"], now.isoformat())
            self.assertEqual(
                payload["expires_at"],
                (now + timedelta(hours=168)).isoformat(),
            )
            self.assertEqual(
                payload["source_manifest"]["sources"],
                [{"url": "https://api.osv.dev"}],
            )
            self.assertEqual(
                payload["source_manifest"]["records_sha256"],
                payload["digests"]["records_sha256"],
            )
            self.assertRegex(payload["digests"]["records_sha256"], r"^[0-9a-f]{64}$")

            verifier = Mock()
            with patch(
                "trustcheck.snapshots.Bundle.from_json",
                return_value=Mock(),
            ), patch(
                "trustcheck.snapshots.Verifier.production",
                return_value=verifier,
            ):
                loaded = AdvisorySnapshotStore(
                    inputs=[path],
                    sigstore_identity="https://github.com/example/project/.github/workflows/snapshot.yml@refs/heads/main",
                    sigstore_issuer="https://token.actions.githubusercontent.com",
                    clock=lambda: now + timedelta(hours=1),
                )
                self.assertEqual(loaded.get("demo", "1")[0].id, "GHSA-one")  # type: ignore[index]
                verifier.verify_artifact.assert_called_once()

                with self.assertRaisesRegex(AdvisorySnapshotError, "maximum age"):
                    AdvisorySnapshotStore(
                        inputs=[path],
                        sigstore_identity="trusted",
                        max_age=timedelta(minutes=30),
                        clock=lambda: now + timedelta(hours=1),
                    )

            payload["records"]["demo==1"][0]["summary"] = "tampered"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with patch(
                "trustcheck.snapshots.Bundle.from_json",
                return_value=Mock(),
            ), patch(
                "trustcheck.snapshots.Verifier.production",
                return_value=Mock(),
            ), self.assertRaisesRegex(AdvisorySnapshotError, "digest mismatch"):
                AdvisorySnapshotStore(
                    inputs=[path],
                    sigstore_identity="trusted",
                    clock=lambda: now,
                )

    def test_snapshot_requires_signature_or_explicit_compatibility(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            with self.assertRaisesRegex(AdvisorySnapshotError, "Sigstore-signed"):
                AdvisorySnapshotStore(output=path).write()

            legacy = {
                "schema": "urn:trustcheck:advisory-snapshot:1.0.0",
                "records": {},
            }
            path.write_text(json.dumps(legacy), encoding="utf-8")
            with self.assertRaisesRegex(AdvisorySnapshotError, "bundle not found"):
                AdvisorySnapshotStore(inputs=[path])
            AdvisorySnapshotStore(inputs=[path], allow_unsigned=True)

    def test_snapshot_security_validation_and_signer_failures(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        records: dict[str, object] = {}
        digest = snapshots_module._records_digest(records)

        def payload() -> dict[str, object]:
            return {
                "schema": ADVISORY_SNAPSHOT_SCHEMA,
                "generated_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "digests": {"records_sha256": digest},
                "source_manifest": {"sources": [], "records_sha256": digest},
                "records": records,
            }

        with self.assertRaisesRegex(AdvisorySnapshotError, "positive"):
            AdvisorySnapshotStore(max_age=timedelta(0))
        with self.assertRaisesRegex(AdvisorySnapshotError, "unable to read"):
            AdvisorySnapshotStore(inputs=["missing-snapshot.json"], allow_unsigned=True)
        with self.assertRaisesRegex(AdvisorySnapshotError, "timezone"):
            snapshots_module._utc(datetime(2030, 1, 1))
        with self.assertRaisesRegex(AdvisorySnapshotError, "ISO-8601"):
            snapshots_module._snapshot_datetime(None, Path("snapshot.json"), "generated_at")
        with self.assertRaisesRegex(AdvisorySnapshotError, "invalid"):
            snapshots_module._snapshot_datetime("bad", Path("snapshot.json"), "generated_at")

        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "snapshot.json"

            for mutate, message in (
                (
                    lambda value: value.update(
                        {
                            "generated_at": (now + timedelta(minutes=6)).isoformat(),
                            "expires_at": (now + timedelta(hours=1)).isoformat(),
                        }
                    ),
                    "future",
                ),
                (
                    lambda value: value.update(
                        {
                            "generated_at": (now - timedelta(hours=2)).isoformat(),
                            "expires_at": (now - timedelta(hours=1)).isoformat(),
                        }
                    ),
                    "expired",
                ),
                (
                    lambda value: value["source_manifest"].update({"sources": {}}),
                    "sources must be an array",
                ),
                (
                    lambda value: value["source_manifest"].update(
                        {"records_sha256": "0" * 64}
                    ),
                    "source manifest digest mismatch",
                ),
                (
                    lambda value: value["source_manifest"].update(
                        {"sources": [{"url": ""}]}
                    ),
                    "source URL",
                ),
            ):
                value = payload()
                mutate(value)
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(message=message), self.assertRaisesRegex(
                    AdvisorySnapshotError, message
                ):
                    AdvisorySnapshotStore(
                        inputs=[path], allow_unsigned=True, clock=lambda: now
                    )

            legacy = {
                "schema": "urn:trustcheck:advisory-snapshot:1.0.0",
                "records": {},
            }
            path.write_text(json.dumps(legacy), encoding="utf-8")
            bundle = path.with_name(f"{path.name}.sigstore.json")
            bundle.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(AdvisorySnapshotError, "identity"):
                AdvisorySnapshotStore(inputs=[path])
            with patch(
                "trustcheck.snapshots.Bundle.from_json", side_effect=ValueError("bad")
            ), self.assertRaisesRegex(AdvisorySnapshotError, "verification failed"):
                AdvisorySnapshotStore(inputs=[path], sigstore_identity="trusted")

            with self.assertRaisesRegex(AdvisorySnapshotError, "unable to start"):
                snapshots_module._sign_snapshot(
                    path, runner=Mock(side_effect=OSError("missing"))
                )
            bundle.unlink()
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="denied")
            with self.assertRaisesRegex(AdvisorySnapshotError, "denied"):
                snapshots_module._sign_snapshot(path, runner=Mock(return_value=failed))
            succeeded = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with self.assertRaisesRegex(AdvisorySnapshotError, "did not create"):
                snapshots_module._sign_snapshot(path, runner=Mock(return_value=succeeded))

    def test_prefetch_populates_snapshot_and_uses_it_offline(self) -> None:
        class Provider:
            request_hook = None
            calls = 0

            def query_batch(
                self,
                packages: list[tuple[str, str]],
            ) -> dict[tuple[str, str], list[dict[str, object]]]:
                self.calls += 1
                return {
                    package: [
                        {
                            "id": f"GHSA-{package[0]}",
                            "summary": "issue",
                        }
                    ]
                    for package in packages
                }

            def query(self, project: str, version: str) -> list[dict[str, object]]:
                raise AssertionError("batch path expected")

        with TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            provider = Provider()
            store = AdvisorySnapshotStore(output=path, allow_unsigned=True)
            client = VulnerabilityIntelligenceClient(
                providers=(OsvProvider("OSV", provider),),  # type: ignore[arg-type]
                snapshot_store=store,
                max_workers=2,
            )
            client.prefetch([("demo", "1"), ("other", "2"), ("demo", "1")])
            client.flush_snapshots()
            self.assertEqual(provider.calls, 1)
            self.assertEqual(client.query("demo", "1")[0].id, "GHSA-demo")

            offline = VulnerabilityIntelligenceClient(
                snapshot_store=AdvisorySnapshotStore(
                    inputs=[path],
                    allow_unsigned=True,
                ),
            )
            self.assertEqual(offline.query("other", "2")[0].id, "GHSA-other")

    def test_coordinator_supports_non_batch_and_plugin_sources(self) -> None:
        class Provider:
            request_hook = None

            def query(self, project: str, version: str) -> list[dict[str, object]]:
                return [{"id": "GHSA-provider", "summary": version}]

        class Source:
            name = "source"

            def query(self, project: str, version: str) -> list[VulnerabilityRecord]:
                return [VulnerabilityRecord(id="PLUGIN-source", summary=project)]

        client = VulnerabilityIntelligenceClient(
            providers=(OsvProvider("OSV", Provider()),),  # type: ignore[arg-type]
            advisory_sources=(Source(),),
        )
        client.prefetch([("demo", "1")])
        self.assertEqual(
            [record.id for record in client.query("demo", "1")],
            ["GHSA-provider", "PLUGIN-source"],
        )
        client.prefetch([("demo", "1")])
        VulnerabilityIntelligenceClient().flush_snapshots()

        class BadSource:
            name = "bad"

            def query(self, project: str, version: str) -> list[object]:
                return [object()]

        with self.assertRaisesRegex(TypeError, "expected VulnerabilityRecord"):
            VulnerabilityIntelligenceClient(
                advisory_sources=(BadSource(),),  # type: ignore[arg-type]
            ).query("demo", "1")


class PluginManagerTests(unittest.TestCase):
    class EntryPoint:
        dist = None

        def __init__(self, name: str, value: str, plugin: object) -> None:
            self.name = name
            self.value = value
            self.plugin = plugin

        def load(self) -> object:
            return self.plugin

    class Advisory:
        name = "advisory-demo"

        def query(self, project: str, version: str) -> list[VulnerabilityRecord]:
            return [VulnerabilityRecord(id="PLUGIN-1", summary=f"{project} {version}")]

    class Artifact:
        name = "artifact-demo"

        def analyze(self, **kwargs: object) -> list[HeuristicFinding]:
            return [
                HeuristicFinding(
                    code="plugin_finding",
                    category="plugin",
                    severity="medium",
                    confidence="high",
                    score=10,
                    message=str(kwargs["filename"]),
                )
            ]

    class Policy:
        name = "policy-demo"

        def evaluate(self, **kwargs: object) -> list[PolicyViolation]:
            return [
                PolicyViolation(
                    code="plugin_policy",
                    severity="high",
                    message=str(kwargs["config"].get("message")),
                )
            ]

    class Renderer:
        name = "demo-format"
        extension = ".demo"

        def render(self, **kwargs: object) -> str:
            return f"{kwargs['source_name']}:{len(kwargs['packages'])}"

    class Index:
        name = "index-demo"

        def supports(self, index_url: str) -> bool:
            return index_url.startswith("demo+")

        def create_client(self, **kwargs: object) -> object:
            return PluginManagerTests.Repository()

    class Repository:
        def get_project(self, index_url: str, project: str) -> str:
            return f"{index_url}:{project}"

        def download(self, url: str, *, index_url: str | None = None) -> bytes:
            return f"{index_url}:{url}".encode()

        def find_dependency_confusion(
            self,
            projects: list[str],
            indexes: list[str],
        ) -> tuple[object, ...]:
            return ()

        def locate_artifact_index(
            self,
            project: str,
            artifact_url: str | None,
            indexes: list[str],
        ) -> str | None:
            return indexes[0] if indexes else None

    def _manager(self, *, selected: tuple[str, ...] = ()) -> PluginManager:
        plugins = {
            "trustcheck.advisory_sources": [
                self.EntryPoint("advisory-demo", "tests:advisory", self.Advisory())
            ],
            "trustcheck.artifact_analyzers": [
                self.EntryPoint("artifact-demo", "tests:artifact", self.Artifact())
            ],
            "trustcheck.policy_rules": [
                self.EntryPoint("policy-demo", "tests:policy", self.Policy())
            ],
            "trustcheck.renderers": [
                self.EntryPoint("demo-format", "tests:renderer", self.Renderer())
            ],
            "trustcheck.indexes": [
                self.EntryPoint("index-demo", "tests:index", self.Index())
            ],
        }
        return PluginManager(
            enabled=True,
            selected=selected,
            config={"policy-demo": {"message": "blocked"}},
            entry_point_loader=lambda *, group: plugins.get(group, []),
            require_signed=False,
            isolate=False,
        )

    def test_discovers_and_executes_every_plugin_category(self) -> None:
        manager = self._manager()
        self.assertEqual(len(manager.descriptors()), 5)
        self.assertEqual(manager.output_formats(), ("demo-format",))
        self.assertEqual(
            manager.advisory_sources()[0].query("demo", "1")[0].id,
            "PLUGIN-1",
        )
        findings = manager.analyze_artifact(
            filename="demo.whl",
            payload=b"wheel",
            project="demo",
            version="1",
            inspection=ArtifactInspection(),
        )
        self.assertEqual(findings[0].code, "plugin_finding")
        self.assertEqual(
            manager.evaluate_policy(_report("demo", "1"))[0].message,
            "blocked",
        )
        self.assertEqual(
            manager.render(
                "demo-format",
                packages=[object()],
                source_name="source",
                failures=[],
            ),
            "source:1",
        )
        repository = manager.repository_client(self.Repository())
        self.assertEqual(
            repository.get_project("demo+https://index/", "demo"),
            "demo+https://index/:demo",
        )

    def test_selection_disabled_and_missing_plugins(self) -> None:
        disabled = PluginManager()
        self.assertEqual(disabled.descriptors(), ())

        with self.assertRaisesRegex(PluginError, "not installed"):
            self._manager(selected=("missing",)).descriptors()

    def test_plugin_configuration_and_contract_failures(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "plugins.json"
            config.write_text('{"policy-demo":{"message":"configured"}}', encoding="utf-8")
            manager = PluginManager.from_options(
                enabled=False,
                selected=("policy-demo",),
                config_path=str(config),
            )
            self.assertTrue(manager.enabled)
            self.assertEqual(manager.config["policy-demo"]["message"], "configured")
            config.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "top-level"):
                PluginManager.from_options(
                    enabled=True,
                    config_path=str(config),
                )

        manager = self._manager()
        with self.assertRaisesRegex(PluginError, "unknown or duplicate"):
            manager.render(
                "missing",
                packages=[],
                source_name="source",
                failures=[],
            )
        manager.config["policy-demo"] = "bad"
        with self.assertRaisesRegex(PluginError, "must be an object"):
            manager.plugin_config("policy-demo")

        class BadArtifact(self.Artifact):
            def analyze(self, **kwargs: object) -> list[object]:
                return [object()]

        class BadPolicy(self.Policy):
            def evaluate(self, **kwargs: object) -> list[object]:
                return [object()]

        bad_artifact = self._manager()
        bad_artifact._plugins = {
            "artifact": [
                (
                    SimpleNamespace(name="bad"),
                    BadArtifact(),
                )
            ]
        }  # type: ignore[assignment]
        bad_artifact._loaded = True
        with self.assertRaisesRegex(PluginError, "expected HeuristicFinding"):
            bad_artifact.analyze_artifact(
                filename="x",
                payload=b"x",
                project="x",
                version="1",
                inspection=ArtifactInspection(),
            )

        bad_policy = self._manager()
        bad_policy._plugins = {
            "policy": [
                (
                    SimpleNamespace(name="bad"),
                    BadPolicy(),
                )
            ]
        }  # type: ignore[assignment]
        bad_policy._loaded = True
        with self.assertRaisesRegex(PluginError, "expected PolicyViolation"):
            bad_policy.evaluate_policy(_report("demo", "1"))

    def test_plugin_loading_errors_classes_and_repository_routing(self) -> None:
        class Raises:
            name = "raises"
            value = "tests:raises"
            dist = None

            def load(self) -> object:
                raise RuntimeError("boom")

        manager = PluginManager(
            enabled=True,
            entry_point_loader=lambda *, group: (
                [Raises()] if group == "trustcheck.renderers" else []
            ),
            require_signed=False,
            isolate=False,
        )
        with self.assertRaisesRegex(PluginError, "unable to load"):
            manager.descriptors()

        class Nameless:
            pass

        manager = PluginManager(
            enabled=True,
            entry_point_loader=lambda *, group: (
                [self.EntryPoint("bad", "tests:bad", Nameless())]
                if group == "trustcheck.renderers"
                else []
            ),
            require_signed=False,
            isolate=False,
        )
        with self.assertRaisesRegex(PluginError, "no valid name"):
            manager.descriptors()

        class ClassPlugin:
            name = "class-plugin"

        entry = self.EntryPoint("class-plugin", "tests:class", ClassPlugin)
        entry.dist = SimpleNamespace(name="distribution")  # type: ignore[misc]
        manager = PluginManager(
            enabled=True,
            entry_point_loader=lambda *, group: (
                [entry] if group == "trustcheck.renderers" else []
            ),
            require_signed=False,
            isolate=False,
        )
        self.assertEqual(manager.descriptors()[0].distribution, "distribution")

        manager = self._manager()
        repository = manager.repository_client(self.Repository())
        self.assertEqual(
            repository.download(
                "https://files/demo.whl",
                index_url="demo+https://index/",
            ),
            b"demo+https://index/:https://files/demo.whl",
        )
        self.assertEqual(
            repository.download("https://files/demo.whl"),
            b"None:https://files/demo.whl",
        )
        self.assertEqual(repository.find_dependency_confusion(["demo"], ["one"]), ())

        class ProjectRepository(self.Repository):
            def get_project(self, index_url: str, project: str) -> object:
                if index_url == "none":
                    return None
                return IndexProject(
                    name=project,
                    index_url=index_url,
                    files=(
                        IndexFile(
                            filename="demo.whl",
                            url="https://files/demo.whl",
                        ),
                    ),
                )

        class ProjectIndex(self.Index):
            def create_client(self, **kwargs: object) -> object:
                return ProjectRepository()

        project_manager = self._manager()
        project_manager._plugins = {
            "index": [
                (
                    SimpleNamespace(name="index-demo"),
                    ProjectIndex(),
                )
            ]
        }  # type: ignore[assignment]
        project_manager._loaded = True
        routed = project_manager.repository_client(ProjectRepository())
        findings = routed.find_dependency_confusion(
            ["demo"],
            ["demo+one", "demo+two"],
        )
        self.assertEqual(findings[0].project, "demo")
        self.assertEqual(
            routed.locate_artifact_index("demo", None, ["only"]),
            "only",
        )
        self.assertEqual(
            routed.locate_artifact_index(
                "demo",
                "https://files/demo.whl",
                ["demo+one", "demo+two"],
            ),
            "demo+one",
        )
        self.assertIsNone(
            routed.locate_artifact_index(
                "demo",
                "https://files/missing.whl",
                ["demo+one", "demo+two"],
            )
        )
        self.assertEqual(
            routed.find_dependency_confusion(
                ["demo"],
                ["demo+one", "none"],
            ),
            (),
        )
        self.assertIsNone(
            routed.locate_artifact_index(
                "demo",
                None,
                ["demo+one", "demo+two"],
            )
        )
        self.assertIs(
            routed._client_for(None),  # type: ignore[attr-defined]
            routed.fallback,  # type: ignore[attr-defined]
        )
        self.assertIs(
            routed._client_for("https://plain.example/simple/"),  # type: ignore[attr-defined]
            routed.fallback,  # type: ignore[attr-defined]
        )
        first_client = routed._client_for("demo+one")  # type: ignore[attr-defined]
        self.assertIs(
            routed._client_for("demo+one"),  # type: ignore[attr-defined]
            first_client,
        )
        self.assertIs(
            PluginManager().repository_client(self.Repository()).__class__,
            self.Repository,
        )


class ResumeScanTests(unittest.TestCase):
    def test_scan_state_round_trip_and_fingerprint_mismatch(self) -> None:
        target = ScanTarget("demo==1", "demo", "1")
        fingerprint = scan_fingerprint({"target": target_key(target)})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = ScanState(
                path,
                fingerprint=fingerprint,
                target_keys=[target_key(target)],
            )
            state.record_report(target_key(target), _report("demo", "1"))
            state.complete()

            loaded = ScanState(
                path,
                fingerprint=fingerprint,
                target_keys=[target_key(target)],
            )
            self.assertEqual(loaded.report(target_key(target)).project, "demo")  # type: ignore[union-attr]
            with self.assertRaisesRegex(ScanStateError, "does not match"):
                ScanState(
                    path,
                    fingerprint="different",
                    target_keys=[target_key(target)],
                )

    def test_scan_state_failures_validation_and_json_helpers(self) -> None:
        target = ScanTarget("demo==1", "demo", "1")
        key = target_key(target)
        fingerprint = scan_fingerprint({"target": key})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = ScanState(path, fingerprint=fingerprint, target_keys=[key])
            self.assertIsNone(state.failure(key))
            state.record_failure(key, requirement="demo==1", message="failed")
            self.assertEqual(state.failure(key)["message"], "failed")  # type: ignore[index]
            state.record_report(key, _report("demo", "1"))
            self.assertIsNone(state.failure(key))
            state.record_failure(key, requirement="demo==1", message="again")
            self.assertIsNone(state.report(key))
            loaded_failure = ScanState(
                path,
                fingerprint=fingerprint,
                target_keys=[key],
            )
            self.assertEqual(
                loaded_failure.failure(key)["message"],  # type: ignore[index]
                "again",
            )

            invalid_payloads = [
                "{bad",
                json.dumps({}),
                json.dumps(
                    {
                        "schema": resume_module.SCAN_STATE_SCHEMA,
                        "fingerprint": fingerprint,
                        "targets": ["other"],
                    }
                ),
                json.dumps(
                    {
                        "schema": resume_module.SCAN_STATE_SCHEMA,
                        "fingerprint": fingerprint,
                        "targets": [key],
                        "reports": [],
                    }
                ),
                json.dumps(
                    {
                        "schema": resume_module.SCAN_STATE_SCHEMA,
                        "fingerprint": fingerprint,
                        "targets": [key],
                        "reports": {"bad": "report"},
                    }
                ),
                json.dumps(
                    {
                        "schema": resume_module.SCAN_STATE_SCHEMA,
                        "fingerprint": fingerprint,
                        "targets": [key],
                        "failures": {"bad": {}},
                    }
                ),
            ]
            for payload in invalid_payloads:
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(ScanStateError):
                        ScanState(path, fingerprint=fingerprint, target_keys=[key])

            @dataclass
            class Value:
                path: Path
                values: tuple[str, ...]

            self.assertTrue(
                scan_fingerprint({"value": Value(Path("x"), ("a",))})
            )
            self.assertTrue(target_key("plain"))
            with self.assertRaisesRegex(TypeError, "not JSON serializable"):
                scan_fingerprint({"bad": object()})

            output = Path(directory) / "atomic.json"
            with patch("trustcheck.resume.os.replace", side_effect=OSError("no")):
                with self.assertRaises(OSError):
                    resume_module._atomic_write_json(output, {})
            self.assertEqual(list(Path(directory).glob(".atomic.json.*.tmp")), [])

    def test_cli_scans_concurrently_and_resumes_completed_targets(self) -> None:
        targets = [
            ScanTarget("one==1", "one", "1"),
            ScanTarget("two==2", "two", "2"),
        ]
        active = 0
        maximum = 0
        calls = 0
        lock = threading.Lock()

        def inspect(project: str, **kwargs: object) -> TrustReport:
            nonlocal active, maximum, calls
            del kwargs
            with lock:
                active += 1
                calls += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return _report(project, "1" if project == "one" else "2")

        with TemporaryDirectory() as directory:
            state = Path(directory) / "resume.json"
            output = StringIO()
            patches = (
                patch("trustcheck.cli._load_scan_targets", return_value=targets),
                patch("trustcheck.cli.inspect_package", side_effect=inspect),
            )
            with patches[0], patches[1], patch("sys.stdout", output):
                first = main(
                    [
                        "scan",
                        "-f",
                        "requirements.txt",
                        "--format",
                        "json",
                        "--workers",
                        "2",
                        "--resume-state",
                        str(state),
                    ]
                )
            self.assertEqual(first, 0)
            self.assertEqual(maximum, 2)
            self.assertEqual(calls, 2)

            output = StringIO()
            with patches[0], patch(
                "trustcheck.cli.inspect_package",
                side_effect=AssertionError("resume should skip inspection"),
            ), patch("sys.stdout", output):
                second = main(
                    [
                        "scan",
                        "-f",
                        "requirements.txt",
                        "--format",
                        "json",
                        "--workers",
                        "2",
                        "--resume-state",
                        str(state),
                    ]
                )
            self.assertEqual(second, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(
                [report["project"] for report in payload["reports"]],
                ["one", "two"],
            )

    def test_scan_worker_checkpoints_failures_and_advisory_batches(self) -> None:
        class Intelligence:
            def __init__(self) -> None:
                self.prefetched: list[tuple[str, str]] = []
                self.flushed = 0

            def prefetch(self, packages: list[tuple[str, str]]) -> None:
                self.prefetched = packages

            def flush_snapshots(self) -> None:
                self.flushed += 1

        targets = [
            ScanTarget("upstream==1", "upstream", "1"),
            ScanTarget("data==1", "data", "1"),
            ScanTarget(
                "broken",
                "broken",
                failure_message="resolution failed",
                failure_exit_code=3,
            ),
        ]
        intelligence = Intelligence()
        with TemporaryDirectory() as directory:
            source = Path(directory) / "requirements.txt"
            source.write_text("upstream==1\ndata==1\n", encoding="utf-8")
            state = Path(directory) / "state.json"
            args = SimpleNamespace(
                command="environment",
                resume_state=str(state),
                with_deps=False,
                with_transitive_deps=False,
                inspect_artifacts=False,
                with_osv=True,
                osv_url=[],
                with_ecosystems=False,
                with_kev=False,
                with_epss=False,
                offline=False,
                trusted_project=[],
                index_url="https://pypi.org/simple/",
                extra_index_url=[],
                keyring_provider="auto",
                allow_dependency_confusion=False,
                max_workers=2,
                format="json",
                cve=False,
                verbose=False,
                output_file=None,
                plan_fixes=False,
                fix=False,
            )

            def inspect(project: str, **kwargs: object) -> TrustReport:
                del kwargs
                if project == "upstream":
                    raise PypiClientError("network")
                raise ValueError("invalid")

            output = StringIO()
            with patch(
                "trustcheck.cli.inspect_package",
                side_effect=inspect,
            ), patch("sys.stdout", output):
                exit_code = _run_scan_targets(
                    str(source),
                    targets,
                    args=args,
                    client=SimpleNamespace(),
                    vulnerability_client=intelligence,  # type: ignore[arg-type]
                    policy=PolicySettings(),
                    include_vulnerabilities=True,
                    vulnerability_only=False,
                    progress_callback=None,
                    dependency_progress_callback=None,
                    resolver=None,
                    plugin_manager=PluginManager(),
                )
            self.assertEqual(exit_code, 3)
            self.assertEqual(
                intelligence.prefetched,
                [("upstream", "1"), ("data", "1")],
            )
            self.assertEqual(intelligence.flushed, 1)
            payload = json.loads(output.getvalue())
            self.assertEqual(len(payload["failures"]), 3)
            state_payload = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(state_payload["status"], "complete")

    def test_cli_runtime_validation_and_callbacks(self) -> None:
        invalid_commands = [
            ["inspect", "demo", "--workers", "0"],
            ["inspect", "demo", "--format", "missing"],
        ]
        for command in invalid_commands:
            with self.subTest(command=command), self.assertRaises(SystemExit):
                main(command)

        calls: list[tuple[object, ...]] = []
        lock = threading.Lock()
        from trustcheck import cli as cli_module

        progress = cli_module._synchronized_progress_callback(
            lambda *args: calls.append(args),
            lock,
        )
        dependency = cli_module._synchronized_dependency_progress_callback(
            lambda *args: calls.append(args),
            lock,
        )
        assert progress is not None and dependency is not None
        progress("demo.whl", 1, 1)
        dependency("demo", 1, 100, True)
        self.assertEqual(len(calls), 2)

    def test_scan_uses_plugin_renderer(self) -> None:
        class Renderer:
            name = "demo-format"
            extension = ".demo"

            def render(self, **kwargs: object) -> str:
                return f"rendered:{kwargs['source_name']}"

        manager = PluginManager()
        manager._loaded = True
        manager._plugins = {
            "renderer": [(SimpleNamespace(name="demo-format"), Renderer())]
        }  # type: ignore[assignment]
        args = SimpleNamespace(
            command="environment",
            resume_state=None,
            with_deps=False,
            with_transitive_deps=False,
            inspect_artifacts=False,
            with_osv=False,
            osv_url=[],
            with_ecosystems=False,
            with_kev=False,
            with_epss=False,
            offline=False,
            trusted_project=[],
            index_url="https://pypi.org/simple/",
            extra_index_url=[],
            keyring_provider="auto",
            allow_dependency_confusion=False,
            max_workers=1,
            format="demo-format",
            cve=False,
            verbose=False,
            output_file=None,
            plan_fixes=False,
            fix=False,
        )
        output = StringIO()
        with patch(
            "trustcheck.cli.inspect_package",
            return_value=_report("demo", "1"),
        ), patch("sys.stdout", output):
            exit_code = _run_scan_targets(
                "source",
                [ScanTarget("demo==1", "demo", "1")],
                args=args,
                client=SimpleNamespace(),
                vulnerability_client=None,
                policy=PolicySettings(),
                include_vulnerabilities=True,
                vulnerability_only=False,
                progress_callback=None,
                dependency_progress_callback=None,
                resolver=None,
                plugin_manager=manager,
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue().strip(), "rendered:source")


class ActionAndServiceExtensionTests(unittest.TestCase):
    def test_action_parses_and_maps_performance_snapshot_and_plugin_inputs(self) -> None:
        with self.assertRaisesRegex(ActionInputError, "integer"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "demo",
                    "TRUSTCHECK_ACTION_WORKERS": "bad",
                }
            )
        with self.assertRaisesRegex(ActionInputError, "between"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "demo",
                    "TRUSTCHECK_ACTION_WORKERS": "65",
                }
            )
        self.assertEqual(
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "demo",
                    "TRUSTCHECK_ACTION_WORKERS": "-1",
                }
            ).max_workers,
            -1,
        )
        with self.assertRaisesRegex(ActionInputError, "number"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "demo",
                    "TRUSTCHECK_ACTION_MAX_ADVISORY_AGE": "old",
                }
            )
        with self.assertRaisesRegex(ActionInputError, "positive"):
            ActionSettings.from_environment(
                {
                    "TRUSTCHECK_ACTION_TARGET": "demo",
                    "TRUSTCHECK_ACTION_MAX_ADVISORY_AGE": "0",
                }
            )

        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            requirements = workspace / "requirements.txt"
            snapshot = workspace / "advisories.json"
            plugin_config = workspace / "plugins.json"
            requirements.write_text("demo==1\n", encoding="utf-8")
            snapshot.write_text("{}", encoding="utf-8")
            plugin_config.write_text("{}", encoding="utf-8")
            settings = ActionSettings(
                target="requirements.txt",
                max_workers=4,
                advisory_snapshots=("advisories.json",),
                write_advisory_snapshot="merged.json",
                max_advisory_age=24,
                advisory_snapshot_identity="trusted@example.com",
                advisory_snapshot_issuer="https://issuer.example",
                sign_advisory_snapshot=True,
                resume_state="resume.json",
                enable_plugins=True,
                plugins=("policy:demo",),
                plugin_config="plugins.json",
            )
            arguments = build_cli_arguments(settings, workspace=workspace)
            self.assertIn("--workers", arguments)
            self.assertIn("--advisory-snapshot", arguments)
            self.assertIn("--write-advisory-snapshot", arguments)
            self.assertIn("--max-advisory-age", arguments)
            self.assertIn("--advisory-snapshot-identity", arguments)
            self.assertIn("--advisory-snapshot-issuer", arguments)
            self.assertIn("--sign-advisory-snapshot", arguments)
            self.assertIn("--resume-state", arguments)
            self.assertIn("--enable-plugins", arguments)
            self.assertIn("--plugin-config", arguments)

            with self.assertRaisesRegex(ActionInputError, "snapshot does not exist"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        advisory_snapshots=("missing.json",),
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "plugin config"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        plugin_config="missing.json",
                    ),
                    workspace=workspace,
                )
            with self.assertRaisesRegex(ActionInputError, "between"):
                build_cli_arguments(
                    ActionSettings(
                        target="requirements.txt",
                        max_workers=0,
                    ),
                    workspace=workspace,
                )
            minus_one_arguments = build_cli_arguments(
                ActionSettings(
                    target="requirements.txt",
                    max_workers=-1,
                ),
                workspace=workspace,
            )
            self.assertIn("--workers", minus_one_arguments)
            self.assertIn("-1", minus_one_arguments)

    def test_nullable_pypi_vulnerability_lists_are_normalized(self) -> None:
        payload = VulnerabilityPayload.model_validate(
            {
                "aliases": None,
                "cwes": "bad",
                "fixed_in": [None, "2.0"],
                "withdrawn": None,
            }
        )
        self.assertEqual(payload.aliases, [])
        self.assertEqual(payload.cwes, [])
        self.assertEqual(payload.fixed_in, ["2.0"])
        self.assertIsNone(payload.withdrawn)

    def test_artifact_plugins_receive_downloaded_bytes(self) -> None:
        class Client:
            timeout = 1.0
            max_retries = 0
            backoff_factor = 0.0
            offline = False
            cache_dir = None
            request_hook = None

            def get_release(self, project: str, version: str) -> dict[str, object]:
                return {
                    "info": {
                        "version": version,
                        "project_urls": {},
                        "requires_dist": [],
                    },
                    "urls": [
                        {
                            "filename": f"{project}-{version}.whl",
                            "url": "https://files.example/demo.whl",
                            "digests": {},
                        }
                    ],
                    "vulnerabilities": [],
                }

            def get_project(self, project: str) -> dict[str, object]:
                return {
                    "info": {"version": "1", "project_urls": {}},
                    "releases": {"1": []},
                    "urls": [],
                    "vulnerabilities": [],
                }

            def get_provenance(
                self,
                project: str,
                version: str,
                filename: str,
            ) -> dict[str, object]:
                return {"version": 1, "attestation_bundles": []}

            def download_distribution(self, url: str) -> bytes:
                return b"not-a-wheel"

        class Analyzer:
            name = "artifact"

            def analyze(self, **kwargs: object) -> list[HeuristicFinding]:
                self.payload = kwargs["payload"]
                return [
                    HeuristicFinding(
                        code="plugin",
                        category="plugin",
                        severity="medium",
                        confidence="high",
                        score=1,
                        message="plugin",
                    )
                ]

        analyzer = Analyzer()
        manager = PluginManager()
        manager._loaded = True
        manager._plugins = {
            "artifact": [(SimpleNamespace(name="artifact"), analyzer)]
        }  # type: ignore[assignment]
        report = inspect_package(
            "demo",
            version="1",
            client=Client(),  # type: ignore[arg-type]
            inspect_artifacts=True,
            plugin_manager=manager,
        )
        self.assertEqual(analyzer.payload, b"not-a-wheel")
        self.assertEqual(
            report.files[0].artifact.heuristic_findings[0].code,
            "plugin",
        )


if __name__ == "__main__":
    unittest.main()
