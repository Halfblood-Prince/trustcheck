from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import trustcheck.dynamic as dynamic_mod
from trustcheck.dynamic import DEFAULT_DYNAMIC_IMAGE, RESULT_PREFIX, analyze_artifact_dynamic

ROOT = Path(__file__).resolve().parents[1]


class DynamicAnalysisTests(unittest.TestCase):
    def test_analyzer_image_definition_preinstalls_common_backends(self) -> None:
        image_dir = ROOT / "packaging" / "dynamic-analyzers"
        dockerfile = (image_dir / "Dockerfile").read_text(encoding="utf-8")
        requirements = (image_dir / "requirements-build-backends.txt").read_text(
            encoding="utf-8"
        )

        self.assertIn("ARG PYTHON_VERSION", dockerfile)
        self.assertIn("/opt/trustcheck/wheelhouse", dockerfile)
        self.assertIn("--no-index", dockerfile)
        for package in (
            "setuptools==",
            "wheel==",
            "hatchling==",
            "flit-core==",
            "poetry-core==",
            "meson-python==",
            "scikit-build-core==",
        ):
            self.assertIn(package, requirements)

    def test_rejects_mutable_container_images_without_executing(self) -> None:
        with patch("trustcheck.dynamic.shutil.which") as which:
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image="python:3.12-slim",
            )

        self.assertTrue(result.enabled)
        self.assertFalse(result.executed)
        self.assertIn("sha256 digest", result.error or "")
        self.assertEqual(result.mode, "bounded-install-analysis")
        self.assertEqual(result.classification, "policy-blocked")
        self.assertEqual(result.failure_type, "policy_blocked")
        which.assert_not_called()

    def test_reports_missing_docker_without_executing(self) -> None:
        with patch("trustcheck.dynamic.shutil.which", return_value=None):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertTrue(result.enabled)
        self.assertFalse(result.executed)
        self.assertIn("Docker CLI", result.error or "")
        self.assertEqual(result.classification, "unsupported")
        self.assertEqual(result.network, "none")

    def test_unsupported_python_requires_configured_digest_pinned_image(self) -> None:
        with patch("trustcheck.dynamic.shutil.which") as which:
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                python_version="3.11",
            )

        self.assertFalse(result.executed)
        self.assertEqual(result.python_version, "3.11")
        self.assertEqual(result.failure_type, "analyzer_image_unavailable")
        which.assert_not_called()

        with patch("trustcheck.dynamic.shutil.which") as which:
            unsupported = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                python_version="3.10",
            )

        self.assertFalse(unsupported.executed)
        self.assertEqual(unsupported.failure_type, "unsupported_python")
        which.assert_not_called()

    def test_runs_disposable_no_network_non_root_container(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="installed\n",
            stderr="",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            return_value=completed,
        ) as run:
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        command = run.call_args.args[0]
        self.assertTrue(result.executed)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.image, DEFAULT_DYNAMIC_IMAGE)
        self.assertEqual(result.classification, "inconclusive")
        self.assertEqual(result.failure_type, "result_unavailable")
        self.assertEqual(result.stdout, ["installed"])
        self.assertIn("--rm", command)
        self.assertIn("none", command[command.index("--network") + 1])
        self.assertIn("65534:65534", command[command.index("--user") + 1])
        self.assertIn("512m", command[command.index("--memory") + 1])
        self.assertIn("cpu=10", command[command.index("--ulimit") + 1])
        self.assertIn("no-new-privileges", command)
        self.assertIn("ALL", command[command.index("--cap-drop") + 1])
        self.assertEqual(command[command.index(DEFAULT_DYNAMIC_IMAGE)], DEFAULT_DYNAMIC_IMAGE)

    def test_parses_phased_result_and_behavioral_evidence(self) -> None:
        runner_payload = {
            "phases": [
                {
                    "name": "archive_validation",
                    "status": "passed",
                    "classification": "passed",
                    "exit_code": 0,
                },
                {
                    "name": "wheel_installation",
                    "status": "passed",
                    "classification": "passed",
                    "exit_code": 0,
                    "stdout": ["installed"],
                },
            ],
            "evidence": {
                "child_processes": ["/tmp/trustcheck-venv/bin/python"],
                "executable_paths": ["/tmp/trustcheck-venv/bin/python"],
                "files_modified": ["/tmp/trustcheck-venv/site.py"],
                "subprocess_arguments": [["python", "-m", "pip", "install"]],
            },
        }
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="pip output\n" + RESULT_PREFIX + json.dumps(runner_payload) + "\n",
            stderr="",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            return_value=completed,
        ):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertEqual(result.classification, "passed")
        self.assertIsNone(result.failure_type)
        self.assertEqual([phase.name for phase in result.phases], [
            "archive_validation",
            "wheel_installation",
        ])
        self.assertEqual(result.evidence.child_processes, [
            "/tmp/trustcheck-venv/bin/python"
        ])
        self.assertEqual(result.evidence.subprocess_arguments[0], [
            "python",
            "-m",
            "pip",
            "install",
        ])
        self.assertEqual(result.stdout, ["pip output"])

    def test_suspicious_evidence_is_not_clean(self) -> None:
        runner_payload = {
            "phases": [
                {
                    "name": "wheel_installation",
                    "status": "passed",
                    "classification": "passed",
                    "exit_code": 0,
                }
            ],
            "evidence": {
                "attempted_network_connections": ["('10.0.0.1', 443)"],
            },
        }
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=RESULT_PREFIX + json.dumps(runner_payload) + "\n",
            stderr="",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            return_value=completed,
        ):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertEqual(result.classification, "suspicious")
        self.assertEqual(result.failure_type, "suspicious_behavior")

    def test_timeout_records_output_excerpt_without_marking_executed(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["docker"],
            timeout=0.5,
            output=b"line 1\nline 2\n",
            stderr=b"error line\n",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            side_effect=timeout,
        ):
            result = analyze_artifact_dynamic("", b"wheel", timeout=0.5)

        self.assertFalse(result.executed)
        self.assertEqual(result.stdout, ["line 1", "line 2"])
        self.assertEqual(result.stderr, ["error line"])
        self.assertEqual(result.classification, "timed-out")
        self.assertEqual(result.failure_type, "timed_out")
        self.assertIn("0.5-second time limit", result.error or "")

    def test_startup_error_is_reported_without_execution(self) -> None:
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertFalse(result.executed)
        self.assertEqual(result.failure_type, "container_start_failed")
        self.assertIn("permission denied", result.error or "")

    def test_nonzero_exit_and_long_output_are_reported(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=42,
            stdout="\n".join(f"line {index}" for index in range(30)),
            stderr="failure\n",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            return_value=completed,
        ):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertTrue(result.executed)
        self.assertEqual(result.exit_code, 42)
        self.assertEqual(result.classification, "inconclusive")
        self.assertEqual(result.stderr, ["failure"])
        self.assertIn("line 0", result.stdout[0])
        self.assertIn("truncated 5 line(s)", result.stdout[-1])
        self.assertIn("non-zero exit code 42", result.error or "")

    def test_parser_helpers_ignore_malformed_payloads_and_classify_edges(self) -> None:
        parsed, kept = dynamic_mod._parse_runner_result(
            "\n".join(
                [
                    "kept",
                    RESULT_PREFIX + "{",
                    RESULT_PREFIX + json.dumps(["not", "an", "object"]),
                ]
            )
        )
        self.assertIsNone(parsed)
        self.assertEqual(kept, "kept")

        phases = dynamic_mod._parse_phases(
            [
                [],
                {
                    "name": "metadata_preparation",
                    "status": "failed",
                    "classification": "inconclusive",
                    "failure_type": None,
                    "exit_code": "1",
                    "stdout": ["line", None],
                    "stderr": "not-a-list",
                    "error": None,
                },
            ]
        )
        self.assertEqual(len(phases), 1)
        self.assertEqual(phases[0].stdout, ["line"])
        self.assertIsNone(phases[0].exit_code)
        self.assertIsNone(phases[0].failure_type)

        evidence = dynamic_mod._parse_evidence(
            {
                "child_processes": [None, "/tmp/python"],
                "subprocess_arguments": [["python", 3], "ignored"],
            }
        )
        self.assertEqual(evidence.child_processes, ["/tmp/python"])
        self.assertEqual(evidence.subprocess_arguments, [["python", "3"]])
        self.assertEqual(dynamic_mod._parse_evidence(None).child_processes, [])

        suspicious_phase = dynamic_mod.DynamicAnalysisPhase(
            name="install",
            status="passed",
            classification="suspicious",
        )
        failed_phase = dynamic_mod.DynamicAnalysisPhase(
            name="install",
            status="failed",
            classification="inconclusive",
            error="boom",
        )
        self.assertEqual(
            dynamic_mod._classify_result(
                0,
                [suspicious_phase],
                dynamic_mod.DynamicAnalysisEvidence(),
            ),
            ("suspicious", "suspicious_behavior"),
        )
        self.assertEqual(
            dynamic_mod._classify_result(
                0,
                [failed_phase],
                dynamic_mod.DynamicAnalysisEvidence(),
            ),
            ("inconclusive", "phase_failed"),
        )
        self.assertEqual(
            dynamic_mod._classify_result(3, [], dynamic_mod.DynamicAnalysisEvidence()),
            ("inconclusive", "analysis_failed"),
        )
        self.assertEqual(
            dynamic_mod._classify_result(
                0,
                [
                    dynamic_mod.DynamicAnalysisPhase(
                        name="archive_validation",
                        status="passed",
                        classification="passed",
                    )
                ],
                dynamic_mod.DynamicAnalysisEvidence(),
            ),
            ("passed", None),
        )
        self.assertEqual(
            dynamic_mod._classify_result(0, [], dynamic_mod.DynamicAnalysisEvidence()),
            ("inconclusive", "result_unavailable"),
        )
        self.assertEqual(
            dynamic_mod._error_from_phases([failed_phase]),
            "install: boom",
        )
        self.assertIsNone(dynamic_mod._error_from_phases([suspicious_phase]))


if __name__ == "__main__":
    unittest.main()
