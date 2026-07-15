from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import trustcheck.dynamic as dynamic_mod
from trustcheck.dynamic import DEFAULT_DYNAMIC_IMAGE, RESULT_PREFIX, analyze_artifact_dynamic

ROOT = Path(__file__).resolve().parents[1]
PINNED_IMAGE = "registry.example/trustcheck-analyzer@sha256:" + "a" * 64


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

    def test_analyzer_image_publication_workflow_is_pinned_and_complete(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "dynamic-analyzers.yml"
        ).read_text(encoding="utf-8")
        readme = (ROOT / "packaging" / "dynamic-analyzers" / "README.md").read_text(
            encoding="utf-8"
        )
        image = "ghcr.io/halfblood-prince/trustcheck-bounded-install-analyzer"

        self.assertIn(image, workflow)
        self.assertIn(image, readme)
        self.assertNotIn("ghcr.io/trustcheck/bounded-install-analyzer", readme)
        self.assertIn('python-version: ["3.11", "3.12", "3.13", "3.14"]', workflow)
        self.assertIn("docker run --rm --network none", workflow)
        self.assertIn("Run benign and malicious dynamic fixtures", workflow)
        self.assertIn("python -m pip_audit", workflow)
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn("dynamic-analyzer-digests/*.txt", workflow)

    def test_pip_audit_wrapper_does_not_record_its_own_log_writes(self) -> None:
        source = dynamic_mod._runner_source(
            "/work/demo.whl",
            import_probe=False,
            entry_point_probe=False,
        )
        allowed_block = source.split("allowed = (", 1)[1].split(")", 1)[0]
        self.assertIn("WRITING_AUDIT = False", source)
        self.assertIn("if WRITING_AUDIT:", source)
        self.assertIn("WRITING_AUDIT = True", source)
        self.assertNotIn("/tmp/trustcheck-audit.jsonl", allowed_block)
        self.assertIn("'--no-index', *find_links_args", source)
        self.assertNotIn("--no-build-isolation", source)

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
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

        self.assertTrue(result.enabled)
        self.assertFalse(result.executed)
        self.assertIn("Docker CLI", result.error or "")
        self.assertEqual(result.classification, "unsupported")
        self.assertEqual(result.network, "none")

    def test_reports_private_artifact_setup_failure_without_container(self) -> None:
        with patch("trustcheck.dynamic.shutil.which", return_value="C:\\Tools\\docker.exe"), patch(
            "trustcheck.dynamic._prepare_private_artifact_mount",
            side_effect=OSError("blocked"),
        ), patch("trustcheck.dynamic.subprocess.run") as run:
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

        self.assertFalse(result.executed)
        self.assertEqual(result.failure_type, "container_setup_failed")
        self.assertIn("blocked", result.error or "")
        run.assert_not_called()

    def test_unsupported_python_requires_configured_digest_pinned_image(self) -> None:
        with patch("trustcheck.dynamic.shutil.which") as which:
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                python_version="3.12",
            )

        self.assertFalse(result.executed)
        self.assertEqual(result.python_version, "3.12")
        self.assertIsNone(DEFAULT_DYNAMIC_IMAGE)
        self.assertEqual(result.failure_type, "analyzer_image_unavailable")
        which.assert_not_called()

        with patch("trustcheck.dynamic.shutil.which") as which:
            missing_profile = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                python_version="3.11",
            )

        self.assertFalse(missing_profile.executed)
        self.assertEqual(missing_profile.python_version, "3.11")
        self.assertEqual(missing_profile.failure_type, "analyzer_image_unavailable")
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
        docker_executable = "C:\\Tools\\docker.exe"
        completed = subprocess.CompletedProcess(
            args=[docker_executable],
            returncode=0,
            stdout="installed\n",
            stderr="",
        )
        with patch("trustcheck.dynamic.shutil.which", return_value=docker_executable), patch(
            "trustcheck.dynamic.subprocess.run",
            return_value=completed,
        ) as run:
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

        command = run.call_args.args[0]
        self.assertTrue(result.executed)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.image, PINNED_IMAGE)
        self.assertEqual(result.classification, "inconclusive")
        self.assertEqual(result.failure_type, "result_unavailable")
        self.assertEqual(result.stdout, ["installed"])
        self.assertEqual(command[0], docker_executable)
        self.assertIn("--rm", command)
        self.assertIn("--cidfile", command)
        self.assertIn("none", command[command.index("--network") + 1])
        self.assertEqual(
            command[command.index("--user") + 1],
            dynamic_mod._container_user(),
        )
        self.assertEqual(result.user, dynamic_mod._container_user())
        self.assertIn("512m", command[command.index("--memory") + 1])
        self.assertIn("cpu=10", command[command.index("--ulimit") + 1])
        self.assertIn("no-new-privileges", command)
        self.assertIn("ALL", command[command.index("--cap-drop") + 1])
        self.assertEqual(
            dynamic_mod.CONTAINER_TEMPFS,
            command[command.index("--tmpfs") + 1],
        )
        self.assertIn(
            "exec",
            command[command.index("--tmpfs") + 1].split(":")[1].split(","),
        )
        self.assertEqual(command[command.index(PINNED_IMAGE)], PINNED_IMAGE)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not meaningful on Windows")
    def test_artifact_mount_stays_private_for_host_user_container(self) -> None:
        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            volume = command[command.index("--volume") + 1]
            host_directory = Path(volume.split(":", 1)[0])
            artifact = host_directory / "demo.whl"
            self.assertEqual(stat.S_IMODE(host_directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(
                command[command.index("--user") + 1],
                dynamic_mod._container_user(),
            )
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="",
                stderr="",
            )

        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            side_effect=run,
        ):
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

        self.assertTrue(result.executed)

    def test_root_and_non_root_container_user_private_mount_ownership(self) -> None:
        with patch("trustcheck.dynamic.os.getuid", return_value=0, create=True), patch(
            "trustcheck.dynamic.os.getgid",
            return_value=0,
            create=True,
        ):
            self.assertEqual(dynamic_mod._container_user(), "65534:65534")

        with patch("trustcheck.dynamic.os.getuid", return_value=1234, create=True), patch(
            "trustcheck.dynamic.os.getgid",
            return_value=5678,
            create=True,
        ):
            self.assertEqual(dynamic_mod._container_user(), "1234:5678")

        with patch("trustcheck.dynamic.os.getuid", None, create=True), patch(
            "trustcheck.dynamic.os.getgid",
            None,
            create=True,
        ):
            self.assertEqual(dynamic_mod._container_user(), "65534:65534")
            self.assertFalse(dynamic_mod._caller_is_root())

        with self.subTest("root chown"):
            with tempfile.TemporaryDirectory(prefix="trustcheck-dynamic-test-") as temp:
                directory = Path(temp)
                artifact = directory / "demo.whl"
                artifact.write_bytes(b"wheel")
                with patch(
                    "trustcheck.dynamic.os.getuid",
                    return_value=0,
                    create=True,
                ), patch("trustcheck.dynamic.os.chown", create=True) as chown:
                    dynamic_mod._prepare_private_artifact_mount(directory, artifact)

                self.assertEqual(
                    chown.call_args_list[0].args,
                    (directory, 65534, 65534),
                )
                self.assertEqual(
                    chown.call_args_list[1].args,
                    (artifact, 65534, 65534),
                )

        with self.subTest("non-root no chown"):
            with tempfile.TemporaryDirectory(prefix="trustcheck-dynamic-test-") as temp:
                directory = Path(temp)
                artifact = directory / "demo.whl"
                artifact.write_bytes(b"wheel")
                with patch(
                    "trustcheck.dynamic.os.getuid",
                    return_value=1234,
                    create=True,
                ), patch("trustcheck.dynamic.os.chown", create=True) as chown:
                    dynamic_mod._prepare_private_artifact_mount(directory, artifact)

                chown.assert_not_called()

    def test_container_cleanup_uses_cidfile_for_terminal_paths(self) -> None:
        docker_executable = "C:\\Tools\\docker.exe"
        scenarios = {
            "normal": subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout="",
                stderr="",
            ),
            "timeout": subprocess.TimeoutExpired(
                cmd=["docker"],
                timeout=0.5,
                output=b"line\n",
                stderr=b"error\n",
            ),
            "interruption": KeyboardInterrupt(),
            "malformed": subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=RESULT_PREFIX + "{\n",
                stderr="",
            ),
            "client-error": OSError("client exited"),
        }
        for name, outcome in scenarios.items():
            with self.subTest(name=name):
                removed: list[str] = []
                container_id = "a" * 64

                def run(
                    command: list[str],
                    **_: object,
                ) -> subprocess.CompletedProcess[str]:
                    self.assertEqual(command[0], docker_executable)
                    if command[1:3] == ["rm", "--force"]:
                        removed.append(command[3])
                        return subprocess.CompletedProcess(command, 0, "", "")
                    cidfile = Path(command[command.index("--cidfile") + 1])
                    cidfile.write_text(container_id, encoding="ascii")
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome

                with patch(
                    "trustcheck.dynamic.shutil.which",
                    return_value=docker_executable,
                ), patch(
                    "trustcheck.dynamic.subprocess.run",
                    side_effect=run,
                ):
                    if isinstance(outcome, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            analyze_artifact_dynamic(
                                "demo.whl",
                                b"wheel",
                                image=PINNED_IMAGE,
                                timeout=0.5,
                            )
                    else:
                        analyze_artifact_dynamic(
                            "demo.whl",
                            b"wheel",
                            image=PINNED_IMAGE,
                            timeout=0.5,
                        )

                self.assertEqual(removed, [container_id])

    def test_container_cleanup_ignores_missing_invalid_and_failed_cleanup(self) -> None:
        docker_executable = "C:\\Tools\\docker.exe"
        with tempfile.TemporaryDirectory(prefix="trustcheck-dynamic-cleanup-") as temp:
            root = Path(temp)
            missing = root / "missing.cid"
            with patch("trustcheck.dynamic.subprocess.run") as run:
                dynamic_mod._force_remove_container(missing, docker_executable)
            run.assert_not_called()

            invalid = root / "invalid.cid"
            invalid.write_text("not-a-container-id", encoding="ascii")
            with patch("trustcheck.dynamic.subprocess.run") as run:
                dynamic_mod._force_remove_container(invalid, docker_executable)
            run.assert_not_called()

            valid = root / "valid.cid"
            valid.write_text("b" * 64, encoding="ascii")
            with patch(
                "trustcheck.dynamic.subprocess.run",
                side_effect=OSError("docker unavailable"),
            ) as run:
                dynamic_mod._force_remove_container(valid, docker_executable)
            self.assertEqual(
                run.call_args.args[0],
                [docker_executable, "rm", "--force", "b" * 64],
            )

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
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

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
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

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
            result = analyze_artifact_dynamic(
                "",
                b"wheel",
                image=PINNED_IMAGE,
                timeout=0.5,
            )

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
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

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
            result = analyze_artifact_dynamic(
                "demo.whl",
                b"wheel",
                image=PINNED_IMAGE,
            )

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
        self.assertEqual(dynamic_mod._parse_phases(None), [])

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
        audit_log_write = dynamic_mod.DynamicAnalysisEvidence(
            writes_outside_expected_locations=["/tmp/trustcheck-audit.jsonl"],
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
                audit_log_write,
            ),
            ("suspicious", "suspicious_behavior"),
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
