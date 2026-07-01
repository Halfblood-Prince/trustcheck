from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from trustcheck.dynamic import DEFAULT_DYNAMIC_IMAGE, analyze_artifact_dynamic


class DynamicAnalysisTests(unittest.TestCase):
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
        which.assert_not_called()

    def test_reports_missing_docker_without_executing(self) -> None:
        with patch("trustcheck.dynamic.shutil.which", return_value=None):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertTrue(result.enabled)
        self.assertFalse(result.executed)
        self.assertIn("Docker CLI", result.error or "")
        self.assertEqual(result.network, "none")

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
        self.assertEqual(result.stdout, ["installed"])
        self.assertIn("--rm", command)
        self.assertIn("none", command[command.index("--network") + 1])
        self.assertIn("65534:65534", command[command.index("--user") + 1])
        self.assertIn("512m", command[command.index("--memory") + 1])
        self.assertIn("cpu=10", command[command.index("--ulimit") + 1])
        self.assertIn("no-new-privileges", command)
        self.assertIn("ALL", command[command.index("--cap-drop") + 1])
        self.assertEqual(command[command.index(DEFAULT_DYNAMIC_IMAGE)], DEFAULT_DYNAMIC_IMAGE)

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
        self.assertIn("0.5-second time limit", result.error or "")

    def test_startup_error_is_reported_without_execution(self) -> None:
        with patch("trustcheck.dynamic.shutil.which", return_value="docker"), patch(
            "trustcheck.dynamic.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            result = analyze_artifact_dynamic("demo.whl", b"wheel")

        self.assertFalse(result.executed)
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
        self.assertEqual(result.stderr, ["failure"])
        self.assertIn("line 0", result.stdout[0])
        self.assertIn("truncated 5 line(s)", result.stdout[-1])
        self.assertIn("non-zero exit code 42", result.error or "")


if __name__ == "__main__":
    unittest.main()
