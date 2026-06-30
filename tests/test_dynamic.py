from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from trustcheck.dynamic import analyze_artifact_dynamic


class DynamicAnalysisTests(unittest.TestCase):
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
        self.assertEqual(result.stdout, ["installed"])
        self.assertIn("--rm", command)
        self.assertIn("none", command[command.index("--network") + 1])
        self.assertIn("65534:65534", command[command.index("--user") + 1])
        self.assertIn("512m", command[command.index("--memory") + 1])
        self.assertIn("cpu=10", command[command.index("--ulimit") + 1])
        self.assertIn("no-new-privileges", command)
        self.assertIn("ALL", command[command.index("--cap-drop") + 1])


if __name__ == "__main__":
    unittest.main()
