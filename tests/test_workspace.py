from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from trustcheck.workspace import (
    _issue_fingerprints,
    _normalize_sources,
    discover_dependency_files,
    main,
    scan_workspace,
)


class WorkspaceTests(unittest.TestCase):
    def test_discovers_supported_files_and_skips_virtual_environments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service").mkdir()
            (root / "service" / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "requirements.txt").write_text("bad==1\n", encoding="utf-8")
            (root / "requirements-api.txt").write_text("demo==1\n", encoding="utf-8")
            files = discover_dependency_files(root)
        self.assertEqual(
            [path.relative_to(root).as_posix() for path in files],
            ["requirements-api.txt", "service/pyproject.toml"],
        )

    def test_aggregates_reports_normalizes_paths_and_applies_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "services" / "api" / "requirements.txt"
            source.parent.mkdir(parents=True)
            source.write_text("demo==1\n", encoding="utf-8")
            output = {
                "reports": [{"project": "demo", "version": "1", "vulnerabilities": []}],
                "resolved": [{"project": "demo", "version": "1", "source_file": str(source)}],
                "failures": [],
            }
            completed = subprocess.CompletedProcess([], 0, json.dumps(output), "")
            with patch("trustcheck.workspace.subprocess.run", return_value=completed) as run:
                payload, exit_code = scan_workspace(
                    root,
                    policy_overrides={"services/api/*": "api-policy.json"},
                )
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["resolved"][0]["source_file"], "services/api/requirements.txt")
        self.assertIn("--policy-file", run.call_args.args[0])

    def test_fingerprints_and_source_normalization_handle_malformed_values(self) -> None:
        self.assertEqual(_issue_fingerprints({"reports": {}}), set())
        payload = {
            "reports": [
                "bad",
                {
                    "project": "demo",
                    "version": "1",
                    "vulnerabilities": ["bad", {"id": "CVE-1"}],
                    "policy": {"violations": ["bad", {"code": "blocked"}]},
                },
                {"vulnerabilities": {}, "policy": {"violations": {}}},
            ]
        }
        self.assertEqual(len(_issue_fingerprints(payload)), 2)
        _normalize_sources({"resolved": {}}, Path.cwd())
        outside = {"resolved": [{"source_file": "C:/outside/demo.txt"}, "bad"]}
        _normalize_sources(outside, Path.cwd())
        self.assertEqual(outside["resolved"][0]["source_file"], "demo.txt")

        backslash = {"resolved": [{"source_file": r"C:\outside\demo.txt"}]}
        _normalize_sources(backslash, Path.cwd())
        self.assertEqual(backslash["resolved"][0]["source_file"], "demo.txt")

    def test_scan_workspace_records_failures_offline_and_invalid_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "requirements.txt"
            source.write_text("demo==1\n", encoding="utf-8")
            failed = subprocess.CompletedProcess([], 3, "", "network failed")
            with patch("trustcheck.workspace.subprocess.run", return_value=failed) as run:
                payload, exit_code = scan_workspace(root, offline=True)
            self.assertEqual(exit_code, 3)
            self.assertEqual(payload["failures"][0]["message"], "network failed")
            self.assertIn("--offline", run.call_args.args[0])

            invalid = subprocess.CompletedProcess([], 0, "[]", "")
            with patch("trustcheck.workspace.subprocess.run", return_value=invalid):
                with self.assertRaisesRegex(ValueError, "not an object"):
                    scan_workspace(root)

    def test_main_writes_json_baseline_and_sarif_states(self) -> None:
        payload = {
            "reports": [],
            "resolved": [],
            "failures": [],
            "issue_fingerprints": ["new", "same"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            output = root / "result.json"
            policies = root / "policies.json"
            baseline.write_text(
                json.dumps({"issue_fingerprints": ["same", "fixed"]}),
                encoding="utf-8",
            )
            policies.write_text(json.dumps({"services/*": "strict.json"}), encoding="utf-8")
            with patch("trustcheck.workspace.scan_workspace", return_value=(payload, 4)):
                result = main(
                    [
                        str(root),
                        "--baseline",
                        str(baseline),
                        "--policy-overrides",
                        str(policies),
                        "--output-file",
                        str(output),
                    ]
                )
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result, 4)
            self.assertEqual(written["baseline"]["new"], ["new"])
            self.assertEqual(written["baseline"]["resolved"], ["fixed"])

            sarif_baseline = root / "previous.sarif"
            sarif_baseline.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "results": [
                                    {"partialFingerprints": {"trustcheck/v1": "same"}}
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rendered_sarif = json.dumps(
                {
                    "runs": [
                        {
                            "results": [
                                {"partialFingerprints": {"trustcheck/v1": "same"}},
                                {"partialFingerprints": {"trustcheck/v1": "new"}},
                            ]
                        }
                    ]
                }
            )
            stdout = StringIO()
            with patch("trustcheck.workspace.scan_workspace", return_value=(payload, 0)), patch(
                "trustcheck.workspace.render_payload_export", return_value=rendered_sarif
            ), redirect_stdout(stdout):
                self.assertEqual(
                    main([str(root), "--format", "sarif", "--baseline", str(sarif_baseline)]),
                    0,
                )
            states = [
                item["baselineState"]
                for item in json.loads(stdout.getvalue())["runs"][0]["results"]
            ]
            self.assertEqual(states, ["unchanged", "new"])

    def test_main_rejects_invalid_policy_map_and_tolerates_malformed_baseline(self) -> None:
        payload = {
            "reports": [],
            "resolved": [],
            "failures": [],
            "issue_fingerprints": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policies = root / "policies.json"
            policies.write_text("[]", encoding="utf-8")
            with self.assertRaises(SystemExit):
                main([str(root), "--policy-overrides", str(policies)])

            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "runs": [
                            "bad",
                            {"results": {}},
                            {
                                "results": [
                                    "bad",
                                    {"partialFingerprints": []},
                                    {"partialFingerprints": {"trustcheck/v1": 3}},
                                ]
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            scan = patch(
                "trustcheck.workspace.scan_workspace", return_value=(payload, 0)
            )
            with scan, redirect_stdout(stdout):
                self.assertEqual(main([str(root), "--baseline", str(baseline)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["baseline"]["new"], [])
