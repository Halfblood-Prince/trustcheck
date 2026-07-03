from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trustcheck.doctor import collect_doctor_report, render_doctor_json, render_doctor_text


class DoctorTests(unittest.TestCase):
    def test_reports_core_runtime_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def finder(name: str) -> str | None:
                return {
                    "docker": "/usr/bin/docker",
                    "podman": None,
                    "bwrap": "/usr/bin/bwrap",
                    "uv": "/usr/bin/uv",
                }.get(name)

            report = collect_doctor_report(
                cache_dir=str(root / "cache"),
                index_urls=("https://user:token@packages.example/simple",),
                keyring_provider="auto",
                sandbox_mode="auto",
                executable_finder=finder,
                module_checker=lambda name: name in {"sigstore", "keyring"},
                environ={
                    "XDG_DATA_HOME": str(root / "data"),
                    "XDG_CACHE_HOME": str(root / "xdg-cache"),
                    "XDG_CONFIG_HOME": str(root / "config"),
                },
                platform_system="Linux",
                home=root,
            )
            checks = {check.name: check for check in report.checks}

        self.assertTrue(report.passed)
        self.assertEqual(checks["Docker"].status, "pass")
        self.assertEqual(checks["Podman"].status, "warn")
        self.assertEqual(checks["Bubblewrap"].status, "pass")
        self.assertEqual(checks["Keyring"].status, "pass")
        self.assertEqual(checks["Sigstore trust roots"].status, "pass")
        self.assertEqual(checks["Private-index authentication"].status, "pass")
        self.assertEqual(checks["Cache permissions"].status, "pass")
        self.assertIn("pylock*.toml", " ".join(checks["Supported lockfile tools"].evidence))
        self.assertIn("overall: pass", render_doctor_text(report))
        self.assertTrue(json.loads(render_doctor_json(report))["passed"])

    def test_strict_failures_are_visible_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = collect_doctor_report(
                cache_dir=str(root / "cache"),
                index_urls=("https://packages.example/simple",),
                keyring_provider="import",
                sandbox_mode="container",
                executable_finder=lambda name: None,
                module_checker=lambda name: False,
                environ={
                    "XDG_DATA_HOME": str(root / "data"),
                    "XDG_CACHE_HOME": str(root / "xdg-cache"),
                    "XDG_CONFIG_HOME": str(root / "config"),
                },
                platform_system="Linux",
                home=root,
            )
            checks = {check.name: check for check in report.checks}

        self.assertFalse(report.passed)
        self.assertEqual(checks["Keyring"].status, "fail")
        self.assertEqual(checks["Sigstore trust roots"].status, "fail")
        self.assertEqual(checks["Resolver sandbox"].status, "fail")


if __name__ == "__main__":
    unittest.main()
