from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import EXIT_OK, build_parser, main
from trustcheck.cli_models import ScanTarget
from trustcheck.impact import analyze_source, build_impact_report
from trustcheck.models import TrustReport, VulnerabilityRecord


def vulnerability(
    identifier: str,
    *,
    severity: str = "HIGH",
    fixed_in: list[str] | None = None,
) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        id=identifier,
        summary="example advisory",
        severity=severity,
        fixed_in=fixed_in or [],
    )


def report(
    project: str,
    version: str,
    vulnerabilities: list[VulnerabilityRecord] | None = None,
) -> TrustReport:
    return TrustReport(
        project=project,
        version=version,
        summary=None,
        package_url=f"https://pypi.org/project/{project}/{version}/",
        vulnerabilities=vulnerabilities or [],
    )


class ImpactAnalysisTests(unittest.TestCase):
    def test_source_usage_prioritizes_vulnerable_dependency_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            source = root / "src" / "api"
            source.mkdir(parents=True)
            (source / "client.py").write_text(
                "import requests\n",
                encoding="utf-8",
            )
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_config.py").write_text(
                "import yaml\n",
                encoding="utf-8",
            )

            targets = [
                ScanTarget(
                    requirement="requests==2.32.0",
                    project="requests",
                    version="2.32.0",
                    requested=True,
                    requires_dist=("urllib3>=1",),
                ),
                ScanTarget(
                    requirement="urllib3==1.26.18",
                    project="urllib3",
                    version="1.26.18",
                    requested=False,
                ),
                ScanTarget(
                    requirement="pyyaml==5.4",
                    project="pyyaml",
                    version="5.4",
                    requested=True,
                ),
                ScanTarget(
                    requirement="unused==1.0",
                    project="unused",
                    version="1.0",
                    requested=True,
                ),
            ]
            reports = {
                "urllib3": report(
                    "urllib3",
                    "1.26.18",
                    [vulnerability("CVE-2024-0001", severity="CRITICAL")],
                ),
                "pyyaml": report(
                    "pyyaml",
                    "5.4",
                    [vulnerability("CVE-2024-0002")],
                ),
                "unused": report(
                    "unused",
                    "1.0",
                    [vulnerability("CVE-2024-0003")],
                ),
            }

            impact = build_impact_report(
                dependency_file=str(root / "requirements.lock"),
                source_roots=[root],
                targets=targets,
                reports=reports,
                import_graph=analyze_source([root]),
            )

        by_project = {finding.project: finding for finding in impact.findings}
        self.assertEqual(
            by_project["urllib3"].classification,
            "transitively_reachable",
        )
        self.assertEqual(by_project["urllib3"].priority, "priority-1")
        self.assertIn("src/api/client.py -> requests -> urllib3", by_project["urllib3"].used_by)
        self.assertEqual(by_project["pyyaml"].classification, "test_only")
        self.assertEqual(by_project["pyyaml"].priority, "likely-unused")
        self.assertEqual(
            by_project["unused"].classification,
            "not_observed_in_project_source",
        )

    def test_dynamic_imports_are_reported_as_unknown_not_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            source = root / "src"
            source.mkdir()
            (source / "plugin_loader.py").write_text(
                "import importlib\n"
                "def load(name):\n"
                "    return importlib.import_module(name)\n",
                encoding="utf-8",
            )
            targets = [
                ScanTarget(
                    requirement="plugin-dep==1",
                    project="plugin-dep",
                    version="1",
                    requested=False,
                )
            ]
            impact = build_impact_report(
                dependency_file=str(root / "requirements.lock"),
                source_roots=[root],
                targets=targets,
                reports={
                    "plugin-dep": report(
                        "plugin-dep",
                        "1",
                        [vulnerability("CVE-2024-0004")],
                    )
                },
                import_graph=analyze_source([root]),
            )

        self.assertEqual(
            impact.findings[0].classification,
            "unknown_due_to_dynamic_loading",
        )
        self.assertIn("Manual review is still required", impact.warning)


class ImpactCommandTests(unittest.TestCase):
    def test_parser_accepts_impact_command(self) -> None:
        args = build_parser().parse_args(
            ["impact", "-f", "requirements.lock", "--source", "."]
        )

        self.assertEqual(args.command, "impact")
        self.assertEqual(args.filename, "requirements.lock")
        self.assertEqual(args.source, ["."])

    def test_cli_impact_outputs_json_without_installing_or_fixing(self) -> None:
        stdout = io.StringIO()
        target = ScanTarget(
            requirement="demo==1",
            project="demo",
            version="1",
            requested=True,
        )
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "app.py").write_text("import demo\n", encoding="utf-8")
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=report(
                        "demo",
                        "1",
                        [vulnerability("CVE-2024-0005", fixed_in=["1.1"])],
                    ),
                ),
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "impact",
                        "-f",
                        "requirements.lock",
                        "--source",
                        str(root),
                        "--format",
                        "json",
                    ]
                )

        self.assertEqual(exit_code, EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema"], "urn:trustcheck:impact:1.0.0")
        self.assertEqual(payload["findings"][0]["classification"], "directly_used")
        self.assertIn("upgrade demo", payload["findings"][0]["action"])


if __name__ == "__main__":
    unittest.main()
