from __future__ import annotations

import argparse
import ast
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from packaging.utils import canonicalize_name

from trustcheck import impact as impact_module
from trustcheck.cli import EXIT_OK, build_parser, main
from trustcheck.cli_commands import impact as impact_command
from trustcheck.cli_commands.context import CommandContext
from trustcheck.cli_models import EXIT_DATA_ERROR, ScanTarget
from trustcheck.impact import analyze_source, build_impact_report, render_impact_text
from trustcheck.models import TrustReport, VulnerabilityRecord
from trustcheck.pypi import PypiClientError
from trustcheck.resolver import TargetEnvironment


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
        rendered = render_impact_text(impact)
        self.assertIn("trustcheck impact results for requirements.lock", rendered)
        self.assertIn("vulnerable packages: 3", rendered)
        self.assertIn("urllib3 1.26.18", rendered)
        self.assertIn("CVE-2024-0001: example advisory", rendered)
        self.assertIn("Advisory severity: CRITICAL", rendered)
        self.assertIn("Used by: src/api/client.py -> requests -> urllib3", rendered)
        self.assertIn("unused 1.0", rendered)
        self.assertIn("Classification: not observed in project source", rendered)

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

    def test_import_graph_discovers_project_contexts_and_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            package = root / "src" / "demo"
            package.mkdir(parents=True)
            (package / "app.py").write_text(
                "import requests, os\n"
                "from yaml import safe_load\n"
                "import importlib\n"
                "__import__('json')\n"
                "importlib.import_module('rich.console')\n"
                "def load(name):\n"
                "    return importlib.import_module(name)\n"
                "plain_assignment = 1\n",
                encoding="utf-8",
            )
            tests = root / "tests"
            tests.mkdir()
            (tests / "conftest.py").write_text(
                "pytest_plugins = ['pytest_cov.plugin', 42]\n",
                encoding="utf-8",
            )
            tools = root / "tools"
            tools.mkdir()
            (tools / "builder.py").write_text(
                "import tool_dep\n",
                encoding="utf-8",
            )
            (root / ".venv").mkdir()
            (root / ".venv" / "ignored.py").write_text(
                "import ignored_dep\n",
                encoding="utf-8",
            )
            (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            (root / "binary.py").write_bytes(b"\xff")
            (root / "pyproject.toml").write_text(
                "[project.scripts]\n"
                'demo-cli = "demo.cli:main"\n'
                "[project.gui-scripts]\n"
                'demo-gui = "demo.gui:start"\n'
                "[tool.poetry.scripts]\n"
                'demo-poetry = { reference = "demo.poetry:main" }\n'
                'demo-legacy = "demo.legacy:main"\n',
                encoding="utf-8",
            )

            graph = analyze_source([root])
            single_file_graph = analyze_source([package / "app.py"])
            non_python_graph = analyze_source([root / "README.md"])
            missing_graph = analyze_source([root / "missing"])

        modules = {item.module for item in graph.imports}
        self.assertIn("requests", modules)
        self.assertIn("yaml", modules)
        self.assertIn("json", modules)
        self.assertIn("rich.console", modules)
        self.assertNotIn("ignored_dep", modules)
        self.assertTrue(any(item.source == "from-import" for item in graph.imports))
        self.assertTrue(any(item.source == "dynamic-import" for item in graph.imports))
        self.assertTrue(
            any(item.source == "pytest-plugin" for item in graph.imports),
        )
        self.assertTrue(
            any(
                item.context == "development" and item.root == "tool_dep"
                for item in graph.imports
            ),
        )
        self.assertEqual(graph.unknown_dynamic_imports[0].expression, "importlib.import_module")
        self.assertEqual(
            {item.source for item in graph.entrypoints},
            {"project.scripts", "project.gui-scripts", "tool.poetry.scripts"},
        )
        self.assertEqual(single_file_graph.imports[0].path, "app.py")
        self.assertEqual(non_python_graph.imports, ())
        self.assertEqual(missing_graph.imports, ())

    def test_impact_helpers_cover_edge_classifications_and_rendering(self) -> None:
        target = ScanTarget(
            requirement="demo==1",
            project="demo",
            version="1",
            requested=False,
            requires_dist=("invalid requirement @@@", "missing>=1"),
        )
        graph = impact_module.SourceImportGraph(
            roots=(),
            imports=(),
            unknown_dynamic_imports=(),
            entrypoints=(),
        )
        empty = build_impact_report(
            dependency_file="requirements.lock",
            source_roots=[],
            targets=[target],
            reports={
                "demo": report("demo", "1"),
                "ghost": report("ghost", "1", [vulnerability("CVE-GHOST")]),
            },
            import_graph=graph,
            failures=[{"requirement": "bad", "message": "could not inspect"}],
        )

        rendered = render_impact_text(empty)
        self.assertIn("No vulnerable packages were reported", rendered)
        self.assertIn("inspection failures:", rendered)
        self.assertIn("bad: could not inspect", rendered)
        self.assertEqual(empty.dependency_graph.edges, ())

        development = impact_module.ImportEvidence(
            module="demo",
            root="demo",
            path="tools/build.py",
            line=3,
            context="development",
        )
        finding = impact_module._classify_vulnerability(
            target,
            vulnerability("NO-SUMMARY", severity="MEDIUM"),
            usage={"demo": [development]},
            production_roots=[],
            adjacency={},
            dynamic_unknown=(),
        )
        self.assertEqual(finding.classification, "development_only")
        self.assertIn("tools/build.py", finding.evidence)
        self.assertIn("pin a safe demo version", finding.action)

        class OddReport(impact_module.ImpactReport):
            def to_dict(self) -> dict[str, object]:  # type: ignore[override]
                payload = super().to_dict()
                payload["summary"] = "bad"
                return payload

        with self.assertRaisesRegex(TypeError, "summary must be a mapping"):
            render_impact_text(
                OddReport(
                    source="",
                    source_roots=(),
                    dependency_file="requirements.lock",
                    import_graph=graph,
                    dependency_graph=impact_module.DependencyGraph((), ()),
                    findings=(),
                )
            )

    def test_private_impact_helpers_handle_small_edge_cases(self) -> None:
        scores = [
            impact_module._severity_rank(
                VulnerabilityRecord(id="critical", summary="", cvss_score=9.1)
            ),
            impact_module._severity_rank(
                VulnerabilityRecord(id="high", summary="", cvss_score=7.1)
            ),
            impact_module._severity_rank(
                VulnerabilityRecord(id="medium", summary="", cvss_score=4.1)
            ),
            impact_module._severity_rank(
                VulnerabilityRecord(id="low", summary="", cvss_score=3.9)
            ),
            impact_module._severity_rank(vulnerability("MED", severity="MED")),
            impact_module._severity_rank(vulnerability("LOW", severity="LOW")),
            impact_module._severity_rank(vulnerability("UNKNOWN", severity="")),
        ]
        self.assertEqual(scores, [4, 3, 2, 1, 2, 1, 0])

        self.assertEqual(
            impact_module._reachable_path(
                "missing",
                ["root"],
                {"root": ["child"], "child": ["root"]},
            ),
            None,
        )
        target = ScanTarget(requirement="x==1", project="x")
        self.assertEqual(impact_module._display_path([], target), [])
        self.assertEqual(
            impact_module._action_for(
                target,
                vulnerability("CVE-FIXED", fixed_in=["2", "3", "4", "5"]),
                ["parent", "x"],
            ),
            "upgrade parent or pin x to a fixed version (2, 3, 4)",
        )
        self.assertEqual(
            impact_module._vulnerability_title(
                VulnerabilityRecord(id="GHSA-1", summary="")
            ),
            "GHSA-1",
        )
        self.assertEqual(
            impact_module._string_values(ast.parse("pytest_plugins = 'one'").body[0].value),  # type: ignore[attr-defined]
            ["one"],
        )
        self.assertEqual(
            impact_module._string_values(ast.parse("pytest_plugins = {1}").body[0].value),  # type: ignore[attr-defined]
            [],
        )
        imports: list[impact_module.ImportEvidence] = []
        impact_module._add_import("", "app.py", 1, "production", imports, source="import")
        self.assertEqual(imports, [])
        self.assertFalse(
            impact_module._is_dynamic_import_call(
                ast.parse("plain()").body[0].value,  # type: ignore[attr-defined]
            )
        )
        self.assertIsNone(
            impact_module._literal_first_arg(
                ast.parse("__import__()").body[0].value,  # type: ignore[attr-defined]
            )
        )
        self.assertEqual(
            impact_module._dynamic_import_name(
                ast.parse("__import__(name)").body[0].value,  # type: ignore[attr-defined]
            ),
            "__import__",
        )
        self.assertEqual(
            impact_module._dynamic_import_name(
                ast.parse("(lambda name: name)('demo')").body[0].value,  # type: ignore[attr-defined]
            ),
            "dynamic import",
        )
        self.assertEqual(
            impact_module._string_values(ast.parse("value = name").body[0].value),  # type: ignore[attr-defined]
            [],
        )
        self.assertEqual(
            impact_module._impact_priority(
                "directly_used",
                vulnerability("MEDIUM", severity="MEDIUM"),
            ),
            ("HIGH", "review"),
        )
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            bad_root = root / "bad"
            bad_root.mkdir()
            (bad_root / "pyproject.toml").write_text("[project\n", encoding="utf-8")
            self.assertEqual(impact_module._entrypoints_from_project_files(bad_root), [])
            no_tables = root / "no-tables"
            no_tables.mkdir()
            (no_tables / "pyproject.toml").write_text("[tool]\n", encoding="utf-8")
            self.assertEqual(impact_module._entrypoints_from_project_files(no_tables), [])
            self.assertEqual(
                impact_module._file_context(root / "conftest.py", root),
                "test",
            )
            self.assertEqual(
                impact_module._relative_path(root / "app.py", root / "other"),
                str(root / "app.py").replace("\\", "/"),
            )
            self.assertFalse(impact_module._is_relative_to(root / "app.py", root / "other"))


class ImpactCommandHelperTests(unittest.TestCase):
    def test_validate_args_requires_file_and_source(self) -> None:
        class RaisingParser(argparse.ArgumentParser):
            def error(self, message: str) -> None:
                raise ValueError(message)

        parser = RaisingParser()
        with self.assertRaisesRegex(ValueError, "requires -f/--file"):
            impact_command.validate_args(
                argparse.Namespace(filename=None, source=["."]),
                parser,
            )
        with self.assertRaisesRegex(ValueError, "at least one --source"):
            impact_command.validate_args(
                argparse.Namespace(filename="requirements.lock", source=[]),
                parser,
            )

    def test_run_collects_target_failures_and_flushes_vulnerability_cache(self) -> None:
        class VulnerabilityClient:
            def __init__(self) -> None:
                self.prefetched: list[tuple[str, str | None]] = []
                self.flushed = False

            def prefetch(self, targets) -> None:
                self.prefetched = list(targets)

            def flush_snapshots(self) -> None:
                self.flushed = True

        class FakeImpactCli:
            canonicalize_name = staticmethod(canonicalize_name)

            def __init__(self) -> None:
                self.vulnerability_client = VulnerabilityClient()
                self.outputs: list[str] = []

            def _resolve_max_workers(self, args, config_payload):
                del args, config_payload
                return 1

            def _build_debug_request_hook(self, **kwargs):
                del kwargs
                return None

            def _build_client(self, args, **kwargs):
                del args, kwargs
                return type("Client", (), {"offline": True})()

            def _build_vulnerability_client(self, *args, **kwargs):
                del args, kwargs
                return self.vulnerability_client

            def _resolver_from_args(self, args, **kwargs):
                del args, kwargs
                return object()

            def _load_scan_targets(self, *args, **kwargs):
                del args, kwargs
                return [
                    ScanTarget(
                        requirement="failed",
                        project="failed",
                        failure_message="resolver failed",
                        failure_exit_code=EXIT_DATA_ERROR,
                    ),
                    ScanTarget(requirement="upstream==1", project="upstream", version="1"),
                    ScanTarget(requirement="invalid==1", project="invalid", version="1"),
                    ScanTarget(requirement="ok==1", project="ok", version="1"),
                ]

            def _target_environment_from_args(self, args):
                del args
                return TargetEnvironment()

            def _clone_pypi_client(self, client):
                return client

            def _client_for_target(self, client, target, **kwargs):
                del target, kwargs
                return client

            def inspect_package(self, project: str, **kwargs):
                del kwargs
                if project == "upstream":
                    raise PypiClientError("temporary outage")
                if project == "invalid":
                    raise ValueError("bad json")
                return report(project, "1")

            def _format_upstream_error(self, exc: Exception) -> str:
                return f"upstream: {exc}"

            def _merge_exit_codes(self, first: int, second: int) -> int:
                return max(first, second)

            def _emit_output(self, rendered: str, output_file: str | None) -> None:
                del output_file
                self.outputs.append(rendered)

        cli = FakeImpactCli()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "app.py").write_text("import ok\n", encoding="utf-8")
            exit_code = impact_command.run(
                argparse.Namespace(
                    filename="requirements.lock",
                    source=[str(root)],
                    constraint=[],
                    extra=[],
                    group=[],
                    keyring_provider="auto",
                    trusted_project=[],
                    debug=False,
                    log_format="text",
                    format="text",
                    output_file=None,
                    max_workers=1,
                ),
                CommandContext(
                    parser=argparse.ArgumentParser(),
                    config_payload={},
                    plugin_manager=None,
                    facade=cli,
                ),
            )

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertTrue(cli.vulnerability_client.flushed)
        self.assertEqual(
            cli.vulnerability_client.prefetched,
            [("upstream", "1"), ("invalid", "1"), ("ok", "1")],
        )
        self.assertIn("inspection failures:", cli.outputs[0])
        self.assertIn("upstream: temporary outage", cli.outputs[0])
        self.assertIn("invalid response", cli.outputs[0])


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
