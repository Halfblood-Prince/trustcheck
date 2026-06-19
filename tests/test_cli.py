from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packaging.requirements import Requirement

from trustcheck.cli import (
    EXIT_DATA_ERROR,
    EXIT_OK,
    EXIT_POLICY_FAILURE,
    EXIT_UPSTREAM_FAILURE,
    ScanTarget,
    _build_debug_request_hook,
    _build_scan_targets,
    _build_vulnerability_client,
    _clean_requirement_line,
    _client_for_target,
    _collect_requirement_strings,
    _evidence_summary,
    _expand_poetry_caret_specifier,
    _expand_poetry_tilde_specifier,
    _extract_poetry_dependency_requirements,
    _extract_scan_requirements_from_toml,
    _format_upstream_error,
    _index_configuration_from_args,
    _load_scan_targets,
    _load_scan_targets_from_toml,
    _locked_versions_from_requirements,
    _merge_exit_codes,
    _parse_version_release_parts,
    _poetry_dependency_to_requirement,
    _post_fix_reproduction_command,
    _read_requirements_file,
    _render_cve_json,
    _render_cve_report,
    _render_scan_json,
    _render_scan_text,
    _render_text_report,
    _resolve_bool,
    _resolve_scan_target_version,
    _resolve_scan_target_version_for_scan,
    _resolver_from_args,
    _scan_project_vulnerabilities,
    _scan_targets_from_lockfile,
    _scan_targets_from_resolution,
    _target_environment_from_args,
    _target_marker_environment,
    _translate_poetry_version_specifier,
    _uses_nondefault_indexes,
    build_parser,
    main,
)
from trustcheck.contract import JSON_SCHEMA_VERSION
from trustcheck.indexes import DependencyConfusionFinding
from trustcheck.lockfiles import LockedPackage, LockfileResolution, load_lockfile
from trustcheck.models import (
    ArtifactInspection,
    CoverageSummary,
    DependencyInspection,
    DependencySummary,
    FileProvenance,
    HeuristicFinding,
    MaliciousPackageAssessment,
    NativeBinaryInspection,
    PolicyViolation,
    ProvenanceConsistency,
    ProvenanceIssue,
    PublisherIdentity,
    PublisherTrustSummary,
    ReleaseDriftSummary,
    ReportDiagnostics,
    RequestFailureDiagnostic,
    RiskFlag,
    SlsaProvenance,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from trustcheck.plugins import PluginManager
from trustcheck.policy import PolicySettings
from trustcheck.pypi import IndexBackedPackageClient, PypiClient, PypiClientError
from trustcheck.resolver import (
    ArtifactReference,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
)
from trustcheck.schemas import ProjectInfoPayload


def make_report() -> TrustReport:
    return TrustReport(
        project="gridoptim",
        version="2.2.0",
        summary="gridoptim package",
        package_url="https://pypi.org/project/gridoptim/2.2.0/",
        declared_dependencies=["depalpha>=1.0"],
        declared_repository_urls=["https://github.com/Halfblood-Prince/gridoptim"],
        repository_urls=["https://github.com/Halfblood-Prince/gridoptim"],
        expected_repository="https://github.com/Halfblood-Prince/gridoptim",
        ownership={
            "organization": "Halfblood-Prince",
            "roles": [{"role": "Owner", "user": "Halfblood-Prince"}],
        },
        vulnerabilities=[],
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
                "GitHub:https://github.com/Halfblood-Prince/gridoptim:release.yml"
            ],
            unique_verified_repositories=["https://github.com/Halfblood-Prince/gridoptim"],
            unique_verified_workflows=["release.yml"],
        ),
        provenance_consistency=ProvenanceConsistency(
            has_sdist=False,
            has_wheel=True,
            sdist_wheel_consistent=None,
        ),
        release_drift=ReleaseDriftSummary(),
        dependencies=[
            DependencyInspection(
                requirement="depalpha>=1.0",
                project="depalpha",
                version="1.4.0",
                depth=1,
                parent_project="gridoptim",
                parent_version="2.2.0",
                package_url="https://pypi.org/project/depalpha/1.4.0/",
                recommendation="review-required",
                risk_flags=[
                    RiskFlag(
                        code="missing_repository_url",
                        severity="medium",
                        message="No repository metadata.",
                    )
                ],
            )
        ],
        dependency_summary=DependencySummary(
            requested=True,
            total_declared=1,
            total_inspected=1,
            unique_dependencies=1,
            max_depth=1,
            highest_risk_recommendation="review-required",
            highest_risk_projects=["depalpha"],
            review_required_projects=["depalpha"],
        ),
        risk_flags=[],
        recommendation="verified",
        diagnostics=ReportDiagnostics(),
    )


class CliBehaviorTests(unittest.TestCase):
    def test_split_commands_reject_ambiguous_or_invalid_targets(self) -> None:
        cases = [
            ["inspect"],
            ["inspect", "gridoptim", "-f", "requirements.txt"],
            ["inspect", "-f", "requirements.txt", "--version", "1.0"],
            [
                "inspect",
                "-f",
                "requirements.txt",
                "--expected-repo",
                "https://example.com/repo",
            ],
            ["scan"],
            ["scan", "gridoptim", "-f", "requirements.txt"],
            ["scan", "gridoptim", "--fix"],
        ]

        for command in cases:
            with self.subTest(command=command):
                with (
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    main(command)
                self.assertEqual(raised.exception.code, 2)

    def test_parser_accepts_resolver_environment_and_installed_path_options(self) -> None:
        parser = build_parser()
        scan_args = parser.parse_args(
            [
                "scan",
                "-f",
                "requirements.txt",
                "--constraint",
                "constraints.txt",
                "--extra",
                "security",
                "--group",
                "test",
                "--python-version",
                "3.12",
                "--platform",
                "manylinux_2_28_x86_64",
                "--implementation",
                "cp",
                "--abi",
                "cp312",
                "--index-url",
                "https://private.example/simple",
                "--extra-index-url",
                "https://pypi.org/simple",
                "--keyring-provider",
                "subprocess",
                "--allow-dependency-confusion",
            ]
        )
        self.assertEqual(scan_args.constraint, ["constraints.txt"])
        self.assertEqual(scan_args.extra, ["security"])
        self.assertEqual(scan_args.group, ["test"])
        self.assertEqual(scan_args.index_url, "https://private.example/simple")
        self.assertEqual(scan_args.extra_index_url, ["https://pypi.org/simple"])
        self.assertEqual(scan_args.keyring_provider, "subprocess")
        self.assertTrue(scan_args.allow_dependency_confusion)
        self.assertEqual(
            _target_environment_from_args(scan_args),
            TargetEnvironment(
                python_version="3.12",
                platforms=("manylinux_2_28_x86_64",),
                implementation="cp",
                abis=("cp312",),
            ),
        )

        environment_args = parser.parse_args(
            ["environment", "--path", "one", "--path", "two"]
        )
        self.assertEqual(environment_args.path, ["one", "two"])
        export_args = parser.parse_args(
            [
                "inspect",
                "demo",
                "--format",
                "sarif",
                "--output-file",
                "report.sarif",
            ]
        )
        self.assertEqual(export_args.format, "sarif")
        self.assertEqual(export_args.output_file, "report.sarif")

    def test_index_and_target_helpers_cover_private_source_variants(self) -> None:
        parser = build_parser()
        default_args = parser.parse_args(["scan", "-f", "requirements.txt"])
        self.assertFalse(_uses_nondefault_indexes(default_args))
        self.assertEqual(
            _index_configuration_from_args(default_args).index_url,
            "https://pypi.org/simple",
        )
        self.assertIsInstance(_resolver_from_args(default_args), object)

        private_args = parser.parse_args(
            [
                "scan",
                "-f",
                "requirements.txt",
                "--index-url",
                "https://private.example/simple",
            ]
        )
        self.assertTrue(_uses_nondefault_indexes(private_args))

        self.assertIn("python_version", _target_marker_environment(None))
        environments = [
            (
                TargetEnvironment(
                    python_version="3.12.1",
                    implementation="cp",
                    platforms=("win_amd64",),
                ),
                ("3.12", "cpython", "win32"),
            ),
            (
                TargetEnvironment(
                    implementation="pp",
                    platforms=("macosx_14_0_arm64",),
                ),
                (
                    _target_marker_environment(None)["python_version"],
                    "pypy",
                    "darwin",
                ),
            ),
            (
                TargetEnvironment(
                    implementation="custom",
                    platforms=("manylinux_2_28_x86_64",),
                ),
                (
                    _target_marker_environment(None)["python_version"],
                    "custom",
                    "linux",
                ),
            ),
        ]
        for target, expected in environments:
            with self.subTest(target=target):
                environment = _target_marker_environment(target)
                self.assertEqual(
                    (
                        environment["python_version"],
                        environment["implementation_name"],
                        environment["sys_platform"],
                    ),
                    expected,
                )

        client = PypiClient()
        self.assertIs(
            _client_for_target(
                client,
                ScanTarget(requirement="demo", project="demo"),
                keyring_provider="auto",
            ),
            client,
        )
        self.assertIs(
            _client_for_target(
                client,
                ScanTarget(
                    requirement="demo==1",
                    project="demo",
                    version="1",
                    index_url="https://pypi.org/simple",
                ),
                keyring_provider="auto",
            ),
            client,
        )
        self.assertIs(
            _client_for_target(
                client,
                ScanTarget(
                    requirement="demo==1",
                    project="demo",
                    version="1",
                    artifacts=(
                        ArtifactReference(
                            url="https://files.pythonhosted.org/demo.whl"
                        ),
                    ),
                ),
                keyring_provider="auto",
            ),
            client,
        )
        private_client = _client_for_target(
            client,
            ScanTarget(
                requirement="demo==1",
                project="demo",
                version="1",
                artifacts=(
                    ArtifactReference(url="https://private.example/demo.whl"),
                ),
            ),
            keyring_provider="disabled",
        )
        self.assertIsInstance(private_client, IndexBackedPackageClient)
        assert isinstance(private_client, IndexBackedPackageClient)
        self.assertEqual(private_client.index_url, "https://private.example/")

    def test_lockfile_targets_record_allowed_dependency_confusion(self) -> None:
        resolution = LockfileResolution(
            requirements=["demo==1"],
            versions={"demo": "1"},
            packages=(
                LockedPackage(
                    name="demo",
                    version="1",
                    requirement="demo==1",
                    index_url="https://private.example/simple",
                ),
            ),
        )

        class Resolver:
            def check_dependency_confusion(self, projects, additional_indexes=()):
                self.projects = projects
                self.indexes = additional_indexes
                return (
                    DependencyConfusionFinding(
                        project="demo",
                        indexes=("private", "public"),
                    ),
                )

        targets = _scan_targets_from_lockfile(
            resolution,
            resolver=Resolver(),  # type: ignore[arg-type]
        )
        self.assertEqual(
            targets[0].dependency_confusion,
            ("private", "public"),
        )

    def test_inspect_uses_private_index_resolution(self) -> None:
        report = make_report()
        artifact = ArtifactReference(
            filename="gridoptim.whl",
            url="https://private.example/gridoptim.whl",
            hashes=(("sha256", "a" * 64),),
        )

        class Resolver:
            def resolve_requirements(self, requirements, **kwargs):
                self.requirements = requirements
                self.kwargs = kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(
                            name="gridoptim",
                            version="2.2.0",
                            artifacts=(artifact,),
                            index_url="https://private.example/simple",
                        )
                    ]
                )

        resolver = Resolver()
        fake_client = PypiClient()
        with patch("trustcheck.cli._resolver_from_args", return_value=resolver), patch(
            "trustcheck.cli._build_client",
            return_value=fake_client,
        ), patch("trustcheck.cli.inspect_package", return_value=report) as inspect:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--index-url",
                        "https://private.example/simple",
                        "--format",
                        "json",
                    ]
                )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(resolver.requirements, ["gridoptim"])
        self.assertEqual(inspect.call_args.kwargs["version"], "2.2.0")
        self.assertEqual(inspect.call_args.kwargs["expected_artifacts"], (artifact,))
        self.assertIsInstance(
            inspect.call_args.kwargs["client"],
            IndexBackedPackageClient,
        )

    def test_inspect_private_index_requires_resolved_root(self) -> None:
        class Resolver:
            def resolve_requirements(self, requirements, **kwargs):
                del requirements, kwargs
                return Resolution(
                    distributions=[ResolvedDistribution("other", "1")]
                )

        with patch("trustcheck.cli._resolver_from_args", return_value=Resolver()), patch(
            "trustcheck.cli._build_client",
            return_value=PypiClient(),
        ):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--index-url",
                        "https://private.example/simple",
                    ]
                )
        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("did not return root", stderr.getvalue())

    def test_scan_uses_complete_pip_resolution_for_all_packages(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls: list[tuple[Path, dict[str, object]]] = []

            def resolve_requirements_file(self, path, **kwargs):
                self.calls.append((Path(path), kwargs))
                return Resolution(
                    distributions=[
                        ResolvedDistribution(
                            "root",
                            "1.0",
                            requested=True,
                            source_url="https://files.example/root.whl",
                        ),
                        ResolvedDistribution("transitive", "2.0"),
                    ]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            requirements = Path(tmpdir) / "requirements.txt"
            requirements.write_text(
                "-r nested.txt\n-c nested-constraints.txt\nroot>=1\n",
                encoding="utf-8",
            )
            constraints = Path(tmpdir) / "constraints.txt"
            constraints.write_text("transitive<3\n", encoding="utf-8")
            resolver = FakeResolver()
            target = TargetEnvironment(python_version="3.12")
            targets = _load_scan_targets(
                str(requirements),
                object(),  # type: ignore[arg-type]
                resolver=resolver,  # type: ignore[arg-type]
                constraints=[constraints],
                target_environment=target,
                offline=True,
            )

        self.assertEqual(
            [(item.project, item.version) for item in targets],
            [("root", "1.0"), ("transitive", "2.0")],
        )
        self.assertTrue(all(item.complete_locked_versions for item in targets))
        self.assertEqual(
            targets[0].locked_versions,
            {"root": "1.0", "transitive": "2.0"},
        )
        self.assertEqual(targets[0].source_url, "https://files.example/root.whl")
        _, kwargs = resolver.calls[0]
        self.assertEqual(kwargs["constraints"], [constraints])
        self.assertEqual(kwargs["target"], target)
        self.assertIs(kwargs["offline"], True)

    def test_toml_selection_supports_extras_and_dependency_group_includes(self) -> None:
        payload = {
            "project": {
                "dependencies": ["base>=1"],
                "optional-dependencies": {
                    "security": ["cryptography>=42"],
                    "docs": ["mkdocs>=1"],
                },
            },
            "dependency-groups": {
                "lint": ["ruff>=0.11"],
                "test": [
                    {"include-group": "lint"},
                    "pytest>=8",
                ],
            },
        }
        self.assertEqual(
            _extract_scan_requirements_from_toml(
                payload,
                extras=["security"],
                groups=["test"],
            ),
            ["base>=1", "cryptography>=42", "ruff>=0.11", "pytest>=8"],
        )
        with self.assertRaisesRegex(ValueError, "unknown optional"):
            _extract_scan_requirements_from_toml(payload, extras=["missing"])
        with self.assertRaisesRegex(ValueError, "unknown dependency group"):
            _extract_scan_requirements_from_toml(payload, groups=["missing"])

        duplicate_extra = {
            "project": {
                "optional-dependencies": {
                    "Demo_Name": ["one"],
                    "demo-name": ["two"],
                }
            }
        }
        with self.assertRaisesRegex(ValueError, "duplicate optional"):
            _extract_scan_requirements_from_toml(duplicate_extra)

        duplicate_group = {
            "dependency-groups": {
                "Demo_Group": ["one"],
                "demo-group": ["two"],
            }
        }
        with self.assertRaisesRegex(ValueError, "duplicate dependency group"):
            _extract_scan_requirements_from_toml(duplicate_group)

        duplicate_poetry_group = {
            "dependency-groups": {"test": ["pytest"]},
            "tool": {
                "poetry": {
                    "group": {
                        "test": {"dependencies": {"coverage": "*"}},
                    }
                }
            },
        }
        with self.assertRaisesRegex(ValueError, "defined more than once"):
            _extract_scan_requirements_from_toml(duplicate_poetry_group)

    def test_dependency_group_validation_rejects_invalid_and_cyclic_groups(self) -> None:
        cases = [
            (
                {"dependency-groups": {"bad": "pytest"}},
                "must be a list",
            ),
            (
                {"dependency-groups": {"bad": ["not valid ???"]}},
                "invalid requirement",
            ),
            (
                {"dependency-groups": {"bad": [{"include-group": 3}]}},
                "must name a group",
            ),
            (
                {"dependency-groups": {"bad": [{"unexpected": "value"}]}},
                "invalid dependency group item",
            ),
            (
                {
                    "dependency-groups": {
                        "one": [{"include-group": "two"}],
                        "two": [{"include-group": "one"}],
                    }
                },
                "cyclic dependency group",
            ),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _extract_scan_requirements_from_toml(payload)

    def test_scan_targets_preserve_editable_and_vcs_source_metadata(self) -> None:
        targets = _scan_targets_from_resolution(
            Resolution(
                distributions=[
                    ResolvedDistribution(
                        "demo",
                        "1.2.3",
                        requested=True,
                        source_url="git+https://example.com/demo.git",
                        is_direct=True,
                        editable=True,
                        vcs="git",
                        vcs_commit="abc",
                    )
                ]
            )
        )
        target = targets[0]
        self.assertTrue(target.requested)
        self.assertTrue(target.editable)
        self.assertEqual(target.vcs, "git")
        self.assertEqual(target.vcs_commit, "abc")
        with self.assertRaisesRegex(ResolutionError, "no distributions"):
            _scan_targets_from_resolution(Resolution())

    def test_toml_scan_delegates_selected_requirements_to_resolver(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls = []

            def resolve_requirements(self, requirements, **kwargs):
                self.calls.append((requirements, kwargs))
                return Resolution(
                    distributions=[ResolvedDistribution("demo", "2.0")]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir) / "pyproject.toml"
            constraint = Path(tmpdir) / "constraints.txt"
            project.write_text(
                "\n".join(
                    [
                        "[project]",
                        "dependencies = ['demo>=1']",
                        "[project.optional-dependencies]",
                        "security = ['cryptography>=42']",
                    ]
                ),
                encoding="utf-8",
            )
            constraint.write_text("demo<3\n", encoding="utf-8")
            resolver = FakeResolver()
            targets = _load_scan_targets_from_toml(
                project,
                object(),  # type: ignore[arg-type]
                resolver=resolver,  # type: ignore[arg-type]
                constraints=[constraint],
                extras=["security"],
                target_environment=TargetEnvironment(python_version="3.12"),
                offline=True,
            )

        self.assertEqual([(item.project, item.version) for item in targets], [("demo", "2.0")])
        requirements, kwargs = resolver.calls[0]
        self.assertEqual(requirements, ["demo>=1", "cryptography>=42"])
        self.assertEqual(kwargs["constraints"], [constraint])
        self.assertIs(kwargs["offline"], True)

    def test_environment_command_audits_discovered_exact_versions(self) -> None:
        resolution = Resolution(
            distributions=[
                ResolvedDistribution("alpha", "1.0", requested=True),
                ResolvedDistribution("beta", "2.0", requested=True),
            ]
        )
        reports = {
            "alpha": make_report(),
            "beta": make_report(),
        }
        reports["alpha"].project = "alpha"
        reports["alpha"].version = "1.0"
        reports["beta"].project = "beta"
        reports["beta"].version = "2.0"
        inspected: list[tuple[str, str | None, bool]] = []

        def fake_inspect(project: str, **kwargs):
            inspected.append(
                (
                    project,
                    kwargs["version"],
                    kwargs["complete_locked_versions"],
                )
            )
            return reports[project]

        stdout = io.StringIO()
        with (
            patch(
                "trustcheck.cli.discover_installed_distributions",
                return_value=resolution,
            ),
            patch("trustcheck.cli.inspect_package", side_effect=fake_inspect),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(["environment", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(
            inspected,
            [("alpha", "1.0", True), ("beta", "2.0", True)],
        )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["resolved"]), 2)

    def test_environment_command_reports_discovery_errors(self) -> None:
        stderr = io.StringIO()
        with (
            patch(
                "trustcheck.cli.discover_installed_distributions",
                side_effect=ResolutionError("site-packages path not found"),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(stderr),
        ):
            exit_code = main(["environment", "--path", "missing"])
        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("site-packages path not found", stderr.getvalue())

    def test_environment_command_records_invalid_package_responses(self) -> None:
        resolution = Resolution(
            distributions=[ResolvedDistribution("broken", "1.0", requested=True)]
        )
        stdout = io.StringIO()
        with (
            patch(
                "trustcheck.cli.discover_installed_distributions",
                return_value=resolution,
            ),
            patch(
                "trustcheck.cli.inspect_package",
                side_effect=ValueError("invalid metadata"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(["environment", "--format", "json"])
        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        payload = json.loads(stdout.getvalue())
        self.assertIn("invalid metadata", payload["failures"][0]["message"])

    def test_merge_exit_codes_prefers_more_severe_outcomes(self) -> None:
        self.assertEqual(_merge_exit_codes(EXIT_OK, EXIT_POLICY_FAILURE), EXIT_POLICY_FAILURE)
        self.assertEqual(
            _merge_exit_codes(EXIT_POLICY_FAILURE, EXIT_UPSTREAM_FAILURE),
            EXIT_UPSTREAM_FAILURE,
        )
        self.assertEqual(
            _merge_exit_codes(EXIT_UPSTREAM_FAILURE, EXIT_DATA_ERROR),
            EXIT_DATA_ERROR,
        )
        self.assertIn(
            "dependency resolver",
            _format_upstream_error(
                PypiClientError(
                    "failed",
                    code="dependency",
                    subcode="resolution_failed",
                )
            ),
        )

    def test_clean_requirement_line_strips_comments(self) -> None:
        self.assertEqual(_clean_requirement_line("requests>=2 # comment"), "requests>=2")
        self.assertEqual(_clean_requirement_line("   # comment"), "")
        self.assertEqual(_clean_requirement_line("urllib3"), "urllib3")

    def test_collect_requirement_strings_filters_non_strings(self) -> None:
        self.assertEqual(_collect_requirement_strings(["requests", "", 3]), ["requests"])
        self.assertEqual(_collect_requirement_strings("requests"), [])

    def test_extract_scan_requirements_from_toml_handles_project_and_poetry(self) -> None:
        payload = {
            "project": {
                "dependencies": ["requests>=2.31"],
                "optional-dependencies": {"dev": ["pytest>=8"]},
            },
            "tool": {
                "poetry": {
                    "dependencies": {"python": "^3.11", "urllib3": "*"},
                    "group": {"lint": {"dependencies": {"ruff": "^0.8"}}},
                }
            },
        }

        self.assertEqual(
            _extract_scan_requirements_from_toml(payload),
            ["requests>=2.31", "pytest>=8", "urllib3", "ruff>=0.8,<0.9"],
        )

    def test_poetry_dependency_translation_helpers(self) -> None:
        self.assertEqual(_poetry_dependency_to_requirement("urllib3", "*"), "urllib3")
        self.assertEqual(
            _poetry_dependency_to_requirement("requests", "^2.31"),
            "requests>=2.31,<3",
        )
        self.assertEqual(
            _poetry_dependency_to_requirement("pytest", {"version": "~8.1"}),
            "pytest>=8.1,<8.2",
        )
        self.assertEqual(
            _poetry_dependency_to_requirement(
                "demo",
                {
                    "git": "https://github.com/example/demo.git",
                    "rev": "abc123",
                    "extras": ["speed"],
                    "markers": "python_version >= '3.11'",
                },
            ),
            "demo[speed] @ git+https://github.com/example/demo.git@abc123; "
            "python_version >= '3.11'",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(
                _poetry_dependency_to_requirement(
                    "local-demo",
                    {"path": "../demo", "markers": "sys_platform == 'linux'"},
                    base_path=Path(tmpdir),
                ),
                "local-demo @ "
                f"{(Path(tmpdir) / '..' / 'demo').resolve().as_uri()}; "
                "sys_platform == 'linux'",
            )
        self.assertEqual(
            _poetry_dependency_to_requirement(
                "archive",
                {"url": "https://example.com/archive.whl"},
            ),
            "archive @ https://example.com/archive.whl",
        )
        self.assertIsNone(_poetry_dependency_to_requirement("demo", ["bad"]))  # type: ignore[list-item]
        self.assertEqual(_translate_poetry_version_specifier("^2.1"), ">=2.1,<3")
        self.assertEqual(_translate_poetry_version_specifier("~1.4"), ">=1.4,<1.5")
        self.assertIsNone(_translate_poetry_version_specifier(">=2"))
        self.assertEqual(_expand_poetry_caret_specifier("0.2.3"), ">=0.2.3,<0.3")
        self.assertEqual(_expand_poetry_tilde_specifier("1"), ">=1,<2")
        self.assertEqual(_parse_version_release_parts("bad"), (0,))

    def test_additional_toml_and_requirement_edge_cases(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertTrue(
                _resolve_bool(
                    False,
                    env_name="TRUSTCHECK_UNUSED",
                    config_value="yes",
                    default=False,
                )
            )
        self.assertEqual(_merge_exit_codes(EXIT_OK, EXIT_OK), EXIT_OK)
        self.assertEqual(
            _extract_scan_requirements_from_toml(
                {
                    "project": {
                        "dependencies": ["demo>=1"],
                        "optional-dependencies": {"dev": ["demo>=1"]},
                    },
                    "tool": {
                        "poetry": {
                            "dependencies": {"python": "^3.11", "plain": ">=1"},
                            "group": {
                                "ignored": "not-a-table",
                                "empty": {"dependencies": None},
                            },
                        }
                    },
                }
            ),
            ["demo>=1", "plain>=1"],
        )
        self.assertEqual(_extract_poetry_dependency_requirements("bad"), [])
        self.assertEqual(_poetry_dependency_to_requirement("plain", ">=1"), "plain>=1")
        self.assertEqual(_poetry_dependency_to_requirement("plain", {}), "plain")
        self.assertEqual(
            _poetry_dependency_to_requirement("plain", {"version": ">=2"}),
            "plain>=2",
        )
        self.assertEqual(_expand_poetry_caret_specifier("0.0.3"), ">=0.0.3,<0.0.4")
        self.assertEqual(_expand_poetry_caret_specifier("0"), ">=0,<1")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "requirements.txt"
            path.write_text("demo==1.0 \\", encoding="utf-8")
            self.assertEqual(_read_requirements_file(path), ["demo==1.0"])

            with self.assertRaisesRegex(ValueError, "no supported package requirements"):
                _build_scan_targets(
                    ["skipme; python_version < '3.0'"],
                    object(),  # type: ignore[arg-type]
                    source_path=path,
                )
            self.assertEqual(
                _locked_versions_from_requirements(
                    ["bad ???", "skipme==1; python_version < '3.0'"],
                    source_path=path,
                ),
                {},
            )
            with self.assertRaisesRegex(ValueError, "multiple active locked versions"):
                _locked_versions_from_requirements(
                    ["demo==1", "demo==2"],
                    source_path=path,
                )

            toml_path = Path(tmpdir) / "pyproject.toml"
            toml_path.write_text("[project]\n", encoding="utf-8")
            with patch("trustcheck.cli.tomllib.load", return_value=[]):
                with self.assertRaisesRegex(ValueError, "top-level table"):
                    _load_scan_targets_from_toml(
                        toml_path,
                        object(),  # type: ignore[arg-type]
                    )

        class InvalidVersionClient:
            def get_project(self, project: str) -> dict[str, object]:
                del project
                return {
                    "info": {"version": "not-a-version"},
                    "releases": {"invalid": [], "1.0": []},
                }

        version, message, exit_code = _resolve_scan_target_version_for_scan(
            Requirement("demo>=2"),
            InvalidVersionClient(),  # type: ignore[arg-type]
        )
        self.assertIsNone(version)
        self.assertIn("unable to resolve scan requirement", message or "")
        self.assertEqual(exit_code, EXIT_DATA_ERROR)

    def test_verbose_report_renders_all_optional_findings(self) -> None:
        report = make_report()
        report.summary = None
        report.dependency_summary.high_risk_projects = ["blocked"]
        report.dependency_summary.metadata_only_projects = ["metadata"]
        report.dependency_summary.verified_projects = ["clean"]
        report.dependencies[0].error = "dependency lookup failed"
        report.files[0].artifact = ArtifactInspection(
            inspected=True,
            kind="wheel",
            archive_valid=False,
            file_count=12,
            total_uncompressed_size=4096,
            record_valid=False,
            record_errors=["hash mismatch"],
            console_scripts=["demo=demo:main"],
            suspicious_entry_points=["setup=demo:setup"],
            native_files=["demo.pyd"],
            unexpected_top_level_files=["install.sh"],
            suspicious_files=["setup.py"],
            oversized_files=["large.bin"],
            unusual_files=["payload.exe"],
            metadata_name="gridoptim",
            metadata_version="2.2.0",
            wheel_version="1.0",
            wheel_root_is_purelib=False,
            wheel_tags=["py3-none-any"],
            metadata_mismatches=["Requires-Dist differs"],
            error="archive warning",
        )
        report.diagnostics.request_failures = [
            RequestFailureDiagnostic(
                url="https://pypi.org/example",
                attempt=1,
                code="upstream",
                subcode="network",
                message="failed",
                transient=False,
                status_code=None,
            )
        ]
        report.policy.violations = [
            PolicyViolation(
                code="manual_review",
                severity="medium",
                message="Review required.",
            )
        ]
        rendered = _render_text_report(report, verbose=True)

        for expected in (
            "high-risk dependencies: blocked",
            "metadata-only dependencies: metadata",
            "verified dependencies: clean",
            "note: dependency lookup failed",
            "sha256: abc123",
            "observed sha256: abc123",
            "wheel RECORD: invalid",
            "wheel metadata:",
            "console scripts:",
            "native files:",
            "unexpected top-level files:",
            "suspicious entry points:",
            "suspicious files:",
            "oversized files:",
            "unusual files:",
            "RECORD errors:",
            "metadata mismatches:",
            "error: archive warning",
            "status=-",
            "manual_review",
        ):
            self.assertIn(expected, rendered)

        unverified = FileProvenance(
            filename="gridoptim-2.2.0.tar.gz",
            url="https://files.pythonhosted.org/gridoptim.tar.gz",
            sha256=None,
            has_provenance=False,
        )
        report.files.append(unverified)
        self.assertIn("mixed evidence", _evidence_summary(report))
        self.assertIn(
            "No known vulnerability records",
            _render_cve_report(
                TrustReport(
                    project="demo",
                    version="1.0",
                    summary=None,
                    package_url="https://pypi.org/project/demo/1.0/",
                )
            ),
        )
        self.assertNotIn(
            "scan failures:",
            _render_scan_text(
                "requirements.txt",
                [],
                failures=[],
                verbose=False,
                vulnerability_only=False,
            ),
        )

    def test_resolve_scan_target_version_variants(self) -> None:
        class FakeClient:
            def get_project(self, project: str) -> dict[str, object]:
                if project == "requests":
                    return {
                        "info": {"version": "2.31.0"},
                        "releases": {"2.30.0": [], "2.31.0": []},
                    }
                if project == "urllib3":
                    return {"info": {"version": "2.2.0"}, "releases": {"broken": []}}
                return {"info": {"version": "1.0.0"}, "releases": {}}

        class NoNetworkClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise AssertionError(f"unexpected project lookup for {project}")

        self.assertIsNone(_resolve_scan_target_version(Requirement("idna"), FakeClient()))
        self.assertEqual(
            _resolve_scan_target_version(Requirement("idna==3.7"), NoNetworkClient()),
            "3.7",
        )
        self.assertEqual(
            _resolve_scan_target_version(Requirement("idna===local-version"), NoNetworkClient()),
            "local-version",
        )
        self.assertEqual(
            _resolve_scan_target_version(Requirement("requests>=2.30"), FakeClient()),
            "2.31.0",
        )
        self.assertEqual(
            _resolve_scan_target_version(Requirement("urllib3>=2.0"), FakeClient()),
            "2.2.0",
        )
        with self.assertRaisesRegex(ValueError, "compatible version"):
            _resolve_scan_target_version(Requirement("certifi>=9"), FakeClient())

    def test_load_scan_targets_errors_for_missing_invalid_and_empty_files(self) -> None:
        missing = Path("tests/_tmp/does-not-exist.txt")
        with self.assertRaisesRegex(ValueError, "scan file not found"):
            _load_scan_targets(str(missing), object())  # type: ignore[arg-type]

        invalid_file = Path("tests/_tmp/invalid-scan.txt")
        invalid_file.write_text("not valid ===\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid requirement"):
            _load_scan_targets(str(invalid_file), object())  # type: ignore[arg-type]

        empty_file = Path("tests/_tmp/empty-scan.txt")
        empty_file.write_text("# comment only\n--index-url https://example.com\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no supported package requirements"):
            _load_scan_targets(str(empty_file), object())  # type: ignore[arg-type]

    def test_load_scan_targets_records_version_resolution_failures_and_continues(self) -> None:
        class FakeClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise PypiClientError(
                    f"offline cache miss for {project}",
                    subcode="offline_cache_miss",
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_file = Path(tmpdir) / "resolution-failure-scan.txt"
            scan_file.write_text("broken>=99\nurllib3\n", encoding="utf-8")
            targets = _load_scan_targets(str(scan_file), FakeClient())  # type: ignore[arg-type]

        self.assertEqual([target.project for target in targets], ["broken", "urllib3"])
        self.assertIsNone(targets[0].version)
        self.assertEqual(targets[0].failure_exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertIn("unable to inspect package from PyPI", targets[0].failure_message or "")
        self.assertIsNone(targets[1].failure_message)

    def test_load_scan_targets_supports_hashed_locked_requirements(self) -> None:
        class NoNetworkClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise AssertionError(f"unexpected project lookup for {project}")

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_file = Path(tmpdir) / "requirements.txt"
            scan_file.write_text(
                "\n".join(
                    [
                        "--require-hashes",
                        "direct-dep==1.4.0 \\",
                        "    --hash=sha256:aaa \\",
                        "    --hash=sha256:bbb",
                        "transitive-dep==2.5.0 --hash=sha256:ccc",
                    ]
                ),
                encoding="utf-8",
            )
            targets = _load_scan_targets(str(scan_file), NoNetworkClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("direct-dep", "1.4.0"), ("transitive-dep", "2.5.0")],
        )
        self.assertEqual(
            targets[0].locked_versions,
            {"direct-dep": "1.4.0", "transitive-dep": "2.5.0"},
        )
        self.assertIs(targets[0].locked_versions, targets[1].locked_versions)
        self.assertEqual(targets[0].source_line, 2)
        self.assertEqual(targets[1].source_line, 5)
        self.assertTrue(
            (targets[0].source_file or "").endswith("requirements.txt")
        )

    def test_load_scan_targets_supports_uv_lock(self) -> None:
        class NoNetworkClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise AssertionError(f"unexpected project lookup for {project}")

        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "uv.lock"
            lock_file.write_text(
                "\n".join(
                    [
                        "version = 1",
                        "",
                        "[[package]]",
                        'name = "local-project"',
                        'version = "0.1.0"',
                        'source = { editable = "." }',
                        "",
                        "[[package]]",
                        'name = "direct-dep"',
                        'version = "1.4.0"',
                        'source = { registry = "https://pypi.org/simple" }',
                        "",
                        "[[package]]",
                        'name = "transitive-dep"',
                        'version = "2.5.0"',
                        'source = { registry = "https://pypi.org/simple" }',
                        "resolution-markers = [\"python_version >= '3.11'\"]",
                        "",
                        "[[package]]",
                        'name = "inactive-dep"',
                        'version = "9.0.0"',
                        'source = { registry = "https://pypi.org/simple" }',
                        "resolution-markers = [\"python_version < '3.0'\"]",
                    ]
                ),
                encoding="utf-8",
            )
            targets = _load_scan_targets(str(lock_file), NoNetworkClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("direct-dep", "1.4.0"), ("transitive-dep", "2.5.0")],
        )
        self.assertEqual(
            targets[0].locked_versions,
            {"direct-dep": "1.4.0", "transitive-dep": "2.5.0"},
        )

    def test_load_scan_targets_supports_poetry_lock(self) -> None:
        class NoNetworkClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise AssertionError(f"unexpected project lookup for {project}")

        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "poetry.lock"
            lock_file.write_text(
                "\n".join(
                    [
                        "[[package]]",
                        'name = "direct-dep"',
                        'version = "1.4.0"',
                        "markers = { main = \"python_version >= '3.11'\" }",
                        "",
                        "[[package]]",
                        'name = "transitive-dep"',
                        'version = "2.5.0"',
                        "",
                        "[[package]]",
                        'name = "git-dep"',
                        'version = "3.0.0"',
                        'source = { type = "git", url = "https://example.com/repo.git" }',
                    ]
                ),
                encoding="utf-8",
            )
            targets = _load_scan_targets(str(lock_file), NoNetworkClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("direct-dep", "1.4.0"), ("transitive-dep", "2.5.0")],
        )

    def test_load_scan_targets_supports_pdm_lock(self) -> None:
        class NoNetworkClient:
            def get_project(self, project: str) -> dict[str, object]:
                raise AssertionError(f"unexpected project lookup for {project}")

        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "pdm.lock"
            lock_file.write_text(
                "\n".join(
                    [
                        "[metadata]",
                        'groups = ["default"]',
                        "",
                        "[[package]]",
                        'name = "direct-dep"',
                        'version = "1.4.0"',
                        "",
                        "[[package]]",
                        'name = "transitive-dep"',
                        'version = "2.5.0"',
                        "",
                        "[[package]]",
                        'name = "local-dep"',
                        'version = "3.0.0"',
                        'path = "../local-dep"',
                    ]
                ),
                encoding="utf-8",
            )
            targets = _load_scan_targets(str(lock_file), NoNetworkClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("direct-dep", "1.4.0"), ("transitive-dep", "2.5.0")],
        )

    def test_load_scan_targets_supports_pylock_and_preserves_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "pylock.toml"
            lock_file.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "locker"',
                        "[[packages]]",
                        'name = "demo"',
                        'version = "1.0"',
                        'index = "https://user:secret@private.example/simple"',
                        "[[packages.wheels]]",
                        'name = "demo-1.0-py3-none-any.whl"',
                        'url = "https://private.example/files/demo.whl"',
                        f'hashes = {{sha256 = "{"a" * 64}"}}',
                    ]
                ),
                encoding="utf-8",
            )
            targets = _load_scan_targets(
                str(lock_file),
                object(),  # type: ignore[arg-type]
            )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].project, "demo")
        self.assertEqual(targets[0].artifacts[0].hashes, (("sha256", "a" * 64),))
        self.assertIn("secret", targets[0].index_url or "")
        rendered = _render_scan_json(
            str(lock_file),
            [],
            failures=[],
            vulnerability_only=False,
            targets=targets,
        )
        resolved = rendered["resolved"]
        assert isinstance(resolved, list)
        self.assertNotIn("secret", json.dumps(resolved))
        self.assertIn("sha256", json.dumps(resolved))
        self.assertIn("source_file", json.dumps(resolved))
        self.assertIn("source_line", json.dumps(resolved))

    def test_load_scan_targets_supports_pipfile_lock(self) -> None:
        payload = {
            "_meta": {
                "sources": [
                    {
                        "name": "private",
                        "url": "https://private.example/simple",
                    }
                ]
            },
            "default": {
                "demo": {
                    "version": "==1.0",
                    "hashes": [f"sha256:{'a' * 64}"],
                    "index": "private",
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = Path(tmpdir) / "Pipfile.lock"
            lock_file.write_text(json.dumps(payload), encoding="utf-8")
            targets = _load_scan_targets(
                str(lock_file),
                object(),  # type: ignore[arg-type]
            )

        self.assertEqual(targets[0].version, "1.0")
        self.assertEqual(targets[0].index_url, "https://private.example/simple")
        self.assertEqual(targets[0].artifacts[0].kind, "lock-hash")

    def test_pip_tools_hashes_override_selected_report_hash_only(self) -> None:
        class FakeResolver:
            def resolve_requirements_file(self, path, **kwargs):
                del path, kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(
                            name="demo",
                            version="1.0",
                            requested=True,
                            artifacts=(
                                ArtifactReference(
                                    filename="demo.whl",
                                    url="https://example.com/demo.whl",
                                    hashes=(("sha256", "a" * 64),),
                                ),
                            ),
                        )
                    ]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            requirements = Path(tmpdir) / "requirements.txt"
            requirements.write_text(
                "demo==1.0 \\\n"
                f"  --hash=sha256:{'a' * 64} \\\n"
                f"  --hash=sha256:{'b' * 64}\n",
                encoding="utf-8",
            )
            targets = _load_scan_targets(
                str(requirements),
                object(),  # type: ignore[arg-type]
                resolver=FakeResolver(),  # type: ignore[arg-type]
            )

        self.assertEqual(len(targets[0].artifacts), 2)
        self.assertEqual(
            {artifact.hashes[0][1] for artifact in targets[0].artifacts},
            {"a" * 64, "b" * 64},
        )

    def test_lockfile_loader_rejects_invalid_and_ambiguous_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_file = Path(tmpdir) / "uv.lock"
            invalid_file.write_text("[[package]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid TOML lockfile"):
                load_lockfile(invalid_file)

            missing_packages = Path(tmpdir) / "poetry.lock"
            missing_packages.write_text("[metadata]\nlock-version = '2.0'\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no supported locked packages"):
                load_lockfile(missing_packages)

            ambiguous_file = Path(tmpdir) / "pdm.lock"
            ambiguous_file.write_text(
                "\n".join(
                    [
                        "[[package]]",
                        'name = "demo"',
                        'version = "1.0.0"',
                        "",
                        "[[package]]",
                        'name = "demo"',
                        'version = "2.0.0"',
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "multiple active locked versions"):
                load_lockfile(ambiguous_file)

    def test_load_scan_targets_from_toml_errors_for_bad_inputs(self) -> None:
        bad_toml = Path("tests/_tmp/bad-scan.toml")
        bad_toml.write_text("[project\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid TOML"):
            _load_scan_targets_from_toml(bad_toml, object())  # type: ignore[arg-type]

        unsupported_toml = Path("tests/_tmp/empty-scan.toml")
        unsupported_toml.write_text("[project]\nname='demo'\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no supported package requirements"):
            _load_scan_targets_from_toml(unsupported_toml, object())  # type: ignore[arg-type]

    def test_render_scan_helpers_and_debug_hook(self) -> None:
        report = make_report()
        report.vulnerabilities = [VulnerabilityRecord(id="PYSEC-1", summary="Example advisory")]
        text = _render_scan_text(
            "requirements.txt",
            [report],
            failures=[{"requirement": "broken", "message": "boom"}],
            verbose=False,
            vulnerability_only=True,
        )
        self.assertIn("trustcheck scan results for requirements.txt", text)
        self.assertIn("known vulnerabilities for gridoptim 2.2.0", text)
        self.assertIn("scan failures:", text)

        payload = _render_scan_json(
            "requirements.txt",
            [report],
            failures=[{"requirement": "broken", "message": "boom"}],
            vulnerability_only=False,
        )
        self.assertEqual(payload["file"], "requirements.txt")
        self.assertEqual(len(payload["reports"]), 1)
        self.assertEqual(payload["failures"][0]["requirement"], "broken")

        self.assertIsNone(_build_debug_request_hook(enabled=False, log_format="text"))
        stderr = io.StringIO()
        hook = _build_debug_request_hook(enabled=True, log_format="text")
        assert hook is not None
        with redirect_stderr(stderr):
            hook("request", {"url": "https://pypi.org"})
        self.assertIn("[debug] event=request url=https://pypi.org", stderr.getvalue())

    def test_project_info_payload_normalizes_project_urls(self) -> None:
        payload = ProjectInfoPayload(project_urls=["bad"]).model_dump()
        self.assertEqual(payload["project_urls"], {})
        payload = ProjectInfoPayload(project_urls={"Repo": 123, None: "x"}).model_dump()
        self.assertEqual(payload["project_urls"], {"Repo": "123"})

    def test_cli_success_text_output(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())
        self.assertIn("summary:", stdout.getvalue())
        self.assertIn("recommendation: verified", stdout.getvalue())
        self.assertIn("why this result: cryptographic verification succeeded", stdout.getvalue())
        self.assertIn("verification: 1/1 artifact(s) verified (all-verified)", stdout.getvalue())
        self.assertIn("publisher trust: strong", stdout.getvalue())
        self.assertIn("dependencies:", stdout.getvalue())
        self.assertIn("highest_risk=review-required", stdout.getvalue())
        self.assertIn("review-required dependencies: depalpha", stdout.getvalue())
        self.assertIn(
            "diagnostics: requests=0 retries=0 failures=0 cache_hits=0",
            stdout.getvalue(),
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_text_output_emits_progress_to_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            progress_callback = kwargs["progress_callback"]
            progress_callback("gridoptim-2.2.0-py3-none-any.whl", 1, 2)
            progress_callback("gridoptim-2.2.0.tar.gz", 2, 2)
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn(
            "[progress] verifying artifact 1/2: gridoptim-2.2.0-py3-none-any.whl",
            stderr.getvalue(),
        )
        self.assertIn(
            "[progress] verifying artifact 2/2: gridoptim-2.2.0.tar.gz",
            stderr.getvalue(),
        )
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())

    def test_cli_text_output_emits_dependency_progress_to_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            dependency_progress_callback = kwargs["dependency_progress_callback"]
            dependency_progress_callback("depalpha", 1, 0, False)
            dependency_progress_callback("depalpha", 1, 100, True)
            dependency_progress_callback("depbeta", 2, 0, False)
            dependency_progress_callback("depbeta", 2, 100, True)
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--with-deps"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn(
            "\r[progress] inspecting dependency depth=1: depalpha (0%)",
            stderr.getvalue(),
        )
        self.assertIn(
            "[progress] inspecting dependency depth=1: depalpha (100%)\n",
            stderr.getvalue(),
        )
        self.assertIn(
            "\r[progress] inspecting dependency depth=2: depbeta (0%)",
            stderr.getvalue(),
        )
        self.assertIn(
            "[progress] inspecting dependency depth=2: depbeta (100%)\n",
            stderr.getvalue(),
        )
        self.assertIn("trustcheck report for gridoptim 2.2.0", stdout.getvalue())

    def test_cli_success_json_output_contract(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--format", "json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(sorted(payload.keys()), ["report", "schema_version"])
        self.assertEqual(payload["schema_version"], JSON_SCHEMA_VERSION)
        report = payload["report"]
        self.assertEqual(
            sorted(report.keys()),
            [
                "coverage",
                "declared_dependencies",
                "declared_repository_urls",
                "dependencies",
                "dependency_summary",
                "diagnostics",
                "expected_repository",
                "files",
                "malicious_package",
                "ownership",
                "package_url",
                "policy",
                "project",
                "provenance_consistency",
                "publisher_trust",
                "recommendation",
                "release_drift",
                "remediation",
                "repository_urls",
                "risk_flags",
                "summary",
                "version",
                "vulnerabilities",
            ],
        )
        self.assertEqual(report["project"], "gridoptim")
        self.assertEqual(
            report["declared_repository_urls"],
            ["https://github.com/Halfblood-Prince/gridoptim"],
        )
        self.assertEqual(report["files"][0]["verified"], True)
        self.assertEqual(report["files"][0]["observed_sha256"], "abc123")
        self.assertEqual(report["coverage"]["status"], "all-verified")
        self.assertEqual(report["publisher_trust"]["depth_label"], "strong")
        self.assertEqual(report["policy"]["profile"], "default")
        self.assertEqual(report["policy"]["passed"], True)
        self.assertEqual(report["diagnostics"]["request_count"], 0)

    def test_cli_json_output_does_not_emit_progress(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertIsNone(kwargs["progress_callback"])
            self.assertIsNone(kwargs["dependency_progress_callback"])
            self.assertFalse(kwargs["include_vulnerabilities"])
            self.assertFalse(kwargs["include_osv"])
            self.assertIsNone(kwargs["vulnerability_client"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["report"]["project"], "gridoptim")

    def test_cli_scan_output_only_shows_vulnerabilities(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="Example advisory",
                aliases=["CVE-2026-0001"],
                source="PyPI",
                severity="HIGH",
                fixed_in=["2.2.1"],
                link="https://example.com/advisory",
            )
        ]

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["include_vulnerabilities"])
            self.assertTrue(kwargs["vulnerability_only"])
            return report

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["scan", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("known vulnerabilities for gridoptim 2.2.0", stdout.getvalue())
        self.assertIn("PYSEC-2026-1: Example advisory", stdout.getvalue())
        self.assertIn("aliases: CVE-2026-0001", stdout.getvalue())
        self.assertIn("source: PyPI", stdout.getvalue())
        self.assertIn("severity: HIGH", stdout.getvalue())
        self.assertIn("fixed in: 2.2.1", stdout.getvalue())
        self.assertIn("link: https://example.com/advisory", stdout.getvalue())
        self.assertNotIn("summary:", stdout.getvalue())
        self.assertNotIn("risk flags:", stdout.getvalue())

    def test_cli_scan_output_handles_empty_vulnerability_list(self) -> None:
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["scan", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn(
            "No known vulnerability records reported by configured sources.",
            stdout.getvalue(),
        )

    def test_cli_scan_json_output_is_minimal(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="Example advisory",
                aliases=["CVE-2026-0001"],
                source="PyPI",
                severity="HIGH",
                fixed_in=["2.2.1"],
                link="https://example.com/advisory",
            )
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["scan", "gridoptim", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            sorted(payload.keys()),
            ["package_url", "project", "version", "vulnerabilities"],
        )
        self.assertEqual(payload["project"], "gridoptim")
        self.assertEqual(payload["vulnerabilities"][0]["id"], "PYSEC-2026-1")
        self.assertEqual(payload["vulnerabilities"][0]["severity"], "HIGH")

    def test_cli_with_osv_enables_external_advisory_query(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["include_osv"])
            self.assertTrue(kwargs["include_vulnerabilities"])
            self.assertTrue(kwargs["vulnerability_only"])
            self.assertIsNotNone(kwargs["vulnerability_client"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["scan", "gridoptim", "--with-osv"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_file_scan_respects_vulnerability_policy_failure(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(id="PYSEC-2026-1", summary="Example advisory")
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "scan",
                        "gridoptim",
                        "--fail-on-vulnerability",
                        "any",
                    ]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("PYSEC-2026-1: Example advisory", stdout.getvalue())

    def test_cli_scan_runs_inspect_for_each_target(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        targets = [
            ScanTarget(requirement="gridoptim==2.2.0", project="gridoptim", version="2.2.0"),
            ScanTarget(requirement="depalpha", project="depalpha", version=None),
        ]
        reports = {
            "gridoptim": make_report(),
            "depalpha": TrustReport(
                project="depalpha",
                version="1.4.0",
                summary="depalpha package",
                package_url="https://pypi.org/project/depalpha/1.4.0/",
                recommendation="metadata-only",
                diagnostics=ReportDiagnostics(),
            ),
        }

        def fake_inspect_package(project: str, **kwargs):
            self.assertIn(project, reports)
            self.assertFalse(kwargs["include_dependencies"])
            self.assertFalse(kwargs["include_transitive_dependencies"])
            self.assertTrue(kwargs["include_vulnerabilities"])
            self.assertTrue(kwargs["vulnerability_only"])
            return reports[project]

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = main(["scan", "-f", "requirements.txt"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("trustcheck scan results for requirements.txt", stdout.getvalue())
        self.assertIn("successful: 2", stdout.getvalue())
        self.assertIn("known vulnerabilities for gridoptim 2.2.0", stdout.getvalue())
        self.assertIn("known vulnerabilities for depalpha 1.4.0", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_scan_json_output_contains_reports(self) -> None:
        stdout = io.StringIO()
        targets = [ScanTarget(requirement="gridoptim", project="gridoptim", version=None)]

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", return_value=make_report()):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(["scan", "-f", "requirements.txt", "--format", "json"])

        self.assertEqual(exit_code, EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["file"], "requirements.txt")
        self.assertEqual(payload["schema_version"], JSON_SCHEMA_VERSION)
        self.assertEqual(len(payload["reports"]), 1)
        self.assertEqual(payload["reports"][0]["project"], "gridoptim")
        self.assertEqual(payload["failures"], [])

    def test_cli_inspect_file_passes_locked_versions_to_dependency_inspection(self) -> None:
        stdout = io.StringIO()
        locked_versions = {"depalpha": "1.4.0", "depbeta": "2.5.0"}
        targets = [
            ScanTarget(
                requirement="depalpha==1.4.0",
                project="depalpha",
                version="1.4.0",
                locked_versions=locked_versions,
            )
        ]

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["include_transitive_dependencies"])
            self.assertFalse(kwargs["include_vulnerabilities"])
            self.assertFalse(kwargs["vulnerability_only"])
            self.assertEqual(kwargs["locked_versions"], locked_versions)
            return make_report()

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(["inspect", "-f", "poetry.lock", "--with-transitive-deps"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_scan_output_shows_vulnerability_intelligence(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="GHSA-aaaa-bbbb-cccc",
                summary="Example advisory",
                source="OSV",
                severity="CRITICAL",
                fixed_in=["2.2.1"],
                link="https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            )
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["scan", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("source: OSV", stdout.getvalue())
        self.assertIn("severity: CRITICAL", stdout.getvalue())
        self.assertIn("fixed in: 2.2.1", stdout.getvalue())
        self.assertIn("link: https://github.com/advisories/GHSA-aaaa-bbbb-cccc", stdout.getvalue())

    def test_scan_project_vulnerabilities_resolves_private_index_root(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], dict[str, object]]] = []

            def resolve_requirements(self, requirements, **kwargs):
                self.calls.append((list(requirements), kwargs))
                return Resolution(
                    distributions=[
                        ResolvedDistribution(
                            name="GridOptim",
                            version="2.3.0",
                            artifacts=(
                                ArtifactReference(
                                    filename="gridoptim-2.3.0.whl",
                                    url="https://private.example/gridoptim.whl",
                                ),
                            ),
                            index_url="https://private.example/simple",
                            requires_dist=("dep>=1",),
                        )
                    ],
                    dependency_confusion=(
                        DependencyConfusionFinding(
                            "gridoptim",
                            ("https://private.example/simple", "https://pypi.org/simple"),
                        ),
                    ),
                )

        args = build_parser().parse_args(
            [
                "scan",
                "gridoptim",
                "--index-url",
                "https://private.example/simple",
                "--keyring-provider",
                "disabled",
                "--python-version",
                "3.12",
            ]
        )
        client = SimpleNamespace(offline=True)
        resolver = FakeResolver()
        report = make_report()
        observed: dict[str, object] = {}

        def fake_inspect_package(project: str, **kwargs):
            observed["project"] = project
            observed.update(kwargs)
            return report

        with (
            patch("trustcheck.cli._client_for_target", return_value=client),
            patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package),
        ):
            result = _scan_project_vulnerabilities(
                "gridoptim",
                version=None,
                args=args,
                client=client,  # type: ignore[arg-type]
                vulnerability_client=None,
                policy=PolicySettings(),
                resolver=resolver,  # type: ignore[arg-type]
                plugin_manager=PluginManager(),
            )

        self.assertIs(result, report)
        self.assertEqual(resolver.calls[0][0], ["gridoptim"])
        self.assertIs(resolver.calls[0][1]["offline"], True)
        self.assertEqual(observed["project"], "gridoptim")
        self.assertEqual(observed["version"], "2.3.0")
        self.assertTrue(observed["vulnerability_only"])
        self.assertEqual(
            observed["dependency_confusion_indexes"],
            ("https://private.example/simple", "https://pypi.org/simple"),
        )

    def test_scan_project_vulnerabilities_errors_when_resolver_omits_root(self) -> None:
        class MissingRootResolver:
            def resolve_requirements(self, requirements, **kwargs):
                del requirements, kwargs
                return Resolution(
                    distributions=[ResolvedDistribution(name="other", version="1.0")]
                )

        args = build_parser().parse_args(
            [
                "scan",
                "gridoptim",
                "--index-url",
                "https://private.example/simple",
            ]
        )

        with self.assertRaisesRegex(ResolutionError, "root package"):
            _scan_project_vulnerabilities(
                "gridoptim",
                version=None,
                args=args,
                client=SimpleNamespace(offline=False),  # type: ignore[arg-type]
                vulnerability_client=None,
                policy=PolicySettings(),
                resolver=MissingRootResolver(),  # type: ignore[arg-type]
                plugin_manager=PluginManager(),
            )

    def test_post_fix_reproduction_command_uses_current_scan_file_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "requirements.txt"
            policy = Path(tmpdir) / "policy.json"
            constraint = Path(tmpdir) / "constraints.txt"
            snapshot = Path(tmpdir) / "advisories.json"
            args = SimpleNamespace(
                with_osv=True,
                osv_url=["https://osv.internal.example"],
                with_ecosystems=True,
                with_kev=True,
                with_epss=True,
                with_deps=True,
                with_transitive_deps=True,
                inspect_artifacts=True,
                extra=["security"],
                group=["test"],
                constraint=[str(constraint)],
                strict=True,
                policy="strict",
                policy_file=str(policy),
                fail_on_vulnerability="any",
                fail_on_risk_severity="high",
                require_verified_provenance="all",
                require_expected_repo_match=True,
                allow_metadata_only=False,
                trusted_publisher_organization=["github:pypa"],
                trusted_project=["internal-sdk"],
                index_url="https://private.example/simple",
                extra_index_url=["https://pypi.org/simple"],
                allow_dependency_confusion=True,
                python_version="3.12",
                platform=["manylinux_2_28_x86_64"],
                implementation="cp",
                abi=["cp312"],
                offline=True,
                advisory_snapshot=[str(snapshot)],
            )

            command = _post_fix_reproduction_command(source, args)

        self.assertEqual(command[:4], ("trustcheck", "scan", "-f", str(source)))
        self.assertIn("--with-osv", command)
        self.assertIn("--fail-on-vulnerability", command)
        self.assertIn("--python-version", command)
        for removed in (
            "--with-deps",
            "--with-transitive-deps",
            "--inspect-artifacts",
            "--fail-on-risk-severity",
            "--require-verified-provenance",
            "--require-expected-repo-match",
            "--disallow-metadata-only",
            "--trusted-publisher-organization",
            "--trusted-project",
        ):
            self.assertNotIn(removed, command)

    def test_vulnerability_client_builder_supports_all_sources_and_config(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "scan",
                "gridoptim",
                "--with-osv",
                "--osv-url",
                "https://private.example/api/",
                "--osv-url",
                "https://api.osv.dev/",
                "--osv-url",
                "",
                "--osv-url",
                "not-a-url",
                "--with-ecosystems",
                "--with-kev",
                "--with-epss",
            ]
        )
        def hook(event: str, payload: dict[str, object]) -> None:
            return None

        pypi = PypiClient(
            timeout=3.0,
            max_retries=4,
            backoff_factor=0.5,
            offline=True,
            request_hook=hook,
        )

        client = _build_vulnerability_client(
            args,
            pypi,
            config_payload={
                "advisories": {
                    "osv": True,
                    "osv_urls": ["https://config.example/osv"],
                    "ecosystems": True,
                    "kev": True,
                    "kev_url": "https://feeds.example/kev.json",
                    "epss": True,
                    "epss_url": "https://scores.example/epss",
                }
            },
        )

        self.assertIsNotNone(client)
        assert client is not None
        self.assertEqual(
            [provider.name for provider in client.providers],
            [
                "OSV",
                "OSV:private.example",
                "OSV:not-a-url",
                "OSV:config.example",
                "Ecosyste.ms",
            ],
        )
        self.assertTrue(all(
            provider.client.request_hook is None
            for provider in client.providers
        ))
        self.assertEqual(client.kev_client.url, "https://feeds.example/kev.json")
        self.assertEqual(client.epss_client.base_url, "https://scores.example/epss")
        self.assertEqual(client.kev_client.timeout, 3.0)
        self.assertTrue(client.kev_client.offline)
        self.assertIs(client.request_hook, hook)

        no_sources = parser.parse_args(["scan", "gridoptim"])
        self.assertIsNone(
            _build_vulnerability_client(
                no_sources,
                pypi,
                config_payload={},
            )
        )

    def test_vulnerability_client_builder_rejects_invalid_config(self) -> None:
        args = build_parser().parse_args(["scan", "gridoptim"])
        cases = [
            ({"advisories": []}, "must be an object"),
            ({"advisories": {"unknown": True}}, "unknown advisories"),
            ({"advisories": {"osv": "yes"}}, "advisories.osv"),
            ({"advisories": {"osv_urls": "url"}}, "list of URLs"),
            ({"advisories": {"osv_urls": [""]}}, "list of URLs"),
            (
                {"advisories": {"kev": True, "kev_url": 123}},
                "advisories.kev_url",
            ),
            (
                {"advisories": {"epss": True, "epss_url": ""}},
                "advisories.epss_url",
            ),
        ]
        for config, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _build_vulnerability_client(
                        args,
                        PypiClient(),
                        config_payload=config,
                    )

    def test_cve_renderers_include_normalized_enrichment_and_suppression(self) -> None:
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="CVE-2026-1234",
                summary="Rich advisory",
                aliases=["GHSA-demo"],
                source="PyPI, OSV",
                severity="CRITICAL",
                cvss_score=9.8,
                cvss_vector=(
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                ),
                cvss_version="3.1",
                cwes=["CWE-79"],
                fixed_in=["2.2.1"],
                link="https://example.com/CVE-2026-1234",
                withdrawn=True,
                withdrawn_at="2026-06-01T00:00:00Z",
                kev=True,
                kev_due_date="2026-06-30",
                epss_score=0.91,
                epss_percentile=0.99,
                suppression=VulnerabilitySuppression(
                    vulnerability_id="CVE-2026-1234",
                    owner="security@example.com",
                    justification="Upgrade scheduled.",
                    expires="2026-06-30",
                    status="active",
                ),
            )
        ]

        payload = _render_cve_json(report)
        rendered = _render_cve_report(report)

        vulnerability = payload["vulnerabilities"][0]
        self.assertEqual(vulnerability["cvss_score"], 9.8)
        self.assertTrue(vulnerability["kev"])
        self.assertEqual(vulnerability["suppression"]["status"], "active")
        self.assertIn("aliases: GHSA-demo", rendered)
        self.assertIn("cvss: 9.8 (CVSS:3.1/", rendered)
        self.assertIn("cwes: CWE-79", rendered)
        self.assertIn("withdrawn: 2026-06-01", rendered)
        self.assertIn("CISA KEV: yes (due 2026-06-30)", rendered)
        self.assertIn("EPSS: 0.9100 (percentile 0.9900)", rendered)
        self.assertIn("owner=security@example.com", rendered)

        report.vulnerabilities[0].cvss_vector = None
        report.vulnerabilities[0].kev_due_date = None
        report.vulnerabilities[0].epss_percentile = None
        rendered_without_optional_details = _render_cve_report(report)
        self.assertIn("cvss: 9.8", rendered_without_optional_details)
        self.assertIn("CISA KEV: yes", rendered_without_optional_details)
        self.assertIn("EPSS: 0.9100", rendered_without_optional_details)

    def test_osv_failure_names_advisory_service(self) -> None:
        error = PypiClientError(
            "OSV unavailable",
            code="advisory",
            subcode="http_transient",
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", side_effect=error):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", "gridoptim", "--with-osv"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertIn("unable to inspect package from advisory service", stderr.getvalue())

    def test_cli_scan_respects_policy_failure(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = [
            VulnerabilityRecord(id="PYSEC-2026-1", summary="Example advisory")
        ]
        targets = [ScanTarget(requirement="gridoptim", project="gridoptim", version=None)]

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", return_value=report):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(
                        [
                            "scan",
                            "-f",
                            "requirements.txt",
                            "--fail-on-vulnerability",
                            "any",
                        ]
                    )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("PYSEC-2026-1: Example advisory", stdout.getvalue())

    def test_cli_scan_records_package_failures_and_continues(self) -> None:
        stdout = io.StringIO()
        targets = [
            ScanTarget(requirement="broken", project="broken", version=None),
            ScanTarget(requirement="gridoptim", project="gridoptim", version=None),
        ]

        def fake_inspect_package(project: str, **kwargs):
            if project == "broken":
                raise PypiClientError("resource not found")
            return make_report()

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(["scan", "-f", "requirements.txt"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertIn(
            "No known vulnerability records reported by configured sources.",
            stdout.getvalue(),
        )
        self.assertIn("scan failures:", stdout.getvalue())
        self.assertIn("broken: error: unable to inspect package from PyPI", stdout.getvalue())

    def test_cli_writes_industry_formats_to_output_file(self) -> None:
        report = make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "reports" / "trustcheck.sarif"
            stdout = io.StringIO()
            with patch("trustcheck.cli.inspect_package", return_value=report):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(
                        [
                            "inspect",
                            "gridoptim",
                            "--format",
                            "sarif",
                            "--output-file",
                            str(output_path),
                        ]
                    )
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("runs", payload)

    def test_cli_scan_reports_target_resolution_failures_and_continues(self) -> None:
        stdout = io.StringIO()
        targets = [
            ScanTarget(
                requirement="broken>=99",
                project="broken",
                failure_message="error: unable to resolve scan requirement broken>=99",
                failure_exit_code=EXIT_DATA_ERROR,
            ),
            ScanTarget(requirement="gridoptim", project="gridoptim", version=None),
        ]
        inspected: list[str] = []

        def fake_inspect_package(project: str, **kwargs):
            inspected.append(project)
            return make_report()

        with patch("trustcheck.cli._load_scan_targets", return_value=targets):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    exit_code = main(["scan", "-f", "requirements.txt"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(inspected, ["gridoptim"])
        self.assertIn("successful: 1", stdout.getvalue())
        self.assertIn("failed: 1", stdout.getvalue())
        self.assertIn("broken>=99: error: unable to resolve scan requirement", stdout.getvalue())

    def test_load_scan_targets_supports_project_toml_dependencies(self) -> None:
        scan_file = Path("tests/_tmp/scan-project.toml")
        scan_file.write_text(
            "\n".join(
                [
                    "[project]",
                    'dependencies = ["requests>=2.31", "urllib3"]',
                    "",
                    "[project.optional-dependencies]",
                    'dev = ["pytest>=8"]',
                ]
            ),
            encoding="utf-8",
        )

        class FakeClient:
            def get_project(self, project: str) -> dict[str, object]:
                versions = {
                    "requests": "2.32.0",
                    "pytest": "8.3.0",
                }
                version = versions.get(project, "2.0.0")
                return {
                    "info": {"version": version},
                    "releases": {version: []},
                }

        targets = _load_scan_targets(str(scan_file), FakeClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("requests", "2.32.0"), ("urllib3", None), ("pytest", "8.3.0")],
        )

    def test_load_scan_targets_supports_poetry_toml_dependencies(self) -> None:
        scan_file = Path("tests/_tmp/scan-poetry.toml")
        scan_file.write_text(
            "\n".join(
                [
                    "[tool.poetry.dependencies]",
                    'python = "^3.11"',
                    'requests = "^2.31"',
                    'urllib3 = "*"',
                    "",
                    "[tool.poetry.group.dev.dependencies]",
                    'pytest = "^8.0"',
                ]
            ),
            encoding="utf-8",
        )

        class FakeClient:
            def get_project(self, project: str) -> dict[str, object]:
                versions = {
                    "requests": "2.32.0",
                    "pytest": "8.3.0",
                }
                version = versions.get(project, "2.0.0")
                return {
                    "info": {"version": version},
                    "releases": {version: []},
                }

        targets = _load_scan_targets(str(scan_file), FakeClient())  # type: ignore[arg-type]

        self.assertEqual(
            [(target.project, target.version) for target in targets],
            [("requests", "2.32.0"), ("urllib3", None), ("pytest", "8.3.0")],
        )

    def test_extract_scan_requirements_from_toml_handles_pdm_dev_groups(self) -> None:
        payload = {
            "project": {"dependencies": ["requests>=2.31"]},
            "tool": {
                "pdm": {
                    "dev-dependencies": {
                        "test": ["pytest>=8"],
                        "lint": ["ruff>=0.8"],
                    }
                }
            },
        }

        self.assertEqual(
            _extract_scan_requirements_from_toml(payload, groups=["test"]),
            ["requests>=2.31", "pytest>=8"],
        )
        with self.assertRaisesRegex(ValueError, "defined more than once"):
            _extract_scan_requirements_from_toml(
                {
                    "dependency-groups": {"test": ["tox>=4"]},
                    "tool": {"pdm": {"dev-dependencies": {"test": ["pytest>=8"]}}},
                }
            )

    def test_cli_with_deps_flag_enables_dependency_inspection(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["include_dependencies"])
            self.assertFalse(kwargs["include_transitive_dependencies"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--with-deps"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_with_transitive_deps_flag_enables_recursive_dependency_inspection(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertFalse(kwargs["include_dependencies"])
            self.assertTrue(kwargs["include_transitive_dependencies"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--with-transitive-deps"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_inspect_artifacts_flag_enables_static_inspection(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertTrue(kwargs["inspect_artifacts"])
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--inspect-artifacts"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_forwards_custom_typosquatting_reference_projects(self) -> None:
        stdout = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            self.assertEqual(
                kwargs["trusted_projects"],
                ["requests", "internal-sdk"],
            )
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--trusted-project",
                        "requests",
                        "--trusted-project",
                        "internal-sdk",
                    ]
                )

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_text_output_shows_file_errors_in_verbose_mode(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.files[0].error = "resource not found"
        report.recommendation = "review-required"
        report.risk_flags = [
            RiskFlag(
                code="no_provenance",
                severity="medium",
                message="No provenance bundles were found.",
                why=["No verified provenance bundle was attached to the artifact."],
                remediation=["Require a release that publishes provenance before use."],
            )
        ]
        report.files[0].artifact = ArtifactInspection(
            inspected=True,
            kind="wheel",
            archive_valid=True,
            file_count=5,
            total_uncompressed_size=2048,
            record_valid=False,
            record_errors=["gridoptim/__init__.py hash does not match RECORD"],
            console_scripts=["gridoptim = gridoptim.cli:main"],
            native_files=["gridoptim/native.pyd"],
            unexpected_top_level_files=["NOTICE.txt"],
            metadata_name="gridoptim",
            metadata_version="2.2.0",
            source_files_analyzed=2,
            source_parse_errors=["bad.py: unable to parse Python AST"],
            native_binaries=[
                NativeBinaryInspection(
                    path="gridoptim/native.pyd",
                    format="PE",
                    architecture="x86-64",
                    imports=["WINHTTP.dll"],
                    signature_present=False,
                    signature_status="no-embedded-certificate",
                    entropy=7.4,
                    embedded_payloads=["zip signature at byte offset 100"],
                    parse_error="partial import table",
                )
            ],
        )
        report.files[0].slsa_provenance = [
            SlsaProvenance(
                source_repository="https://github.com/Halfblood-Prince/gridoptim",
                source_commit="abc123",
                builder_id="https://github.com/actions/runner",
                build_type="https://slsa.dev/container-based-build/v1",
                workflow_path=".github/workflows/release.yml",
                workflow_ref="refs/tags/v2.2.0",
                action_references=["actions/checkout@v6"],
                issues=[
                    ProvenanceIssue(
                        code="unpinned_action",
                        severity="medium",
                        message="Action reference is not pinned to a digest.",
                    )
                ],
            )
        ]
        report.vulnerabilities = [
            VulnerabilityRecord(
                id="PYSEC-2026-1",
                summary="Known issue",
                source="OSV",
                severity="CRITICAL",
                cvss_score=9.1,
                cwes=["CWE-79"],
                fixed_in=["2.2.1"],
                withdrawn=True,
                withdrawn_at="2026-06-01T00:00:00Z",
                kev=True,
                kev_due_date="2026-07-01",
                epss_score=0.8123,
                epss_percentile=0.9812,
                link="https://osv.dev/vulnerability/PYSEC-2026-1",
                suppression=VulnerabilitySuppression(
                    vulnerability_id="PYSEC-2026-1",
                    owner="security",
                    justification="temporary exception",
                    expires="2026-07-01",
                    status="active",
                ),
            )
        ]
        report.malicious_package = MaliciousPackageAssessment(
            score=58,
            level="high",
            artifact_analysis=True,
            findings=[
                HeuristicFinding(
                    code="ast_credential_network_chain",
                    category="credential-access",
                    severity="critical",
                    confidence="medium",
                    score=58,
                    message="Credential access and network capability are combined.",
                    evidence=["credential-access", "network"],
                    location="gridoptim/setup.py:4",
                    artifact="gridoptim.tar.gz",
                )
            ],
        )
        direct_rendered = _render_text_report(report, verbose=True)
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--verbose"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("note: resource not found", stdout.getvalue())
        self.assertIn("[medium] no_provenance", stdout.getvalue())
        self.assertIn("why:", stdout.getvalue())
        self.assertIn("remediation:", stdout.getvalue())
        self.assertIn("requirement: depalpha>=1.0", stdout.getvalue())
        self.assertIn("artifact inspection:", stdout.getvalue())
        self.assertIn("wheel RECORD: invalid", stdout.getvalue())
        self.assertIn("console scripts:", stdout.getvalue())
        self.assertIn("gridoptim/native.pyd", stdout.getvalue())
        self.assertIn("malicious-package heuristic indicators:", stdout.getvalue())
        self.assertIn("not proof", stdout.getvalue())
        self.assertIn("native binary analysis:", stdout.getvalue())
        self.assertIn("WINHTTP.dll", stdout.getvalue())
        self.assertIn("embedded payloads:", stdout.getvalue())
        self.assertIn("parse note:", stdout.getvalue())
        self.assertIn("SLSA provenance:", stdout.getvalue())
        self.assertIn("actions/checkout@v6", stdout.getvalue())
        self.assertIn("issue: [medium] unpinned_action", stdout.getvalue())
        self.assertIn("vulnerabilities:", stdout.getvalue())
        self.assertIn("cvss=9.1", stdout.getvalue())
        self.assertIn("kev_due=2026-07-01", stdout.getvalue())
        self.assertIn("epss=0.8123", stdout.getvalue())
        self.assertIn("suppression=active:security:2026-07-01", direct_rendered)

    def test_cli_non_verbose_output_is_concise(self) -> None:
        report = make_report()
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertNotIn("files:", stdout.getvalue())
        self.assertNotIn("sha256:", stdout.getvalue())

    def test_cli_strict_mode_fails_on_missing_verification(self) -> None:
        report = make_report()
        report.files[0].verified = False
        report.coverage.verified_files = 0
        report.coverage.status = "all-attested"
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--strict"])

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("recommendation:", stdout.getvalue())
        self.assertIn("policy: strict (fail)", stdout.getvalue())

    def test_cli_strict_mode_passes_for_fully_verified_release(self) -> None:
        stdout = io.StringIO()

        with patch("trustcheck.cli.inspect_package", return_value=make_report()):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--strict"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_policy_file_can_require_expected_repository(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.expected_repository = None
        policy_path = Path(__file__).parent / "fixtures" / "policy_require_expected_repo.json"

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--policy-file", str(policy_path)])

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("policy: team-policy (fail)", stdout.getvalue())
        self.assertIn("expected_repository_required", stdout.getvalue())

    def test_cli_policy_flags_override_builtin_policy(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.vulnerabilities = []

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--policy",
                        "strict",
                        "--require-verified-provenance",
                        "none",
                        "--fail-on-risk-severity",
                        "none",
                        "--allow-metadata-only",
                    ]
                )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("policy: strict (pass)", stdout.getvalue())

    def test_cli_enforces_trusted_publisher_organization(self) -> None:
        stdout = io.StringIO()
        report = make_report()
        report.files[0].publisher_identities = [
            PublisherIdentity(
                kind="GitHub",
                repository="https://github.com/Halfblood-Prince/gridoptim",
                workflow="release.yml",
                environment=None,
            )
        ]

        with patch("trustcheck.cli.inspect_package", return_value=report):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                exit_code = main(
                    [
                        "inspect",
                        "gridoptim",
                        "--trusted-publisher-organization",
                        "github:other-org",
                    ]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("publisher_organization_not_allowed", stdout.getvalue())

    def test_cli_builds_client_from_config_file(self) -> None:
        config_path = Path(__file__).parent / "fixtures" / "client_config.json"

        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            self.assertEqual(client.timeout, 3.5)
            self.assertEqual(client.max_retries, 4)
            self.assertEqual(client.backoff_factor, 0.75)
            self.assertTrue(client.offline)
            self.assertEqual(client.cache_dir, ".cache/trustcheck")
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main(["inspect", "gridoptim", "--config-file", str(config_path)])

        self.assertEqual(exit_code, EXIT_OK)

    def test_cli_env_overrides_network_settings(self) -> None:
        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            self.assertEqual(client.timeout, 1.5)
            self.assertEqual(client.max_retries, 5)
            self.assertEqual(client.backoff_factor, 0.6)
            self.assertTrue(client.offline)
            self.assertEqual(client.cache_dir, ".env-cache")
            return make_report()

        with patch.dict(
            "os.environ",
            {
                "TRUSTCHECK_TIMEOUT": "1.5",
                "TRUSTCHECK_RETRIES": "5",
                "TRUSTCHECK_BACKOFF": "0.6",
                "TRUSTCHECK_OFFLINE": "true",
                "TRUSTCHECK_CACHE_DIR": ".env-cache",
            },
            clear=False,
        ):
            with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)

    def test_network_outage_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError("unable to reach PyPI: timed out"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unable to inspect package from PyPI", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_missing_package_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError("resource not found: https://pypi.org/pypi/gridoptim/json"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim", "--version", "9.9.9"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("resource not found", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_server_response_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=ValueError("missing required provenance fields"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("received an invalid response", stderr.getvalue())
        self.assertIn("missing required provenance fields", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_unexpected_failure_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=RuntimeError("unexpected explosion"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unexpected failure", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_debug_mode_prints_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", side_effect=ValueError("broken payload")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("Traceback", stderr.getvalue())

    def test_cli_json_debug_logs_are_structured(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def fake_inspect_package(*args, **kwargs):
            client = kwargs["client"]
            assert client.request_hook is not None
            client.request_hook(
                "retry",
                {
                    "url": "https://pypi.org/pypi/gridoptim/json",
                    "attempt": 1,
                    "delay": 0.25,
                },
            )
            return make_report()

        with patch("trustcheck.cli.inspect_package", side_effect=fake_inspect_package):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "--log-format", "json", "inspect", "gridoptim"])

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn('"event": "retry"', stderr.getvalue())
