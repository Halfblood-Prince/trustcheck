from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustcheck.indexes import (
    DependencyConfusionFinding,
    IndexConfiguration,
    IndexError,
)
from trustcheck.resolver import (
    ArtifactReference,
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
    _archive_hashes,
    _filename_from_url,
    discover_installed_distributions,
    parse_installation_report,
    validate_resolved_requirement,
)


def installation_report() -> dict[str, object]:
    return {
        "version": "1",
        "pip_version": "26.1.2",
        "environment": {
            "implementation_name": "cpython",
            "python_version": "3.12",
        },
        "install": [
            {
                "download_info": {
                    "url": "https://files.pythonhosted.org/demo.whl",
                    "archive_info": {"hash": "sha256=abc"},
                },
                "is_direct": False,
                "is_yanked": False,
                "requested": True,
                "requested_extras": ["security"],
                "metadata": {
                    "name": "Demo",
                    "version": "2.0.0",
                    "requires_dist": ["dep>=1"],
                },
            },
            {
                "download_info": {
                    "url": "git+https://example.com/dep.git",
                    "vcs_info": {
                        "vcs": "git",
                        "commit_id": "abcdef",
                    },
                    "dir_info": {"editable": True},
                },
                "is_direct": True,
                "is_yanked": False,
                "requested": False,
                "metadata": {
                    "name": "dep",
                    "version": "1.4.0",
                },
            },
        ],
    }


class ResolverTests(unittest.TestCase):
    def test_parse_installation_report_preserves_resolution_metadata(self) -> None:
        resolution = parse_installation_report(installation_report())

        self.assertEqual(
            resolution.versions,
            {"demo": "2.0.0", "dep": "1.4.0"},
        )
        self.assertEqual(resolution.pip_version, "26.1.2")
        self.assertEqual(resolution.environment["python_version"], "3.12")
        self.assertEqual(
            [item.name for item in resolution.requested_distributions()],
            ["Demo"],
        )
        demo, dependency = resolution.distributions
        self.assertEqual(demo.requested_extras, ("security",))
        self.assertEqual(demo.requires_dist, ("dep>=1",))
        self.assertEqual(
            demo.artifacts,
            (
                ArtifactReference(
                    filename="demo.whl",
                    url="https://files.pythonhosted.org/demo.whl",
                    hashes=(("sha256", "abc"),),
                ),
            ),
        )
        self.assertTrue(dependency.is_direct)
        self.assertTrue(dependency.editable)
        self.assertEqual(dependency.vcs, "git")
        self.assertEqual(dependency.vcs_commit, "abcdef")

        payload = installation_report()
        install = payload["install"]
        assert isinstance(install, list)
        direct = install[1]
        assert isinstance(direct, dict)
        download_info = direct["download_info"]
        assert isinstance(download_info, dict)
        download_info["url"] = "git+https://user:secret@example.com/dep.git"
        redacted = parse_installation_report(payload).distributions[1]
        self.assertEqual(
            redacted.source_url,
            "git+https://<redacted>@example.com/dep.git",
        )

    def test_parse_installation_report_rejects_invalid_shapes_and_versions(self) -> None:
        cases = [
            ([], "JSON object"),
            ({"version": "2", "install": []}, "unsupported"),
            ({"version": "1"}, "install array"),
            ({"version": "1", "install": ["bad"]}, "not an object"),
            (
                {"version": "1", "install": [{"metadata": {}}]},
                "no package name",
            ),
            (
                {"version": "1", "install": [{"metadata": None}]},
                "missing metadata",
            ),
            (
                {"version": "1", "install": [{"metadata": {"name": "demo"}}]},
                "no package version",
            ),
            (
                {
                    "version": "1",
                    "install": [
                        {"metadata": {"name": "demo", "version": "not valid"}}
                    ],
                },
                "invalid version",
            ),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ResolutionError, message):
                    parse_installation_report(payload)

    def test_parse_installation_report_rejects_conflicting_duplicate_versions(self) -> None:
        payload = installation_report()
        install = payload["install"]
        assert isinstance(install, list)
        install.append(
            {
                "metadata": {
                    "name": "demo",
                    "version": "3.0.0",
                }
            }
        )
        with self.assertRaisesRegex(ResolutionError, "multiple versions"):
            parse_installation_report(payload)

    def test_parse_installation_report_deduplicates_and_defaults_optional_fields(self) -> None:
        payload = {
            "version": "1",
            "install": [
                {"metadata": {"name": "demo", "version": "1.0"}},
                {"metadata": {"name": "Demo", "version": "1.0"}},
            ],
            "environment": "not-a-mapping",
        }
        resolution = parse_installation_report(payload)
        self.assertEqual(len(resolution.distributions), 1)
        self.assertIsNone(resolution.distributions[0].source_url)
        self.assertEqual(resolution.environment, {})
        self.assertIsNone(resolution.pip_version)

    def test_pip_resolver_builds_dry_run_command_with_constraints_and_target(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def runner(command, **kwargs):
            calls.append((command, kwargs["cwd"]))
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            requirements = Path(tmpdir) / "requirements.txt"
            constraints = Path(tmpdir) / "constraints.txt"
            requirements.write_text("-r nested.txt\n", encoding="utf-8")
            constraints.write_text("dep<2\n", encoding="utf-8")

            resolution = PipResolver(
                python_executable="python-test",
                runner=runner,
            ).resolve_requirements_file(
                requirements,
                constraints=[constraints],
                target=TargetEnvironment(
                    python_version="3.12",
                    platforms=("manylinux_2_28_x86_64",),
                    implementation="cp",
                    abis=("cp312",),
                ),
                offline=True,
            )

        self.assertEqual(resolution.versions["demo"], "2.0.0")
        command, cwd = calls[0]
        self.assertEqual(command[:4], ["python-test", "-m", "pip", "install"])
        self.assertIn("--dry-run", command)
        self.assertIn("--ignore-installed", command)
        self.assertIn("--report", command)
        self.assertIn("--requirement", command)
        self.assertIn("--constraint", command)
        self.assertIn("--python-version", command)
        self.assertIn("--platform", command)
        self.assertIn("--implementation", command)
        self.assertIn("--abi", command)
        self.assertIn("--only-binary", command)
        self.assertIn("--no-index", command)
        self.assertEqual(cwd, str(requirements.parent.resolve()))

    def test_pip_resolver_supports_direct_editable_vcs_and_dependency_groups(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            del kwargs
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir) / "pyproject.toml"
            constraints = Path(tmpdir) / "constraints.txt"
            project.write_text(
                "[dependency-groups]\ndev = ['pytest']\n",
                encoding="utf-8",
            )
            constraints.write_text("requests<3\n", encoding="utf-8")
            PipResolver(runner=runner).resolve_requirements(
                [
                    "--editable",
                    "git+https://example.com/demo.git#egg=demo",
                    "requests[security]>=2",
                ],
                constraints=[constraints],
                dependency_groups=[(project, "dev")],
            )

        command = calls[0]
        self.assertIn("--editable", command)
        self.assertIn("git+https://example.com/demo.git#egg=demo", command)
        self.assertIn("requests[security]>=2", command)
        self.assertIn("--constraint", command)
        self.assertIn("--group", command)
        self.assertIn(f"{project.resolve()}:dev", command)

    def test_pip_resolver_passes_index_and_keyring_options(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            del kwargs
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        class IndexClient:
            def find_dependency_confusion(self, projects, indexes):
                self.projects = list(projects)
                self.indexes = indexes
                return ()

            def locate_artifact_index(self, project, artifact_url, indexes):
                del project, artifact_url
                return indexes[0]

        resolver = PipResolver(
            runner=runner,
            indexes=IndexConfiguration(
                index_url="https://private.example/simple",
                extra_index_urls=("https://pypi.org/simple",),
                keyring_provider="subprocess",
            ),
            index_client=IndexClient(),  # type: ignore[arg-type]
        )
        resolution = resolver.resolve_requirements(["demo"])

        command = calls[0]
        self.assertIn("--index-url", command)
        self.assertIn("https://private.example/simple", command)
        self.assertIn("--extra-index-url", command)
        self.assertIn("--keyring-provider", command)
        self.assertEqual(
            resolution.distributions[0].index_url,
            "https://private.example/simple/",
        )
        self.assertEqual(
            resolution.indexes,
            ("https://private.example/simple/", "https://pypi.org/simple/"),
        )

    def test_pip_resolver_blocks_or_reports_dependency_confusion(self) -> None:
        finding = DependencyConfusionFinding(
            project="Demo",
            indexes=(
                "https://private.example/simple",
                "https://pypi.org/simple",
            ),
        )

        class IndexClient:
            def find_dependency_confusion(self, projects, indexes):
                del projects, indexes
                return (finding,)

            def locate_artifact_index(self, project, artifact_url, indexes):
                del project, artifact_url
                return indexes[0]

        def runner(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        configuration = IndexConfiguration(
            index_url="https://private.example/simple",
            extra_index_urls=("https://pypi.org/simple",),
        )
        with self.assertRaisesRegex(ResolutionError, "dependency-confusion"):
            PipResolver(
                runner=runner,
                indexes=configuration,
                index_client=IndexClient(),  # type: ignore[arg-type]
            ).resolve_requirements(["demo"])

        resolution = PipResolver(
            runner=runner,
            indexes=configuration,
            index_client=IndexClient(),  # type: ignore[arg-type]
            allow_dependency_confusion=True,
        ).resolve_requirements(["demo"])
        self.assertEqual(resolution.dependency_confusion, (finding,))

    def test_pip_resolver_reports_index_inspection_failures(self) -> None:
        class IndexClient:
            def find_dependency_confusion(self, projects, indexes):
                del projects, indexes
                raise IndexError("authentication failed")

        resolver = PipResolver(
            indexes=IndexConfiguration(
                extra_index_urls=("https://private.example/simple",),
            ),
            index_client=IndexClient(),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(ResolutionError, "authentication failed"):
            resolver.check_dependency_confusion(["demo"])

    def test_check_dependency_confusion_uses_additional_indexes(self) -> None:
        calls: list[tuple[list[str], tuple[str, ...]]] = []

        class IndexClient:
            def find_dependency_confusion(self, projects, indexes):
                calls.append((list(projects), tuple(indexes)))
                return ()

        resolver = PipResolver(
            index_client=IndexClient(),  # type: ignore[arg-type]
        )
        self.assertEqual(
            resolver.check_dependency_confusion(
                ["demo"],
                additional_indexes=[
                    "https://private.example/simple",
                    "https://private.example/simple",
                ],
            ),
            (),
        )
        self.assertEqual(len(calls[0][1]), 2)

    def test_resolver_index_annotation_empty_and_location_errors(self) -> None:
        resolver = PipResolver()
        empty = Resolution()
        self.assertIs(resolver.annotate_indexes(empty), empty)
        self.assertEqual(empty.indexes, ("https://pypi.org/simple/",))

        class FailingIndexClient:
            def find_dependency_confusion(self, projects, indexes):
                del projects, indexes
                return ()

            def locate_artifact_index(self, project, artifact_url, indexes):
                del project, artifact_url, indexes
                raise IndexError("bad project page")

        resolver = PipResolver(
            indexes=IndexConfiguration(
                extra_index_urls=("https://private.example/simple",),
            ),
            index_client=FailingIndexClient(),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(ResolutionError, "bad project page"):
            resolver.annotate_indexes(
                Resolution(
                    distributions=[
                        ResolvedDistribution("demo", "1.0")
                    ]
                )
            )

    def test_archive_hash_and_filename_helpers(self) -> None:
        self.assertEqual(
            _archive_hashes(
                {
                    "hashes": {"sha256": "AA", 3: "bad", "sha512": 4},
                    "hash": "sha256=bb",
                }
            ),
            (("sha256", "aa"),),
        )
        self.assertEqual(
            _archive_hashes({"hash": "md5:CC"}),
            (("md5", "cc"),),
        )
        self.assertEqual(_archive_hashes({"hash": "invalid"}), ())
        self.assertIsNone(_filename_from_url(None))
        self.assertIsNone(_filename_from_url("https://example.com/"))

    def test_installed_distribution_preserves_archive_hashes(self) -> None:
        class FakeDistribution:
            metadata = {"Name": "demo"}
            version = "1.0"
            requires = None

            def read_text(self, filename: str) -> str:
                del filename
                return json.dumps(
                    {
                        "url": "https://example.com/demo.whl",
                        "archive_info": {
                            "hashes": {"sha256": "a" * 64}
                        },
                    }
                )

        with patch(
            "trustcheck.resolver.distributions",
            return_value=[FakeDistribution()],
        ):
            item = discover_installed_distributions().distributions[0]
        self.assertEqual(item.artifacts[0].hashes, (("sha256", "a" * 64),))

    def test_pip_resolver_validates_inputs_before_running_pip(self) -> None:
        resolver = PipResolver(
            runner=lambda command, **kwargs: self.fail("runner should not be called")
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            requirements = root / "requirements.txt"
            requirements.write_text("demo\n", encoding="utf-8")
            with self.assertRaisesRegex(ResolutionError, "requirements file"):
                resolver.resolve_requirements_file(root / "missing.txt")
            with self.assertRaisesRegex(ResolutionError, "constraints file"):
                resolver.resolve_requirements_file(
                    requirements,
                    constraints=[root / "missing-constraints.txt"],
                )
            with self.assertRaisesRegex(ResolutionError, "constraints file"):
                resolver.resolve_requirements(
                    ["demo"],
                    constraints=[root / "missing-constraints.txt"],
                )
            with self.assertRaisesRegex(ResolutionError, "pyproject.toml"):
                resolver.resolve_requirements(
                    [],
                    dependency_groups=[(root / "project.toml", "test")],
                )
        with self.assertRaisesRegex(ResolutionError, "no requirements"):
            resolver.resolve_requirements([])

    def test_pip_resolver_reports_subprocess_and_json_failures(self) -> None:
        failures = [
            (
                lambda command, **kwargs: subprocess.CompletedProcess(
                    command,
                    1,
                    stdout="",
                    stderr="resolution conflict",
                ),
                "resolution conflict",
            ),
            (
                lambda command, **kwargs: subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="not-json",
                    stderr="",
                ),
                "invalid installation report",
            ),
        ]
        for runner, message in failures:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ResolutionError, message):
                    PipResolver(runner=runner).resolve_requirements(["demo"])

        def os_error(command, **kwargs):
            del command, kwargs
            raise OSError("cannot execute")

        with self.assertRaisesRegex(ResolutionError, "unable to start"):
            PipResolver(runner=os_error).resolve_requirements(["demo"])

        def empty_error(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(command, 5, stdout="", stderr="")

        with self.assertRaisesRegex(ResolutionError, "status 5"):
            PipResolver(runner=empty_error).resolve_requirements(["demo"])

    def test_validate_resolved_requirement(self) -> None:
        validate_resolved_requirement("demo>=1", {"demo": "2.0"})
        with self.assertRaisesRegex(ResolutionError, "does not satisfy"):
            validate_resolved_requirement("demo>=3", {"demo": "2.0"})
        with self.assertRaisesRegex(ResolutionError, "did not produce"):
            validate_resolved_requirement("missing>=1", {"demo": "2.0"})
        with self.assertRaisesRegex(ResolutionError, "invalid resolved"):
            validate_resolved_requirement("not valid ???", {"demo": "2.0"})

    def test_discover_installed_distributions_supports_paths_and_direct_urls(self) -> None:
        class FakeDistribution:
            metadata = {"Name": "Editable-Demo"}
            version = "1.2.3"
            requires = ["dep>=1"]

            def read_text(self, filename: str) -> str | None:
                self.assert_filename = filename
                return json.dumps(
                    {
                        "url": "file:///workspace/demo",
                        "dir_info": {"editable": True},
                        "vcs_info": {"vcs": "git", "commit_id": "abc"},
                    }
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "trustcheck.resolver.distributions",
                return_value=[FakeDistribution()],
            ) as discover:
                resolution = discover_installed_distributions([tmpdir])

        discover.assert_called_once_with(path=[str(Path(tmpdir).resolve())])
        item = resolution.distributions[0]
        self.assertEqual(item.name, "Editable-Demo")
        self.assertEqual(item.version, "1.2.3")
        self.assertTrue(item.requested)
        self.assertTrue(item.editable)
        self.assertEqual(item.vcs, "git")
        self.assertEqual(item.requires_dist, ("dep>=1",))

    def test_discover_installed_distributions_handles_duplicates_and_errors(self) -> None:
        class FakeDistribution:
            def __init__(
                self,
                name: str,
                version: str,
                direct_url: str | Exception | None = None,
            ) -> None:
                self.metadata = {"Name": name}
                self.version = version
                self.requires = None
                self.direct_url = direct_url

            def read_text(self, filename: str) -> str | None:
                self.filename = filename
                if isinstance(self.direct_url, Exception):
                    raise self.direct_url
                return self.direct_url

        with patch(
            "trustcheck.resolver.distributions",
            return_value=[
                FakeDistribution("Demo", "1.0"),
                FakeDistribution("demo", "1.0"),
            ],
        ) as discover:
            resolution = discover_installed_distributions()
        discover.assert_called_once_with()
        self.assertEqual(len(resolution.distributions), 1)

        with patch(
            "trustcheck.resolver.distributions",
            return_value=[
                FakeDistribution("Demo", "1.0"),
                FakeDistribution("demo", "2.0"),
            ],
        ):
            with self.assertRaisesRegex(ResolutionError, "multiple installed"):
                discover_installed_distributions()

        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing"
            with self.assertRaisesRegex(ResolutionError, "path not found"):
                discover_installed_distributions([missing])

        invalid_distributions = [
            FakeDistribution("", "1.0"),
            FakeDistribution("demo", "invalid version"),
        ]
        messages = ["missing Name", "invalid version"]
        for distribution, message in zip(invalid_distributions, messages):
            with self.subTest(message=message):
                with patch(
                    "trustcheck.resolver.distributions",
                    return_value=[distribution],
                ):
                    with self.assertRaisesRegex(ResolutionError, message):
                        discover_installed_distributions()

    def test_installed_direct_url_reader_tolerates_missing_and_invalid_metadata(self) -> None:
        class FakeDistribution:
            metadata = {"Name": "demo"}
            version = "1.0"
            requires = None

            def __init__(self, result: str | Exception | None) -> None:
                self.result = result

            def read_text(self, filename: str) -> str | None:
                self.filename = filename
                if isinstance(self.result, Exception):
                    raise self.result
                return self.result

        cases = [
            None,
            "{invalid",
            "[]",
            FileNotFoundError(),
            PermissionError(),
        ]
        for result in cases:
            with self.subTest(result=type(result).__name__):
                with patch(
                    "trustcheck.resolver.distributions",
                    return_value=[FakeDistribution(result)],
                ):
                    item = discover_installed_distributions().distributions[0]
                self.assertIsNone(item.source_url)
                self.assertFalse(item.is_direct)

        with patch(
            "trustcheck.resolver.distributions",
            return_value=[
                FakeDistribution(
                    json.dumps(
                        {
                            "url": 3,
                            "dir_info": "bad",
                            "vcs_info": {
                                "vcs": 3,
                                "commit_id": 4,
                            },
                        }
                    )
                )
            ],
        ):
            item = discover_installed_distributions().distributions[0]
        self.assertIsNone(item.source_url)
        self.assertFalse(item.editable)
        self.assertIsNone(item.vcs)


if __name__ == "__main__":
    unittest.main()
