from __future__ import annotations

import json
import subprocess
import sys
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
    DEFAULT_SANDBOX_IMAGE,
    ArtifactReference,
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
    _archive_hashes,
    _bubblewrap_readonly_binds,
    _containerize_argument,
    _dependency_group_risks,
    _filename_from_url,
    _local_requirement_path,
    _logical_requirement_lines,
    _nested_requirement_path,
    _path_requirement_risks,
    _requirement_file_risks,
    _requirement_risks,
    _resolve_local_path,
    _stage_sandbox_inputs,
    _translate_workspace_reference,
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
                sandbox_mode="warn",
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
            PipResolver(runner=runner, sandbox_mode="warn").resolve_requirements(
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

    def test_resolver_warn_and_off_modes_preserve_compatibility(self) -> None:
        calls: list[list[str]] = []
        warnings: list[str] = []

        def runner(command, **kwargs):
            del kwargs
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        resolution = PipResolver(
            runner=runner,
            sandbox_mode="warn",
            warning_handler=warnings.append,
        ).resolve_requirements(
            ["demo @ git+https://example.com/demo.git"],
            offline=True,
        )
        self.assertEqual(resolution.sandbox_mode, "warn")
        self.assertEqual(resolution.sandbox_warnings, tuple(warnings))
        self.assertIn("VCS requirement", warnings[0])
        self.assertNotIn("--isolated", calls[0])
        self.assertNotIn("--only-binary", calls[0])

        warnings.clear()
        PipResolver(
            runner=runner,
            sandbox_mode="off",
            warning_handler=warnings.append,
        ).resolve_requirements(["demo"], offline=True)
        self.assertEqual(warnings, [])

    def test_strict_mode_is_isolated_and_wheel_only(self) -> None:
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

        resolution = PipResolver(
            runner=runner,
            sandbox_mode="strict",
        ).resolve_requirements(
            ["demo>=1", "wheel-demo @ https://example.com/demo.whl"],
            offline=True,
        )
        command = calls[0]
        self.assertEqual(resolution.sandbox_mode, "strict")
        self.assertEqual(command[1:3], ["-m", "trustcheck._resolver_guard"])
        self.assertIn("--isolated", command)
        self.assertEqual(
            command[command.index("--only-binary") + 1],
            ":all:",
        )

    def test_strict_mode_rejects_unsafe_requirement_forms(self) -> None:
        rejected = (
            "--editable ./demo",
            "-e./demo",
            "demo @ git+https://example.com/demo.git",
            "./demo",
            "project/demo",
            "${PROJECT_ROOT}/demo",
            "https://example.com/demo.tar.gz",
            "demo @ https://example.com/download",
            "--no-binary=:all:",
            "--only-binary :none:",
        )
        resolver = PipResolver(
            sandbox_mode="strict",
            runner=lambda command, **kwargs: self.fail(
                f"runner should not be called: {command!r}, {kwargs!r}"
            ),
        )
        for requirement in rejected:
            with self.subTest(requirement=requirement):
                with self.assertRaisesRegex(ResolutionError, "strict resolver sandbox"):
                    resolver.resolve_requirements([requirement])

    def test_strict_mode_inspects_nested_files_and_dependency_groups(self) -> None:
        resolver = PipResolver(
            sandbox_mode="strict",
            runner=lambda command, **kwargs: self.fail(
                f"runner should not be called: {command!r}, {kwargs!r}"
            ),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            requirements = root / "requirements.txt"
            nested = root / "nested.txt"
            project = root / "pyproject.toml"
            requirements.write_text("-r nested.txt\n", encoding="utf-8")
            nested.write_text("-e ./project\n", encoding="utf-8")
            project.write_text(
                "[dependency-groups]\n"
                "dev = ['demo @ https://example.com/demo.zip']\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ResolutionError, "editable requirement"):
                resolver.resolve_requirements_file(requirements)
            with self.assertRaisesRegex(ResolutionError, "source archive requirement"):
                resolver.resolve_requirements(
                    [],
                    dependency_groups=[(project, "dev")],
                )

    def test_container_mode_wraps_pip_with_read_only_runtime(self) -> None:
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
            workspace = Path(tmpdir).resolve()
            resolution = PipResolver(
                runner=runner,
                sandbox_mode="container",
                container_runtime="docker",
                container_image=(
                    "registry.example/resolver@sha256:"
                    + "a" * 64
                ),
                executable_finder=lambda executable: (
                    "docker-test" if executable == "docker" else None
                ),
            ).resolve_requirements(
                ["demo"],
                cwd=workspace,
                offline=True,
            )

        command, cwd = calls[0]
        self.assertEqual(resolution.sandbox_mode, "container")
        self.assertEqual(command[:3], ["docker-test", "run", "--rm"])
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertIn("--user=65534:65534", command)
        mount = next(
            item for item in command
            if item.startswith("type=bind,source=")
        )
        self.assertNotIn(f"source={workspace},", mount)
        self.assertTrue(mount.endswith("target=/workspace,readonly"))
        image_index = command.index(
            "registry.example/resolver@sha256:" + "a" * 64
        )
        self.assertEqual(command[image_index + 1 : image_index + 5], [
            "python",
            "-m",
            "pip",
            "install",
        ])
        self.assertIsNone(cwd)

    def test_container_mode_rejects_unmounted_paths_and_missing_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace = root / "workspace"
            workspace.mkdir()
            external_wheel = root / "external.whl"
            resolver = PipResolver(
                sandbox_mode="container",
                executable_finder=lambda executable: "docker-test",
            )
            with self.assertRaisesRegex(ResolutionError, "outside the resolver workspace"):
                resolver.resolve_requirements(
                    [str(external_wheel.resolve())],
                    cwd=workspace,
                )

        with self.assertRaisesRegex(ResolutionError, "requires Docker or Podman"):
            PipResolver(
                sandbox_mode="container",
                executable_finder=lambda executable: None,
            ).resolve_requirements(["demo"])

    def test_enforced_sandboxes_mount_only_staged_resolver_inputs(self) -> None:
        mounted_sources: list[Path] = []

        def runner(command, **kwargs):
            del kwargs
            if command[0] == "docker-test":
                mount = next(
                    item for item in command
                    if item.startswith("type=bind,source=")
                )
                source = Path(
                    mount.removeprefix("type=bind,source=").removesuffix(
                        ",target=/workspace,readonly"
                    )
                )
            else:
                bind_index = next(
                    index for index, item in enumerate(command)
                    if item == "--ro-bind"
                    and command[index + 2] == "/workspace"
                )
                source = Path(command[bind_index + 1])
            mounted_sources.append(source)
            self.assertTrue((source / "requirements.txt").is_file())
            self.assertTrue((source / "constraints.txt").is_file())
            self.assertTrue((source / "nested" / "requirements.txt").is_file())
            self.assertTrue((source / "local-demo" / "pyproject.toml").is_file())
            self.assertFalse((source / ".env").exists())
            self.assertFalse((source / "private-source.py").exists())
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir).resolve()
            nested = workspace / "nested"
            local = workspace / "local-demo"
            nested.mkdir()
            local.mkdir()
            (workspace / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
            (workspace / "private-source.py").write_text("secret = 1\n", encoding="utf-8")
            requirements = workspace / "requirements.txt"
            constraints = workspace / "constraints.txt"
            requirements.write_text("-r nested/requirements.txt\n", encoding="utf-8")
            constraints.write_text("demo<3\n", encoding="utf-8")
            (nested / "requirements.txt").write_text(
                "-e ../local-demo\n",
                encoding="utf-8",
            )
            (local / "pyproject.toml").write_text(
                "[project]\nname = 'local-demo'\nversion = '1'\n",
                encoding="utf-8",
            )

            PipResolver(
                runner=runner,
                sandbox_mode="container",
                container_runtime="docker",
                executable_finder=lambda executable: "docker-test",
            ).resolve_requirements_file(
                requirements,
                constraints=[constraints],
                offline=True,
            )
            with patch(
                "trustcheck.resolver.platform_module.system",
                return_value="Linux",
            ):
                PipResolver(
                    python_executable="/usr/bin/python3",
                    runner=runner,
                    sandbox_mode="bubblewrap",
                    executable_finder=lambda executable: "/usr/bin/bwrap",
                ).resolve_requirements_file(
                    requirements,
                    constraints=[constraints],
                    offline=True,
                )

        self.assertEqual(len(mounted_sources), 2)
        self.assertTrue(all(not source.exists() for source in mounted_sources))

    def test_container_image_is_digest_pinned(self) -> None:
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
            resolver = PipResolver(
                runner=runner,
                sandbox_mode="container",
                executable_finder=lambda executable: "docker-test",
            )
            resolver.resolve_requirements(
                ["demo"],
                cwd=tmpdir,
                offline=True,
            )
            self.assertIn(DEFAULT_SANDBOX_IMAGE, calls[0])

            with self.assertRaisesRegex(ResolutionError, "full sha256 digest"):
                PipResolver(
                    sandbox_mode="container",
                    container_image="python:3.13-slim",
                    executable_finder=lambda executable: "docker-test",
                ).resolve_requirements(
                    ["demo"],
                    cwd=tmpdir,
                    offline=True,
                )
            with self.assertRaisesRegex(ResolutionError, "full sha256 digest"):
                PipResolver(
                    sandbox_mode="strict",
                    container_image="python:3.13-slim",
                ).resolve_requirements(["demo"], offline=True)

    def test_auto_selects_bubblewrap_container_or_strict(self) -> None:
        calls: list[list[str]] = []
        warnings: list[str] = []

        def runner(command, **kwargs):
            del kwargs
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(installation_report()),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "trustcheck.resolver.platform_module.system",
            return_value="Linux",
        ):
            workspace = Path(tmpdir).resolve()
            bubblewrap = PipResolver(
                python_executable="/usr/bin/python3",
                runner=runner,
                sandbox_mode="auto",
                executable_finder=lambda executable: (
                    "/usr/bin/bwrap" if executable == "bwrap" else None
                ),
            ).resolve_requirements(["demo"], cwd=workspace, offline=True)
            self.assertEqual(bubblewrap.sandbox_mode, "bubblewrap")
            self.assertEqual(calls[-1][0], "/usr/bin/bwrap")
            self.assertIn("--clearenv", calls[-1])
            self.assertIn("--share-net", calls[-1])
            self.assertNotIn(str(workspace), calls[-1])
            self.assertIn("/workspace", calls[-1])

        with patch(
            "trustcheck.resolver.platform_module.system",
            return_value="Windows",
        ):
            container = PipResolver(
                runner=runner,
                sandbox_mode="auto",
                executable_finder=lambda executable: (
                    "podman-test" if executable == "podman" else None
                ),
            ).resolve_requirements(["demo"], offline=True)
            self.assertEqual(container.sandbox_mode, "container")
            self.assertEqual(calls[-1][0], "podman-test")

            strict = PipResolver(
                runner=runner,
                sandbox_mode="auto",
                executable_finder=lambda executable: None,
                warning_handler=warnings.append,
            ).resolve_requirements(["demo"], offline=True)
            self.assertEqual(strict.sandbox_mode, "strict")
            self.assertIn("--isolated", calls[-1])
            self.assertIn("fell back to strict", warnings[0])

    def test_bubblewrap_requires_linux_and_runtime(self) -> None:
        with patch(
            "trustcheck.resolver.platform_module.system",
            return_value="Windows",
        ), self.assertRaisesRegex(ResolutionError, "only supported on Linux"):
            PipResolver(sandbox_mode="bubblewrap").resolve_requirements(["demo"])

        with patch(
            "trustcheck.resolver.platform_module.system",
            return_value="Linux",
        ), self.assertRaisesRegex(ResolutionError, "requires bwrap"):
            PipResolver(
                sandbox_mode="bubblewrap",
                executable_finder=lambda executable: None,
            ).resolve_requirements(["demo"])

    def test_invalid_sandbox_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "sandbox_mode"):
            PipResolver(sandbox_mode="invalid")

    def test_sandbox_internal_guards_report_invalid_runtime_states(self) -> None:
        resolver = PipResolver(sandbox_mode="off")
        with self.assertRaisesRegex(ResolutionError, "unsupported resolver sandbox"):
            resolver._sandbox_command(
                ["python"],
                mode="unknown",
                workspace=Path.cwd(),
            )
        resolver.container_runtime = ""
        resolver.executable_finder = lambda executable: None
        self.assertIsNone(resolver._container_executable(required=False))
        with patch.object(PipResolver, "_container_executable", return_value=None):
            with self.assertRaisesRegex(ResolutionError, "runtime is unavailable"):
                resolver._container_command(["python"], Path.cwd())

    def test_container_path_translation_handles_uris_and_relative_workspaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir).resolve()
            translated = _containerize_argument(
                f"demo @ {workspace.as_uri()}/demo.whl",
                workspace,
            )
            self.assertEqual(translated, "demo @ file:///workspace/demo.whl")
            with self.assertRaisesRegex(ResolutionError, "cannot mount"):
                _containerize_argument(
                    "demo @ file:///outside/demo.whl",
                    workspace,
                )
        self.assertEqual(_containerize_argument("demo", Path(".")), "demo")

    def test_bubblewrap_bind_selection_removes_nested_paths(self) -> None:
        binds = _bubblewrap_readonly_binds(
            Path(sys.prefix),
            Path(sys.executable),
        )
        self.assertEqual(len(binds), len(set(binds)))
        self.assertTrue(any(Path(sys.prefix).is_relative_to(path) for path in binds))

    def test_requirement_preflight_helpers_cover_malformed_and_nested_inputs(self) -> None:
        self.assertEqual(
            _logical_requirement_lines(
                "# comment\n\n"
                "demo==1 \\\n"
                "  --hash=sha256:abc\n"
                "unfinished \\\n"
            ),
            ["demo==1 --hash=sha256:abc", "unfinished"],
        )
        self.assertIsNone(_nested_requirement_path("'unterminated"))
        self.assertIsNone(_nested_requirement_path(""))
        self.assertIsNone(_nested_requirement_path("-r"))
        self.assertEqual(_nested_requirement_path("-rnested.txt"), "nested.txt")
        self.assertEqual(
            _nested_requirement_path("--constraint=constraints.txt"),
            "constraints.txt",
        )
        self.assertIsNone(_nested_requirement_path("demo>=1"))

        self.assertEqual(_requirement_risks(""), [])
        self.assertEqual(_requirement_risks("# ignored"), [])
        self.assertEqual(_requirement_risks("--hash=sha256:abc"), [])
        self.assertEqual(_requirement_risks("demo>=1"), [])
        self.assertEqual(_path_requirement_risks("demo.whl"), [])
        self.assertEqual(
            _path_requirement_risks("demo.tar.gz"),
            ["source archive requirement"],
        )
        self.assertEqual(
            _requirement_risks("demo @ file:///project/demo"),
            ["local path requirement without a prebuilt wheel"],
        )

    def test_sandbox_input_staging_covers_nested_files_and_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace = root / "workspace"
            destination = root / "stage"
            workspace.mkdir()
            destination.mkdir()
            first = workspace / "first.txt"
            second = workspace / "second.txt"
            wheel = workspace / "local.whl"
            project = workspace / "pyproject.toml"
            first.write_text("-r second.txt\n", encoding="utf-8")
            second.write_text("-r first.txt\n", encoding="utf-8")
            wheel.write_bytes(b"wheel")
            project.write_text(
                "[dependency-groups]\n"
                "base = ['./local.whl']\n"
                "dev = [{include-group = 'base'}, 'demo']\n"
                "cycle = [{include-group = 'cycle'}]\n",
                encoding="utf-8",
            )

            staged = _stage_sandbox_inputs(
                [
                    "-rfirst.txt",
                    "--constraint",
                    str(second),
                    "--group",
                    f"{project}:dev",
                    f"--group={project}:cycle",
                    "--group",
                    "missing-separator",
                    "--group=missing-separator",
                    str(wheel),
                    "--requirement",
                ],
                workspace=workspace,
                destination=destination,
            )

            self.assertTrue((destination / "first.txt").is_file())
            self.assertTrue((destination / "second.txt").is_file())
            self.assertTrue((destination / "local.whl").is_file())
            self.assertTrue((destination / "pyproject.toml").is_file())
            self.assertIn(str(destination / "local.whl"), staged)

    def test_sandbox_input_staging_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace = root / "workspace"
            destination = root / "stage"
            outside = root / "outside.txt"
            workspace.mkdir()
            destination.mkdir()
            outside.write_text("demo\n", encoding="utf-8")

            with self.assertRaisesRegex(ResolutionError, "outside"):
                _stage_sandbox_inputs(
                    [str(outside)],
                    workspace=workspace,
                    destination=destination,
                )
            with self.assertRaisesRegex(ResolutionError, "not found"):
                _stage_sandbox_inputs(
                    ["./missing.whl"],
                    workspace=workspace,
                    destination=destination,
                )
            with self.assertRaisesRegex(ResolutionError, "requirement file"):
                _stage_sandbox_inputs(
                    ["--requirement", str(workspace)],
                    workspace=workspace,
                    destination=destination,
                )

            invalid_project = workspace / "pyproject.toml"
            invalid_project.write_text("not = [valid", encoding="utf-8")
            with self.assertRaisesRegex(ResolutionError, "dependency group"):
                _stage_sandbox_inputs(
                    ["--group", f"{invalid_project}:dev"],
                    workspace=workspace,
                    destination=destination,
                )

    def test_local_requirement_staging_helpers_cover_supported_forms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            local = root / "local-demo"
            local.mkdir()
            forms = (
                f"-e {local}",
                f"--editable={local}",
                f"-f {local}",
                f"--find-links={local}",
                f"demo @ {local.as_uri()}",
                f"{local}[testing]",
            )
            for value in forms:
                with self.subTest(value=value):
                    self.assertEqual(
                        _local_requirement_path(value, root),
                        local,
                    )

            self.assertEqual(_resolve_local_path(local.as_uri(), root), local)
            self.assertIsNone(_local_requirement_path("", root))
            self.assertIsNone(_local_requirement_path("'unterminated", root))
            self.assertIsNone(_local_requirement_path("--editable", root))
            self.assertIsNone(_local_requirement_path("--index-url value", root))
            self.assertIsNone(_local_requirement_path("demo>=1", root))
            self.assertIsNone(
                _local_requirement_path("demo @ https://example.com/demo.whl", root)
            )
            self.assertIsNone(
                _local_requirement_path("git+https://example.com/demo.git", root)
            )
            self.assertIsNone(
                _local_requirement_path("https://example.com/demo.whl", root)
            )
            self.assertEqual(
                _translate_workspace_reference(
                    f"{root}/local-demo {root.as_uri()}/local-demo",
                    root,
                    "/workspace",
                ),
                "/workspace/local-demo file:///workspace/local-demo",
            )
            self.assertEqual(
                _translate_workspace_reference("demo", root, "relative"),
                "demo",
            )

    def test_requirement_file_preflight_handles_cycles_and_read_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("-r second.txt\n", encoding="utf-8")
            second.write_text("-r first.txt\n", encoding="utf-8")
            self.assertEqual(_requirement_file_risks([first]), [])

            with patch.object(
                Path,
                "read_text",
                side_effect=OSError("denied"),
            ), self.assertRaisesRegex(ResolutionError, "unable to inspect"):
                _requirement_file_risks([first])

    def test_dependency_group_preflight_handles_invalid_or_missing_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir) / "pyproject.toml"
            project.write_text("not valid = [", encoding="utf-8")
            with self.assertRaisesRegex(ResolutionError, "unable to inspect"):
                _dependency_group_risks(project, "dev")

            project.write_text("[project]\nname = 'demo'\n", encoding="utf-8")
            self.assertEqual(_dependency_group_risks(project, "dev"), [])
            project.write_text(
                "[dependency-groups]\ndev = 'not-a-list'\n",
                encoding="utf-8",
            )
            self.assertEqual(_dependency_group_risks(project, "dev"), [])

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
