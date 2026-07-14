from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from trustcheck.cli_commands import doctor as doctor_command
from trustcheck.doctor import (
    _bubblewrap_check,
    _cache_permissions_check,
    _directory_writable,
    _externally_managed_environment_check,
    _first_output_line,
    _keyring_check,
    _lockfile_tools_check,
    _module_available,
    _pip_runtime_check,
    _private_index_auth_check,
    _resolver_container_image_check,
    _sandbox_selection_check,
    _sigstore_check,
    _sigstore_state_directories,
    collect_doctor_report,
    render_doctor_json,
    render_doctor_text,
    supported_lockfile_patterns,
)


def pip_version_runner(version: str = "26.1.2", *, returncode: int = 0):
    def runner(command, **kwargs):
        del kwargs
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout=f"pip {version} from /env/site-packages/pip (python 3.13)",
            stderr="",
        )

    return runner


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
                command_runner=pip_version_runner(),
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
        self.assertEqual(checks["Resolver pip"].status, "pass")
        self.assertEqual(checks["Externally managed Python"].status, "pass")
        self.assertEqual(checks["Keyring"].status, "pass")
        self.assertEqual(checks["Sigstore trust roots"].status, "pass")
        self.assertEqual(checks["Private-index authentication"].status, "pass")
        self.assertEqual(checks["Cache permissions"].status, "pass")
        self.assertEqual(checks["Resolver container image"].status, "pass")
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
                command_runner=pip_version_runner(),
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
        self.assertEqual(checks["Resolver pip"].status, "pass")

    def test_check_helpers_cover_platform_and_configuration_branches(self) -> None:
        self.assertEqual(
            _bubblewrap_check(
                executable_finder=lambda name: None,
                platform_system="Windows",
            ).status,
            "warn",
        )
        self.assertEqual(
            _keyring_check(
                keyring_provider="disabled",
                module_checker=lambda name: False,
            ).status,
            "warn",
        )
        self.assertEqual(
            _private_index_auth_check(
                index_urls=("https://pypi.org/simple/",),
                keyring_provider="auto",
                keyring_available=False,
            ).status,
            "pass",
        )
        username_only = _private_index_auth_check(
            index_urls=("https://user@packages.example/simple/",),
            keyring_provider="auto",
            keyring_available=True,
        )
        self.assertEqual(username_only.status, "pass")
        self.assertIn("packages.example", username_only.evidence[0])
        self.assertEqual(
            _cache_permissions_check(cache_dir=None, environ={}).status,
            "warn",
        )
        self.assertEqual(
            _sandbox_selection_check(
                sandbox_mode="invalid",
                executable_finder=lambda name: None,
                platform_system="Linux",
            ).status,
            "fail",
        )
        self.assertEqual(
            _sandbox_selection_check(
                sandbox_mode="off",
                executable_finder=lambda name: None,
                platform_system="Linux",
            ).status,
            "pass",
        )
        self.assertEqual(
            _sandbox_selection_check(
                sandbox_mode="bubblewrap",
                executable_finder=lambda name: "/usr/bin/bwrap"
                if name == "bwrap"
                else None,
                platform_system="Linux",
            ).status,
            "pass",
        )
        self.assertEqual(
            _sandbox_selection_check(
                sandbox_mode="auto",
                executable_finder=lambda name: "/usr/bin/docker"
                if name == "docker"
                else None,
                platform_system="Windows",
            ).status,
            "pass",
        )
        self.assertEqual(
            _sandbox_selection_check(
                sandbox_mode="auto",
                executable_finder=lambda name: None,
                platform_system="Windows",
            ).evidence,
            ("fallback=strict-wheel-only",),
        )
        self.assertEqual(
            _pip_runtime_check(
                python_executable=sys.executable,
                command_runner=pip_version_runner("22.2"),
            ).status,
            "pass",
        )
        self.assertEqual(
            _pip_runtime_check(
                python_executable=sys.executable,
                command_runner=pip_version_runner("26.0"),
            ).status,
            "pass",
        )
        self.assertEqual(
            _pip_runtime_check(
                python_executable=sys.executable,
                command_runner=pip_version_runner("21.3"),
            ).status,
            "fail",
        )

        def unavailable_pip(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="pip module missing\nsecond line",
            )

        unavailable = _pip_runtime_check(
            python_executable="python-broken",
            command_runner=unavailable_pip,
        )
        self.assertEqual(unavailable.status, "fail")
        self.assertIn("exit=1", unavailable.evidence)
        self.assertIn("pip module missing", unavailable.evidence)

        def unparsable_pip(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="pip mystery output",
                stderr="",
            )

        unparsable = _pip_runtime_check(
            python_executable="python-weird",
            command_runner=unparsable_pip,
        )
        self.assertEqual(unparsable.status, "fail")
        self.assertIn("pip mystery output", unparsable.evidence)
        self.assertIsNone(_first_output_line("\n  \n"))
        self.assertEqual(_first_output_line("  useful line  \nsecond"), "useful line")
        self.assertEqual(len(_first_output_line("x" * 300) or ""), 240)

        def missing_pip(command, **kwargs):
            del command, kwargs
            raise OSError("missing pip")

        self.assertEqual(
            _pip_runtime_check(
                python_executable="python-missing",
                command_runner=missing_pip,
            ).status,
            "fail",
        )
        self.assertEqual(
            _resolver_container_image_check(
                container_image="python:latest",
            ).status,
            "fail",
        )
        self.assertEqual(
            _resolver_container_image_check(
                container_image="python@sha256:" + "a" * 64,
            ).status,
            "pass",
        )
        lockfiles = _lockfile_tools_check(
            executable_finder=lambda name: f"/usr/bin/{name}",
        )
        self.assertNotIn("missing generators", "\n".join(lockfiles.evidence))
        self.assertIn("pylock", "\n".join(supported_lockfile_patterns()))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("trustcheck.doctor._directory_writable", return_value=False):
                sigstore = _sigstore_check(
                    module_checker=lambda name: True,
                    environ={
                        "XDG_DATA_HOME": str(root / "data"),
                        "XDG_CACHE_HOME": str(root / "cache"),
                        "XDG_CONFIG_HOME": str(root / "config"),
                    },
                    home=root,
                )
                cache = _cache_permissions_check(
                    cache_dir=str(root / "cache"),
                    environ={},
                )
            self.assertEqual(sigstore.status, "fail")
            self.assertEqual(cache.status, "fail")

            file_path = root / "not-a-directory"
            file_path.write_text("x", encoding="utf-8")
            self.assertFalse(_directory_writable(file_path))
            marker_root = root / "stdlib"
            marker_root.mkdir()
            (marker_root / "EXTERNALLY-MANAGED").write_text("", encoding="utf-8")
            self.assertEqual(
                _externally_managed_environment_check(
                    stdlib_path=marker_root,
                    in_virtualenv=False,
                ).status,
                "warn",
            )
            self.assertEqual(
                _externally_managed_environment_check(
                    stdlib_path=marker_root,
                    in_virtualenv=True,
                ).status,
                "pass",
            )

            with patch("trustcheck.doctor.sys.platform", "linux"):
                roots = _sigstore_state_directories(environ={}, home=root)
            self.assertEqual(roots[0], root / ".local" / "share" / "sigstore")

        with patch(
            "trustcheck.doctor.importlib.util.find_spec",
            side_effect=ValueError("bad module"),
        ):
            self.assertFalse(_module_available("bad"))

    def test_doctor_command_renders_json_text_and_strict_status(self) -> None:
        passed_report = SimpleNamespace(passed=True)
        failed_report = SimpleNamespace(passed=False)
        emitted: list[tuple[str, str | None]] = []
        facade = SimpleNamespace(
            EXIT_OK=0,
            EXIT_POLICY_FAILURE=2,
            _emit_output=lambda rendered, output_file: emitted.append(
                (rendered, output_file)
            ),
        )
        context = SimpleNamespace(facade=facade)

        json_args = SimpleNamespace(
            cache_dir=".cache",
            index_url="https://pypi.org/simple/",
            extra_index_url=[],
            keyring_provider="auto",
            sandbox="strict",
            sandbox_image=None,
            format="json",
            output_file="doctor.json",
            strict=False,
        )
        with (
            patch.object(
                doctor_command,
                "collect_doctor_report",
                return_value=passed_report,
            ) as collect,
            patch.object(
                doctor_command,
                "render_doctor_json",
                return_value='{"passed": true}',
            ),
            patch.object(
                doctor_command,
                "render_doctor_text",
                return_value="unused",
            ),
        ):
            self.assertEqual(doctor_command.run(json_args, context), 0)

        collect.assert_called_once_with(
            cache_dir=".cache",
            index_urls=("https://pypi.org/simple/",),
            keyring_provider="auto",
            sandbox_mode="strict",
            sandbox_image=None,
        )
        self.assertEqual(emitted[-1], ('{"passed": true}', "doctor.json"))

        text_args = SimpleNamespace(
            cache_dir=None,
            index_url="https://pypi.org/simple/",
            extra_index_url=["https://packages.example/simple/"],
            keyring_provider="import",
            sandbox="container",
            sandbox_image="python@sha256:" + "a" * 64,
            format="text",
            output_file=None,
            strict=True,
        )
        with (
            patch.object(
                doctor_command,
                "collect_doctor_report",
                return_value=failed_report,
            ),
            patch.object(
                doctor_command,
                "render_doctor_json",
                return_value="unused",
            ),
            patch.object(
                doctor_command,
                "render_doctor_text",
                return_value="trustcheck doctor",
            ),
        ):
            self.assertEqual(doctor_command.run(text_args, context), 2)

        self.assertEqual(emitted[-1], ("trustcheck doctor", None))

    def test_cli_diagnostics_run_without_importable_sigstore(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            str(root / "src")
            + os.pathsep
            + env.get("PYTHONPATH", "")
        ).rstrip(os.pathsep)
        script = r'''
import importlib.abc
import io
import json
import sys
import tempfile
from contextlib import redirect_stdout


class BlockSigstore(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "sigstore" or fullname.startswith("sigstore."):
            raise ModuleNotFoundError("No module named 'sigstore'", name="sigstore")
        return None


sys.meta_path.insert(0, BlockSigstore())

import trustcheck
from trustcheck.cli import main
from trustcheck.doctor import collect_doctor_report

assert trustcheck.__version__
assert collect_doctor_report(module_checker=lambda name: False).checks

for args in (["--help"], ["--version"]):
    output = io.StringIO()
    try:
        with redirect_stdout(output):
            result = main(args)
    except SystemExit as exc:
        result = exc.code
    assert result == 0, (args, result, output.getvalue())

output = io.StringIO()
with redirect_stdout(output):
    result = main(
        [
            "doctor",
            "--format",
            "json",
            "--cache-dir",
            tempfile.mkdtemp(),
            "--sandbox",
            "strict",
        ]
    )
assert result == 0, result
payload = json.loads(output.getvalue())
assert payload["passed"] is False
assert any(
    check["name"] == "Sigstore trust roots" and check["status"] == "fail"
    for check in payload["checks"]
)
'''
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
