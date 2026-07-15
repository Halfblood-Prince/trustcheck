from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
import venv
import warnings
import zipfile
from contextlib import redirect_stdout
from importlib.metadata import distributions
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from trustcheck.cli import main as cli_main
from trustcheck.plugin_manifest import (
    build_plugin_manifest_draft,
    fingerprint_public_key,
    fingerprint_public_key_file,
    sign_plugin_wheel,
    verify_plugin_manifest,
)
from trustcheck.plugins import PluginError, PluginManager


class PluginManifestToolTests(unittest.TestCase):
    def test_signs_real_wheel_discovers_plugin_and_rejects_tampering(self) -> None:
        try:
            import build  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("python-build is not installed")

        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-wheel-") as temp:
            root = Path(temp)
            project = root / "project"
            dist = root / "dist"
            project.mkdir()
            dist.mkdir()
            _write_plugin_project(project)
            wheel = _build_wheel(project, dist)
            key_path, public_key_path, signer = _write_key_pair(root)

            draft = build_plugin_manifest_draft(wheel)
            self.assertEqual(
                draft["schema"],
                "urn:trustcheck:plugin-manifest:2",
            )
            self.assertEqual(
                draft["manifest"]["schema"],
                "urn:trustcheck:plugin-statement:2",
            )

            summary = sign_plugin_wheel(wheel, key=key_path)
            verified = verify_plugin_manifest(wheel)
            self.assertEqual(summary.signer_sha256, signer)
            self.assertEqual(verified.signer_sha256, signer)
            self.assertEqual(fingerprint_public_key_file(public_key_path), signer)
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    ["plugin-manifest", "fingerprint", str(public_key_path)]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().strip(), signer)
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(["plugin-manifest", "verify", str(wheel)])
            self.assertEqual(exit_code, 0)
            self.assertIn("plugin manifest verified:", stdout.getvalue())
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    ["plugin-manifest", "verify", "--format", "json", str(wheel)]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                json.loads(stdout.getvalue())["trust_policy"],
                "not evaluated",
            )

            site_packages = _install_wheel_into_venv(wheel, root / "venv")
            sys.path.insert(0, str(site_packages))
            importlib.invalidate_caches()
            try:
                manager = PluginManager(
                    enabled=True,
                    allowlist=("advisory:demo",),
                    trusted_signers=(signer,),
                    entry_point_loader=_entry_points_from(site_packages),
                    timeout=10,
                )
                records = manager.advisory_sources()[0].query("demo", "1.0")
                self.assertEqual(records[0].id, "PLUGIN-demo-1.0")
                self.assertTrue(manager.executions())
                self.assertTrue(manager.executions()[0].resource_bounded)

                plugin_file = site_packages / "demo_plugin.py"
                _write_malicious_timestamp_pyc(plugin_file)
                sys.modules.pop("demo_plugin", None)
                poisoned = PluginManager(
                    enabled=True,
                    allowlist=("advisory:demo",),
                    trusted_signers=(signer,),
                    entry_point_loader=_entry_points_from(site_packages),
                    timeout=10,
                )
                records = poisoned.advisory_sources()[0].query("demo", "1.0")
                self.assertEqual(records[0].id, "PLUGIN-demo-1.0")

                plugin_file.write_text(
                    plugin_file.read_text(encoding="utf-8") + "\n# tampered\n",
                    encoding="utf-8",
                )
                tampered = PluginManager(
                    enabled=True,
                    allowlist=("advisory:demo",),
                    trusted_signers=(signer,),
                    entry_point_loader=_entry_points_from(site_packages),
                    timeout=10,
                )
                with self.assertRaisesRegex(PluginError, "hash does not match RECORD"):
                    tampered.advisory_sources()
            finally:
                sys.path.remove(str(site_packages))
                sys.modules.pop("demo_plugin", None)

    def test_signing_preserves_unchanged_zip_metadata_and_separate_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-sign-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(root)
            key_path, _, signer = _write_key_pair(root)
            output = root / "signed" / wheel.name

            with patch.dict("os.environ", {"SOURCE_DATE_EPOCH": "1704164646"}):
                summary = sign_plugin_wheel(wheel, key=key_path, output=output)

            self.assertEqual(summary.signer_sha256, signer)
            self.assertTrue(output.is_file())
            with zipfile.ZipFile(output) as archive:
                helper = archive.getinfo("bin/helper")
                manifest = archive.getinfo("trustcheck-plugin.json")
                record = archive.getinfo("trustcheck_demo_plugin-1.0.0.dist-info/RECORD")
            self.assertEqual(helper.date_time, (2024, 1, 2, 3, 4, 6))
            self.assertEqual((helper.external_attr >> 16) & 0o777, 0o755)
            self.assertEqual(helper.compress_type, zipfile.ZIP_STORED)
            self.assertEqual(manifest.date_time, (2024, 1, 2, 3, 4, 6))
            self.assertEqual(record.date_time, (2024, 1, 2, 3, 4, 6))

    def test_signing_rejects_console_script_layout_and_invalid_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-sign-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(root, console_script=True)
            key_path, _, _ = _write_key_pair(root)

            with self.assertRaisesRegex(PluginError, "console_scripts"):
                sign_plugin_wheel(wheel, key=key_path)
            with self.assertRaisesRegex(PluginError, ".whl"):
                sign_plugin_wheel(wheel, key=key_path, output=root / "signed.zip")

    def test_signing_and_fingerprint_wrap_key_loading_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-keys-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(root)
            invalid_key = root / "invalid-key.pem"
            invalid_key.write_text("not a key\n", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "private key"):
                sign_plugin_wheel(wheel, key=invalid_key)
            with self.assertRaisesRegex(PluginError, "public key"):
                fingerprint_public_key_file(invalid_key)

            encrypted_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            encrypted_path = root / "encrypted-key.pem"
            encrypted_path.write_bytes(
                encrypted_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(b"password"),
                )
            )
            with self.assertRaisesRegex(PluginError, "private key"):
                sign_plugin_wheel(wheel, key=encrypted_path)

    def test_signing_rejects_invalid_wheel_layouts(self) -> None:
        layout_cases = [
            (
                {"omit_metadata": True},
                "exactly one METADATA",
            ),
            (
                {
                    "extra_entries": {
                        "other-1.0.0.dist-info/METADATA": (
                            b"Metadata-Version: 2.1\nName: other\nVersion: 1\n"
                        )
                    }
                },
                "exactly one METADATA",
            ),
            ({"omit_record": True}, "RECORD"),
            ({"entry_points": ""}, "does not declare"),
            (
                {
                    "entry_points": (
                        "[trustcheck.advisory_sources]\n"
                        "demo = demo_plugin:Plugin\n"
                        "[trustcheck.policy_rules]\n"
                        "other = demo_plugin:Plugin\n"
                    )
                },
                "exactly one",
            ),
            (
                {
                    "entry_points": (
                        "[trustcheck.advisory_sources]\n"
                        "bad = not-a-module\n"
                    )
                },
                "invalid Trustcheck entry point",
            ),
        ]
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-layout-") as temp:
            base = Path(temp)
            key_path, _, _ = _write_key_pair(base)
            for index, (kwargs, message) in enumerate(layout_cases):
                root = base / f"case-{index}"
                root.mkdir()
                wheel = _write_minimal_plugin_wheel(root, **kwargs)
                with self.subTest(message=message), self.assertRaisesRegex(
                    PluginError,
                    message,
                ):
                    sign_plugin_wheel(wheel, key=key_path)

            duplicate = base / "duplicate-1.0.0-py3-none-any.whl"
            _write_minimal_plugin_wheel(base / "duplicate-source", output=duplicate)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "a") as archive:
                    archive.writestr("demo_plugin.py", b"duplicate\n")
            with self.assertRaisesRegex(PluginError, "duplicate"):
                sign_plugin_wheel(duplicate, key=key_path)

            unsafe = base / "unsafe-1.0.0-py3-none-any.whl"
            _write_minimal_plugin_wheel(base / "unsafe-source", output=unsafe)
            with zipfile.ZipFile(unsafe, "a") as archive:
                archive.writestr("../evil.py", b"evil\n")
            with self.assertRaisesRegex(PluginError, "unsafe path"):
                sign_plugin_wheel(unsafe, key=key_path)

    def test_verify_rejects_malformed_and_oversized_wheels(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-verify-") as temp:
            root = Path(temp)
            malformed = root / "demo-1.0-py3-none-any.whl"
            malformed.write_bytes(b"not a zip")
            with self.assertRaisesRegex(PluginError, "valid zip"):
                verify_plugin_manifest(malformed)

            wheel = _write_minimal_plugin_wheel(root)
            key_path, _, _ = _write_key_pair(root)
            with patch(
                "trustcheck.plugin_manifest.MAX_ARCHIVE_MEMBERS",
                1,
            ):
                with self.assertRaisesRegex(PluginError, "members"):
                    sign_plugin_wheel(wheel, key=key_path)

    def test_plugin_manifest_help_is_authoring_scoped(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            cli_main(["plugin-manifest", "sign", "--help"])

        self.assertEqual(raised.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("--key", help_text)
        self.assertIn("--output", help_text)
        self.assertNotIn("--enable-plugins", help_text)
        self.assertNotIn("--workers", help_text)
        self.assertNotIn("--advisory-snapshot", help_text)


def _write_plugin_project(project: Path) -> None:
    (project / "pyproject.toml").write_text(
        """
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "trustcheck-demo-plugin"
version = "1.0.0"
dependencies = []

[project.entry-points."trustcheck.advisory_sources"]
demo = "demo_plugin:Plugin"

[tool.setuptools]
py-modules = ["demo_plugin"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (project / "demo_plugin.py").write_text(
        """
from trustcheck.models import VulnerabilityRecord


class Plugin:
    name = "demo"

    def query(self, project, version):
        return [VulnerabilityRecord(id=f"PLUGIN-{project}-{version}", summary="demo")]
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_malicious_timestamp_pyc(source: Path) -> None:
    code = compile(
        """
from trustcheck.models import VulnerabilityRecord


class Plugin:
    name = "demo"

    def query(self, project, version):
        return [VulnerabilityRecord(id="MALICIOUS", summary="bad")]
""".strip()
        + "\n",
        str(source),
        "exec",
    )
    cache_path = Path(importlib.util.cache_from_source(str(source)))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    stat = source.stat()
    payload = importlib._bootstrap_external._code_to_timestamp_pyc(
        code,
        int(stat.st_mtime),
        stat.st_size,
    )
    cache_path.write_bytes(payload)


def _write_minimal_plugin_wheel(
    root: Path,
    *,
    console_script: bool = False,
    entry_points: str | None = None,
    extra_entries: dict[str, bytes] | None = None,
    omit_metadata: bool = False,
    omit_record: bool = False,
    output: Path | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    wheel = output or root / "trustcheck_demo_plugin-1.0.0-py3-none-any.whl"
    dist_info = "trustcheck_demo_plugin-1.0.0.dist-info"
    entry_points_payload = (
        "[trustcheck.advisory_sources]\n"
        "demo = demo_plugin:Plugin\n"
        if entry_points is None
        else entry_points
    )
    if console_script:
        entry_points_payload += "\n[console_scripts]\ndemo-cli = demo_plugin:main\n"
    entries = {
        "demo_plugin.py": b"class Plugin:\n    name = 'demo'\n",
        "bin/helper": b"#!/bin/sh\nexit 0\n",
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: trustcheck-demo-plugin\n"
            "Version: 1.0.0\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: trustcheck fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8"),
        f"{dist_info}/entry_points.txt": entry_points_payload.encode("utf-8"),
    }
    if omit_metadata:
        entries.pop(f"{dist_info}/METADATA")
    if not omit_record:
        entries[f"{dist_info}/RECORD"] = b""
    if extra_entries:
        entries.update(extra_entries)
    wheel.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 2, 3, 4, 6))
            info.compress_type = (
                zipfile.ZIP_STORED
                if name == "bin/helper"
                else zipfile.ZIP_DEFLATED
            )
            info.create_system = 3
            mode = 0o100755 if name == "bin/helper" else 0o100644
            info.external_attr = mode << 16
            archive.writestr(info, payload)
    return wheel


def _build_wheel(project: Path, dist: Path) -> Path:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(dist),
            str(project),
        ],
        check=False,
        cwd=project,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "plugin fixture wheel build failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected one wheel, found {wheels!r}")
    return wheels[0]


def _write_key_pair(root: Path) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = root / "plugin-key.pem"
    public_key_path = root / "plugin-key.pub.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = key.public_key()
    public_key_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key_path, public_key_path, fingerprint_public_key(public_key)


def _install_wheel_into_venv(wheel: Path, venv_dir: Path) -> Path:
    venv.create(venv_dir, with_pip=True)
    python = (
        venv_dir / "Scripts" / "python.exe"
        if sys.platform == "win32"
        else venv_dir / "bin" / "python"
    )
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    completed = subprocess.run(
        [
            str(python),
            "-c",
            "import json, site; print(json.dumps(site.getsitepackages()))",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    paths = [Path(item) for item in json.loads(completed.stdout)]
    for path in paths:
        if path.name == "site-packages":
            return path
    return paths[-1]


def _entry_points_from(site_packages: Path):
    def load(*, group: str):
        found = []
        for distribution in distributions(path=[str(site_packages)]):
            found.extend(
                entry_point
                for entry_point in distribution.entry_points
                if entry_point.group == group
            )
        return found

    return load


if __name__ == "__main__":
    unittest.main()
