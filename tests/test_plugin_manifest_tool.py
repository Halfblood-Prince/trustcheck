from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
import venv
from contextlib import redirect_stdout
from importlib.metadata import distributions
from io import StringIO
from pathlib import Path

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
