from __future__ import annotations

import io
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_distribution_artifacts import (
    ArtifactValidationError,
    validate_artifact,
)


def _write_wheel(path: Path, extra_files: dict[str, bytes] | None = None) -> None:
    files = {
        "trustcheck/__init__.py": b"__version__ = '1.0.0'\n",
        "trustcheck/py.typed": b"",
        "trustcheck/plugin_schemas/plugin-ipc-request-1.json": b"{}",
        "trustcheck-1.0.0.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: trustcheck\nVersion: 1.0.0\n"
        ),
        "trustcheck-1.0.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        "trustcheck-1.0.0.dist-info/RECORD": b"",
    }
    files.update(extra_files or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def _write_sdist(path: Path, extra_files: dict[str, bytes] | None = None) -> None:
    files = {
        "trustcheck-1.0.0/PKG-INFO": (
            b"Metadata-Version: 2.4\nName: trustcheck\nVersion: 1.0.0\n"
        ),
        "trustcheck-1.0.0/MANIFEST.in": b"include README.md\n",
        "trustcheck-1.0.0/pyproject.toml": b"[project]\nname = 'trustcheck'\n",
        "trustcheck-1.0.0/scripts/validate_distribution_artifacts.py": b"pass\n",
        "trustcheck-1.0.0/scripts/verify_release_version.py": b"pass\n",
        "trustcheck-1.0.0/src/trustcheck/_version.py": b"version = '1.0.0'\n",
        "trustcheck-1.0.0/src/trustcheck/py.typed": b"",
        "trustcheck-1.0.0/tests/test_release_version.py": b"def test_ok(): pass\n",
    }
    files.update(extra_files or {})
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


class DistributionArtifactValidationTests(unittest.TestCase):
    def test_clean_synthetic_wheel_and_sdist_validate(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "trustcheck-1.0.0-py3-none-any.whl"
            sdist = root / "trustcheck-1.0.0.tar.gz"
            _write_wheel(wheel)
            _write_sdist(sdist)

            validate_artifact(wheel)
            validate_artifact(sdist)

    def test_rejects_bytecode_cache_and_temporary_test_output(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "trustcheck-1.0.0-py3-none-any.whl"
            sdist = root / "trustcheck-1.0.0.tar.gz"
            _write_wheel(wheel, {"trustcheck/__pycache__/cli.cpython-314.pyc": b"x"})
            _write_sdist(sdist, {"trustcheck-1.0.0/tests/_tmp/report.json": b"{}"})

            with self.assertRaisesRegex(ArtifactValidationError, "bytecode|cache"):
                validate_artifact(wheel)
            with self.assertRaisesRegex(ArtifactValidationError, "temporary test output"):
                validate_artifact(sdist)

    def test_rejects_local_reports_plugin_bundles_and_unexpected_binaries(self) -> None:
        cases = {
            "coverage": {"trustcheck-1.0.0/coverage.xml": b"<coverage />"},
            "plugin": {"trustcheck-1.0.0/plugins/agent-plugin/plugin.json": b"{}"},
            "binary": {"trustcheck-1.0.0/dist/trustcheck.exe": b"MZ"},
        }
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, extra in cases.items():
                with self.subTest(name=name):
                    sdist = root / f"trustcheck-1.0.0-{name}.tar.gz"
                    _write_sdist(sdist, extra)
                    with self.assertRaises(ArtifactValidationError):
                        validate_artifact(sdist)

    def test_rejects_secret_markers_and_unsafe_archive_paths(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "trustcheck-1.0.0-secret.tar.gz"
            traversal = root / "trustcheck-1.0.0-traversal.tar.gz"
            _write_sdist(
                secret,
                {"trustcheck-1.0.0/reports/token.txt": b"PYPI_" b"TOKEN=pypi-" b"AgEIsecret"},
            )
            with tarfile.open(traversal, "w:gz") as archive:
                payload = b"x"
                info = tarfile.TarInfo("../escape.txt")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))

            with self.assertRaisesRegex(ArtifactValidationError, "secret-like"):
                validate_artifact(secret)
            with self.assertRaisesRegex(ArtifactValidationError, "unsafe archive path"):
                validate_artifact(traversal)


if __name__ == "__main__":
    unittest.main()
