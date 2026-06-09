from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import unittest
import zipfile
from collections.abc import Mapping
from unittest.mock import Mock, patch

from trustcheck.artifacts import (
    MAX_METADATA_BYTES,
    OVERSIZED_FILE_BYTES,
    _canonical_requirements,
    _inspect_wheel_contents,
    _inspect_zip_structure,
    _read_tar_member,
    _record_sdist_file_findings,
    compare_artifact_metadata,
    inspect_artifact,
)
from trustcheck.models import ArtifactInspection


def build_wheel(
    *,
    project: str = "demo",
    version: str = "1.0.0",
    module_payload: bytes = b"VALUE = 1\n",
    tamper_module_after_record: bool = False,
    native_file: bool = False,
    entry_points: str | bytes | None = None,
    metadata_payload: bytes | None = None,
    wheel_payload: bytes | None = None,
    extra_files: Mapping[str, bytes] | None = None,
) -> bytes:
    dist_info = f"{project}-{version}.dist-info"
    files: dict[str, bytes] = {
        f"{project}/__init__.py": module_payload,
        f"{dist_info}/METADATA": metadata_payload
        or (
            f"Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n"
            "Requires-Dist: packaging>=24\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": wheel_payload
        or (
            "Wheel-Version: 1.0\nGenerator: trustcheck-tests\n"
            f"Root-Is-Purelib: {'false' if native_file else 'true'}\n"
            f"Tag: {'cp312-abi3-any' if native_file else 'py3-none-any'}\n"
        ).encode(),
    }
    if native_file:
        files[f"{project}/native.pyd"] = b"MZ\x00native-extension"
    if entry_points is not None:
        files[f"{dist_info}/entry_points.txt"] = (
            entry_points.encode() if isinstance(entry_points, str) else entry_points
        )
    files.update(extra_files or {})

    record_rows = []
    for name, payload in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        record_rows.append(f"{name},sha256={digest.decode()},{len(payload)}")
    record_name = f"{dist_info}/RECORD"
    record_rows.append(f"{record_name},,")
    files[record_name] = ("\n".join(record_rows) + "\n").encode()

    if tamper_module_after_record:
        files[f"{project}/__init__.py"] = b"VALUE = 2\n"

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return output.getvalue()


def build_sdist(
    *,
    project: str = "demo",
    version: str = "1.0.0",
    requires_dist: str = "packaging>=24",
    setup_payload: bytes = b"from setuptools import setup\nsetup()\n",
) -> bytes:
    output = io.BytesIO()
    root = f"{project}-{version}"
    files = {
        f"{root}/PKG-INFO": (
            f"Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n"
            f"Requires-Dist: {requires_dist}\n\n"
        ).encode(),
        f"{root}/setup.py": setup_payload,
        f"{root}/secrets.pem": b"not-a-real-key",
    }
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o755 if name.endswith("setup.py") else 0o644
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


class WheelArtifactInspectionTests(unittest.TestCase):
    def test_valid_wheel_record_console_scripts_and_top_level_files(self) -> None:
        payload = build_wheel(
            entry_points="[console_scripts]\nDemo-Tool = demo.cli:main\n",
            extra_files={"NOTICE.txt": b"notice"},
        )

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            payload,
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertTrue(result.archive_valid)
        self.assertTrue(result.record_valid)
        self.assertEqual(result.console_scripts, ["Demo-Tool = demo.cli:main"])
        self.assertEqual(result.unexpected_top_level_files, ["NOTICE.txt"])
        self.assertEqual(result.wheel_version, "1.0")
        self.assertTrue(result.wheel_root_is_purelib)
        self.assertEqual(result.wheel_tags, ["py3-none-any"])
        self.assertEqual(result.metadata_mismatches, [])

    def test_tampered_wheel_fails_record_hash_validation(self) -> None:
        payload = build_wheel(tamper_module_after_record=True)

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            payload,
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertFalse(result.record_valid)
        self.assertIn("hash does not match RECORD", "\n".join(result.record_errors))

    def test_native_extension_and_suspicious_entry_point_are_reported(self) -> None:
        payload = build_wheel(
            native_file=True,
            entry_points="[console_scripts]\nrun-system = os:system\n",
        )

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            payload,
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertEqual(result.native_files, ["demo/native.pyd"])
        self.assertEqual(result.suspicious_entry_points, ["run-system = os:system"])

    def test_wheel_inspection_does_not_import_or_execute_package_code(self) -> None:
        payload = build_wheel(
            module_payload=b"raise RuntimeError('package code executed')\n"
        )

        with patch("importlib.import_module") as import_module:
            result = inspect_artifact(
                "demo-1.0.0-py3-none-any.whl",
                payload,
                expected_project="demo",
                expected_version="1.0.0",
            )

        self.assertTrue(result.record_valid)
        import_module.assert_not_called()

    def test_missing_record_and_metadata_mismatch_are_reported(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(
                "other-2.0.0.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: other\nVersion: 2.0.0\n\n",
            )

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertFalse(result.record_valid)
        self.assertGreaterEqual(len(result.metadata_mismatches), 3)

    def test_artifact_dependencies_are_compared_with_release_metadata(self) -> None:
        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(),
            expected_project="demo",
            expected_version="1.0.0",
            expected_requires_dist=["packaging>=25"],
        )

        self.assertIn(
            "artifact Requires-Dist metadata does not match selected release metadata",
            result.metadata_mismatches,
        )

    def test_legacy_record_signatures_do_not_need_record_rows(self) -> None:
        payload = build_wheel(
            extra_files={
                "demo-1.0.0.dist-info/RECORD.jws": b"deprecated-signature",
                "demo-1.0.0.dist-info/RECORD.p7s": b"deprecated-signature",
            }
        )
        with zipfile.ZipFile(io.BytesIO(payload), "r") as source:
            files = {
                member.filename: source.read(member)
                for member in source.infolist()
                if not member.is_dir()
            }
        record_name = "demo-1.0.0.dist-info/RECORD"
        record = files[record_name].decode()
        record = "\n".join(
            line
            for line in record.splitlines()
            if not line.startswith(f"{record_name}.jws,")
            and not line.startswith(f"{record_name}.p7s,")
        )
        files[record_name] = (record + "\n").encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertTrue(result.record_valid)

    def test_unsupported_and_corrupt_archives_are_reported(self) -> None:
        unsupported = inspect_artifact(
            "demo-1.0.0.exe",
            b"binary",
            expected_project="demo",
            expected_version="1.0.0",
        )
        wheel = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            b"not a zip file",
            expected_project="demo",
            expected_version="1.0.0",
        )
        sdist = inspect_artifact(
            "demo-1.0.0.tar.gz",
            b"not a tar file",
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertEqual(unsupported.kind, "unsupported")
        self.assertIn("not supported", unsupported.error or "")
        self.assertFalse(wheel.archive_valid)
        self.assertFalse(wheel.record_valid)
        self.assertIn("invalid wheel archive", wheel.error or "")
        self.assertFalse(sdist.archive_valid)
        self.assertIn("invalid sdist archive", sdist.error or "")

    def test_record_rejects_malformed_weak_and_incomplete_rows(self) -> None:
        payload = build_wheel(
            entry_points="[console_scripts]\ndemo = demo.cli:main\n",
            extra_files={
                "x.bin": b"x",
                "y.bin": b"y",
                "z.bin": b"z",
                "boot.pth": b"import os",
                "../escape.py": b"pass",
            },
        )
        with zipfile.ZipFile(io.BytesIO(payload), "r") as source:
            files = {
                member.filename: source.read(member)
                for member in source.infolist()
                if not member.is_dir()
            }

        def digest(content: bytes, algorithm: str = "sha256") -> str:
            value = hashlib.new(algorithm, content).digest()
            return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

        record_name = "demo-1.0.0.dist-info/RECORD"
        files[record_name] = (
            "\n".join(
                [
                    "bad-row,only",
                    ",sha256=abc,1",
                    "demo/__init__.py,,10",
                    "demo-1.0.0.dist-info/METADATA,malformed,1",
                    "demo-1.0.0.dist-info/WHEEL,nope=abc,1",
                    (
                        "demo-1.0.0.dist-info/entry_points.txt,"
                        f"sha1={digest(files['demo-1.0.0.dist-info/entry_points.txt'], 'sha1')},"
                        f"{len(files['demo-1.0.0.dist-info/entry_points.txt'])}"
                    ),
                    f"x.bin,sha256={digest(files['x.bin'])},not-an-integer",
                    f"y.bin,sha256={digest(files['y.bin'])},2",
                    f"missing.py,sha256={digest(b'missing')},7",
                    f"{record_name},,",
                ]
            )
            + "\n"
        ).encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )
        errors = "\n".join(result.record_errors)

        self.assertFalse(result.record_valid)
        self.assertIn("must contain path, hash, and size", errors)
        self.assertIn("empty or duplicate path", errors)
        self.assertIn("missing a required RECORD hash or size", errors)
        self.assertIn("malformed RECORD hash", errors)
        self.assertIn("insecure or unsupported", errors)
        self.assertIn("weaker than sha256", errors)
        self.assertIn("non-integer RECORD size", errors)
        self.assertIn("size mismatch", errors)
        self.assertIn("listed in RECORD but missing", errors)
        self.assertIn("present in the wheel but missing from RECORD", errors)
        self.assertIn("boot.pth", result.suspicious_files)
        self.assertIn("../escape.py (unsafe archive path)", result.unusual_files)

    def test_invalid_wheel_metadata_and_entry_points_are_findings(self) -> None:
        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(
                entry_points=b"\xff",
                wheel_payload=b"Root-Is-Purelib: perhaps\n",
            ),
            expected_project="demo",
            expected_version="1.0.0",
        )
        findings = "\n".join(result.metadata_mismatches)

        self.assertIn("invalid value", findings)
        self.assertIn("does not declare Wheel-Version", findings)
        self.assertIn("does not declare any compatibility Tag", findings)
        self.assertIn("unable to parse entry points", result.suspicious_entry_points[0])

    def test_native_code_conflicting_with_purelib_is_a_metadata_mismatch(self) -> None:
        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(
                native_file=True,
                entry_points="[gui_scripts]\ndemo = demo.cli:main\n",
                wheel_payload=(
                    b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                ),
            ),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertEqual(result.console_scripts, [])
        self.assertIn(
            "wheel contains native extensions but Root-Is-Purelib is true",
            result.metadata_mismatches,
        )

    def test_duplicate_metadata_files_and_oversized_metadata_are_rejected(self) -> None:
        duplicate = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(
                extra_files={
                    "other.dist-info/METADATA": b"Name: other\nVersion: 1\n",
                    "other.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
                }
            ),
            expected_project="demo",
            expected_version="1.0.0",
        )
        oversized = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(metadata_payload=b"x" * (MAX_METADATA_BYTES + 1)),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertIn(
            "wheel must contain exactly one .dist-info/METADATA file",
            duplicate.metadata_mismatches,
        )
        self.assertIn(
            "wheel must contain exactly one .dist-info/WHEEL metadata file",
            duplicate.metadata_mismatches,
        )
        self.assertIn(
            "artifact package metadata does not declare Name",
            duplicate.metadata_mismatches,
        )
        self.assertFalse(oversized.archive_valid)
        self.assertIn("inspection limit", oversized.error or "")

    def test_malformed_record_bytes_are_reported(self) -> None:
        payload = build_wheel()
        with zipfile.ZipFile(io.BytesIO(payload), "r") as source:
            files = {
                member.filename: source.read(member)
                for member in source.infolist()
                if not member.is_dir()
            }
        files["demo-1.0.0.dist-info/RECORD"] = b"\xff"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)

        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertFalse(result.record_valid)
        self.assertIn("unable to parse", result.record_errors[0])

    def test_structure_helpers_cover_directory_size_and_encryption_findings(self) -> None:
        directory = zipfile.ZipInfo("demo/")
        safe_root = zipfile.ZipInfo("root.py")
        typed_root = zipfile.ZipInfo("py.typed")
        oversized = zipfile.ZipInfo("demo/data.bin")
        oversized.file_size = OVERSIZED_FILE_BYTES + 1
        duplicate_a = zipfile.ZipInfo("demo/value.py")
        duplicate_b = zipfile.ZipInfo("demo/value.py")
        encrypted = zipfile.ZipInfo("demo/secret.py")
        encrypted.flag_bits = 0x1
        result = ArtifactInspection(
            inspected=True,
            kind="wheel",
            wheel_root_is_purelib=True,
        )

        _inspect_zip_structure([duplicate_a, duplicate_b, encrypted], result)
        _inspect_wheel_contents(
            [directory, safe_root, typed_root, oversized],
            result,
        )

        self.assertIn("demo/data.bin", result.oversized_files)
        self.assertNotIn("root.py", result.unexpected_top_level_files)
        self.assertNotIn("py.typed", result.unexpected_top_level_files)
        self.assertIn(
            "demo/value.py (duplicate archive member)",
            result.unusual_files,
        )
        self.assertIn(
            "demo/secret.py (encrypted archive member)",
            result.unusual_files,
        )
        self.assertIn("appears more than once", "\n".join(result.record_errors))
        self.assertIn("cannot be validated safely", "\n".join(result.record_errors))

    def test_missing_root_is_purelib_is_reported(self) -> None:
        result = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(
                wheel_payload=b"Wheel-Version: 1.0\nTag: py3-none-any\n",
            ),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertIn(
            "wheel metadata does not declare Root-Is-Purelib",
            result.metadata_mismatches,
        )


class SdistArtifactInspectionTests(unittest.TestCase):
    def test_sdist_detects_suspicious_scripts_and_unusual_files(self) -> None:
        payload = build_sdist(
            setup_payload=b"import subprocess\nsubprocess.run(['curl', 'https://example.com'])\n"
        )

        result = inspect_artifact(
            "demo-1.0.0.tar.gz",
            payload,
            expected_project="demo",
            expected_version="1.0.0",
        )

        findings = "\n".join(result.suspicious_files)
        self.assertIn("network download", findings)
        self.assertIn("process execution", findings)
        self.assertIn("demo-1.0.0/secrets.pem", result.unusual_files)
        self.assertEqual(result.metadata_name, "demo")

    def test_oversized_file_and_cross_artifact_metadata_difference(self) -> None:
        oversized = ArtifactInspection(inspected=True, kind="sdist")
        _record_sdist_file_findings(
            "demo-1.0.0/data.bin",
            OVERSIZED_FILE_BYTES + 1,
            oversized,
        )
        self.assertEqual(oversized.oversized_files, ["demo-1.0.0/data.bin"])

        wheel = inspect_artifact(
            "demo-1.0.0-py3-none-any.whl",
            build_wheel(version="1.0.0"),
            expected_project="demo",
            expected_version="1.0.0",
        )
        sdist = inspect_artifact(
            "demo-1.0.0.tar.gz",
            build_sdist(version="1.0.0", requires_dist="packaging>=25"),
            expected_project="demo",
            expected_version="1.0.0",
        )
        compare_artifact_metadata([wheel, sdist])

        self.assertIn(
            "wheel and sdist Requires-Dist metadata differ",
            wheel.metadata_mismatches,
        )

    def test_zip_sdist_detects_scripts_native_files_and_unsafe_paths(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(
                "demo-1.0.0/PKG-INFO",
                (
                    "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"
                    "Requires-Dist: packaging>=24\n\n"
                ),
            )
            archive.writestr(
                "demo-1.0.0/scripts/install.py",
                "exec('pass')\n",
            )
            archive.writestr("demo-1.0.0/vendor.zip", b"nested")
            archive.writestr("demo-1.0.0/native.so", b"native")
            archive.writestr("../outside.sh", b"wget https://example.com\n")

        result = inspect_artifact(
            "demo-1.0.0.zip",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertTrue(result.archive_valid)
        self.assertIn("demo-1.0.0/native.so", result.native_files)
        self.assertIn("demo-1.0.0/vendor.zip", result.unusual_files)
        self.assertIn("../outside.sh (unsafe archive path)", result.unusual_files)
        self.assertIn("dynamic execution", "\n".join(result.suspicious_files))
        self.assertIn("network download", "\n".join(result.suspicious_files))

    def test_tar_sdist_reports_special_members_and_executable_scripts(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            script = b"eval('1 + 1')\n"
            script_info = tarfile.TarInfo("demo-1.0.0/configure")
            script_info.size = len(script)
            script_info.mode = 0o755
            archive.addfile(script_info, io.BytesIO(script))
            link_info = tarfile.TarInfo("demo-1.0.0/current")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "../outside"
            archive.addfile(link_info)

        result = inspect_artifact(
            "demo-1.0.0.tgz",
            output.getvalue(),
            expected_project="demo",
            expected_version="1.0.0",
        )

        self.assertIn(
            "demo-1.0.0/current (special archive member)",
            result.unusual_files,
        )
        self.assertIn("dynamic execution", "\n".join(result.suspicious_files))
        self.assertIn(
            "artifact package metadata does not declare Name",
            result.metadata_mismatches,
        )
        self.assertIn(
            "artifact package metadata does not declare Version",
            result.metadata_mismatches,
        )

    def test_cross_artifact_name_and_version_mismatches_are_not_duplicated(self) -> None:
        wheel = ArtifactInspection(
            inspected=True,
            kind="wheel",
            metadata_name="demo",
            metadata_version="1.0.0",
        )
        sdist = ArtifactInspection(
            inspected=True,
            kind="sdist",
            metadata_name="other",
            metadata_version="2.0.0",
        )

        compare_artifact_metadata([wheel, sdist])
        compare_artifact_metadata([wheel, sdist])

        self.assertEqual(
            sum("metadata names differ" in item for item in wheel.metadata_mismatches),
            1,
        )
        self.assertEqual(
            sum("metadata versions differ" in item for item in wheel.metadata_mismatches),
            1,
        )

    def test_requirement_normalization_handles_extras_urls_markers_and_invalid_text(
        self,
    ) -> None:
        normalized = _canonical_requirements(
            [
                "Demo[Beta,alpha] @ https://example.com/demo.whl ; python_version >= '3.11'",
                "not a valid requirement @@@",
            ]
        )

        self.assertIn("demo[alpha,beta] @ https://example.com/demo.whl", normalized[0])
        self.assertEqual(normalized[1], "not a valid requirement @@@")

    def test_tar_member_reader_enforces_limits_and_handles_missing_streams(self) -> None:
        oversized = tarfile.TarInfo("demo-1.0.0/PKG-INFO")
        oversized.size = MAX_METADATA_BYTES + 1
        with self.assertRaisesRegex(ValueError, "inspection limit"):
            _read_tar_member(
                Mock(),
                oversized,
                limit=MAX_METADATA_BYTES,
            )

        missing = tarfile.TarInfo("demo-1.0.0/missing.txt")
        archive = Mock()
        archive.extractfile.return_value = None
        self.assertEqual(_read_tar_member(archive, missing, limit=10), b"")
