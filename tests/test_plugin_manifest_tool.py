from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
import venv
import warnings
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import distributions
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import trustcheck.plugin_manifest as plugin_manifest_mod
from trustcheck.cli import main as cli_main
from trustcheck.cli_commands import plugin_manifest as plugin_manifest_command
from trustcheck.cli_commands.context import CommandContext
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

            site_packages = _install_wheel_into_venv(output, root / "venv")
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
                self.assertEqual(manager.advisory_sources()[0].query("demo", "1"), [])
            finally:
                sys.path.remove(str(site_packages))
                sys.modules.pop("demo_plugin", None)

    def test_configuration_schema_directory_verification_and_cli_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-cli-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(
                root / "wheel",
                requires=("demo-dep>=1",),
            )
            key_path, public_key_path, signer = _write_key_pair(root)
            schema = {"type": "object", "additionalProperties": False}
            schema_path = root / "schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")

            draft = build_plugin_manifest_draft(
                wheel,
                configuration_schema=schema,
            )
            self.assertEqual(draft["configuration_schema"], schema)
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "plugin-manifest",
                        "init",
                        "--configuration-schema",
                        str(schema_path),
                        str(wheel),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["configuration_schema"], schema)

            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "plugin-manifest",
                        "fingerprint",
                        "--format",
                        "json",
                        str(public_key_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["fingerprint_sha256"], signer)

            signed = root / "signed" / wheel.name
            output_file = root / "summary.txt"
            with redirect_stdout(StringIO()):
                exit_code = cli_main(
                    [
                        "plugin-manifest",
                        "sign",
                        "--key",
                        str(key_path),
                        "--configuration-schema",
                        str(schema_path),
                        "--output",
                        str(signed),
                        "--output-file",
                        str(output_file),
                        str(wheel),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertIn("plugin manifest signed:", output_file.read_text(encoding="utf-8"))

            extracted = root / "extracted"
            plugin_manifest_mod._extract_wheel(signed, extracted)
            self.assertEqual(verify_plugin_manifest(extracted).signer_sha256, signer)
            dist_info = next(extracted.glob("*.dist-info"))
            self.assertEqual(verify_plugin_manifest(dist_info).signer_sha256, signer)

            with self.assertRaisesRegex(PluginError, "not a wheel or directory"):
                verify_plugin_manifest(root / "not-a-wheel.txt")
            with self.assertRaisesRegex(PluginError, "configuration schema"):
                build_plugin_manifest_draft(wheel, configuration_schema=root / "missing.json")
            list_schema = root / "schema-list.json"
            list_schema.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "JSON object"):
                build_plugin_manifest_draft(wheel, configuration_schema=list_schema)

            for output in (root, root / "bad.zip"):
                with self.subTest(output=output), self.assertRaises(SystemExit):
                    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                        cli_main(
                            [
                                "plugin-manifest",
                                "sign",
                                "--key",
                                str(key_path),
                                "--output",
                                str(output),
                                str(wheel),
                            ]
                        )

    def test_plugin_manifest_command_run_error_branch(self) -> None:
        class Parser:
            def error(self, message: str) -> None:
                raise RuntimeError(message)

        class Facade:
            def _emit_output(self, rendered: str, output_file: str | None) -> None:
                raise AssertionError("unexpected output")

        args = SimpleNamespace(plugin_manifest_action="unknown")
        context = CommandContext(
            parser=Parser(),
            config_payload={},
            plugin_manager=PluginManager(),
            facade=Facade(),
        )
        with self.assertRaisesRegex(RuntimeError, "unknown plugin-manifest action"):
            plugin_manifest_command.run(args, context)

    def test_signing_rejects_console_script_layout_and_invalid_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-sign-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(root, console_script=True)
            key_path, _, _ = _write_key_pair(root)

            with self.assertRaisesRegex(PluginError, "console_scripts"):
                sign_plugin_wheel(wheel, key=key_path)
            with self.assertRaisesRegex(PluginError, ".whl"):
                sign_plugin_wheel(wheel, key=key_path, output=root / "signed.zip")

            valid_wheel = _write_minimal_plugin_wheel(root / "valid")
            with self.assertRaisesRegex(PluginError, "valid wheel filename"):
                sign_plugin_wheel(valid_wheel, key=key_path, output=root / "signed.whl")

    def test_signing_rejects_weak_rsa_keys_and_accepts_modern_sizes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-key-size-") as temp:
            root = Path(temp)
            wheel = _write_minimal_plugin_wheel(root / "wheel")
            weak_key_path, weak_public_path, _ = _write_key_pair(
                root / "weak",
                key_size=1024,
                allow_weak=True,
            )

            with self.assertRaisesRegex(PluginError, "at least 2048 bits"):
                sign_plugin_wheel(wheel, key=weak_key_path)
            with self.assertRaisesRegex(PluginError, "at least 2048 bits"):
                fingerprint_public_key_file(weak_public_path)

            for key_size in (2048, 3072):
                with self.subTest(key_size=key_size):
                    key_path, public_key_path, signer = _write_key_pair(
                        root / f"rsa-{key_size}",
                        key_size=key_size,
                    )
                    output = root / f"signed-{key_size}" / wheel.name
                    summary = sign_plugin_wheel(wheel, key=key_path, output=output)
                    self.assertEqual(summary.signer_sha256, signer)
                    self.assertEqual(fingerprint_public_key_file(public_key_path), signer)

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

            ec_key = ec.generate_private_key(ec.SECP256R1())
            ec_public_path = root / "ec-public.pem"
            ec_public_path.write_bytes(
                ec_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            with self.assertRaisesRegex(PluginError, "RSA public key"):
                fingerprint_public_key_file(ec_public_path)
            with self.assertRaisesRegex(PluginError, "RSA public key"):
                plugin_manifest_mod.fingerprint_public_key_pem(
                    ec_public_path.read_text(encoding="ascii")
                )
            with self.assertRaisesRegex(PluginError, "invalid public key data"):
                plugin_manifest_mod.fingerprint_public_key_pem("not a key")

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

            ec_private_path = root / "ec-private.pem"
            ec_private_path.write_bytes(
                ec_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            with self.assertRaisesRegex(PluginError, "RSA private key"):
                sign_plugin_wheel(wheel, key=ec_private_path)

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
            (
                {"entry_points_bytes": b"\xff"},
                "invalid entry point metadata",
            ),
            (
                {"metadata": "Metadata-Version: 2.1\nVersion: 1.0.0\n"},
                "missing Name",
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

            for scheme in ("scripts", "headers", "data"):
                with self.subTest(scheme=scheme):
                    external = base / f"external_{scheme}-1.0.0-py3-none-any.whl"
                    _write_minimal_plugin_wheel(
                        base / f"external-{scheme}-source",
                        output=external,
                        extra_entries={
                            f"trustcheck_demo_plugin-1.0.0.data/{scheme}/raw-helper": (
                                b"#!/bin/sh\nexit 0\n"
                            )
                        },
                    )
                    with self.assertRaisesRegex(PluginError, f".data/{scheme}"):
                        sign_plugin_wheel(external, key=key_path)

            unknown_data = base / "external_other-1.0.0-py3-none-any.whl"
            _write_minimal_plugin_wheel(
                base / "external-other-source",
                output=unknown_data,
                extra_entries={
                    "trustcheck_demo_plugin-1.0.0.data/stdlib/raw-helper": b""
                },
            )
            with self.assertRaisesRegex(PluginError, "unsupported .data scheme"):
                sign_plugin_wheel(unknown_data, key=key_path)

            for member in (
                "trustcheck_demo_plugin-1.0.0.data",
                "trustcheck_demo_plugin-1.0.0.data/purelib/",
            ):
                with self.subTest(member=member), self.assertRaisesRegex(
                    PluginError,
                    "malformed .data member",
                ):
                    plugin_manifest_mod._installed_wheel_path(member)

            for signature_name in ("RECORD.jws", "RECORD.p7s"):
                with self.subTest(signature_name=signature_name):
                    normalized_signature = signature_name.replace(".", "_")
                    stale = base / f"stale_{normalized_signature}-1.0.0-py3-none-any.whl"
                    _write_minimal_plugin_wheel(
                        base / f"stale-{signature_name}-source",
                        output=stale,
                        extra_entries={
                            f"trustcheck_demo_plugin-1.0.0.dist-info/{signature_name}": (
                                b"stale-signature"
                            )
                        },
                    )
                    with self.assertRaisesRegex(PluginError, "existing RECORD signature"):
                        sign_plugin_wheel(stale, key=key_path)

            malformed = base / "malformed-1.0.0-py3-none-any.whl"
            malformed.write_bytes(b"not a zip")
            with self.assertRaisesRegex(PluginError, "valid zip"):
                sign_plugin_wheel(malformed, key=key_path)

            missing_input = base / "missing-1.0.0-py3-none-any.whl"
            with self.assertRaisesRegex(PluginError, "requires a wheel file"):
                sign_plugin_wheel(missing_input, key=key_path)

    def test_wheel_path_helpers_cover_install_layout_edges(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-paths-") as temp:
            root = Path(temp)
            input_path = root / "trustcheck_demo_plugin-1.0.0-py3-none-any.whl"
            other_valid = root / "other_demo_plugin-1.0.0-py3-none-any.whl"

            with self.assertRaisesRegex(PluginError, "must match"):
                plugin_manifest_mod._validate_signing_output_path(
                    input_path,
                    other_valid,
                )

            with self.assertRaisesRegex(PluginError, "reserved path"):
                plugin_manifest_mod._build_record(
                    {
                        (
                            "trustcheck_demo_plugin-1.0.0.data/"
                            "purelib/trustcheck-plugin.json"
                        ): b"manifest",
                    },
                    "trustcheck_demo_plugin-1.0.0.dist-info/RECORD",
                )

            with self.assertRaisesRegex(PluginError, "duplicate path"):
                plugin_manifest_mod._build_record(
                    {
                        "demo.py": b"root",
                        "trustcheck_demo_plugin-1.0.0.data/purelib/demo.py": b"data",
                    },
                    "trustcheck_demo_plugin-1.0.0.dist-info/RECORD",
                )

            record_bytes = plugin_manifest_mod._render_record(
                [
                    (
                        "trustcheck_demo_plugin-1.0.0.data/purelib/demo.py",
                        "sha256=abc",
                        "3",
                    ),
                    ("trustcheck_demo_plugin-1.0.0.dist-info/RECORD", "", ""),
                ]
            )
            installed = plugin_manifest_mod._installed_record_payload(
                record_bytes,
                Path("trustcheck_demo_plugin-1.0.0.dist-info/RECORD"),
            )
            self.assertIn(b"demo.py,sha256=abc,3\n", installed)

    def test_supported_data_schemes_install_and_load_after_signing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-data-") as temp:
            root = Path(temp)
            for scheme in ("purelib", "platlib"):
                with self.subTest(scheme=scheme):
                    wheel = _write_minimal_plugin_wheel(
                        root / scheme / "wheel",
                        extra_entries={
                            (
                                "trustcheck_demo_plugin-1.0.0.data/"
                                f"{scheme}/demo_{scheme}.py"
                            ): f"SCHEME = {scheme!r}\n".encode("utf-8")
                        },
                    )
                    key_path, _, signer = _write_key_pair(root / scheme / "key")
                    output = root / scheme / "signed" / wheel.name

                    sign_plugin_wheel(wheel, key=key_path, output=output)
                    site_packages = _install_wheel_into_venv(
                        output,
                        root / scheme / "venv",
                    )
                    self.assertTrue((site_packages / f"demo_{scheme}.py").is_file())
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
                        self.assertEqual(
                            manager.advisory_sources()[0].query("demo", "1"),
                            [],
                        )
                    finally:
                        sys.path.remove(str(site_packages))
                        sys.modules.pop("demo_plugin", None)

    def test_verify_rejects_malformed_manifests_and_archive_limits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-verify-") as temp:
            root = Path(temp)
            malformed = root / "demo-1.0-py3-none-any.whl"
            malformed.write_bytes(b"not a zip")
            with self.assertRaisesRegex(PluginError, "valid zip"):
                verify_plugin_manifest(malformed)

            wheel = _write_minimal_plugin_wheel(root)
            key_path, _, _ = _write_key_pair(root)
            signed = root / "signed" / wheel.name
            sign_plugin_wheel(wheel, key=key_path, output=signed)

            duplicate_signed = root / "duplicate" / wheel.name
            sign_plugin_wheel(wheel, key=key_path, output=duplicate_signed)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate_signed, "a") as archive:
                    archive.writestr("trustcheck-plugin.json", b"duplicate\n")
            with self.assertRaisesRegex(PluginError, "duplicate"):
                verify_plugin_manifest(duplicate_signed)

            with patch(
                "trustcheck.plugin_manifest.MAX_ARCHIVE_MEMBERS",
                1,
            ):
                with self.assertRaisesRegex(PluginError, "members"):
                    sign_plugin_wheel(wheel, key=key_path)
                with self.assertRaisesRegex(PluginError, "members"):
                    verify_plugin_manifest(signed)

            with patch("trustcheck.plugin_manifest.MAX_ARTIFACT_BYTES", 1):
                with self.assertRaisesRegex(PluginError, "artifact limit"):
                    sign_plugin_wheel(wheel, key=key_path)
                with self.assertRaisesRegex(PluginError, "artifact limit"):
                    verify_plugin_manifest(signed)

            with patch("trustcheck.plugin_manifest.MAX_ARCHIVE_UNCOMPRESSED_BYTES", 1):
                with self.assertRaisesRegex(PluginError, "expanded size"):
                    sign_plugin_wheel(wheel, key=key_path)

            with patch("trustcheck.plugin_manifest.MIN_COMPRESSION_RATIO_BYTES", 1), patch(
                "trustcheck.plugin_manifest.MAX_COMPRESSION_RATIO",
                1.0,
            ):
                with self.assertRaisesRegex(PluginError, "compression ratio"):
                    sign_plugin_wheel(wheel, key=key_path)

            empty = root / "empty-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(empty, "w"):
                pass
            with self.assertRaisesRegex(PluginError, "contains no files"):
                sign_plugin_wheel(empty, key=key_path)

            invalid_epoch_output = root / "invalid-epoch" / wheel.name
            with patch.dict("os.environ", {"SOURCE_DATE_EPOCH": "not-an-int"}):
                sign_plugin_wheel(wheel, key=key_path, output=invalid_epoch_output)
            with zipfile.ZipFile(invalid_epoch_output) as archive:
                self.assertEqual(
                    archive.getinfo("trustcheck-plugin.json").date_time,
                    (1980, 1, 1, 0, 0, 0),
                )

            extracted = root / "extracted"
            plugin_manifest_mod._extract_wheel(signed, extracted)
            manifest = extracted / "trustcheck-plugin.json"
            original_manifest = manifest.read_text(encoding="utf-8")
            for payload, message in (
                ("{", "unable to read signed plugin manifest"),
                ("[]", "is invalid"),
                (
                    json.dumps(
                        {
                            "schema": "urn:trustcheck:plugin-manifest:2",
                            "manifest": "bad",
                            "public_key": "bad",
                        }
                    ),
                    "is incomplete",
                ),
                (
                    json.dumps(
                        {
                            "schema": "urn:trustcheck:plugin-manifest:2",
                            "manifest": {},
                            "public_key": 1,
                        }
                    ),
                    "is incomplete",
                ),
                (
                    json.dumps(
                        {
                            "schema": "urn:trustcheck:plugin-manifest:2",
                            "manifest": {},
                            "public_key": "bad",
                        }
                    ),
                    "invalid public key data",
                ),
            ):
                with self.subTest(message=message):
                    manifest.write_text(payload, encoding="utf-8")
                    with self.assertRaisesRegex(PluginError, message):
                        verify_plugin_manifest(extracted)
            manifest.write_text(original_manifest, encoding="utf-8")

            multi_dist = root / "multi-dist"
            multi_dist.mkdir()
            (multi_dist / "one.dist-info").mkdir()
            (multi_dist / "two.dist-info").mkdir()
            with self.assertRaisesRegex(PluginError, "exactly one dist-info"):
                verify_plugin_manifest(multi_dist)

            dist_info = next(extracted.glob("*.dist-info")).name
            distribution = plugin_manifest_mod._PathDistribution(extracted, dist_info)
            self.assertEqual(distribution.requires, [])
            self.assertEqual(
                distribution.locate_file("demo_plugin.py"),
                extracted / "demo_plugin.py",
            )
            with patch.object(Path, "read_bytes", side_effect=OSError("blocked")):
                with self.assertRaisesRegex(PluginError, "unable to read plugin RECORD"):
                    distribution.files

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
    entry_points_bytes: bytes | None = None,
    extra_entries: dict[str, bytes] | None = None,
    metadata: str | None = None,
    omit_metadata: bool = False,
    omit_record: bool = False,
    output: Path | None = None,
    requires: tuple[str, ...] = (),
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
    metadata_payload = (
        metadata
        if metadata is not None
        else (
            "Metadata-Version: 2.1\n"
            "Name: trustcheck-demo-plugin\n"
            "Version: 1.0.0\n"
            + "".join(f"Requires-Dist: {item}\n" for item in requires)
        )
    )
    entries = {
        "demo_plugin.py": (
            b"class Plugin:\n"
            b"    name = 'demo'\n"
            b"    def query(self, project, version):\n"
            b"        return []\n"
        ),
        "bin/helper": b"#!/bin/sh\nexit 0\n",
        f"{dist_info}/METADATA": metadata_payload.encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: trustcheck fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8"),
        f"{dist_info}/entry_points.txt": (
            entry_points_payload.encode("utf-8")
            if entry_points_bytes is None
            else entry_points_bytes
        ),
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


def _write_key_pair(
    root: Path,
    *,
    key_size: int = 2048,
    allow_weak: bool = False,
) -> tuple[Path, Path, str]:
    root.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
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
    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signer = (
        hashlib.sha256(public_key_der).hexdigest()
        if allow_weak
        else fingerprint_public_key(public_key)
    )
    return key_path, public_key_path, signer


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
