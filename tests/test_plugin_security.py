from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from trustcheck.models import VulnerabilityRecord
from trustcheck.plugins import (
    PluginError,
    PluginManager,
    _IsolatedPlugin,
    _run_plugin_process,
    _verified_manifest,
)


class Distribution:
    name = "demo-distribution"

    def __init__(self, root: Path) -> None:
        self.root = root

    def locate_file(self, name: str) -> Path:
        return self.root / name


class EntryPoint:
    name = "demo"
    value = "demo_plugin:Plugin"

    def __init__(self, root: Path) -> None:
        self.dist = Distribution(root)


def write_manifest(root: Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    manifest = {
        "name": "demo",
        "kind": "advisory",
        "entry_point": "demo_plugin:Plugin",
        "api_version": "1",
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    signer = __import__("hashlib").sha256(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    envelope = {
        "schema": "urn:trustcheck:plugin-manifest:1",
        "manifest": manifest,
        "public_key": public,
        "signature": base64.b64encode(
            key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        ).decode(),
    }
    (root / "trustcheck-plugin.json").write_text(json.dumps(envelope), encoding="utf-8")
    return signer


class PluginSecurityTests(unittest.TestCase):
    def test_signed_allowlisted_plugin_is_isolated_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer = write_manifest(root)
            entry = EntryPoint(root)
            manager = PluginManager(
                enabled=True,
                allowlist=("demo",),
                trusted_signers=(signer,),
                entry_point_loader=lambda *, group: (
                    [entry] if group == "trustcheck.advisory_sources" else []
                ),
            )
            descriptor = manager.descriptors()[0]
            self.assertTrue(descriptor.isolated)
            self.assertEqual(descriptor.signer_sha256, signer)
            with patch(
                "trustcheck.plugins._run_plugin_process",
                return_value=[VulnerabilityRecord(id="PLUGIN-1", summary="plugin")],
            ):
                result = manager.advisory_sources()[0].query("demo", "1")
        self.assertEqual(result[0].id, "PLUGIN-1")
        self.assertEqual(manager.executions()[0].status, "succeeded")

    def test_enable_all_without_allowlist_is_rejected(self) -> None:
        with self.assertRaisesRegex(PluginError, "explicit"):
            PluginManager.from_options(enabled=True)

    def test_config_controls_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugins.json"
            for payload, message in (
                ({"_trustcheck": "bad"}, "control"),
                ({"_trustcheck": {"allowlist": [3]}}, "allowlist"),
                ({"_trustcheck": {"trusted_signers": [3]}}, "trusted_signers"),
            ):
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaisesRegex(
                    PluginError, message
                ):
                    PluginManager.from_options(enabled=False, config_path=str(path))
            path.write_text(
                json.dumps({"_trustcheck": {"allowlist": ["demo"], "timeout": 2}}),
                encoding="utf-8",
            )
            manager = PluginManager.from_options(enabled=False, config_path=str(path))
            self.assertTrue(manager.enabled)
            self.assertEqual(manager.timeout, 2)
            path.write_text(json.dumps({"_trustcheck": None}), encoding="utf-8")
            self.assertFalse(
                PluginManager.from_options(enabled=False, config_path=str(path)).enabled
            )

    def test_manifest_failures_are_fail_closed(self) -> None:
        missing = SimpleNamespace(name="demo", value="module:Plugin", dist=None)
        with self.assertRaisesRegex(PluginError, "no distribution"):
            _verified_manifest(missing, kind="advisory", trusted_signers=())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer = write_manifest(root)
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "not allowlisted"):
                _verified_manifest(entry, kind="advisory", trusted_signers=("0" * 64,))
            path = root / "trustcheck-plugin.json"
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["signature"] = "AAAA"
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "signature is invalid"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "unsupported schema"):
                _verified_manifest(entry, kind="advisory", trusted_signers=())

            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "unable to read"):
                _verified_manifest(entry, kind="advisory", trusted_signers=())

            for mutate, message in (
                (lambda value: value.pop("public_key"), "incomplete"),
                (
                    lambda value: value["manifest"].update({"api_version": "2"}),
                    "incompatible",
                ),
                (lambda value: value.update({"public_key": "bad"}), "invalid signing"),
            ):
                write_manifest(root)
                envelope = json.loads(path.read_text(encoding="utf-8"))
                mutate(envelope)
                path.write_text(json.dumps(envelope), encoding="utf-8")
                with self.subTest(message=message), self.assertRaisesRegex(
                    PluginError, message
                ):
                    _verified_manifest(entry, kind="advisory", trusted_signers=())

            write_manifest(root)
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["public_key"] = ec.generate_private_key(
                ec.SECP256R1()
            ).public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "RSA"):
                _verified_manifest(entry, kind="advisory", trusted_signers=())

    def test_in_process_plugin_load_failure_is_wrapped(self) -> None:
        entry = SimpleNamespace(
            name="demo",
            value="demo:Plugin",
            load=Mock(side_effect=RuntimeError("boom")),
        )
        manager = PluginManager(
            enabled=True,
            allowlist=("demo",),
            require_signed=False,
            isolate=False,
            entry_point_loader=lambda *, group: [entry],
        )
        with self.assertRaisesRegex(PluginError, "unable to load"):
            manager.descriptors()

        entry.load = Mock(return_value=SimpleNamespace(name="other"))
        manager = PluginManager(
            enabled=True,
            allowlist=("demo",),
            require_signed=False,
            isolate=False,
            entry_point_loader=lambda *, group: [entry],
        )
        with self.assertRaisesRegex(PluginError, "runtime name"):
            manager.descriptors()

    def test_isolated_proxy_covers_all_plugin_and_repository_operations(self) -> None:
        manager = PluginManager()
        proxy = _IsolatedPlugin("demo", "artifact", "module:Plugin", manager)
        with patch.object(
            PluginManager,
            "_invoke_isolated",
            side_effect=[
                [],
                [],
                [],
                "rendered",
                True,
                "project",
                b"bytes",
                (),
                "index",
            ],
        ):
            self.assertEqual(proxy.query("demo", "1"), [])
            self.assertEqual(proxy.analyze(filename="demo.whl"), [])
            self.assertEqual(proxy.evaluate(report={}), [])
            self.assertEqual(proxy.render(packages=[]), "rendered")
            self.assertTrue(proxy.supports("demo+index"))
            repository = proxy.create_client(index_url="demo+index", config={})
            self.assertEqual(repository.get_project("demo+index", "demo"), "project")
            self.assertEqual(repository.download("url"), b"bytes")
            self.assertEqual(repository.find_dependency_confusion([], []), ())
            self.assertEqual(repository.locate_artifact_index("demo", None, []), "index")

    def test_plugin_process_reports_success_failure_timeout_and_eof(self) -> None:
        def context_for(*, ready: bool, received: object = (True, "ok")) -> Mock:
            receiver = Mock()
            receiver.poll.return_value = ready
            if isinstance(received, BaseException):
                receiver.recv.side_effect = received
            else:
                receiver.recv.return_value = received
            process = Mock()
            process.is_alive.return_value = False
            context = Mock()
            context.Pipe.return_value = (receiver, Mock())
            context.Process.return_value = process
            return context

        for context, message in (
            (context_for(ready=False), "exceeded"),
            (context_for(ready=True, received=(False, "boom")), "failed"),
            (context_for(ready=True, received=EOFError()), "unexpectedly"),
        ):
            with self.subTest(message=message), patch(
                "trustcheck.plugins.multiprocessing.get_context", return_value=context
            ), self.assertRaisesRegex(PluginError, message):
                _run_plugin_process("module:Plugin", "query", {}, timeout=0.01)
        context = context_for(ready=True)
        context.Process.return_value.is_alive.return_value = True
        with patch("trustcheck.plugins.multiprocessing.get_context", return_value=context):
            self.assertEqual(
                _run_plugin_process("module:Plugin", "query", {}, timeout=1), "ok"
            )
        context.Process.return_value.terminate.assert_called_once()
