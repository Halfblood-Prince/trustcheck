from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from trustcheck.export_models import ExportPackage
from trustcheck.indexes import DependencyConfusionFinding, IndexProject
from trustcheck.models import (
    ArtifactInspection,
    HeuristicFinding,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
)
from trustcheck.plugins import (
    PLUGIN_IPC_PROTOCOL_VERSION,
    PluginError,
    PluginManager,
    _IsolatedPlugin,
    _run_plugin_process,
    _verified_manifest,
)


class Distribution:
    name = "demo-distribution"
    version = "1.0.0"

    def __init__(self, root: Path, *, requires: tuple[str, ...] = ()) -> None:
        self.root = root
        self.requires = requires

    @property
    def files(self) -> tuple[str, ...]:
        record = self.root / f"{self.name}-{self.version}.dist-info" / "RECORD"
        if not record.is_file():
            return ()
        return tuple(
            line.split(",", 1)[0]
            for line in record.read_text(encoding="utf-8").splitlines()
            if line
        )

    def locate_file(self, name: str) -> Path:
        return self.root / name


class EntryPoint:
    name = "demo"

    def __init__(
        self,
        root: Path,
        *,
        value: str = "demo_plugin:Plugin",
        requires: tuple[str, ...] = (),
    ) -> None:
        self.value = value
        self.dist = Distribution(root, requires=requires)


def _record_digest(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode(
        "ascii"
    )


def _record_row(root: Path, relative: str) -> tuple[str, str, str]:
    payload = (root / relative).read_bytes()
    return relative, f"sha256={_record_digest(payload)}", str(len(payload))


def _write_record(root: Path, rows: list[tuple[str, str, str]]) -> bytes:
    text = "".join(",".join(row) + "\n" for row in rows)
    record = root / "demo-distribution-1.0.0.dist-info" / "RECORD"
    record.parent.mkdir(parents=True, exist_ok=True)
    payload = text.encode("utf-8")
    record.write_bytes(payload)
    return payload


def _plugin_file_paths(entry_point: str) -> list[str]:
    module_name = entry_point.split(":", 1)[0]
    parts = module_name.split(".")
    if len(parts) == 1:
        return [f"{parts[0]}.py"]
    files = [
        "/".join([*parts[:index], "__init__.py"])
        for index in range(1, len(parts))
    ]
    files.append("/".join(parts) + ".py")
    return files


def _canonical_configuration_schema_hash(value: object) -> str:
    if value is None:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def write_manifest(
    root: Path,
    *,
    kind: str = "advisory",
    capabilities: list[str] | None = None,
    dependencies: list[str] | None = None,
    statement_overrides: dict[str, object] | None = None,
    configuration_schema: dict[str, object] | None = None,
    entry_point: str = "demo_plugin:Plugin",
    sigstore_identity: str | None = None,
    sigstore_issuer: str | None = None,
) -> tuple[str, dict[str, str]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    plugin_files = _plugin_file_paths(entry_point)
    for relative in plugin_files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (
            "class Plugin:\n    name = 'demo'\n"
            if relative == plugin_files[-1]
            else ""
        )
        path.write_text(payload, encoding="utf-8")
    record_relative = "demo-distribution-1.0.0.dist-info/RECORD"
    rows = [
        *[_record_row(root, relative) for relative in plugin_files],
        ("trustcheck-plugin.json", "", ""),
        (record_relative, "", ""),
    ]
    record_payload = _write_record(root, rows)
    wheel_lines = []
    for relative in plugin_files:
        payload = (root / relative).read_bytes()
        wheel_lines.append(f"{relative}\0{hashlib.sha256(payload).hexdigest()}\0{len(payload)}")
    wheel_payload = "\n".join(sorted(wheel_lines)).encode("utf-8")
    digests = {
        "record_sha256": hashlib.sha256(record_payload).hexdigest(),
        "wheel_sha256": hashlib.sha256(wheel_payload).hexdigest(),
        "configuration_schema_sha256": _canonical_configuration_schema_hash(
            configuration_schema
        ),
    }
    manifest = {
        "schema": "urn:trustcheck:plugin-statement:1",
        "name": "demo",
        "kind": kind,
        "entry_point": entry_point,
        "api_version": "1",
        "distribution": "demo-distribution",
        "distribution_version": "1.0.0",
        "wheel_sha256": digests["wheel_sha256"],
        "record_sha256": digests["record_sha256"],
        "configuration_schema_sha256": digests["configuration_schema_sha256"],
        "protocol_version": "1",
        "capabilities": capabilities or ["query"],
        "requires_network": False,
        "requires_filesystem": False,
        "requires_subprocess": False,
        "dependencies": dependencies or [],
    }
    if sigstore_identity is not None:
        manifest["sigstore_identity"] = sigstore_identity
    if sigstore_issuer is not None:
        manifest["sigstore_issuer"] = sigstore_issuer
    if statement_overrides:
        manifest.update(statement_overrides)
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
    if configuration_schema is not None:
        envelope["configuration_schema"] = configuration_schema
    (root / "trustcheck-plugin.json").write_text(json.dumps(envelope), encoding="utf-8")
    return signer, digests


def _ipc_response(
    request_id: str,
    *,
    ok: bool = True,
    result: object = None,
    error: dict[str, str] | None = None,
    protocol_version: str = PLUGIN_IPC_PROTOCOL_VERSION,
) -> bytes:
    payload: dict[str, object] = {
        "plugin_protocol_version": protocol_version,
        "request_id": request_id,
        "ok": ok,
    }
    if ok:
        payload["result"] = result
    else:
        payload["error"] = error or {"type": "ValueError", "message": "boom"}
    return json.dumps(payload).encode("utf-8")


def _process_context(*, ready: bool, received: object = b"") -> Mock:
    request_receiver = Mock()
    request_sender = Mock()
    response_receiver = Mock()
    response_sender = Mock()
    response_receiver.poll.return_value = ready
    if isinstance(received, BaseException):
        response_receiver.recv_bytes.side_effect = received
    else:
        response_receiver.recv_bytes.return_value = received
    process = Mock()
    process.is_alive.return_value = False
    context = Mock()
    context.Pipe.side_effect = [
        (request_receiver, request_sender),
        (response_receiver, response_sender),
    ]
    context.Process.return_value = process
    return context


class PluginSecurityTests(unittest.TestCase):
    def test_signed_allowlisted_plugin_is_isolated_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, digests = write_manifest(root)
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
            self.assertEqual(descriptor.wheel_sha256, digests["wheel_sha256"])
            self.assertEqual(descriptor.record_sha256, digests["record_sha256"])
            self.assertEqual(descriptor.trust_policy_mode, "trusted-key")
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
                ({"_trustcheck": {"trusted_wheel_sha256": [3]}}, "trusted_wheel"),
                (
                    {"_trustcheck": {"trusted_sigstore_identities": ["bad"]}},
                    "trusted_sigstore",
                ),
                ({"_trustcheck": {"trust_policy_mode": "bad"}}, "trust_policy"),
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
            signer, _ = write_manifest(root)
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "self-signed plugin metadata"):
                _verified_manifest(entry, kind="advisory", trusted_signers=())
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

    def test_signed_statement_binds_installed_record_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(root)
            entry = EntryPoint(root)
            (root / "demo_plugin.py").write_text("tampered = True\n", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "hash does not match RECORD"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(root)
            entry = EntryPoint(root)
            record = root / "demo-distribution-1.0.0.dist-info" / "RECORD"
            lines = record.read_text(encoding="utf-8").splitlines()
            record.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "record_sha256"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(
                root,
                statement_overrides={"wheel_sha256": "0" * 64},
            )
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "wheel_sha256"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(root, entry_point="demo_package.plugin:Plugin")
            (root / "demo_package" / "helper.py").write_text("x = 1\n", encoding="utf-8")
            entry = EntryPoint(root, value="demo_package.plugin:Plugin")
            with self.assertRaisesRegex(PluginError, "unrecorded file"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

    def test_signed_statement_binds_dependencies_config_and_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(root, dependencies=["demo-dep==1"])
            entry = EntryPoint(root, requires=("demo-dep==2",))
            with self.assertRaisesRegex(PluginError, "dependencies"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(
                root,
                configuration_schema={"type": "object", "additionalProperties": False},
            )
            path = root / "trustcheck-plugin.json"
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["configuration_schema"]["additionalProperties"] = True
            path.write_text(json.dumps(envelope), encoding="utf-8")
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "configuration_schema_sha256"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, _ = write_manifest(root, kind="policy", capabilities=["query"])
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "runtime capability"):
                _verified_manifest(entry, kind="policy", trusted_signers=(signer,))

    def test_plugin_trust_policy_modes_cover_digest_and_sigstore_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, digests = write_manifest(root)
            entry = EntryPoint(root)
            manifest, _, _, wheel_sha256, _ = _verified_manifest(
                entry,
                kind="advisory",
                trusted_signers=(),
                trusted_wheel_sha256=(digests["wheel_sha256"],),
                trust_policy_mode="allowlisted-digest",
            )
            self.assertEqual(manifest["name"], "demo")
            self.assertEqual(wheel_sha256, digests["wheel_sha256"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifest(
                root,
                sigstore_identity="https://github.com/example/plugin/.github/workflows/release.yml@refs/tags/v1",
                sigstore_issuer="https://token.actions.githubusercontent.com",
            )
            entry = EntryPoint(root)
            _verified_manifest(
                entry,
                kind="advisory",
                trusted_signers=(),
                trusted_sigstore_identities=(
                    (
                        "https://github.com/example/plugin/.github/workflows/release.yml@refs/tags/v1",
                        "https://token.actions.githubusercontent.com",
                    ),
                ),
                trust_policy_mode="sigstore-identity",
            )
            with self.assertRaisesRegex(PluginError, "Sigstore identity"):
                _verified_manifest(
                    entry,
                    kind="advisory",
                    trusted_signers=(),
                    trusted_sigstore_identities=(
                        (
                            "https://github.com/example/plugin/.github/workflows/release.yml@refs/tags/v1",
                            "https://issuer.example/wrong",
                        ),
                    ),
                    trust_policy_mode="sigstore-identity",
                )

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
        kwargs = {"packages": [], "source_name": "source", "failures": [], "config": {}}
        for context, message in (
            (_process_context(ready=False), "exceeded"),
            (
                _process_context(
                    ready=True,
                    received=_ipc_response("request-1", ok=False),
                ),
                "failed",
            ),
            (_process_context(ready=True, received=EOFError()), "unexpectedly"),
        ):
            with self.subTest(message=message), patch(
                "trustcheck.plugins.multiprocessing.get_context", return_value=context
            ), patch(
                "trustcheck.plugins._new_plugin_request_id",
                return_value="request-1",
            ), self.assertRaisesRegex(PluginError, message):
                _run_plugin_process("module:Plugin", "render", kwargs, timeout=0.01)
        context = _process_context(
            ready=True,
            received=_ipc_response("request-1", result="ok"),
        )
        context.Process.return_value.is_alive.return_value = True
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ):
            self.assertEqual(
                _run_plugin_process("module:Plugin", "render", kwargs, timeout=1),
                "ok",
            )
        context.Process.return_value.terminate.assert_called_once()

    def test_plugin_ipc_protocol_validation_and_size_limits(self) -> None:
        query_kwargs = {"project": "demo", "version": "1"}
        context = _process_context(
            ready=True,
            received=_ipc_response(
                "request-1",
                result=[{"id": "PLUGIN-1", "summary": "plugin", "extra": True}],
            ),
        )
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "schema validation"):
            _run_plugin_process("module:Plugin", "query", query_kwargs, timeout=1)

        context = _process_context(
            ready=True,
            received=_ipc_response(
                "request-1",
                result=[{"id": "PLUGIN-1", "summary": "plugin", "aliases": "bad"}],
            ),
        )
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "schema validation"):
            _run_plugin_process("module:Plugin", "query", query_kwargs, timeout=1)

        context = _process_context(
            ready=True,
            received=_ipc_response(
                "request-1",
                result=[],
                protocol_version="2",
            ),
        )
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "incompatible plugin IPC protocol"):
            _run_plugin_process("module:Plugin", "query", query_kwargs, timeout=1)

        with patch("trustcheck.plugins.PLUGIN_IPC_MAX_STRING_LENGTH", 4):
            with self.assertRaisesRegex(PluginError, "string length"):
                _run_plugin_process(
                    "module:Plugin",
                    "render",
                    {
                        "packages": [],
                        "source_name": "source",
                        "failures": [],
                        "config": {},
                    },
                    timeout=1,
                )

        context = _process_context(
            ready=True,
            received=_ipc_response(
                "request-1",
                result={"name": 3, "index_url": "demo+https://index/", "files": []},
            ),
        )
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "index project name"):
            _run_plugin_process(
                "module:Plugin",
                "client.get_project",
                {
                    "client_index_url": "demo+https://index/",
                    "client_config": {},
                    "index_url": "demo+https://index/",
                    "project": "demo",
                },
                timeout=1,
            )

    def test_plugin_ipc_schema_files_are_versioned_json(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "src" / "trustcheck" / "plugin_schemas"
        for filename, schema_id in (
            ("plugin-statement-1.json", "urn:trustcheck:plugin-statement:1"),
            ("plugin-ipc-request-1.json", "urn:trustcheck:plugin-ipc-request:1"),
            ("plugin-ipc-response-1.json", "urn:trustcheck:plugin-ipc-response:1"),
        ):
            with self.subTest(filename=filename):
                schema = json.loads((schema_root / filename).read_text(encoding="utf-8"))
                self.assertEqual(schema["$id"], schema_id)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_plugin_ipc_reconstructs_trusted_worker_models(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe_plugin.py").write_text(
                "\n".join(
                    [
                        "from trustcheck.indexes import DependencyConfusionFinding",
                        "from trustcheck.indexes import IndexFile, IndexProject",
                        "from trustcheck.models import HeuristicFinding",
                        "from trustcheck.models import PolicyViolation",
                        "from trustcheck.models import VulnerabilityRecord",
                        "",
                        "class Client:",
                        "    def get_project(self, index_url, project):",
                        "        return IndexProject(",
                        "            name=project,",
                        "            index_url=index_url,",
                        "            files=(IndexFile(filename='demo.whl', url='https://files/demo.whl'),),",
                        "        )",
                        "    def download(self, url, *, index_url=None):",
                        "        return f'{index_url}:{url}'.encode()",
                        "    def find_dependency_confusion(self, projects, indexes):",
                        "        return (",
                        "            DependencyConfusionFinding(",
                        "                project=projects[0],",
                        "                indexes=tuple(indexes),",
                        "            ),",
                        "        )",
                        "    def locate_artifact_index(self, project, artifact_url, indexes):",
                        "        return indexes[0] if indexes else None",
                        "",
                        "class Plugin:",
                        "    name = 'safe'",
                        "    def query(self, project, version):",
                        "        return [VulnerabilityRecord(",
                        "            id=f'{project}-{version}',",
                        "            summary='ok',",
                        "        )]",
                        "    def analyze(",
                        "        self, *, filename, payload, project, version,",
                        "        inspection, config",
                        "    ):",
                        "        assert isinstance(payload, bytes)",
                        "        return [HeuristicFinding(",
                        "            code='plugin',",
                        "            category='plugin',",
                        "            severity='medium',",
                        "            confidence='high',",
                        "            score=10,",
                        "            message=(",
                        "                f'{filename}:{inspection.kind}:'",
                        "                f'{config[\"message\"]}'",
                        "            ),",
                        "        )]",
                        "    def evaluate(self, *, report, config):",
                        "        return [PolicyViolation(",
                        "            code='policy',",
                        "            severity='high',",
                        "            message=f'{report.project}:{config[\"message\"]}',",
                        "        )]",
                        "    def render(self, *, packages, source_name, failures, config):",
                        "        return (",
                        "            f'{source_name}:{len(packages)}:'",
                        "            f'{packages[0].report.project}'",
                        "        )",
                        "    def supports(self, index_url):",
                        "        return index_url.startswith('demo+')",
                        "    def create_client(self, *, index_url, config):",
                        "        return Client()",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            report = TrustReport(
                project="demo",
                version="1",
                summary=None,
                package_url="pkg:pypi/demo@1",
            )
            sys.path.insert(0, str(root))
            try:
                query = _run_plugin_process(
                    "safe_plugin:Plugin",
                    "query",
                    {"project": "demo", "version": "1"},
                    timeout=5,
                )
                self.assertIsInstance(query[0], VulnerabilityRecord)
                self.assertEqual(query[0].id, "demo-1")

                findings = _run_plugin_process(
                    "safe_plugin:Plugin",
                    "analyze",
                    {
                        "filename": "demo.whl",
                        "payload": b"wheel",
                        "project": "demo",
                        "version": "1",
                        "inspection": ArtifactInspection(kind="wheel"),
                        "config": {"message": "checked"},
                    },
                    timeout=5,
                )
                self.assertIsInstance(findings[0], HeuristicFinding)
                self.assertEqual(findings[0].message, "demo.whl:wheel:checked")

                violations = _run_plugin_process(
                    "safe_plugin:Plugin",
                    "evaluate",
                    {"report": report, "config": {"message": "blocked"}},
                    timeout=5,
                )
                self.assertIsInstance(violations[0], PolicyViolation)
                self.assertEqual(violations[0].message, "demo:blocked")

                self.assertEqual(
                    _run_plugin_process(
                        "safe_plugin:Plugin",
                        "render",
                        {
                            "packages": [ExportPackage(report=report)],
                            "source_name": "source",
                            "failures": [],
                            "config": {},
                        },
                        timeout=5,
                    ),
                    "source:1:demo",
                )
                self.assertTrue(
                    _run_plugin_process(
                        "safe_plugin:Plugin",
                        "supports",
                        {"index_url": "demo+https://index/"},
                        timeout=5,
                    )
                )
                project = _run_plugin_process(
                    "safe_plugin:Plugin",
                    "client.get_project",
                    {
                        "client_index_url": "demo+https://index/",
                        "client_config": {},
                        "index_url": "demo+https://index/",
                        "project": "demo",
                    },
                    timeout=5,
                )
                self.assertIsInstance(project, IndexProject)
                self.assertEqual(project.files[0].filename, "demo.whl")
                self.assertEqual(
                    _run_plugin_process(
                        "safe_plugin:Plugin",
                        "client.download",
                        {
                            "client_index_url": "demo+https://index/",
                            "client_config": {},
                            "url": "https://files/demo.whl",
                            "index_url": "demo+https://index/",
                        },
                        timeout=5,
                    ),
                    b"demo+https://index/:https://files/demo.whl",
                )
                confusion = _run_plugin_process(
                    "safe_plugin:Plugin",
                    "client.find_dependency_confusion",
                    {
                        "client_index_url": "demo+https://index/",
                        "client_config": {},
                        "projects": ["demo"],
                        "indexes": ["one", "two"],
                    },
                    timeout=5,
                )
                self.assertIsInstance(confusion[0], DependencyConfusionFinding)
                self.assertEqual(confusion[0].indexes, ("one", "two"))
                self.assertEqual(
                    _run_plugin_process(
                        "safe_plugin:Plugin",
                        "client.locate_artifact_index",
                        {
                            "client_index_url": "demo+https://index/",
                            "client_config": {},
                            "project": "demo",
                            "artifact_url": "https://files/demo.whl",
                            "indexes": ["demo+https://index/"],
                        },
                        timeout=5,
                    ),
                    "demo+https://index/",
                )
            finally:
                sys.path.remove(str(root))
                sys.modules.pop("safe_plugin", None)

    def test_plugin_ipc_rejects_reduction_objects_without_parent_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "marker.txt"
            (root / "evil_plugin.py").write_text(
                "\n".join(
                    [
                        "from pathlib import Path",
                        f"MARKER = {json.dumps(str(marker))}",
                        "",
                        "class Exploit:",
                        "    def __reduce__(self):",
                        "        return (Path(MARKER).write_text, ('executed',))",
                        "",
                        "class Plugin:",
                        "    name = 'evil'",
                        "    def render(self, **kwargs):",
                        "        return Exploit()",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                with self.assertRaisesRegex(PluginError, "expected str"):
                    _run_plugin_process(
                        "evil_plugin:Plugin",
                        "render",
                        {
                            "packages": [],
                            "source_name": "source",
                            "failures": [],
                            "config": {},
                        },
                        timeout=5,
                    )
            finally:
                sys.path.remove(str(root))
                sys.modules.pop("evil_plugin", None)
            self.assertFalse(marker.exists())
