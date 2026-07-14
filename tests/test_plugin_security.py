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

import trustcheck.plugins as plugin_mod
from trustcheck.export_models import ExportPackage, SourceLocation
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
    _ResourceBoundedPlugin,
    _run_plugin_process,
    _verified_manifest,
)
from trustcheck.resolver import ArtifactReference


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
        "schema": "urn:trustcheck:plugin-statement:2",
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
        "schema": "urn:trustcheck:plugin-manifest:2",
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


class ResourceModule:
    RLIM_INFINITY = -1
    RLIMIT_CPU = 1
    RLIMIT_AS = 2

    def __init__(self, limits: dict[int, tuple[int, int]]) -> None:
        self.limits = limits
        self.calls: list[tuple[int, tuple[int, int]]] = []
        self.fail_next_set = False

    def getrlimit(self, limit_name: int) -> tuple[int, int]:
        return self.limits[limit_name]

    def setrlimit(self, limit_name: int, values: tuple[int, int]) -> None:
        if self.fail_next_set:
            self.fail_next_set = False
            raise ValueError("unsupported limit")
        soft, hard = values
        _, current_hard = self.limits[limit_name]
        if current_hard != self.RLIM_INFINITY and hard > current_hard:
            raise ValueError("current limit exceeds maximum limit")
        if hard != self.RLIM_INFINITY and soft > hard:
            raise ValueError("current limit exceeds maximum limit")
        self.calls.append((limit_name, values))


class PluginSecurityTests(unittest.TestCase):
    def test_signed_allowlisted_plugin_is_resource_bounded_and_reported(self) -> None:
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
            self.assertTrue(descriptor.resource_bounded)
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
        self.assertTrue(manager.executions()[0].resource_bounded)
        report = TrustReport(
            project="demo",
            version="1",
            summary=None,
            package_url="pkg:pypi/demo@1",
        )
        manager.attach_executions(report)
        self.assertEqual(
            report.diagnostics.plugin_executions[0]["resource_bounded"],
            True,
        )
        self.assertNotIn("isolated", report.diagnostics.plugin_executions[0])

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
                    "Sigstore bundle verification is not implemented",
                ),
                (
                    {"_trustcheck": {"trusted_sigstore_identities": []}},
                    "Sigstore bundle verification is not implemented",
                ),
                ({"_trustcheck": {"trust_policy_mode": "bad"}}, "trust_policy"),
                (
                    {"_trustcheck": {"trust_policy_mode": "sigstore-identity"}},
                    "trust_policy",
                ),
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
            path.write_text(
                json.dumps(
                    {
                        "_trustcheck": {
                            "allowlist": ["demo"],
                            "trust_policy_mode": "disabled",
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(
                PluginManager.from_options(
                    enabled=False,
                    config_path=str(path),
                ).require_signed
            )
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
                (lambda value: value.update({"manifest": "bad"}), "incomplete"),
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

            write_manifest(root, statement_overrides={"schema": "unsupported"})
            with self.assertRaisesRegex(PluginError, "signed statement"):
                _verified_manifest(entry, kind="advisory", trusted_signers=(signer,))

    def test_legacy_manifest_v1_fixture_is_rejected_with_migration_error(self) -> None:
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures"
            / "plugin-legacy-v1"
            / "trustcheck-plugin.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trustcheck-plugin.json").write_text(
                fixture.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            entry = EntryPoint(root)
            with self.assertRaisesRegex(
                PluginError,
                "legacy manifest v1 security model",
            ):
                _verified_manifest(entry, kind="policy", trusted_signers=())

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
            lines[-1] = "demo-distribution-1.0.0.dist-info/RECORD,,0"
            record.write_text("\n".join(lines) + "\n", encoding="utf-8")
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

    def test_plugin_trust_policy_modes_cover_digest_and_organization_policy_roots(
        self,
    ) -> None:
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
            signer, _ = write_manifest(
                root,
                sigstore_identity="https://github.com/example/plugin/.github/workflows/release.yml@refs/tags/v1",
                sigstore_issuer="https://token.actions.githubusercontent.com",
            )
            entry = EntryPoint(root)
            with self.assertRaisesRegex(PluginError, "unsupported claimed Sigstore"):
                _verified_manifest(
                    entry,
                    kind="advisory",
                    trusted_signers=(signer,),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signer, digests = write_manifest(root)
            entry = EntryPoint(root)
            _verified_manifest(
                entry,
                kind="advisory",
                trusted_signers=(signer,),
                trust_policy_mode="organization-policy",
            )
            _verified_manifest(
                entry,
                kind="advisory",
                trusted_signers=(),
                trusted_wheel_sha256=(digests["wheel_sha256"],),
                trust_policy_mode="organization-policy",
            )
            with self.assertRaisesRegex(PluginError, "organization policy"):
                _verified_manifest(
                    entry,
                    kind="advisory",
                    trusted_signers=(),
                    trust_policy_mode="organization-policy",
                )

    def test_plugin_trust_root_helper_rejects_untrusted_modes_and_roots(self) -> None:
        manifest = {"wheel_sha256": "a" * 64}

        self.assertEqual(
            plugin_mod._default_plugin_trust_policy_mode(
                trusted_signers=("signer",),
                trusted_wheel_sha256=(),
            ),
            "trusted-key",
        )
        self.assertEqual(
            plugin_mod._default_plugin_trust_policy_mode(
                trusted_signers=(),
                trusted_wheel_sha256=("digest",),
            ),
            "allowlisted-digest",
        )
        self.assertEqual(
            plugin_mod._default_plugin_trust_policy_mode(
                trusted_signers=(),
                trusted_wheel_sha256=(),
            ),
            "trusted-key",
        )

        plugin_mod._verify_plugin_trust_root(
            manifest,
            signer_sha256="B" * 64,
            trusted_signers=("b" * 64,),
            trusted_wheel_sha256=(),
            trust_policy_mode="trusted-key",
            plugin_name="advisory:demo",
        )
        plugin_mod._verify_plugin_trust_root(
            manifest,
            signer_sha256="b" * 64,
            trusted_signers=(),
            trusted_wheel_sha256=("A" * 64,),
            trust_policy_mode="allowlisted-digest",
            plugin_name="advisory:demo",
        )
        plugin_mod._verify_plugin_trust_root(
            manifest,
            signer_sha256="b" * 64,
            trusted_signers=("B" * 64,),
            trusted_wheel_sha256=(),
            trust_policy_mode="organization-policy",
            plugin_name="advisory:demo",
        )

        cases = [
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "disabled",
                },
                "requires a trust root",
            ),
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "trusted-key",
                },
                "requires trusted_signers",
            ),
            (
                {
                    "trusted_signers": ("c" * 64,),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "trusted-key",
                },
                "not allowlisted",
            ),
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "allowlisted-digest",
                },
                "requires trusted_wheel_sha256",
            ),
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": ("c" * 64,),
                    "trust_policy_mode": "allowlisted-digest",
                },
                "wheel digest is not allowlisted",
            ),
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "organization-policy",
                },
                "organization policy",
            ),
            (
                {
                    "trusted_signers": (),
                    "trusted_wheel_sha256": (),
                    "trust_policy_mode": "unknown",
                },
                "unsupported plugin trust policy mode",
            ),
        ]
        for kwargs, message in cases:
            with self.subTest(mode=kwargs["trust_policy_mode"]):
                with self.assertRaisesRegex(PluginError, message):
                    plugin_mod._verify_plugin_trust_root(
                        manifest,
                        signer_sha256="b" * 64,
                        plugin_name="advisory:demo",
                        **kwargs,
                    )

        with self.assertRaisesRegex(PluginError, "wheel_sha256"):
            plugin_mod._verify_plugin_trust_root(
                {},
                signer_sha256="b" * 64,
                trusted_signers=("b" * 64,),
                trusted_wheel_sha256=(),
                trust_policy_mode="trusted-key",
                plugin_name="advisory:demo",
            )

    def test_distribution_record_helpers_validate_metadata_and_record_edges(self) -> None:
        class StaticDistribution:
            def __init__(self, root: Path, files: tuple[str, ...]) -> None:
                self.root = root
                self.files = files

            def locate_file(self, name: str) -> Path:
                return self.root / name

        self.assertEqual(
            plugin_mod._distribution_name(
                SimpleNamespace(name="", metadata={"Name": "metadata-name"}),
            ),
            "metadata-name",
        )
        self.assertEqual(
            plugin_mod._distribution_version(
                SimpleNamespace(version="", metadata={"Version": "2.0.0"}),
            ),
            "2.0.0",
        )
        with self.assertRaisesRegex(PluginError, "missing a name"):
            plugin_mod._distribution_name(SimpleNamespace(metadata={}))
        with self.assertRaisesRegex(PluginError, "missing a name"):
            plugin_mod._distribution_name(SimpleNamespace(name=""))
        with self.assertRaisesRegex(PluginError, "missing a version"):
            plugin_mod._distribution_version(SimpleNamespace(metadata={}))
        with self.assertRaisesRegex(PluginError, "missing a version"):
            plugin_mod._distribution_version(SimpleNamespace(version=""))
        with self.assertRaisesRegex(PluginError, "configuration_schema"):
            plugin_mod._configuration_schema_sha256({"configuration_schema": []})
        with self.assertRaisesRegex(PluginError, "missing RECORD"):
            plugin_mod._distribution_files(SimpleNamespace(files=None))

        class CallableFilesDistribution:
            def files(self):
                return None

        with self.assertRaisesRegex(PluginError, "missing RECORD"):
            plugin_mod._distribution_files(CallableFilesDistribution())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(PluginError, "does not expose"):
                plugin_mod._distribution_record_path(
                    StaticDistribution(root, ("demo_plugin.py",))
                )
        with self.assertRaisesRegex(PluginError, "not UTF-8"):
            plugin_mod._record_rows(b"\xff", Path("RECORD"))
        with self.assertRaisesRegex(PluginError, "invalid row"):
            plugin_mod._record_rows(b"one,two\n", Path("RECORD"))
        platform_absolute_path = str(Path(Path.cwd().anchor) / "absolute.py")
        for value in ("", "../evil.py", platform_absolute_path, r"pkg\..\evil.py"):
            with self.subTest(path=value), self.assertRaisesRegex(
                PluginError,
                "unsafe path",
            ):
                plugin_mod._normalized_record_path(value)
        with self.assertRaisesRegex(PluginError, "cannot locate"):
            plugin_mod._locate_distribution_file(SimpleNamespace(), "pkg/file.py")
        with self.assertRaisesRegex(PluginError, "invalid hash"):
            plugin_mod._record_hash_digest("sha256", "pkg/file.py")
        with self.assertRaisesRegex(PluginError, "invalid hash"):
            plugin_mod._record_hash_digest("sha256=\u00f8", "pkg/file.py")

        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "payload.py"
            payload = b"payload"
            file_path.write_bytes(payload)
            digest = _record_digest(payload)
            wrong_digest = _record_digest(b"other")
            for hash_spec, size_text, message in (
                ("", "", "missing a hash"),
                (f"md5={digest}", "", "must use sha256"),
                (f"sha256={wrong_digest}", "", "hash does not match"),
                (f"sha256={digest}", "many", "invalid size"),
                (f"sha256={digest}", str(len(payload) + 1), "size does not match"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(
                    PluginError,
                    message,
                ):
                    plugin_mod._verify_recorded_file(
                        file_path,
                        "pkg/payload.py",
                        hash_spec,
                        size_text,
                    )
            self.assertEqual(
                plugin_mod._verify_recorded_file(
                    file_path,
                    "pkg/payload.py",
                    f"sha256={digest}",
                    str(len(payload)),
                ),
                (len(payload), hashlib.sha256(payload).hexdigest()),
            )
            self.assertEqual(
                plugin_mod._verify_recorded_file(
                    file_path,
                    "pkg/payload.py",
                    f"sha256={digest}",
                    "",
                ),
                (len(payload), hashlib.sha256(payload).hexdigest()),
            )
            with self.assertRaisesRegex(PluginError, "unable to read plugin file"):
                plugin_mod._verify_recorded_file(
                    Path(directory),
                    "pkg/directory",
                    f"sha256={digest}",
                    "",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifest(root)
            record_relative = "demo-distribution-1.0.0.dist-info/RECORD"
            record_path = root / record_relative
            manifest_path = root / "trustcheck-plugin.json"
            distribution = StaticDistribution(
                root,
                ("demo_plugin.py", "trustcheck-plugin.json", record_relative),
            )
            with patch(
                "trustcheck.plugins._distribution_record_path",
                return_value=root,
            ):
                with self.assertRaisesRegex(PluginError, "unable to read plugin RECORD"):
                    plugin_mod._verify_distribution_record(
                        distribution,
                        manifest_path=manifest_path,
                    )

            record_path.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "RECORD .* is empty"):
                plugin_mod._verify_distribution_record(
                    StaticDistribution(root, (record_relative,)),
                    manifest_path=manifest_path,
                )

            rows = [
                _record_row(root, "demo_plugin.py"),
                _record_row(root, "demo_plugin.py"),
                ("trustcheck-plugin.json", "", ""),
                (record_relative, "", ""),
            ]
            _write_record(root, rows)
            with self.assertRaisesRegex(PluginError, "duplicate entry"):
                plugin_mod._verify_distribution_record(
                    distribution,
                    manifest_path=manifest_path,
                )

            rows = [
                ("missing.py", "sha256=" + _record_digest(b""), "0"),
                ("trustcheck-plugin.json", "", ""),
                (record_relative, "", ""),
            ]
            _write_record(root, rows)
            with self.assertRaisesRegex(PluginError, "missing file"):
                plugin_mod._verify_distribution_record(
                    StaticDistribution(
                        root,
                        ("missing.py", "trustcheck-plugin.json", record_relative),
                    ),
                    manifest_path=manifest_path,
                )

            rows = [
                _record_row(root, "demo_plugin.py"),
                _record_row(root, "trustcheck-plugin.json"),
                (record_relative, "", ""),
            ]
            _write_record(root, rows)
            with self.assertRaisesRegex(PluginError, "manifest RECORD entry"):
                plugin_mod._verify_distribution_record(
                    distribution,
                    manifest_path=manifest_path,
                )

            rows = [_record_row(root, "demo_plugin.py"), (record_relative, "", "")]
            _write_record(root, rows)
            with self.assertRaisesRegex(PluginError, "manifest is not listed"):
                plugin_mod._verify_distribution_record(
                    StaticDistribution(root, ("demo_plugin.py", record_relative)),
                    manifest_path=manifest_path,
                )

            rows = [_record_row(root, "demo_plugin.py"), ("trustcheck-plugin.json", "", "")]
            _write_record(root, rows)
            with self.assertRaisesRegex(PluginError, "RECORD does not list itself"):
                plugin_mod._verify_distribution_record(
                    distribution,
                    manifest_path=manifest_path,
                )

            with self.assertRaisesRegex(PluginError, "unrecorded file"):
                plugin_mod._reject_unrecorded_distribution_files(
                    StaticDistribution(root, ("extra.py",)),
                    set(),
                )
            plugin_mod._reject_unrecorded_physical_file(
                root / "outside.py",
                root / "other-root",
                set(),
            )
            with patch("pathlib.Path.resolve", side_effect=OSError("bad path")):
                self.assertFalse(plugin_mod._same_file(root / "a", root / "b"))

        class RequiresCallableDistribution:
            def requires(self):
                return (" requests>=2 ", "")

        class MetadataRequires:
            def get_all(self, name):
                return ["demo-dep==1"] if name == "Requires-Dist" else []

        self.assertEqual(
            plugin_mod._distribution_dependencies(RequiresCallableDistribution()),
            ["requests>=2"],
        )
        self.assertEqual(
            plugin_mod._distribution_dependencies(
                SimpleNamespace(requires=None, metadata=MetadataRequires()),
            ),
            ["demo-dep==1"],
        )
        self.assertEqual(
            plugin_mod._distribution_dependencies(SimpleNamespace(requires=None)),
            [],
        )
        with self.assertRaisesRegex(PluginError, "must be a sequence"):
            plugin_mod._distribution_dependencies(SimpleNamespace(requires="demo"))
        plugin_mod._verify_manifest_capabilities(
            {
                "capabilities": ["query"],
            },
            kind="advisory",
        )
        with self.assertRaisesRegex(PluginError, "unsupported capability"):
            plugin_mod._verify_manifest_capabilities(
                {
                    "capabilities": ["query", "extra"],
                },
                kind="advisory",
            )
        with self.assertRaisesRegex(PluginError, "unsupported resource"):
            plugin_mod._verify_manifest_capabilities(
                {
                    "capabilities": ["query"],
                    "requires_network": False,
                },
                kind="advisory",
            )
        with self.assertRaisesRegex(PluginError, "capabilities"):
            plugin_mod._required_string_list(
                {"capabilities": ["query", 3]},
                "capabilities",
                "plugin manifest",
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

    def test_resource_bounded_proxy_covers_all_plugin_and_repository_operations(
        self,
    ) -> None:
        manager = PluginManager()
        proxy = _ResourceBoundedPlugin("demo", "artifact", "module:Plugin", manager)
        with patch.object(
            PluginManager,
            "_invoke_resource_bounded",
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

    def test_plugin_resource_limits_never_raise_existing_platform_caps(self) -> None:
        resource = ResourceModule(
            {
                ResourceModule.RLIMIT_CPU: (
                    ResourceModule.RLIM_INFINITY,
                    ResourceModule.RLIM_INFINITY,
                ),
                ResourceModule.RLIMIT_AS: (128 * 1024 * 1024, 128 * 1024 * 1024),
            }
        )

        plugin_mod._set_plugin_resource_limit(resource, resource.RLIMIT_CPU, 8)
        plugin_mod._set_plugin_resource_limit(
            resource,
            resource.RLIMIT_AS,
            256 * 1024 * 1024,
        )

        self.assertEqual(resource.calls[0], (resource.RLIMIT_CPU, (8, 8)))
        self.assertEqual(
            resource.calls[1],
            (resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024)),
        )

        resource.fail_next_set = True
        plugin_mod._set_plugin_resource_limit(resource, resource.RLIMIT_CPU, 4)
        plugin_mod._set_plugin_resource_limit(resource, None, 4)
        plugin_mod._set_plugin_resource_limit(SimpleNamespace(), 1, 4)

        class FailingLimitResource:
            RLIM_INFINITY = -1

            def getrlimit(self, limit_name):
                del limit_name
                raise OSError("unsupported")

            def setrlimit(self, limit_name, values):
                raise AssertionError((limit_name, values))

        plugin_mod._set_plugin_resource_limit(FailingLimitResource(), 1, 4)

        capped_resource = ResourceModule(
            {
                ResourceModule.RLIMIT_CPU: (10, 5),
                ResourceModule.RLIMIT_AS: (10, 5),
            }
        )
        plugin_mod._set_plugin_resource_limit(
            capped_resource,
            capped_resource.RLIMIT_CPU,
            8,
        )
        self.assertEqual(
            capped_resource.calls[-1],
            (capped_resource.RLIMIT_CPU, (5, 5)),
        )

    def test_plugin_ipc_result_serialization_round_trips_supported_operations(self) -> None:
        report = TrustReport(
            project="demo",
            version="1",
            summary=None,
            package_url="pkg:pypi/demo@1",
        )
        inspection = ArtifactInspection(kind="wheel")
        finding = HeuristicFinding(
            code="plugin",
            category="plugin",
            severity="medium",
            confidence="high",
            score=10,
            message="checked",
        )
        violation = PolicyViolation(code="policy", severity="high", message="blocked")
        project = IndexProject(
            name="demo",
            index_url="demo+https://index/",
            files=(),
        )
        confusion = DependencyConfusionFinding(project="demo", indexes=("one", "two"))

        cases = [
            ("query", [VulnerabilityRecord(id="PLUGIN-1", summary="plugin")]),
            ("analyze", [finding]),
            ("evaluate", [violation]),
            ("render", "rendered"),
            ("supports", True),
            ("client.get_project", project),
            ("client.download", b"payload"),
            ("client.find_dependency_confusion", [confusion]),
            ("client.locate_artifact_index", "demo+https://index/"),
            ("client.locate_artifact_index", None),
        ]
        for operation, value in cases:
            with self.subTest(operation=operation, value_type=type(value).__name__):
                data = plugin_mod._plugin_result_to_data(operation, value)
                restored = plugin_mod._plugin_result_from_data(operation, data)
                if operation in {"query", "analyze", "evaluate"}:
                    self.assertEqual(type(restored[0]), type(value[0]))
                elif operation == "client.find_dependency_confusion":
                    self.assertIsInstance(restored[0], DependencyConfusionFinding)
                else:
                    self.assertEqual(restored, value)

        package = ExportPackage(
            report=report,
            source=SourceLocation(uri="file:///src/demo.py", line=7),
            artifacts=(
                ArtifactReference(
                    filename="demo.whl",
                    hashes=(("sha256", "0" * 64),),
                    size=10,
                    kind="wheel",
                ),
            ),
        )
        request_data = plugin_mod._request_value_to_data(
            {
                "payload": b"wheel",
                "inspection": inspection,
                "report": report,
                "package": package,
                "artifact": package.artifacts[0],
            }
        )
        restored_request = plugin_mod._request_value_from_data(request_data)
        self.assertEqual(restored_request["payload"], b"wheel")
        self.assertIsInstance(restored_request["inspection"], ArtifactInspection)
        self.assertIsInstance(restored_request["report"], TrustReport)
        self.assertIsInstance(restored_request["package"], ExportPackage)
        self.assertIsInstance(restored_request["artifact"], ArtifactReference)

    def test_plugin_ipc_helpers_reject_invalid_json_and_model_shapes(self) -> None:
        with self.assertRaisesRegex(PluginError, "unsupported plugin operation"):
            plugin_mod._validate_plugin_operation_keys("unknown", [])
        with self.assertRaisesRegex(PluginError, "missing version"):
            plugin_mod._validate_plugin_operation_keys("query", ["project"])
        with self.assertRaisesRegex(PluginError, "unknown extra"):
            plugin_mod._validate_plugin_operation_keys(
                "query",
                ["project", "version", "extra"],
            )
        with self.assertRaisesRegex(PluginError, "kwargs must be an object"):
            plugin_mod._plugin_kwargs_from_data("query", [])
        with self.assertRaisesRegex(PluginError, "non-string object key"):
            plugin_mod._request_value_to_data({1: "bad"})
        with self.assertRaisesRegex(PluginError, "unsupported typed request value"):
            plugin_mod._request_value_from_data(
                {"__trustcheck_type__": "Unknown", "data": {}}
            )
        with self.assertRaisesRegex(PluginError, "TrustReport request data"):
            plugin_mod._request_value_from_data(
                {"__trustcheck_type__": "TrustReport", "data": []}
            )
        with self.assertRaisesRegex(PluginError, "bytes value must be an object"):
            plugin_mod._bytes_from_data([])
        with self.assertRaisesRegex(PluginError, "unsupported type tag"):
            plugin_mod._bytes_from_data({"__trustcheck_type__": "str", "data": ""})
        with self.assertRaisesRegex(PluginError, "not valid base64"):
            plugin_mod._bytes_from_data(
                {"__trustcheck_type__": "bytes", "data": "not-base64!"}
            )
        source = SourceLocation(uri="file:///src/demo.py", line=7)
        source_data = plugin_mod._request_value_to_data(source)
        self.assertEqual(
            plugin_mod._request_value_from_data([source_data])[0],
            source,
        )
        with self.assertRaisesRegex(PluginError, "ExportPackage report"):
            plugin_mod._export_package_from_data(
                {"report": [], "source": None, "artifacts": []}
            )
        with self.assertRaisesRegex(PluginError, "index file yanked"):
            plugin_mod._index_file_from_data(
                {"filename": "demo.whl", "url": "https://files/demo.whl", "yanked": 3}
            )
        for value, message in (
            ([["sha256"]], "two-item lists"),
            ([[3, "digest"]], "contain strings"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                PluginError,
                message,
            ):
                plugin_mod._hash_pairs_from_data(value, "hashes")
        with self.assertRaisesRegex(PluginError, "DemoModel must be an object"):
            plugin_mod._strict_mapping([], "DemoModel", set())
        with self.assertRaisesRegex(PluginError, "unsupported field"):
            plugin_mod._reject_unknown_fields({"extra": 1}, "DemoModel", set())
        with self.assertRaisesRegex(PluginError, "items must be a list"):
            plugin_mod._required_list("bad", "items")
        with self.assertRaisesRegex(PluginError, "demo must be an object"):
            plugin_mod._required_string([], "name", "demo")
        with self.assertRaisesRegex(PluginError, "demo value must be a string"):
            plugin_mod._required_string(3, "", "demo")
        with self.assertRaisesRegex(PluginError, "maybe must be a string or null"):
            plugin_mod._optional_string({"maybe": 3}, "maybe", "demo")
        with self.assertRaisesRegex(PluginError, "count must be an integer or null"):
            plugin_mod._optional_int({"count": True}, "count", "demo")

        with self.assertRaisesRegex(PluginError, "non-finite number"):
            plugin_mod._json_value(float("nan"), path="value")
        with self.assertRaisesRegex(PluginError, "non-string object key"):
            plugin_mod._json_value({1: "bad"}, path="value")
        with patch("trustcheck.plugins.PLUGIN_IPC_MAX_DEPTH", 1):
            with self.assertRaisesRegex(PluginError, "depth limit"):
                plugin_mod._json_value([[[]]], path="value")
        with patch("trustcheck.plugins.PLUGIN_IPC_MAX_MAPPING_LENGTH", 1):
            with self.assertRaisesRegex(PluginError, "mapping length"):
                plugin_mod._json_value({"a": 1, "b": 2}, path="value")
        with patch("trustcheck.plugins.PLUGIN_IPC_MAX_LIST_LENGTH", 1):
            with self.assertRaisesRegex(PluginError, "list length"):
                plugin_mod._json_value([1, 2], path="value")
        with patch("trustcheck.plugins.PLUGIN_IPC_MAX_STRING_LENGTH", 1):
            with self.assertRaisesRegex(PluginError, "object key"):
                plugin_mod._json_value({"long": 1}, path="value")
            with self.assertRaisesRegex(PluginError, "string length"):
                plugin_mod._json_value("long", path="value")
        with self.assertRaisesRegex(PluginError, "unsupported value type"):
            plugin_mod._json_value(object(), path="value")
        with self.assertRaisesRegex(PluginError, "byte limit"):
            plugin_mod._encode_plugin_message(
                {"ok": True},
                max_bytes=1,
                label="message",
            )

        with self.assertRaisesRegex(PluginError, "byte limit"):
            plugin_mod._decode_plugin_message(b"{}", max_bytes=1, label="message")
        with self.assertRaisesRegex(PluginError, "not valid JSON"):
            plugin_mod._decode_plugin_message(b"{", max_bytes=100, label="message")
        with self.assertRaisesRegex(PluginError, "must be a JSON object"):
            plugin_mod._decode_plugin_message(b"[]", max_bytes=100, label="message")

        envelope = {
            "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
            "request_id": "request-1",
            "entry_value": "module:Plugin",
            "operation": "query",
            "kwargs": {"project": "demo", "version": "1"},
        }
        for update, message in (
            ({"plugin_protocol_version": "2"}, "incompatible plugin IPC protocol"),
            ({"entry_value": ""}, "entry point cannot be empty"),
            ({"request_id": ""}, "request id cannot be empty"),
            ({"kwargs": []}, "kwargs must be an object"),
        ):
            candidate = {**envelope, **update}
            with self.subTest(message=message), self.assertRaisesRegex(
                PluginError,
                message,
            ):
                plugin_mod._validate_request_envelope(candidate)

        with self.assertRaisesRegex(PluginError, "supports result must be a boolean"):
            plugin_mod._plugin_result_from_data("supports", "true")
        with self.assertRaisesRegex(PluginError, "render result must be a string"):
            plugin_mod._plugin_result_from_data("render", 3)
        with self.assertRaisesRegex(PluginError, "string or null"):
            plugin_mod._plugin_result_from_data("client.locate_artifact_index", 3)
        with self.assertRaisesRegex(PluginError, "unsupported plugin operation"):
            plugin_mod._plugin_result_from_data("unknown", None)

        self.assertIsNone(plugin_mod._plugin_result_to_data("client.get_project", None))

        for operation, value, message in (
            ("query", "bad", "expected a sequence"),
            ("query", [object()], "expected VulnerabilityRecord"),
            ("render", 3, "expected str"),
            ("supports", "true", "expected bool"),
            ("client.download", "payload", "expected bytes"),
            ("client.locate_artifact_index", 3, "expected str or None"),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                TypeError,
                message,
            ):
                plugin_mod._plugin_result_to_data(operation, value)
        with self.assertRaisesRegex(PluginError, "unsupported plugin operation"):
            plugin_mod._plugin_result_to_data("unknown", None)

    def test_plugin_ipc_helpers_reject_malformed_envelopes(self) -> None:
        with patch("trustcheck.plugins._new_plugin_request_id", return_value="request-1"):
            request_id, payload = plugin_mod._plugin_request_payload(
                "module:Plugin",
                "render",
                {
                    "packages": [],
                    "source_name": "source",
                    "failures": [],
                    "config": {},
                },
            )
        decoded = plugin_mod._decode_plugin_message(
            payload,
            max_bytes=plugin_mod.PLUGIN_IPC_MAX_REQUEST_BYTES,
            label="plugin IPC request",
        )
        self.assertEqual(request_id, "request-1")
        self.assertEqual(plugin_mod._validate_request_envelope(decoded), "request-1")
        self.assertEqual(
            plugin_mod._plugin_result_from_response(
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "request-1",
                    "ok": True,
                    "result": "ok",
                },
                request_id="request-1",
                operation="render",
            ),
            "ok",
        )

        bad_responses = [
            (
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "other",
                    "ok": True,
                    "result": "ok",
                },
                "request id",
            ),
            (
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "request-1",
                    "ok": "yes",
                    "result": "ok",
                },
                "ok must be a boolean",
            ),
            (
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "request-1",
                    "ok": True,
                },
                "missing result",
            ),
            (
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "request-1",
                    "ok": False,
                    "error": "boom",
                },
                "error object",
            ),
        ]
        for response, message in bad_responses:
            with self.subTest(message=message), self.assertRaisesRegex(PluginError, message):
                plugin_mod._plugin_result_from_response(
                    response,
                    request_id="request-1",
                    operation="render",
                )

        with self.assertRaisesRegex(PluginError, "plugin operation failed: RuntimeError"):
            plugin_mod._plugin_result_from_response(
                {
                    "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                    "request_id": "request-1",
                    "ok": False,
                    "error": {"type": "RuntimeError", "message": ""},
                },
                request_id="request-1",
                operation="render",
            )

    def test_direct_plugin_execution_and_worker_response_fallbacks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "exec_plugin.py").write_text(
                "\n".join(
                    [
                        "from trustcheck.models import VulnerabilityRecord",
                        "",
                        "class Client:",
                        "    def download(self, url, *, index_url=None):",
                        "        return f'{index_url}:{url}'.encode()",
                        "",
                        "class Plugin:",
                        "    def query(self, project, version):",
                        "        return [VulnerabilityRecord(",
                        "            id=f'{project}-{version}',",
                        "            summary='ok',",
                        "        )]",
                        "    def supports(self, index_url):",
                        "        return index_url.startswith('demo+')",
                        "    def create_client(self, *, index_url, config):",
                        "        return Client()",
                        "",
                        "plugin = Plugin()",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                query_data = plugin_mod._execute_plugin_request(
                    {
                        "entry_value": "exec_plugin:Plugin",
                        "operation": "query",
                        "kwargs": plugin_mod._plugin_kwargs_to_data(
                            "query",
                            {"project": "demo", "version": "1"},
                        ),
                    }
                )
                self.assertEqual(query_data[0]["id"], "demo-1")
                self.assertTrue(
                    plugin_mod._execute_plugin_request(
                        {
                            "entry_value": "exec_plugin:plugin",
                            "operation": "supports",
                            "kwargs": plugin_mod._plugin_kwargs_to_data(
                                "supports",
                                {"index_url": "demo+https://index/"},
                            ),
                        }
                    )
                )
                download_data = plugin_mod._execute_plugin_request(
                    {
                        "entry_value": "exec_plugin:Plugin",
                        "operation": "client.download",
                        "kwargs": plugin_mod._plugin_kwargs_to_data(
                            "client.download",
                            {
                                "client_index_url": "demo+https://index/",
                                "client_config": {},
                                "url": "https://files/demo.whl",
                                "index_url": "demo+https://index/",
                            },
                        ),
                    }
                )
                self.assertEqual(
                    plugin_mod._bytes_from_data(download_data),
                    b"demo+https://index/:https://files/demo.whl",
                )
                with self.assertRaisesRegex(ValueError, "module:attribute"):
                    plugin_mod._execute_plugin_request(
                        {
                            "entry_value": "exec_plugin",
                            "operation": "query",
                            "kwargs": plugin_mod._plugin_kwargs_to_data(
                                "query",
                                {"project": "demo", "version": "1"},
                            ),
                        }
                    )
            finally:
                sys.path.remove(str(root))
                sys.modules.pop("exec_plugin", None)

        error = plugin_mod._plugin_error_response("request-1", RuntimeError("x" * 5000))
        self.assertLessEqual(len(error["error"]["message"]), 4096)
        self.assertTrue(error["error"]["message"].endswith("..."))

        sender = Mock()
        plugin_mod._send_plugin_response(
            sender,
            {
                "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                "request_id": "request-1",
                "ok": True,
                "result": object(),
            },
        )
        decoded = plugin_mod._decode_plugin_message(
            sender.send_bytes.call_args.args[0],
            max_bytes=plugin_mod.PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
        self.assertFalse(decoded["ok"])
        self.assertEqual(decoded["request_id"], "request-1")
        self.assertIn("unsupported value type", decoded["error"]["message"])

        sender = Mock()
        plugin_mod._send_plugin_response(
            sender,
            {
                "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                "request_id": "request-2",
                "ok": True,
                "result": "ok",
            },
        )
        decoded = plugin_mod._decode_plugin_message(
            sender.send_bytes.call_args.args[0],
            max_bytes=plugin_mod.PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
        self.assertEqual(decoded["result"], "ok")

        sender = Mock()
        plugin_mod._send_plugin_response(
            sender,
            {
                "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
                "request_id": 3,
                "ok": True,
                "result": object(),
            },
        )
        decoded = plugin_mod._decode_plugin_message(
            sender.send_bytes.call_args.args[0],
            max_bytes=plugin_mod.PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
        self.assertEqual(decoded["request_id"], "unknown")

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

        request_receiver = Mock()
        request_sender = Mock()
        request_sender.send_bytes.side_effect = OSError("closed")
        response_receiver = Mock()
        response_sender = Mock()
        response_receiver.poll.return_value = True
        response_receiver.recv_bytes.return_value = _ipc_response(
            "request-1",
            result="ok",
        )
        process = Mock()
        process.is_alive.return_value = False
        context = Mock()
        context.Pipe.side_effect = [
            (request_receiver, request_sender),
            (response_receiver, response_sender),
        ]
        context.Process.return_value = process
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "could not receive request"):
            _run_plugin_process("module:Plugin", "render", kwargs, timeout=1)

        context = _process_context(ready=True, received=ValueError("too large"))
        with patch(
            "trustcheck.plugins.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "trustcheck.plugins._new_plugin_request_id",
            return_value="request-1",
        ), self.assertRaisesRegex(PluginError, "response exceeded"):
            _run_plugin_process("module:Plugin", "render", kwargs, timeout=1)

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
        schema_root = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "trustcheck"
            / "plugin_schemas"
        )
        expected = {
            "plugin-statement-2.json": (
                "urn:trustcheck:plugin-statement:2",
                "16b4d80108a950cbe9f210e3e871fb37c083bf8cdddaa22d328b7d12576f9742",
            ),
            "plugin-ipc-request-1.json": (
                "urn:trustcheck:plugin-ipc-request:1",
                "78c0a8b2e2bbf50623979e4b1ffeda9aa082f208ef79c542b7a633262469b86d",
            ),
            "plugin-ipc-response-1.json": (
                "urn:trustcheck:plugin-ipc-response:1",
                "9b3c06148b76202dbfd4d5ec950def4e0b2104449acf0155e8a7c08d616092fd",
            ),
        }
        for filename, (schema_id, digest) in expected.items():
            path = schema_root / filename
            payload = path.read_bytes()
            schema = json.loads(payload.decode("utf-8"))
            with self.subTest(filename=filename):
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                self.assertEqual(schema["$id"], schema_id)
                self.assertEqual(
                    schema["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )

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
