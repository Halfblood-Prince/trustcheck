from __future__ import annotations

import base64
import csv
import hashlib
import importlib
import json
import math
import multiprocessing
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields
from importlib.metadata import EntryPoint, entry_points
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .contract import (
    ArtifactInspectionPayload,
    HeuristicFindingPayload,
    NativeBinaryInspectionPayload,
    PolicyViolationPayload,
    VulnerabilityRecordPayload,
    VulnerabilitySuppressionPayload,
    deserialize_report,
    serialize_report,
)
from .export_models import ExportPackage, SourceLocation
from .indexes import (
    DependencyConfusionFinding,
    IndexFile,
    IndexProject,
    redact_url_credentials,
)
from .models import (
    ArtifactInspection,
    HeuristicFinding,
    NativeBinaryInspection,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from .resolver import ArtifactReference

PLUGIN_API_VERSION = "1"
PLUGIN_IPC_PROTOCOL_VERSION = "1"
PLUGIN_IPC_REQUEST_SCHEMA = "urn:trustcheck:plugin-ipc-request:1"
PLUGIN_IPC_RESPONSE_SCHEMA = "urn:trustcheck:plugin-ipc-response:1"
PLUGIN_SIGNED_STATEMENT_SCHEMA = "urn:trustcheck:plugin-statement:1"
PLUGIN_IPC_MAX_REQUEST_BYTES = 192 * 1024 * 1024
PLUGIN_IPC_MAX_RESPONSE_BYTES = 192 * 1024 * 1024
PLUGIN_IPC_MAX_DEPTH = 32
PLUGIN_IPC_MAX_LIST_LENGTH = 10_000
PLUGIN_IPC_MAX_MAPPING_LENGTH = 10_000
PLUGIN_IPC_MAX_STRING_LENGTH = 192 * 1024 * 1024
PLUGIN_MANIFEST_SCHEMA = "urn:trustcheck:plugin-manifest:1"
PLUGIN_MANIFEST_NAME = "trustcheck-plugin.json"
PLUGIN_EMPTY_CONFIGURATION_SCHEMA_SHA256 = hashlib.sha256(b"").hexdigest()
DEFAULT_PLUGIN_TIMEOUT = 10.0
PLUGIN_CPU_SECONDS = 8
PLUGIN_MEMORY_BYTES = 256 * 1024 * 1024
PLUGIN_TRUST_POLICY_MODES = frozenset(
    {
        "disabled",
        "allowlisted-digest",
        "trusted-key",
        "organization-policy",
    }
)
PLUGIN_GROUPS = {
    "advisory": "trustcheck.advisory_sources",
    "index": "trustcheck.indexes",
    "artifact": "trustcheck.artifact_analyzers",
    "policy": "trustcheck.policy_rules",
    "renderer": "trustcheck.renderers",
}
PLUGIN_KIND_CAPABILITIES: dict[str, frozenset[str]] = {
    "advisory": frozenset({"query"}),
    "artifact": frozenset({"analyze"}),
    "policy": frozenset({"evaluate"}),
    "renderer": frozenset({"render"}),
    "index": frozenset(
        {
            "supports",
            "create_client",
            "client.get_project",
            "client.download",
            "client.find_dependency_confusion",
            "client.locate_artifact_index",
        }
    ),
}


class PluginError(RuntimeError):
    """Raised when a requested plugin cannot be loaded or violates its contract."""


class AdvisorySourcePlugin(Protocol):
    name: str

    def query(self, project: str, version: str) -> Sequence[VulnerabilityRecord]: ...


class ArtifactAnalyzerPlugin(Protocol):
    name: str

    def analyze(
        self,
        *,
        filename: str,
        payload: bytes,
        project: str,
        version: str,
        inspection: ArtifactInspection,
        config: Mapping[str, Any],
    ) -> Sequence[HeuristicFinding]: ...


class PolicyRulePlugin(Protocol):
    name: str

    def evaluate(
        self,
        *,
        report: TrustReport,
        config: Mapping[str, Any],
    ) -> Sequence[PolicyViolation]: ...


class RendererPlugin(Protocol):
    name: str
    extension: str

    def render(
        self,
        *,
        packages: Sequence[object],
        source_name: str,
        failures: Sequence[Mapping[str, str]],
        config: Mapping[str, Any],
    ) -> str: ...


class IndexPlugin(Protocol):
    name: str

    def supports(self, index_url: str) -> bool: ...

    def create_client(
        self,
        *,
        index_url: str,
        config: Mapping[str, Any],
    ) -> object: ...


class RepositoryClient(Protocol):
    def get_project(self, index_url: str, project: str) -> object: ...

    def download(self, url: str, *, index_url: str | None = None) -> bytes: ...

    def find_dependency_confusion(
        self,
        projects: Sequence[str],
        indexes: Sequence[str],
    ) -> tuple[DependencyConfusionFinding, ...]: ...

    def locate_artifact_index(
        self,
        project: str,
        artifact_url: str | None,
        indexes: Sequence[str],
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class PluginDescriptor:
    name: str
    kind: str
    group: str
    value: str
    distribution: str | None = None
    distribution_version: str | None = None
    api_version: str = PLUGIN_API_VERSION
    signer_sha256: str | None = None
    wheel_sha256: str | None = None
    record_sha256: str | None = None
    trust_policy_mode: str | None = None
    manifest_path: str | None = None
    isolated: bool = True


@dataclass(frozen=True, slots=True)
class PluginExecution:
    plugin: str
    kind: str
    operation: str
    status: str
    duration_ms: float
    isolated: bool


@dataclass(slots=True)
class PluginManager:
    enabled: bool = False
    selected: tuple[str, ...] = ()
    config: dict[str, Any] = field(default_factory=dict)
    allowlist: tuple[str, ...] = ()
    trusted_signers: tuple[str, ...] = ()
    trusted_wheel_sha256: tuple[str, ...] = ()
    require_signed: bool = True
    trust_policy_mode: str = "trusted-key"
    isolate: bool = True
    timeout: float = DEFAULT_PLUGIN_TIMEOUT
    entry_point_loader: Callable[..., object] = entry_points
    _plugins: dict[str, list[tuple[PluginDescriptor, object]]] = field(
        default_factory=dict,
        init=False,
    )
    _loaded: bool = field(default=False, init=False)
    _executions: list[PluginExecution] = field(default_factory=list, init=False)

    @classmethod
    def from_options(
        cls,
        *,
        enabled: bool,
        selected: Sequence[str] = (),
        config_path: str | None = None,
    ) -> PluginManager:
        config: dict[str, Any] = {}
        if config_path:
            payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise PluginError("plugin config must contain a top-level JSON object")
            config = payload
        controls = config.get("_trustcheck", {})
        if controls is None:
            controls = {}
        if not isinstance(controls, dict):
            raise PluginError("plugin config _trustcheck control must be an object")
        raw_allowlist = controls.get("allowlist", [])
        raw_signers = controls.get("trusted_signers", [])
        raw_wheel_digests = controls.get("trusted_wheel_sha256", [])
        trust_policy_mode = str(controls.get("trust_policy_mode", "") or "")
        if not isinstance(raw_allowlist, list) or any(
            not isinstance(item, str) for item in raw_allowlist
        ):
            raise PluginError("plugin allowlist must contain plugin names")
        if not isinstance(raw_signers, list) or any(
            not isinstance(item, str) for item in raw_signers
        ):
            raise PluginError("trusted_signers must contain SHA-256 fingerprints")
        if not isinstance(raw_wheel_digests, list) or any(
            not isinstance(item, str) for item in raw_wheel_digests
        ):
            raise PluginError("trusted_wheel_sha256 must contain SHA-256 digests")
        if controls.get("trusted_sigstore_identities"):
            raise PluginError(
                "trusted_sigstore_identities is not supported for plugins; "
                "real Sigstore bundle verification is not implemented"
            )
        if not trust_policy_mode:
            trust_policy_mode = _default_plugin_trust_policy_mode(
                trusted_signers=raw_signers,
                trusted_wheel_sha256=raw_wheel_digests,
            )
        if trust_policy_mode not in PLUGIN_TRUST_POLICY_MODES:
            raise PluginError(
                "plugin trust_policy_mode must be one of: "
                + ", ".join(sorted(PLUGIN_TRUST_POLICY_MODES))
            )
        allowlist = tuple(dict.fromkeys([*selected, *raw_allowlist]))
        if enabled and not allowlist:
            raise PluginError(
                "--enable-plugins requires an explicit --plugin or configured allowlist"
            )
        require_signed = controls.get("require_signed", True) is not False
        if trust_policy_mode == "disabled":
            require_signed = False
        return cls(
            enabled=enabled or bool(allowlist),
            selected=tuple(selected),
            config=config,
            allowlist=allowlist,
            trusted_signers=tuple(item.lower() for item in raw_signers),
            trusted_wheel_sha256=tuple(item.lower() for item in raw_wheel_digests),
            require_signed=require_signed,
            trust_policy_mode=trust_policy_mode,
            isolate=controls.get("isolate", True) is not False,
            timeout=float(controls.get("timeout", DEFAULT_PLUGIN_TIMEOUT)),
        )

    def executions(self) -> tuple[PluginExecution, ...]:
        return tuple(self._executions)

    def attach_executions(self, report: TrustReport) -> None:
        report.diagnostics.plugin_executions = [
            {
                "plugin": item.plugin,
                "kind": item.kind,
                "operation": item.operation,
                "status": item.status,
                "duration_ms": item.duration_ms,
                "isolated": item.isolated,
            }
            for item in self._executions
        ]

    def descriptors(self) -> tuple[PluginDescriptor, ...]:
        self._ensure_loaded()
        return tuple(
            descriptor
            for kind in sorted(self._plugins)
            for descriptor, _ in self._plugins[kind]
        )

    def advisory_sources(self) -> tuple[AdvisorySourcePlugin, ...]:
        return self._typed_plugins("advisory")

    def artifact_analyzers(self) -> tuple[ArtifactAnalyzerPlugin, ...]:
        return self._typed_plugins("artifact")

    def policy_rules(self) -> tuple[PolicyRulePlugin, ...]:
        return self._typed_plugins("policy")

    def renderers(self) -> tuple[RendererPlugin, ...]:
        return self._typed_plugins("renderer")

    def index_plugins(self) -> tuple[IndexPlugin, ...]:
        return self._typed_plugins("index")

    def output_formats(self) -> tuple[str, ...]:
        return tuple(sorted(plugin.name for plugin in self.renderers()))

    def render(
        self,
        output_format: str,
        *,
        packages: Sequence[object],
        source_name: str,
        failures: Sequence[Mapping[str, str]],
    ) -> str:
        matches = [
            plugin for plugin in self.renderers() if plugin.name == output_format
        ]
        if len(matches) != 1:
            raise PluginError(f"unknown or duplicate renderer plugin: {output_format}")
        plugin = matches[0]
        return plugin.render(
            packages=packages,
            source_name=source_name,
            failures=failures,
            config=self.plugin_config(plugin.name),
        )

    def analyze_artifact(
        self,
        *,
        filename: str,
        payload: bytes,
        project: str,
        version: str,
        inspection: ArtifactInspection,
    ) -> list[HeuristicFinding]:
        findings: list[HeuristicFinding] = []
        for plugin in self.artifact_analyzers():
            values = plugin.analyze(
                filename=filename,
                payload=payload,
                project=project,
                version=version,
                inspection=inspection,
                config=self.plugin_config(plugin.name),
            )
            for finding in values:
                if not isinstance(finding, HeuristicFinding):
                    raise PluginError(
                        f"artifact plugin {plugin.name!r} returned "
                        f"{type(finding).__name__}, expected HeuristicFinding"
                    )
                findings.append(finding)
        return findings

    def evaluate_policy(self, report: TrustReport) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for plugin in self.policy_rules():
            values = plugin.evaluate(
                report=report,
                config=self.plugin_config(plugin.name),
            )
            for violation in values:
                if not isinstance(violation, PolicyViolation):
                    raise PluginError(
                        f"policy plugin {plugin.name!r} returned "
                        f"{type(violation).__name__}, expected PolicyViolation"
                    )
                violations.append(violation)
        return violations

    def plugin_config(self, name: str) -> Mapping[str, Any]:
        value = self.config.get(name, {})
        if not isinstance(value, dict):
            raise PluginError(f"plugin config for {name!r} must be an object")
        return value

    def repository_client(self, fallback: RepositoryClient) -> RepositoryClient:
        plugins = self.index_plugins()
        if not plugins:
            return fallback
        return PluginRepositoryClient(
            plugins=plugins,
            fallback=fallback,
            manager=self,
        )

    def _typed_plugins(self, kind: str) -> tuple[Any, ...]:
        self._ensure_loaded()
        return tuple(plugin for _, plugin in self._plugins.get(kind, []))

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled:
            return
        selected = set(self.allowlist or self.selected)
        discovered_names: set[str] = set()
        for kind, group in PLUGIN_GROUPS.items():
            raw_entry_points = self.entry_point_loader(group=group)
            for entry_point in sorted(
                cast(Sequence[EntryPoint], raw_entry_points),
                key=lambda item: (item.name, item.value),
            ):
                qualified_name = f"{kind}:{entry_point.name}"
                if selected and (
                    entry_point.name not in selected
                    and qualified_name not in selected
                ):
                    continue
                discovered_names.update({entry_point.name, qualified_name})
                signer_sha256: str | None = None
                manifest_path: str | None = None
                wheel_sha256: str | None = None
                record_sha256: str | None = None
                distribution_version: str | None = None
                declared_name = entry_point.name
                if self.require_signed:
                    (
                        manifest,
                        manifest_path,
                        signer_sha256,
                        wheel_sha256,
                        record_sha256,
                    ) = _verified_manifest(
                        entry_point,
                        kind=kind,
                        trusted_signers=self.trusted_signers,
                        trusted_wheel_sha256=self.trusted_wheel_sha256,
                        trust_policy_mode=self.trust_policy_mode,
                    )
                    declared_name = str(manifest["name"])
                    distribution_version = str(manifest["distribution_version"])
                if self.isolate:
                    plugin: object = _IsolatedPlugin(
                        name=declared_name,
                        kind=kind,
                        entry_value=entry_point.value,
                        manager=self,
                    )
                else:
                    try:
                        loaded = entry_point.load()
                        plugin = loaded() if isinstance(loaded, type) else loaded
                    except Exception as exc:
                        raise PluginError(
                            f"unable to load plugin {qualified_name}: {exc}"
                        ) from exc
                    runtime_name = getattr(plugin, "name", None)
                    if not isinstance(runtime_name, str) or not runtime_name:
                        raise PluginError(f"plugin {qualified_name} has no valid name")
                    if runtime_name != declared_name:
                        raise PluginError(
                            f"plugin {qualified_name} runtime name does not match manifest"
                        )
                descriptor = PluginDescriptor(
                    name=declared_name,
                    kind=kind,
                    group=group,
                    value=entry_point.value,
                    distribution=(
                        entry_point.dist.name
                        if entry_point.dist is not None
                        else None
                    ),
                    distribution_version=distribution_version,
                    signer_sha256=signer_sha256,
                    wheel_sha256=wheel_sha256,
                    record_sha256=record_sha256,
                    trust_policy_mode=(
                        self.trust_policy_mode if self.require_signed else "disabled"
                    ),
                    manifest_path=manifest_path,
                    isolated=self.isolate,
                )
                self._plugins.setdefault(kind, []).append((descriptor, plugin))
        missing = selected - discovered_names
        if missing:
            raise PluginError(
                "requested plugin(s) were not installed: " + ", ".join(sorted(missing))
            )

    def _invoke_isolated(
        self,
        *,
        plugin: str,
        kind: str,
        entry_value: str,
        operation: str,
        kwargs: dict[str, Any],
    ) -> Any:
        started = time.perf_counter()
        status = "failed"
        try:
            result = _run_plugin_process(
                entry_value,
                operation,
                kwargs,
                timeout=self.timeout,
            )
            status = "succeeded"
            return result
        finally:
            self._executions.append(
                PluginExecution(
                    plugin=plugin,
                    kind=kind,
                    operation=operation,
                    status=status,
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    isolated=True,
                )
            )


def _verified_manifest(
    entry_point: EntryPoint,
    *,
    kind: str,
    trusted_signers: Sequence[str],
    trusted_wheel_sha256: Sequence[str] = (),
    trust_policy_mode: str = "trusted-key",
) -> tuple[dict[str, Any], str, str, str, str]:
    distribution = entry_point.dist
    if distribution is None:
        raise PluginError(f"plugin {kind}:{entry_point.name} has no distribution manifest")
    path = Path(str(distribution.locate_file(PLUGIN_MANIFEST_NAME)))
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PluginError(f"unable to read signed plugin manifest {path}: {exc}") from exc
    if not isinstance(envelope, dict) or envelope.get("schema") != PLUGIN_MANIFEST_SCHEMA:
        raise PluginError(f"plugin manifest {path} has an unsupported schema")
    manifest = envelope.get("manifest")
    if isinstance(manifest, dict):
        _reject_claimed_sigstore_fields(manifest, path)
    public_key_pem = envelope.get("public_key")
    signature_text = envelope.get("signature")
    if not isinstance(manifest, dict) or not isinstance(public_key_pem, str) or not isinstance(
        signature_text, str
    ):
        raise PluginError(f"plugin manifest {path} is incomplete")
    distribution_name = _distribution_name(distribution)
    distribution_version = _distribution_version(distribution)
    config_schema_sha256 = _configuration_schema_sha256(envelope)
    content = _verify_distribution_record(distribution, manifest_path=path)
    _reject_unrecorded_entry_point_files(
        distribution,
        entry_value=entry_point.value,
        recorded_paths=cast(set[str], content["recorded_paths"]),
    )
    expected = {
        "name": entry_point.name,
        "kind": kind,
        "entry_point": entry_point.value,
        "api_version": PLUGIN_API_VERSION,
        "distribution": distribution_name,
        "distribution_version": distribution_version,
        "protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
        "wheel_sha256": content["wheel_sha256"],
        "record_sha256": content["record_sha256"],
        "configuration_schema_sha256": config_schema_sha256,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise PluginError(
                f"plugin manifest {path} {key}={manifest.get(key)!r} is incompatible; "
                f"expected {value!r}"
            )
    if manifest.get("schema") != PLUGIN_SIGNED_STATEMENT_SCHEMA:
        raise PluginError(
            f"plugin manifest {path} signed statement has an unsupported schema"
        )
    _verify_manifest_capabilities(manifest, kind=kind)
    _verify_manifest_dependencies(manifest, content["dependencies"], path)
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PluginError(f"plugin manifest {path} has invalid signing data") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PluginError(f"plugin manifest {path} must use an RSA public key")
    signed_payload = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        public_key.verify(signature, signed_payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise PluginError(f"plugin manifest {path} signature is invalid") from exc
    signer = hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    _verify_plugin_trust_root(
        manifest,
        signer_sha256=signer,
        trusted_signers=trusted_signers,
        trusted_wheel_sha256=trusted_wheel_sha256,
        trust_policy_mode=trust_policy_mode,
        plugin_name=f"{kind}:{entry_point.name}",
    )
    return (
        manifest,
        str(path),
        signer,
        str(content["wheel_sha256"]),
        str(content["record_sha256"]),
    )


def _default_plugin_trust_policy_mode(
    *,
    trusted_signers: Sequence[object],
    trusted_wheel_sha256: Sequence[object],
) -> str:
    if trusted_signers:
        return "trusted-key"
    if trusted_wheel_sha256:
        return "allowlisted-digest"
    return "trusted-key"


def _reject_claimed_sigstore_fields(
    manifest: Mapping[str, object],
    path: Path,
) -> None:
    claimed_fields = {"sigstore_identity", "sigstore_issuer"} & set(manifest)
    if claimed_fields:
        raise PluginError(
            f"plugin manifest {path} contains unsupported claimed Sigstore "
            "field(s): "
            + ", ".join(sorted(claimed_fields))
            + "; real Sigstore bundle verification is not implemented"
        )


def _distribution_name(distribution: object) -> str:
    value = getattr(distribution, "name", None)
    if isinstance(value, str) and value:
        return value
    metadata = getattr(distribution, "metadata", None)
    if metadata is not None:
        name = metadata.get("Name") if hasattr(metadata, "get") else None
        if isinstance(name, str) and name:
            return name
    raise PluginError("plugin distribution metadata is missing a name")


def _distribution_version(distribution: object) -> str:
    value = getattr(distribution, "version", None)
    if isinstance(value, str) and value:
        return value
    metadata = getattr(distribution, "metadata", None)
    if metadata is not None:
        version = metadata.get("Version") if hasattr(metadata, "get") else None
        if isinstance(version, str) and version:
            return version
    raise PluginError("plugin distribution metadata is missing a version")


def _configuration_schema_sha256(envelope: Mapping[str, object]) -> str:
    if "configuration_schema" not in envelope:
        return PLUGIN_EMPTY_CONFIGURATION_SCHEMA_SHA256
    schema = envelope["configuration_schema"]
    if not isinstance(schema, dict):
        raise PluginError("plugin configuration_schema must be an object")
    return hashlib.sha256(_canonical_json(schema)).hexdigest()


def _verify_distribution_record(
    distribution: object,
    *,
    manifest_path: Path,
) -> dict[str, object]:
    record_path = _distribution_record_path(distribution)
    try:
        record_bytes = record_path.read_bytes()
    except OSError as exc:
        raise PluginError(f"unable to read plugin RECORD {record_path}: {exc}") from exc
    rows = _record_rows(record_bytes, record_path)
    if not rows:
        raise PluginError(f"plugin RECORD {record_path} is empty")

    record_sha256 = hashlib.sha256(record_bytes).hexdigest()
    recorded_paths: set[str] = set()
    canonical_entries: list[str] = []
    manifest_recorded = False
    record_recorded = False
    for relative_path, hash_spec, size_text in rows:
        normalized = _normalized_record_path(relative_path)
        if normalized in recorded_paths:
            raise PluginError(f"plugin RECORD contains duplicate entry {normalized}")
        recorded_paths.add(normalized)
        file_path = _locate_distribution_file(distribution, normalized)
        if not file_path.is_file():
            raise PluginError(f"plugin RECORD references missing file {normalized}")
        if _same_file(file_path, manifest_path):
            manifest_recorded = True
            if hash_spec:
                raise PluginError(
                    "plugin manifest RECORD entry must be unhashed because it "
                    "contains the signed content statement"
                )
            continue
        if _same_file(file_path, record_path):
            record_recorded = True
            continue
        actual_size, actual_digest = _verify_recorded_file(
            file_path,
            normalized,
            hash_spec,
            size_text,
        )
        canonical_entries.append(f"{normalized}\0{actual_digest}\0{actual_size}")

    if not manifest_recorded:
        raise PluginError("plugin manifest is not listed in RECORD")
    if not record_recorded:
        raise PluginError("plugin RECORD does not list itself")
    _reject_unrecorded_distribution_files(distribution, recorded_paths)
    dependencies = _distribution_dependencies(distribution)
    wheel_sha256 = hashlib.sha256(
        "\n".join(sorted(canonical_entries)).encode("utf-8")
    ).hexdigest()
    return {
        "record_sha256": record_sha256,
        "wheel_sha256": wheel_sha256,
        "dependencies": dependencies,
        "recorded_paths": recorded_paths,
    }


def _distribution_record_path(distribution: object) -> Path:
    for item in _distribution_files(distribution):
        relative = _normalized_record_path(str(item))
        if relative.endswith(".dist-info/RECORD"):
            return _locate_distribution_file(distribution, relative)
    raise PluginError("plugin distribution does not expose a RECORD file")


def _distribution_files(distribution: object) -> tuple[object, ...]:
    files = getattr(distribution, "files", None)
    if files is None:
        raise PluginError("plugin distribution metadata is missing RECORD file entries")
    if callable(files):
        files = files()
    if files is None:
        raise PluginError("plugin distribution metadata is missing RECORD file entries")
    return tuple(cast(Iterable[object], files))


def _record_rows(record_bytes: bytes, record_path: Path) -> list[tuple[str, str, str]]:
    try:
        text = record_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PluginError(f"plugin RECORD {record_path} is not UTF-8") from exc
    rows: list[tuple[str, str, str]] = []
    for row in csv.reader(text.splitlines()):
        if len(row) != 3:
            raise PluginError(f"plugin RECORD {record_path} has an invalid row")
        rows.append((row[0], row[1], row[2]))
    return rows


def _normalized_record_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = Path(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise PluginError(f"plugin RECORD contains unsafe path {value!r}")
    return normalized


def _locate_distribution_file(distribution: object, relative_path: str) -> Path:
    locate_file = getattr(distribution, "locate_file", None)
    if not callable(locate_file):
        raise PluginError("plugin distribution cannot locate installed files")
    return Path(str(locate_file(relative_path)))


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _verify_recorded_file(
    file_path: Path,
    relative_path: str,
    hash_spec: str,
    size_text: str,
) -> tuple[int, str]:
    if not hash_spec:
        raise PluginError(f"plugin RECORD entry {relative_path} is missing a hash")
    algorithm, expected_digest = _record_hash_digest(hash_spec, relative_path)
    if algorithm != "sha256":
        raise PluginError(f"plugin RECORD entry {relative_path} must use sha256")
    try:
        payload = file_path.read_bytes()
    except OSError as exc:
        raise PluginError(f"unable to read plugin file {relative_path}: {exc}") from exc
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        raise PluginError(f"plugin file {relative_path} hash does not match RECORD")
    if size_text:
        try:
            expected_size = int(size_text)
        except ValueError as exc:
            raise PluginError(
                f"plugin RECORD entry {relative_path} has an invalid size"
            ) from exc
        if expected_size != len(payload):
            raise PluginError(f"plugin file {relative_path} size does not match RECORD")
    return len(payload), actual_digest


def _record_hash_digest(hash_spec: str, relative_path: str) -> tuple[str, str]:
    if "=" not in hash_spec:
        raise PluginError(f"plugin RECORD entry {relative_path} has an invalid hash")
    algorithm, encoded = hash_spec.split("=", 1)
    padding_length = (-len(encoded)) % 4
    try:
        digest = base64.urlsafe_b64decode((encoded + "=" * padding_length).encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise PluginError(
            f"plugin RECORD entry {relative_path} has an invalid hash"
        ) from exc
    return algorithm.lower(), digest.hex()


def _reject_unrecorded_distribution_files(
    distribution: object,
    recorded_paths: set[str],
) -> None:
    for item in _distribution_files(distribution):
        relative = _normalized_record_path(str(item))
        if relative not in recorded_paths:
            raise PluginError(f"plugin distribution exposes unrecorded file {relative}")


def _reject_unrecorded_entry_point_files(
    distribution: object,
    *,
    entry_value: str,
    recorded_paths: set[str],
) -> None:
    module_name = entry_value.partition(":")[0]
    top_level = module_name.split(".", 1)[0]
    record_root = _distribution_record_path(distribution).parent.parent
    candidates = [record_root / f"{top_level}.py", record_root / top_level]
    for candidate in candidates:
        if candidate.is_file():
            _reject_unrecorded_physical_file(candidate, record_root, recorded_paths)
        elif candidate.is_dir():
            for item in candidate.rglob("*"):
                if item.is_file() and "__pycache__" not in item.parts:
                    _reject_unrecorded_physical_file(item, record_root, recorded_paths)


def _reject_unrecorded_physical_file(
    path: Path,
    root: Path,
    recorded_paths: set[str],
) -> None:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return
    if relative not in recorded_paths:
        raise PluginError(f"plugin distribution contains unrecorded file {relative}")


def _distribution_dependencies(distribution: object) -> list[str]:
    requires = getattr(distribution, "requires", None)
    if callable(requires):
        requires = requires()
    if requires is None:
        metadata = getattr(distribution, "metadata", None)
        if metadata is not None and hasattr(metadata, "get_all"):
            requires = metadata.get_all("Requires-Dist") or []
    if requires is None:
        return []
    if not isinstance(requires, Sequence) or isinstance(requires, str):
        raise PluginError("plugin distribution dependencies must be a sequence")
    return sorted(str(item).strip() for item in requires if str(item).strip())


def _verify_manifest_capabilities(manifest: Mapping[str, object], *, kind: str) -> None:
    capabilities = set(_required_string_list(manifest, "capabilities", "plugin manifest"))
    expected = PLUGIN_KIND_CAPABILITIES[kind]
    missing = expected - capabilities
    unsupported = capabilities - expected
    if missing:
        raise PluginError(
            "plugin manifest does not declare runtime capability "
            + ", ".join(sorted(missing))
        )
    if unsupported:
        raise PluginError(
            "plugin manifest declares unsupported capability "
            + ", ".join(sorted(unsupported))
        )
    for key in ("requires_network", "requires_filesystem", "requires_subprocess"):
        if not isinstance(manifest.get(key), bool):
            raise PluginError(f"plugin manifest {key} must be a boolean")


def _verify_manifest_dependencies(
    manifest: Mapping[str, object],
    dependencies: object,
    path: Path,
) -> None:
    declared = sorted(_required_string_list(manifest, "dependencies", "plugin manifest"))
    if not isinstance(dependencies, list) or declared != dependencies:
        raise PluginError(
            f"plugin manifest {path} dependencies={declared!r} is incompatible; "
            f"expected {dependencies!r}"
        )


def _verify_plugin_trust_root(
    manifest: Mapping[str, object],
    *,
    signer_sha256: str,
    trusted_signers: Sequence[str],
    trusted_wheel_sha256: Sequence[str],
    trust_policy_mode: str,
    plugin_name: str,
) -> None:
    signer = signer_sha256.lower()
    trusted_signer_set = {item.lower() for item in trusted_signers}
    wheel_digest = _required_string(manifest, "wheel_sha256", "plugin manifest").lower()
    trusted_wheel_set = {item.lower() for item in trusted_wheel_sha256}

    if trust_policy_mode == "disabled":
        raise PluginError("signed plugin verification requires a trust root")
    if trust_policy_mode == "trusted-key":
        if not trusted_signer_set:
            raise PluginError(
                "trusted-key plugin mode requires trusted_signers; "
                "self-signed plugin metadata is not trusted"
            )
        if signer not in trusted_signer_set:
            raise PluginError(f"plugin {plugin_name} signer {signer_sha256} is not allowlisted")
        return
    if trust_policy_mode == "allowlisted-digest":
        if not trusted_wheel_set:
            raise PluginError("allowlisted-digest plugin mode requires trusted_wheel_sha256")
        if wheel_digest not in trusted_wheel_set:
            raise PluginError(f"plugin {plugin_name} wheel digest is not allowlisted")
        return
    if trust_policy_mode == "organization-policy":
        if signer in trusted_signer_set or wheel_digest in trusted_wheel_set:
            return
        raise PluginError(f"plugin {plugin_name} is not trusted by organization policy")
    raise PluginError(f"unsupported plugin trust policy mode: {trust_policy_mode}")


def _required_string_list(
    value: Mapping[str, object],
    key: str,
    label: str,
) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise PluginError(f"{label} {key} must be a list of strings")
    return item


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(slots=True)
class _IsolatedPlugin:
    name: str
    kind: str
    entry_value: str
    manager: PluginManager
    extension: str = ".plugin"

    def _invoke(self, operation: str, **kwargs: Any) -> Any:
        return self.manager._invoke_isolated(
            plugin=self.name,
            kind=self.kind,
            entry_value=self.entry_value,
            operation=operation,
            kwargs=kwargs,
        )

    def query(self, project: str, version: str) -> Sequence[VulnerabilityRecord]:
        return cast(
            Sequence[VulnerabilityRecord],
            self._invoke("query", project=project, version=version),
        )

    def analyze(self, **kwargs: Any) -> Sequence[HeuristicFinding]:
        return cast(Sequence[HeuristicFinding], self._invoke("analyze", **kwargs))

    def evaluate(self, **kwargs: Any) -> Sequence[PolicyViolation]:
        return cast(Sequence[PolicyViolation], self._invoke("evaluate", **kwargs))

    def render(self, **kwargs: Any) -> str:
        return str(self._invoke("render", **kwargs))

    def supports(self, index_url: str) -> bool:
        return bool(self._invoke("supports", index_url=index_url))

    def create_client(self, *, index_url: str, config: Mapping[str, Any]) -> object:
        return _IsolatedRepositoryClient(
            plugin=self,
            index_url=index_url,
            config=dict(config),
        )


@dataclass(slots=True)
class _IsolatedRepositoryClient:
    plugin: _IsolatedPlugin
    index_url: str
    config: dict[str, Any]

    def _invoke(self, method: str, **kwargs: Any) -> Any:
        return self.plugin._invoke(
            f"client.{method}",
            client_index_url=self.index_url,
            client_config=self.config,
            **kwargs,
        )

    def get_project(self, index_url: str, project: str) -> object:
        return self._invoke("get_project", index_url=index_url, project=project)

    def download(self, url: str, *, index_url: str | None = None) -> bytes:
        return bytes(self._invoke("download", url=url, index_url=index_url))

    def find_dependency_confusion(
        self, projects: Sequence[str], indexes: Sequence[str]
    ) -> tuple[DependencyConfusionFinding, ...]:
        return tuple(self._invoke("find_dependency_confusion", projects=projects, indexes=indexes))

    def locate_artifact_index(
        self, project: str, artifact_url: str | None, indexes: Sequence[str]
    ) -> str | None:
        value = self._invoke(
            "locate_artifact_index",
            project=project,
            artifact_url=artifact_url,
            indexes=indexes,
        )
        return str(value) if value is not None else None


_PLUGIN_OPERATION_KEYS: dict[str, frozenset[str]] = {
    "query": frozenset({"project", "version"}),
    "analyze": frozenset(
        {"filename", "payload", "project", "version", "inspection", "config"}
    ),
    "evaluate": frozenset({"report", "config"}),
    "render": frozenset({"packages", "source_name", "failures", "config"}),
    "supports": frozenset({"index_url"}),
    "client.get_project": frozenset(
        {"client_index_url", "client_config", "index_url", "project"}
    ),
    "client.download": frozenset(
        {"client_index_url", "client_config", "url", "index_url"}
    ),
    "client.find_dependency_confusion": frozenset(
        {"client_index_url", "client_config", "projects", "indexes"}
    ),
    "client.locate_artifact_index": frozenset(
        {"client_index_url", "client_config", "project", "artifact_url", "indexes"}
    ),
}
_T = TypeVar("_T")


def _new_plugin_request_id() -> str:
    return hashlib.sha256(str(time.time_ns()).encode("ascii")).hexdigest()[:32]


def _plugin_request_payload(
    entry_value: str,
    operation: str,
    kwargs: Mapping[str, object],
) -> tuple[str, bytes]:
    request_id = _new_plugin_request_id()
    message = {
        "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
        "request_id": request_id,
        "entry_value": entry_value,
        "operation": operation,
        "kwargs": _plugin_kwargs_to_data(operation, kwargs),
    }
    return request_id, _encode_plugin_message(
        message,
        max_bytes=PLUGIN_IPC_MAX_REQUEST_BYTES,
        label="plugin IPC request",
    )


def _plugin_kwargs_to_data(
    operation: str,
    kwargs: Mapping[str, object],
) -> dict[str, object]:
    _validate_plugin_operation_keys(operation, kwargs.keys())
    return {
        key: _request_value_to_data(kwargs[key])
        for key in sorted(_PLUGIN_OPERATION_KEYS[operation])
    }


def _validate_plugin_operation_keys(
    operation: str,
    keys: Iterable[str],
) -> None:
    expected = _PLUGIN_OPERATION_KEYS.get(operation)
    if expected is None:
        raise PluginError(f"unsupported plugin operation: {operation}")
    actual = set(keys)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unknown " + ", ".join(sorted(extra)))
        raise PluginError(
            f"plugin operation {operation} received invalid arguments: "
            + "; ".join(details)
        )


def _request_value_to_data(value: object) -> object:
    if isinstance(value, bytes):
        return _bytes_to_data(value)
    if isinstance(value, ArtifactInspection):
        return _typed_value("ArtifactInspection", _artifact_inspection_to_data(value))
    if isinstance(value, TrustReport):
        return _typed_value("TrustReport", _trust_report_to_data(value))
    if isinstance(value, ExportPackage):
        return _typed_value("ExportPackage", _export_package_to_data(value))
    if isinstance(value, SourceLocation):
        return _typed_value("SourceLocation", _model_to_data(value))
    if isinstance(value, ArtifactReference):
        return _typed_value("ArtifactReference", _model_to_data(value))
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PluginError("plugin request value contains a non-string object key")
            result[key] = _request_value_to_data(item)
        return _json_value(
            result,
            path="plugin request value",
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _json_value(
            [_request_value_to_data(item) for item in value],
            path="plugin request value",
        )
    return _json_value(value, path="plugin request value")


def _request_value_from_data(value: object) -> object:
    if isinstance(value, list):
        return [_request_value_from_data(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"__trustcheck_type__", "data"}:
            type_name = _required_string(value, "__trustcheck_type__", "typed request value")
            data = value["data"]
            if type_name == "bytes":
                return _bytes_from_data(value)
            if type_name == "ArtifactInspection":
                return _artifact_inspection_from_data(data)
            if type_name == "TrustReport":
                if not isinstance(data, dict):
                    raise PluginError("TrustReport request data must be an object")
                return deserialize_report(cast(Mapping[str, object], data))
            if type_name == "ExportPackage":
                return _export_package_from_data(data)
            if type_name == "SourceLocation":
                return _source_location_from_data(data)
            if type_name == "ArtifactReference":
                return _artifact_reference_from_data(data)
            raise PluginError(f"unsupported typed request value: {type_name}")
        return {key: _request_value_from_data(item) for key, item in value.items()}
    return value


def _plugin_kwargs_from_data(
    operation: str,
    value: object,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PluginError("plugin request kwargs must be an object")
    _validate_plugin_operation_keys(operation, value.keys())
    return {
        key: _request_value_from_data(value[key])
        for key in sorted(_PLUGIN_OPERATION_KEYS[operation])
    }


def _typed_value(type_name: str, data: object) -> dict[str, object]:
    return {"__trustcheck_type__": type_name, "data": data}


def _bytes_to_data(value: bytes) -> dict[str, object]:
    return _typed_value("bytes", base64.b64encode(value).decode("ascii"))


def _bytes_from_data(value: object) -> bytes:
    if not isinstance(value, dict):
        raise PluginError("bytes value must be an object")
    _reject_unknown_fields(value, "bytes value", {"__trustcheck_type__", "data"})
    if value.get("__trustcheck_type__") != "bytes":
        raise PluginError("bytes value has an unsupported type tag")
    data = _required_string(value, "data", "bytes value")
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PluginError("bytes value is not valid base64") from exc


def _encode_plugin_message(
    message: Mapping[str, object],
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    value = _json_value(message, path=label)
    payload = json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > max_bytes:
        raise PluginError(f"{label} exceeds the {max_bytes}-byte limit")
    return payload


def _decode_plugin_message(
    payload: bytes,
    *,
    max_bytes: int,
    label: str,
) -> dict[str, object]:
    if len(payload) > max_bytes:
        raise PluginError(f"{label} exceeds the {max_bytes}-byte limit")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginError(f"{label} is not valid JSON") from exc
    value = _json_value(raw, path=label)
    if not isinstance(value, dict):
        raise PluginError(f"{label} must be a JSON object")
    return value


def _json_value(value: object, *, path: str, depth: int = 0) -> object:
    if depth > PLUGIN_IPC_MAX_DEPTH:
        raise PluginError(f"{path} exceeds the JSON depth limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PluginError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > PLUGIN_IPC_MAX_STRING_LENGTH:
            raise PluginError(f"{path} string exceeds the JSON string length limit")
        return value
    if isinstance(value, Mapping):
        if len(value) > PLUGIN_IPC_MAX_MAPPING_LENGTH:
            raise PluginError(f"{path} object exceeds the JSON mapping length limit")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PluginError(f"{path} contains a non-string object key")
            if len(key) > PLUGIN_IPC_MAX_STRING_LENGTH:
                raise PluginError(f"{path} object key exceeds the JSON string limit")
            result[key] = _json_value(item, path=f"{path}.{key}", depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if len(value) > PLUGIN_IPC_MAX_LIST_LENGTH:
            raise PluginError(f"{path} list exceeds the JSON list length limit")
        return [
            _json_value(item, path=f"{path}[]", depth=depth + 1)
            for item in value
        ]
    raise PluginError(f"{path} contains unsupported value type {type(value).__name__}")


def _validate_request_envelope(message: Mapping[str, object]) -> str:
    _reject_unknown_fields(
        message,
        "plugin IPC request",
        {"plugin_protocol_version", "request_id", "entry_value", "operation", "kwargs"},
    )
    version = _required_string(
        message,
        "plugin_protocol_version",
        "plugin IPC request",
    )
    if version != PLUGIN_IPC_PROTOCOL_VERSION:
        raise PluginError(
            f"incompatible plugin IPC protocol {version!r}; "
            f"expected {PLUGIN_IPC_PROTOCOL_VERSION!r}"
        )
    request_id = _required_string(message, "request_id", "plugin IPC request")
    entry_value = _required_string(message, "entry_value", "plugin IPC request")
    operation = _required_string(message, "operation", "plugin IPC request")
    if not entry_value:
        raise PluginError("plugin IPC request entry point cannot be empty")
    if not request_id:
        raise PluginError("plugin IPC request id cannot be empty")
    kwargs = message.get("kwargs")
    if not isinstance(kwargs, dict):
        raise PluginError("plugin IPC request kwargs must be an object")
    _validate_plugin_operation_keys(operation, kwargs.keys())
    return request_id


def _plugin_result_from_response(
    message: Mapping[str, object],
    *,
    request_id: str,
    operation: str,
) -> Any:
    _reject_unknown_fields(
        message,
        "plugin IPC response",
        {"plugin_protocol_version", "request_id", "ok", "result", "error"},
    )
    version = _required_string(
        message,
        "plugin_protocol_version",
        "plugin IPC response",
    )
    if version != PLUGIN_IPC_PROTOCOL_VERSION:
        raise PluginError(
            f"incompatible plugin IPC protocol {version!r}; "
            f"expected {PLUGIN_IPC_PROTOCOL_VERSION!r}"
        )
    if _required_string(message, "request_id", "plugin IPC response") != request_id:
        raise PluginError("plugin IPC response request id did not match the request")
    ok = message.get("ok")
    if not isinstance(ok, bool):
        raise PluginError("plugin IPC response ok must be a boolean")
    if not ok:
        _reject_unknown_fields(
            message,
            "plugin IPC error response",
            {"plugin_protocol_version", "request_id", "ok", "error"},
        )
        error = message.get("error")
        if not isinstance(error, dict):
            raise PluginError("plugin IPC error response must contain an error object")
        _reject_unknown_fields(error, "plugin IPC error", {"type", "message"})
        error_type = _required_string(error, "type", "plugin IPC error")
        error_message = _required_string(error, "message", "plugin IPC error")
        detail = f"{error_type}: {error_message}" if error_message else error_type
        raise PluginError(f"plugin operation failed: {detail}")
    _reject_unknown_fields(
        message,
        "plugin IPC success response",
        {"plugin_protocol_version", "request_id", "ok", "result"},
    )
    if "result" not in message:
        raise PluginError("plugin IPC success response is missing result")
    return _plugin_result_from_data(operation, message["result"])


def _plugin_result_from_data(operation: str, value: object) -> Any:
    if operation == "query":
        return [
            _vulnerability_from_data(item)
            for item in _required_list(value, "query result")
        ]
    if operation == "analyze":
        return [
            _heuristic_finding_from_data(item)
            for item in _required_list(value, "analyze result")
        ]
    if operation == "evaluate":
        return [
            _policy_violation_from_data(item)
            for item in _required_list(value, "evaluate result")
        ]
    if operation == "render":
        if not isinstance(value, str):
            raise PluginError("render result must be a string")
        return value
    if operation == "supports":
        if not isinstance(value, bool):
            raise PluginError("supports result must be a boolean")
        return value
    if operation == "client.get_project":
        return None if value is None else _index_project_from_data(value)
    if operation == "client.download":
        return _bytes_from_data(value)
    if operation == "client.find_dependency_confusion":
        return tuple(
            _dependency_confusion_from_data(item)
            for item in _required_list(value, "dependency confusion result")
        )
    if operation == "client.locate_artifact_index":
        if value is not None and not isinstance(value, str):
            raise PluginError("artifact index location result must be a string or null")
        return value
    raise PluginError(f"unsupported plugin operation: {operation}")


def _plugin_result_to_data(operation: str, value: object) -> object:
    if operation == "query":
        return [
            _model_to_data(_require_instance(item, VulnerabilityRecord, "query result"))
            for item in _result_sequence(value, "query result")
        ]
    if operation == "analyze":
        return [
            _model_to_data(_require_instance(item, HeuristicFinding, "analyze result"))
            for item in _result_sequence(value, "analyze result")
        ]
    if operation == "evaluate":
        return [
            _model_to_data(_require_instance(item, PolicyViolation, "evaluate result"))
            for item in _result_sequence(value, "evaluate result")
        ]
    if operation == "render":
        if not isinstance(value, str):
            raise TypeError(
                f"render result returned {type(value).__name__}, expected str"
            )
        return value
    if operation == "supports":
        if not isinstance(value, bool):
            raise TypeError(
                f"supports result returned {type(value).__name__}, expected bool"
            )
        return value
    if operation == "client.get_project":
        if value is None:
            return None
        return _model_to_data(_require_instance(value, IndexProject, "index project"))
    if operation == "client.download":
        if not isinstance(value, bytes):
            raise TypeError(
                f"download result returned {type(value).__name__}, expected bytes"
            )
        return _bytes_to_data(value)
    if operation == "client.find_dependency_confusion":
        return [
            _model_to_data(
                _require_instance(item, DependencyConfusionFinding, "dependency confusion")
            )
            for item in _result_sequence(value, "dependency confusion result")
        ]
    if operation == "client.locate_artifact_index":
        if value is not None and not isinstance(value, str):
            raise TypeError(
                "artifact index location result returned "
                f"{type(value).__name__}, expected str or None"
            )
        return value
    raise PluginError(f"unsupported plugin operation: {operation}")


def _execute_plugin_request(message: Mapping[str, object]) -> object:
    entry_value = _required_string(message, "entry_value", "plugin IPC request")
    operation = _required_string(message, "operation", "plugin IPC request")
    kwargs = _plugin_kwargs_from_data(operation, message["kwargs"])
    module_name, separator, attribute_path = entry_value.partition(":")
    if not separator:
        raise ValueError("entry point must use module:attribute syntax")
    loaded: object = importlib.import_module(module_name)
    for attribute in attribute_path.split("."):
        loaded = getattr(loaded, attribute)
    plugin = loaded() if isinstance(loaded, type) else loaded
    if operation.startswith("client."):
        client = cast(Any, plugin).create_client(
            index_url=kwargs.pop("client_index_url"),
            config=kwargs.pop("client_config"),
        )
        target = getattr(client, operation.removeprefix("client."))
    else:
        target = getattr(plugin, operation)
    result = target(**kwargs)
    return _plugin_result_to_data(operation, result)


def _result_sequence(value: object, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(
            f"{label} returned {type(value).__name__}, expected a sequence"
        )
    return value


def _require_instance(value: object, model: type[_T], label: str) -> _T:
    if not isinstance(value, model):
        raise TypeError(
            f"{label} returned {type(value).__name__}, expected {model.__name__}"
        )
    return value


def _model_to_data(value: Any) -> dict[str, object]:
    return cast(
        dict[str, object],
        _json_value(asdict(value), path=type(value).__name__),
    )


def _trust_report_to_data(value: TrustReport) -> dict[str, object]:
    return cast(
        dict[str, object],
        _json_value(serialize_report(value)["report"], path="TrustReport"),
    )


def _artifact_inspection_to_data(value: ArtifactInspection) -> dict[str, object]:
    return _model_to_data(value)


def _export_package_to_data(value: ExportPackage) -> dict[str, object]:
    data = {
        "report": _trust_report_to_data(value.report),
        "source": (
            None if value.source is None else _model_to_data(value.source)
        ),
        "artifacts": [_model_to_data(item) for item in value.artifacts],
    }
    return cast(dict[str, object], _json_value(data, path="ExportPackage"))


def _validated_payload(model: Any, value: object, label: str) -> dict[str, object]:
    try:
        return cast(
            dict[str, object],
            model.model_validate(value).model_dump(mode="python"),
        )
    except ValueError as exc:
        raise PluginError(f"{label} failed schema validation: {exc}") from exc


def _vulnerability_from_data(value: object) -> VulnerabilityRecord:
    data = _validated_payload(
        VulnerabilityRecordPayload,
        value,
        "vulnerability record",
    )
    suppression = data.get("suppression")
    return VulnerabilityRecord(
        **cast(Any, {
            **data,
            "suppression": (
                None
                if suppression is None
                else VulnerabilitySuppression(
                    **cast(
                        Any,
                        _validated_payload(
                            VulnerabilitySuppressionPayload,
                            suppression,
                            "vulnerability suppression",
                        ),
                    )
                )
            ),
        })
    )


def _heuristic_finding_from_data(value: object) -> HeuristicFinding:
    return HeuristicFinding(
        **cast(
            Any,
            _validated_payload(HeuristicFindingPayload, value, "heuristic finding"),
        )
    )


def _policy_violation_from_data(value: object) -> PolicyViolation:
    return PolicyViolation(
        **cast(
            Any,
            _validated_payload(PolicyViolationPayload, value, "policy violation"),
        )
    )


def _artifact_inspection_from_data(value: object) -> ArtifactInspection:
    data = _validated_payload(
        ArtifactInspectionPayload,
        value,
        "artifact inspection",
    )
    native_binaries = data.get("native_binaries", [])
    heuristic_findings = data.get("heuristic_findings", [])
    return ArtifactInspection(
        **cast(Any, {
            **data,
            "native_binaries": [
                NativeBinaryInspection(
                    **cast(
                        Any,
                        _validated_payload(
                            NativeBinaryInspectionPayload,
                            item,
                            "native binary inspection",
                        ),
                    )
                )
                for item in _required_list(native_binaries, "native binaries")
            ],
            "heuristic_findings": [
                _heuristic_finding_from_data(item)
                for item in _required_list(heuristic_findings, "heuristic findings")
            ],
        })
    )


def _source_location_from_data(value: object) -> SourceLocation:
    data = _strict_model_data(value, SourceLocation)
    return SourceLocation(
        uri=_required_string(data, "uri", "source location"),
        line=_optional_int(data, "line", "source location"),
    )


def _artifact_reference_from_data(value: object) -> ArtifactReference:
    data = _strict_model_data(value, ArtifactReference)
    return ArtifactReference(
        filename=_optional_string(data, "filename", "artifact reference"),
        url=_optional_string(data, "url", "artifact reference"),
        path=_optional_string(data, "path", "artifact reference"),
        hashes=_hash_pairs_from_data(data.get("hashes", []), "artifact hashes"),
        size=_optional_int(data, "size", "artifact reference"),
        kind=_required_string(data, "kind", "artifact reference"),
    )


def _export_package_from_data(value: object) -> ExportPackage:
    data = _strict_mapping(
        value,
        "ExportPackage",
        {"report", "source", "artifacts"},
    )
    report = data.get("report")
    if not isinstance(report, dict):
        raise PluginError("ExportPackage report must be an object")
    source = data.get("source")
    return ExportPackage(
        report=deserialize_report(cast(Mapping[str, object], report)),
        source=None if source is None else _source_location_from_data(source),
        artifacts=tuple(
            _artifact_reference_from_data(item)
            for item in _required_list(data.get("artifacts", []), "ExportPackage artifacts")
        ),
    )


def _index_project_from_data(value: object) -> IndexProject:
    data = _strict_model_data(value, IndexProject)
    files_value = data.get("files", [])
    return IndexProject(
        name=_required_string(data, "name", "index project"),
        index_url=_required_string(data, "index_url", "index project"),
        files=tuple(
            _index_file_from_data(item)
            for item in _required_list(files_value, "index project files")
        ),
        api_version=_optional_string(data, "api_version", "index project"),
    )


def _index_file_from_data(value: object) -> IndexFile:
    data = _strict_model_data(value, IndexFile)
    yanked = data.get("yanked", False)
    if not isinstance(yanked, (bool, str)):
        raise PluginError("index file yanked must be a boolean or string")
    return IndexFile(
        filename=_required_string(data, "filename", "index file"),
        url=_required_string(data, "url", "index file"),
        hashes=_hash_pairs_from_data(data.get("hashes", []), "index file hashes"),
        requires_python=_optional_string(data, "requires_python", "index file"),
        yanked=yanked,
        size=_optional_int(data, "size", "index file"),
        upload_time=_optional_string(data, "upload_time", "index file"),
        metadata_url=_optional_string(data, "metadata_url", "index file"),
        metadata_hashes=_hash_pairs_from_data(
            data.get("metadata_hashes", []),
            "index file metadata hashes",
        ),
    )


def _dependency_confusion_from_data(value: object) -> DependencyConfusionFinding:
    data = _strict_model_data(value, DependencyConfusionFinding)
    indexes = _required_list(
        data.get("indexes", []),
        "dependency confusion indexes",
    )
    return DependencyConfusionFinding(
        project=_required_string(data, "project", "dependency confusion finding"),
        indexes=tuple(
            _required_string(item, "", "dependency confusion index")
            for item in indexes
        ),
    )


def _hash_pairs_from_data(value: object, label: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for item in _required_list(value, label):
        if not isinstance(item, list) or len(item) != 2:
            raise PluginError(f"{label} entries must be two-item lists")
        algorithm, digest = item
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise PluginError(f"{label} entries must contain strings")
        pairs.append((algorithm, digest))
    return tuple(pairs)


def _strict_model_data(value: object, model: type[Any]) -> dict[str, object]:
    return _strict_mapping(value, model.__name__, {item.name for item in fields(model)})


def _strict_mapping(
    value: object,
    label: str,
    allowed_fields: set[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PluginError(f"{label} must be an object")
    _reject_unknown_fields(value, label, allowed_fields)
    return cast(dict[str, object], value)


def _reject_unknown_fields(
    value: Mapping[str, object],
    label: str,
    allowed_fields: set[str],
) -> None:
    unknown = set(value) - allowed_fields
    if unknown:
        raise PluginError(
            f"{label} contains unsupported field(s): " + ", ".join(sorted(unknown))
        )


def _required_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise PluginError(f"{label} must be a list")
    return value


def _required_string(
    value: Mapping[str, object] | object,
    key: str,
    label: str,
) -> str:
    if key:
        if not isinstance(value, Mapping):
            raise PluginError(f"{label} must be an object")
        item = value.get(key)
    else:
        item = value
    if not isinstance(item, str):
        raise PluginError(f"{label} {key or 'value'} must be a string")
    return item


def _optional_string(
    value: Mapping[str, object],
    key: str,
    label: str,
) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise PluginError(f"{label} {key} must be a string or null")
    return item


def _optional_int(
    value: Mapping[str, object],
    key: str,
    label: str,
) -> int | None:
    item = value.get(key)
    if item is None:
        return None
    if type(item) is not int:
        raise PluginError(f"{label} {key} must be an integer or null")
    return item


def _run_plugin_process(
    entry_value: str,
    operation: str,
    kwargs: dict[str, Any],
    *,
    timeout: float,
) -> Any:
    request_id, request_payload = _plugin_request_payload(entry_value, operation, kwargs)
    context = multiprocessing.get_context("spawn")
    request_receiver, request_sender = context.Pipe(duplex=False)
    response_receiver, response_sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_plugin_worker,
        args=(request_receiver, response_sender),
        name="trustcheck-plugin",
        daemon=True,
    )
    try:
        process.start()
        request_receiver.close()
        response_sender.close()
        try:
            request_sender.send_bytes(request_payload)
        except OSError as exc:
            raise PluginError(
                f"plugin {entry_value} operation {operation} could not receive request"
            ) from exc
        finally:
            request_sender.close()
        if not response_receiver.poll(timeout):
            process.terminate()
            process.join(timeout=1)
            raise PluginError(
                f"plugin {entry_value} operation {operation} exceeded {timeout:g} seconds"
            )
        try:
            response_payload = response_receiver.recv_bytes(PLUGIN_IPC_MAX_RESPONSE_BYTES)
        except EOFError as exc:
            raise PluginError(f"plugin {entry_value} worker exited unexpectedly") from exc
        except (OSError, ValueError) as exc:
            raise PluginError(
                f"plugin {entry_value} operation {operation} response exceeded "
                f"the {PLUGIN_IPC_MAX_RESPONSE_BYTES}-byte limit"
            ) from exc
        process.join(timeout=1)
        response = _decode_plugin_message(
            response_payload,
            max_bytes=PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
        try:
            return _plugin_result_from_response(
                response,
                request_id=request_id,
                operation=operation,
            )
        except PluginError as exc:
            raise PluginError(
                f"plugin {entry_value} operation {operation} failed: {exc}"
            ) from exc
    finally:
        request_receiver.close()
        request_sender.close()
        response_receiver.close()
        response_sender.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)


def _plugin_worker(
    request_receiver: Connection,
    response_sender: Connection,
) -> None:  # pragma: no cover - executed in spawned worker
    request_id = "unknown"
    try:
        _apply_plugin_limits()
        payload = request_receiver.recv_bytes(PLUGIN_IPC_MAX_REQUEST_BYTES)
        request = _decode_plugin_message(
            payload,
            max_bytes=PLUGIN_IPC_MAX_REQUEST_BYTES,
            label="plugin IPC request",
        )
        request_id = _validate_request_envelope(request)
        response = {
            "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": True,
            "result": _execute_plugin_request(request),
        }
    except BaseException as exc:
        response = _plugin_error_response(request_id, exc)
    try:
        _send_plugin_response(response_sender, response)
    finally:
        request_receiver.close()
        response_sender.close()


def _plugin_error_response(request_id: str, exc: BaseException) -> dict[str, object]:
    message = str(exc)
    if len(message) > 4096:
        message = message[:4093] + "..."
    return {
        "plugin_protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": False,
        "error": {
            "type": type(exc).__name__,
            "message": message,
        },
    }


def _send_plugin_response(
    sender: Connection,
    response: Mapping[str, object],
) -> None:
    try:
        payload = _encode_plugin_message(
            response,
            max_bytes=PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
    except PluginError as exc:
        request_id = "unknown"
        if isinstance(response.get("request_id"), str):
            request_id = cast(str, response["request_id"])
        payload = _encode_plugin_message(
            _plugin_error_response(request_id, exc),
            max_bytes=PLUGIN_IPC_MAX_RESPONSE_BYTES,
            label="plugin IPC response",
        )
    sender.send_bytes(payload)


def _apply_plugin_limits() -> None:  # pragma: no cover - OS-specific worker bootstrap
    try:
        import resource
    except ImportError:
        return
    _set_plugin_resource_limit(
        resource,
        getattr(resource, "RLIMIT_CPU", None),
        PLUGIN_CPU_SECONDS,
    )
    _set_plugin_resource_limit(
        resource,
        getattr(resource, "RLIMIT_AS", None),
        PLUGIN_MEMORY_BYTES,
    )


def _set_plugin_resource_limit(
    resource_module: Any,
    limit_name: object,
    desired_limit: int,
) -> None:
    if limit_name is None:
        return
    getrlimit = getattr(resource_module, "getrlimit", None)
    setrlimit = getattr(resource_module, "setrlimit", None)
    if getrlimit is None or setrlimit is None:
        return
    try:
        current_soft, current_hard = getrlimit(limit_name)
    except (OSError, ValueError):
        return
    infinity = getattr(resource_module, "RLIM_INFINITY", -1)

    def capped(current: int) -> int:
        if current == infinity:
            return desired_limit
        return min(current, desired_limit)

    soft = capped(int(current_soft))
    hard = capped(int(current_hard))
    if hard != infinity and soft > hard:
        soft = hard
    try:
        setrlimit(limit_name, (soft, hard))
    except (OSError, ValueError):
        return


@dataclass(slots=True)
class PluginRepositoryClient:
    plugins: tuple[IndexPlugin, ...]
    fallback: RepositoryClient
    manager: PluginManager
    _clients: dict[tuple[str, str], RepositoryClient] = field(default_factory=dict)

    def get_project(self, index_url: str, project: str) -> object:
        client = self._client_for(index_url)
        return client.get_project(index_url, project)

    def download(self, url: str, *, index_url: str | None = None) -> bytes:
        client = self._client_for(index_url) if index_url else self.fallback
        return bytes(client.download(url, index_url=index_url))

    def find_dependency_confusion(
        self,
        projects: Sequence[str],
        indexes: Sequence[str],
    ) -> tuple[DependencyConfusionFinding, ...]:
        if len(indexes) < 2:
            return ()
        findings: list[DependencyConfusionFinding] = []
        for project in sorted(set(projects)):
            matches = [
                redact_url_credentials(index_url)
                for index_url in indexes
                if self.get_project(index_url, project) is not None
            ]
            if len(matches) > 1:
                findings.append(
                    DependencyConfusionFinding(
                        project=project,
                        indexes=tuple(matches),
                    )
                )
        return tuple(findings)

    def locate_artifact_index(
        self,
        project: str,
        artifact_url: str | None,
        indexes: Sequence[str],
    ) -> str | None:
        if len(indexes) == 1:
            return redact_url_credentials(indexes[0])
        if artifact_url:
            normalized = redact_url_credentials(artifact_url)
            for index_url in indexes:
                index_project = self.get_project(index_url, project)
                files = getattr(index_project, "files", ())
                if any(
                    redact_url_credentials(str(getattr(item, "url", "")))
                    == normalized
                    for item in files
                ):
                    return redact_url_credentials(index_url)
        return None

    def _client_for(self, index_url: str | None) -> RepositoryClient:
        if not index_url:
            return self.fallback
        for plugin in self.plugins:
            if not plugin.supports(index_url):
                continue
            key = (plugin.name, index_url)
            if key not in self._clients:
                self._clients[key] = cast(
                    RepositoryClient,
                    plugin.create_client(
                        index_url=index_url,
                        config=self.manager.plugin_config(plugin.name),
                    ),
                )
            return self._clients[key]
        return self.fallback
