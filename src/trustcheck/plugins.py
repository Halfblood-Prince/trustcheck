from __future__ import annotations

import base64
import hashlib
import importlib
import json
import multiprocessing
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .indexes import DependencyConfusionFinding, redact_url_credentials
from .models import (
    ArtifactInspection,
    HeuristicFinding,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
)

PLUGIN_API_VERSION = "1"
PLUGIN_MANIFEST_SCHEMA = "urn:trustcheck:plugin-manifest:1"
PLUGIN_MANIFEST_NAME = "trustcheck-plugin.json"
DEFAULT_PLUGIN_TIMEOUT = 10.0
PLUGIN_CPU_SECONDS = 8
PLUGIN_MEMORY_BYTES = 256 * 1024 * 1024
PLUGIN_GROUPS = {
    "advisory": "trustcheck.advisory_sources",
    "index": "trustcheck.indexes",
    "artifact": "trustcheck.artifact_analyzers",
    "policy": "trustcheck.policy_rules",
    "renderer": "trustcheck.renderers",
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
    api_version: str = PLUGIN_API_VERSION
    signer_sha256: str | None = None
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
    require_signed: bool = True
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
        if not isinstance(raw_allowlist, list) or any(
            not isinstance(item, str) for item in raw_allowlist
        ):
            raise PluginError("plugin allowlist must contain plugin names")
        if not isinstance(raw_signers, list) or any(
            not isinstance(item, str) for item in raw_signers
        ):
            raise PluginError("trusted_signers must contain SHA-256 fingerprints")
        allowlist = tuple(dict.fromkeys([*selected, *raw_allowlist]))
        if enabled and not allowlist:
            raise PluginError(
                "--enable-plugins requires an explicit --plugin or configured allowlist"
            )
        return cls(
            enabled=enabled or bool(allowlist),
            selected=tuple(selected),
            config=config,
            allowlist=allowlist,
            trusted_signers=tuple(item.lower() for item in raw_signers),
            require_signed=controls.get("require_signed", True) is not False,
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
                declared_name = entry_point.name
                if self.require_signed:
                    manifest, manifest_path, signer_sha256 = _verified_manifest(
                        entry_point,
                        kind=kind,
                        trusted_signers=self.trusted_signers,
                    )
                    declared_name = str(manifest["name"])
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
                    signer_sha256=signer_sha256,
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
) -> tuple[dict[str, Any], str, str]:
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
    public_key_pem = envelope.get("public_key")
    signature_text = envelope.get("signature")
    if not isinstance(manifest, dict) or not isinstance(public_key_pem, str) or not isinstance(
        signature_text, str
    ):
        raise PluginError(f"plugin manifest {path} is incomplete")
    expected = {
        "name": entry_point.name,
        "kind": kind,
        "entry_point": entry_point.value,
        "api_version": PLUGIN_API_VERSION,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise PluginError(
                f"plugin manifest {path} {key}={manifest.get(key)!r} is incompatible; "
                f"expected {value!r}"
            )
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
    if trusted_signers and signer.lower() not in set(trusted_signers):
        raise PluginError(
            f"plugin {kind}:{entry_point.name} signer {signer} is not allowlisted"
        )
    return manifest, str(path), signer


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


def _run_plugin_process(
    entry_value: str,
    operation: str,
    kwargs: dict[str, Any],
    *,
    timeout: float,
) -> Any:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_plugin_worker,
        args=(sender, entry_value, operation, kwargs),
        name="trustcheck-plugin",
        daemon=True,
    )
    try:
        process.start()
        sender.close()
        if not receiver.poll(timeout):
            process.terminate()
            process.join(timeout=1)
            raise PluginError(
                f"plugin {entry_value} operation {operation} exceeded {timeout:g} seconds"
            )
        try:
            ok, value = receiver.recv()
        except EOFError as exc:
            raise PluginError(f"plugin {entry_value} worker exited unexpectedly") from exc
        process.join(timeout=1)
        if not ok:
            raise PluginError(f"plugin {entry_value} operation {operation} failed: {value}")
        return value
    finally:
        receiver.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)


def _plugin_worker(
    sender: Connection,
    entry_value: str,
    operation: str,
    kwargs: dict[str, Any],
) -> None:  # pragma: no cover - executed in spawned worker
    try:
        _apply_plugin_limits()
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
        sender.send((True, target(**kwargs)))
    except BaseException as exc:
        sender.send((False, f"{type(exc).__name__}: {exc}"))
    finally:
        sender.close()


def _apply_plugin_limits() -> None:  # pragma: no cover - OS-specific worker bootstrap
    try:
        import resource
    except ImportError:
        return
    setrlimit = getattr(resource, "setrlimit", None)
    cpu = getattr(resource, "RLIMIT_CPU", None)
    memory = getattr(resource, "RLIMIT_AS", None)
    if setrlimit is not None and cpu is not None:
        setrlimit(cpu, (PLUGIN_CPU_SECONDS, PLUGIN_CPU_SECONDS))
    if setrlimit is not None and memory is not None:
        setrlimit(memory, (PLUGIN_MEMORY_BYTES, PLUGIN_MEMORY_BYTES))


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
