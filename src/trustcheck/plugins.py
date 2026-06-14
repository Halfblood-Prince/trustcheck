from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Any, Protocol, cast

from .indexes import DependencyConfusionFinding, redact_url_credentials
from .models import (
    ArtifactInspection,
    HeuristicFinding,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
)

PLUGIN_API_VERSION = "1"
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


@dataclass(slots=True)
class PluginManager:
    enabled: bool = False
    selected: tuple[str, ...] = ()
    config: dict[str, Any] = field(default_factory=dict)
    entry_point_loader: Callable[..., object] = entry_points
    _plugins: dict[str, list[tuple[PluginDescriptor, object]]] = field(
        default_factory=dict,
        init=False,
    )
    _loaded: bool = field(default=False, init=False)

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
        return cls(
            enabled=enabled or bool(selected),
            selected=tuple(selected),
            config=config,
        )

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
        selected = set(self.selected)
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
                try:
                    loaded = entry_point.load()
                    plugin = loaded() if isinstance(loaded, type) else loaded
                except Exception as exc:
                    raise PluginError(
                        f"unable to load plugin {qualified_name}: {exc}"
                    ) from exc
                declared_name = getattr(plugin, "name", None)
                if not isinstance(declared_name, str) or not declared_name:
                    raise PluginError(f"plugin {qualified_name} has no valid name")
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
                )
                self._plugins.setdefault(kind, []).append((descriptor, plugin))
        missing = selected - discovered_names
        if missing:
            raise PluginError(
                "requested plugin(s) were not installed: " + ", ".join(sorted(missing))
            )


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
