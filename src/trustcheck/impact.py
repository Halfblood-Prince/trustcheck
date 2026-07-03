from __future__ import annotations

import ast
import json
import tomllib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .cli_models import ScanTarget
from .models import TrustReport, VulnerabilityRecord

IMPACT_SCHEMA = "urn:trustcheck:impact:1.0.0"
UNKNOWN_DYNAMIC_WARNING = (
    "No first-party usage was observed by static analysis. Manual review is "
    "still required for dynamic imports, plugins, and runtime configuration."
)

SKIPPED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "site-packages",
    "venv",
}
TEST_PARTS = {"test", "tests", "testing"}
DEVELOPMENT_PARTS = {
    "benchmark",
    "benchmarks",
    "dev",
    "docs",
    "example",
    "examples",
    "script",
    "scripts",
    "tool",
    "tools",
}
COMMON_IMPORT_ROOTS: dict[str, tuple[str, ...]] = {
    "beautifulsoup4": ("bs4",),
    "opencv-python": ("cv2",),
    "opencv-contrib-python": ("cv2",),
    "pillow": ("pil",),
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
}
FRAMEWORK_ROOTS = {
    "celery",
    "django",
    "fastapi",
    "flask",
    "pytest",
}


@dataclass(frozen=True, slots=True)
class ImportEvidence:
    module: str
    root: str
    path: str
    line: int
    context: str = "production"
    dynamic: bool = False
    source: str = "import"

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module,
            "root": self.root,
            "path": self.path,
            "line": self.line,
            "context": self.context,
            "dynamic": self.dynamic,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class UnknownDynamicImport:
    path: str
    line: int
    expression: str
    context: str = "production"

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "expression": self.expression,
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class SourceImportGraph:
    roots: tuple[str, ...]
    imports: tuple[ImportEvidence, ...]
    unknown_dynamic_imports: tuple[UnknownDynamicImport, ...]
    entrypoints: tuple[ImportEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "roots": list(self.roots),
            "imports": [item.to_dict() for item in self.imports],
            "unknown_dynamic_imports": [
                item.to_dict() for item in self.unknown_dynamic_imports
            ],
            "entrypoints": [item.to_dict() for item in self.entrypoints],
        }


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    packages: tuple[dict[str, object], ...]
    edges: tuple[dict[str, str | None], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "package_count": len(self.packages),
            "edge_count": len(self.edges),
            "packages": list(self.packages),
            "edges": list(self.edges),
        }


@dataclass(frozen=True, slots=True)
class ImpactFinding:
    project: str
    version: str
    vulnerability: VulnerabilityRecord
    classification: str
    impact: str
    priority: str
    evidence: str
    used_by: tuple[str, ...] = ()
    import_evidence: tuple[ImportEvidence, ...] = ()
    dependency_path: tuple[str, ...] = ()
    action: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "version": self.version,
            "vulnerability": _vulnerability_payload(self.vulnerability),
            "classification": self.classification,
            "impact": self.impact,
            "priority": self.priority,
            "evidence": self.evidence,
            "used_by": list(self.used_by),
            "import_evidence": [item.to_dict() for item in self.import_evidence],
            "dependency_path": list(self.dependency_path),
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class ImpactReport:
    source: str
    source_roots: tuple[str, ...]
    dependency_file: str
    import_graph: SourceImportGraph
    dependency_graph: DependencyGraph
    findings: tuple[ImpactFinding, ...]
    failures: tuple[dict[str, str], ...] = ()
    warning: str = UNKNOWN_DYNAMIC_WARNING

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": IMPACT_SCHEMA,
            "source": self.source,
            "source_roots": list(self.source_roots),
            "dependency_file": self.dependency_file,
            "summary": {
                "vulnerable_packages": len(
                    {canonicalize_name(finding.project) for finding in self.findings}
                ),
                "findings": len(self.findings),
                "priority_1": len(
                    [item for item in self.findings if item.priority == "priority-1"]
                ),
                "review": len([item for item in self.findings if item.priority == "review"]),
                "likely_unused": len(
                    [item for item in self.findings if item.priority == "likely-unused"]
                ),
                "unknown": len(
                    [item for item in self.findings if item.priority == "manual-review"]
                ),
            },
            "import_graph": self.import_graph.to_dict(),
            "dependency_graph": self.dependency_graph.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "failures": list(self.failures),
            "warning": self.warning,
        }


def analyze_source(paths: Sequence[str | Path]) -> SourceImportGraph:
    roots = tuple(str(Path(path).resolve()) for path in paths)
    imports: list[ImportEvidence] = []
    unknown_dynamic: list[UnknownDynamicImport] = []
    entrypoints: list[ImportEvidence] = []
    for raw_root in paths:
        root = Path(raw_root).resolve()
        if root.is_file():
            files = [root] if root.suffix == ".py" else []
            project_root = root.parent
        else:
            project_root = root
            files = list(_python_files(root))
        for file_path in files:
            _inspect_python_file(
                file_path,
                project_root=project_root,
                imports=imports,
                unknown_dynamic=unknown_dynamic,
            )
        entrypoints.extend(_entrypoints_from_project_files(project_root))
    return SourceImportGraph(
        roots=roots,
        imports=tuple(sorted(imports, key=_import_sort_key)),
        unknown_dynamic_imports=tuple(
            sorted(unknown_dynamic, key=lambda item: (item.path, item.line))
        ),
        entrypoints=tuple(sorted(entrypoints, key=_import_sort_key)),
    )


def build_dependency_graph(targets: Sequence[ScanTarget]) -> DependencyGraph:
    known = {canonicalize_name(target.project) for target in targets}
    packages: list[dict[str, object]] = []
    edges: list[dict[str, str | None]] = []
    for target in sorted(targets, key=lambda item: canonicalize_name(item.project)):
        key = canonicalize_name(target.project)
        packages.append(
            {
                "project": target.project,
                "normalized_name": key,
                "version": target.version,
                "requested": target.requested,
                "source_type": target.source_type,
                "source_file": target.source_file,
                "source_line": target.source_line,
            }
        )
        for raw_requirement in sorted(target.requires_dist):
            try:
                requirement = Requirement(raw_requirement)
            except InvalidRequirement:
                continue
            child = canonicalize_name(requirement.name)
            if child not in known:
                continue
            edges.append(
                {
                    "parent": key,
                    "child": child,
                    "requirement": raw_requirement,
                    "marker": (
                        str(requirement.marker)
                        if requirement.marker is not None
                        else None
                    ),
                }
            )
    edges.sort(key=lambda item: (str(item["parent"]), str(item["child"])))
    return DependencyGraph(packages=tuple(packages), edges=tuple(edges))


def build_impact_report(
    *,
    dependency_file: str,
    source_roots: Sequence[str | Path],
    targets: Sequence[ScanTarget],
    reports: Mapping[str, TrustReport],
    import_graph: SourceImportGraph,
    failures: Sequence[dict[str, str]] = (),
) -> ImpactReport:
    target_by_key = {canonicalize_name(target.project): target for target in targets}
    dependency_graph = build_dependency_graph(targets)
    import_map = _package_import_map(targets)
    usage = _usage_by_package(import_graph, import_map)
    adjacency = _dependency_adjacency(dependency_graph)
    production_roots = sorted(
        key
        for key, evidence in usage.items()
        if any(item.context == "production" for item in evidence)
    )
    findings: list[ImpactFinding] = []
    for key, report in sorted(reports.items(), key=lambda item: item[0]):
        target = target_by_key.get(canonicalize_name(key))
        if target is None:
            continue
        for vulnerability in report.vulnerabilities:
            findings.append(
                _classify_vulnerability(
                    target,
                    vulnerability,
                    usage=usage,
                    production_roots=production_roots,
                    adjacency=adjacency,
                    dynamic_unknown=import_graph.unknown_dynamic_imports,
                )
            )
    return ImpactReport(
        source=str(Path(source_roots[0]).resolve()) if source_roots else "",
        source_roots=tuple(str(Path(path).resolve()) for path in source_roots),
        dependency_file=str(Path(dependency_file).resolve()),
        import_graph=import_graph,
        dependency_graph=dependency_graph,
        findings=tuple(sorted(findings, key=_finding_sort_key)),
        failures=tuple(failures),
    )


def render_impact_text(report: ImpactReport) -> str:
    data = report.to_dict()
    summary = data["summary"]
    if not isinstance(summary, dict):
        raise TypeError("Impact report summary must be a mapping.")
    lines = [
        f"trustcheck impact results for {Path(report.dependency_file).name}",
        f"source: {', '.join(report.source_roots)}",
        (
            "vulnerable packages: "
            f"{summary['vulnerable_packages']} "
            f"(findings: {summary['findings']}, "
            f"priority 1: {summary['priority_1']}, "
            f"review: {summary['review']}, "
            f"likely unused: {summary['likely_unused']}, "
            f"unknown: {summary['unknown']})"
        ),
    ]
    if not report.findings:
        lines.append("")
        lines.append("No vulnerable packages were reported by configured sources.")
    for finding in report.findings:
        lines.append("")
        lines.append(f"{finding.impact} - {finding.priority.replace('-', ' ')}")
        lines.append(f"{finding.project} {finding.version}")
        lines.append(_vulnerability_title(finding.vulnerability))
        if finding.used_by:
            lines.append(f"Used by: {finding.used_by[0]}")
        else:
            lines.append(f"Classification: {finding.classification.replace('_', ' ')}")
        lines.append(f"Evidence: {finding.evidence}")
        if finding.vulnerability.severity:
            lines.append(f"Advisory severity: {finding.vulnerability.severity}")
        if finding.action:
            lines.append(f"Action: {finding.action}")
    if report.failures:
        lines.append("")
        lines.append("inspection failures:")
        lines.extend(
            f"  - {failure['requirement']}: {failure['message']}"
            for failure in report.failures
        )
    lines.append("")
    lines.append(report.warning)
    return "\n".join(lines)


def _inspect_python_file(
    file_path: Path,
    *,
    project_root: Path,
    imports: list[ImportEvidence],
    unknown_dynamic: list[UnknownDynamicImport],
) -> None:
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return
    relative = _relative_path(file_path, project_root)
    context = _file_context(file_path, project_root)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _add_import(
                    alias.name,
                    relative,
                    getattr(node, "lineno", 0),
                    context,
                    imports,
                    source="import",
                )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                _add_import(
                    node.module,
                    relative,
                    getattr(node, "lineno", 0),
                    context,
                    imports,
                    source="from-import",
                )
        elif isinstance(node, ast.Call) and _is_dynamic_import_call(node):
            module = _literal_first_arg(node)
            if module:
                _add_import(
                    module,
                    relative,
                    getattr(node, "lineno", 0),
                    context,
                    imports,
                    dynamic=True,
                    source="dynamic-import",
                )
            else:
                unknown_dynamic.append(
                    UnknownDynamicImport(
                        path=relative,
                        line=getattr(node, "lineno", 0),
                        expression=_dynamic_import_name(node),
                        context=context,
                    )
                )
        elif isinstance(node, ast.Assign):
            imports.extend(_pytest_plugin_imports(node, relative, context))


def _python_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for candidate in root.rglob("*.py"):
        if any(part in SKIPPED_DIRS for part in candidate.parts):
            continue
        files.append(candidate)
    return files


def _add_import(
    module: str,
    path: str,
    line: int,
    context: str,
    imports: list[ImportEvidence],
    *,
    dynamic: bool = False,
    source: str,
) -> None:
    root = module.split(".", 1)[0].strip()
    if not root:
        return
    imports.append(
        ImportEvidence(
            module=module,
            root=root,
            path=path,
            line=line,
            context=context,
            dynamic=dynamic,
            source=source,
        )
    )


def _is_dynamic_import_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "__import__":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        return True
    return False


def _literal_first_arg(node: ast.Call) -> str | None:
    if not node.args:
        return None
    first = node.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None


def _dynamic_import_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return f"{ast.unparse(func.value)}.{func.attr}"
    return "dynamic import"


def _pytest_plugin_imports(
    node: ast.Assign,
    path: str,
    context: str,
) -> list[ImportEvidence]:
    if not any(
        isinstance(target, ast.Name) and target.id == "pytest_plugins"
        for target in node.targets
    ):
        return []
    values = _string_values(node.value)
    return [
        ImportEvidence(
            module=value,
            root=value.split(".", 1)[0],
            path=path,
            line=getattr(node, "lineno", 0),
            context=context,
            dynamic=True,
            source="pytest-plugin",
        )
        for value in values
    ]


def _string_values(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for item in node.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                values.append(item.value)
        return values
    return []


def _entrypoints_from_project_files(root: Path) -> list[ImportEvidence]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return []
    try:
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return []
    modules: list[tuple[str, str]] = []
    project = payload.get("project")
    if isinstance(project, dict):
        for table_name in ("scripts", "gui-scripts"):
            table = project.get(table_name)
            if isinstance(table, dict):
                modules.extend(
                    (str(value).split(":", 1)[0], f"project.{table_name}")
                    for value in table.values()
                    if isinstance(value, str)
                )
    tool = payload.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        scripts = poetry.get("scripts")
        if isinstance(scripts, dict):
            for value in scripts.values():
                module = value.get("reference") if isinstance(value, dict) else value
                if isinstance(module, str):
                    modules.append((module.split(":", 1)[0], "tool.poetry.scripts"))
    return [
        ImportEvidence(
            module=module,
            root=module.split(".", 1)[0],
            path=_relative_path(pyproject, root),
            line=1,
            context="production",
            dynamic=True,
            source=source,
        )
        for module, source in modules
        if module
    ]


def _package_import_map(targets: Sequence[ScanTarget]) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for target in targets:
        key = canonicalize_name(target.project)
        roots = {key.replace("-", "_"), key.replace("-", "")}
        roots.update(COMMON_IMPORT_ROOTS.get(key, ()))
        mapping[key] = {canonicalize_name(root) for root in roots if root}
    return mapping


def _usage_by_package(
    graph: SourceImportGraph,
    import_map: Mapping[str, set[str]],
) -> dict[str, list[ImportEvidence]]:
    by_root: dict[str, list[ImportEvidence]] = {}
    for item in (*graph.imports, *graph.entrypoints):
        by_root.setdefault(canonicalize_name(item.root), []).append(item)
    usage: dict[str, list[ImportEvidence]] = {}
    for package, roots in import_map.items():
        for root in roots:
            usage.setdefault(package, []).extend(by_root.get(root, []))
    return {key: value for key, value in usage.items() if value}


def _dependency_adjacency(graph: DependencyGraph) -> dict[str, list[str]]:
    adjacency: dict[str, list[str]] = {}
    for edge in graph.edges:
        parent = str(edge["parent"])
        child = str(edge["child"])
        adjacency.setdefault(parent, []).append(child)
    for children in adjacency.values():
        children.sort()
    return adjacency


def _classify_vulnerability(
    target: ScanTarget,
    vulnerability: VulnerabilityRecord,
    *,
    usage: Mapping[str, list[ImportEvidence]],
    production_roots: Sequence[str],
    adjacency: Mapping[str, list[str]],
    dynamic_unknown: Sequence[UnknownDynamicImport],
) -> ImpactFinding:
    key = canonicalize_name(target.project)
    evidence = usage.get(key, [])
    production = [item for item in evidence if item.context == "production"]
    tests = [item for item in evidence if item.context == "test"]
    development = [item for item in evidence if item.context == "development"]
    if production:
        selected = production[0]
        return _finding(
            target,
            vulnerability,
            classification="directly_used",
            evidence=f"imported by production source at {selected.path}:{selected.line}",
            used_by=(f"{selected.path} -> {target.project}",),
            import_evidence=tuple(production[:5]),
        )
    path = _reachable_path(key, production_roots, adjacency)
    if path:
        root = path[0]
        source = usage.get(root, [])[0]
        names = _display_path(path, target)
        return _finding(
            target,
            vulnerability,
            classification="transitively_reachable",
            evidence="reachable from a production import through resolved dependencies",
            used_by=(f"{source.path} -> {' -> '.join(names)}",),
            import_evidence=(source,),
            dependency_path=tuple(names),
        )
    if tests and not production and not development:
        selected = tests[0]
        return _finding(
            target,
            vulnerability,
            classification="test_only",
            evidence=f"only test imports observed, first at {selected.path}:{selected.line}",
            used_by=(f"{selected.path} -> {target.project}",),
            import_evidence=tuple(tests[:5]),
        )
    if development and not production:
        selected = development[0]
        return _finding(
            target,
            vulnerability,
            classification="development_only",
            evidence=(
                "only development/tooling imports observed, first at "
                f"{selected.path}:{selected.line}"
            ),
            used_by=(f"{selected.path} -> {target.project}",),
            import_evidence=tuple(development[:5]),
        )
    if any(item.context == "production" for item in dynamic_unknown):
        return _finding(
            target,
            vulnerability,
            classification="unknown_due_to_dynamic_loading",
            evidence=(
                "production source contains dynamic imports that static "
                "analysis cannot resolve"
            ),
        )
    return _finding(
        target,
        vulnerability,
        classification="not_observed_in_project_source",
        evidence="no first-party import was observed in the configured source roots",
    )


def _finding(
    target: ScanTarget,
    vulnerability: VulnerabilityRecord,
    *,
    classification: str,
    evidence: str,
    used_by: tuple[str, ...] = (),
    import_evidence: tuple[ImportEvidence, ...] = (),
    dependency_path: tuple[str, ...] = (),
) -> ImpactFinding:
    impact, priority = _impact_priority(classification, vulnerability)
    return ImpactFinding(
        project=target.project,
        version=target.version or "",
        vulnerability=vulnerability,
        classification=classification,
        impact=impact,
        priority=priority,
        evidence=evidence,
        used_by=used_by,
        import_evidence=import_evidence,
        dependency_path=dependency_path,
        action=_action_for(target, vulnerability, dependency_path),
    )


def _impact_priority(
    classification: str,
    vulnerability: VulnerabilityRecord,
) -> tuple[str, str]:
    severity = _severity_rank(vulnerability)
    if classification in {"directly_used", "transitively_reachable"}:
        if severity >= 3:
            return "CRITICAL", "priority-1"
        return "HIGH", "review"
    if classification == "unknown_due_to_dynamic_loading":
        return "HIGH", "manual-review"
    return "LOW", "likely-unused"


def _severity_rank(vulnerability: VulnerabilityRecord) -> int:
    if vulnerability.cvss_score is not None:
        if vulnerability.cvss_score >= 9:
            return 4
        if vulnerability.cvss_score >= 7:
            return 3
        if vulnerability.cvss_score >= 4:
            return 2
        return 1
    value = (vulnerability.severity or "").upper()
    if value == "CRITICAL":
        return 4
    if value == "HIGH":
        return 3
    if value in {"MED", "MEDIUM", "MODERATE"}:
        return 2
    if value == "LOW":
        return 1
    return 0


def _reachable_path(
    target: str,
    starts: Sequence[str],
    adjacency: Mapping[str, list[str]],
) -> list[str] | None:
    for start in starts:
        queue: deque[list[str]] = deque([[start]])
        seen = {start}
        while queue:
            path = queue.popleft()
            current = path[-1]
            for child in adjacency.get(current, []):
                if child in seen:
                    continue
                child_path = [*path, child]
                if child == target:
                    return child_path
                seen.add(child)
                queue.append(child_path)
    return None


def _display_path(path: Sequence[str], target: ScanTarget) -> list[str]:
    names = list(path)
    if names:
        names[-1] = target.project
    return names


def _action_for(
    target: ScanTarget,
    vulnerability: VulnerabilityRecord,
    dependency_path: Sequence[str],
) -> str:
    fixed = ", ".join(vulnerability.fixed_in[:3])
    base = target.project
    if dependency_path and dependency_path[0] != canonicalize_name(target.project):
        base = dependency_path[0]
        if fixed:
            return (
                f"upgrade {base} or pin {target.project} to a fixed version "
                f"({fixed})"
            )
        return f"review whether upgrading {base} removes the vulnerable transitive dependency"
    if fixed:
        return f"upgrade {target.project} to a fixed version ({fixed})"
    if target.requested:
        return f"upgrade, remove, or move {target.project} based on confirmed runtime need"
    return f"upgrade the parent dependency or pin a safe {target.project} version"


def _vulnerability_payload(vulnerability: VulnerabilityRecord) -> dict[str, object]:
    return {
        "id": vulnerability.id,
        "summary": vulnerability.summary,
        "aliases": list(vulnerability.aliases),
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "fixed_in": list(vulnerability.fixed_in),
        "link": vulnerability.link,
        "kev": vulnerability.kev,
    }


def _vulnerability_title(vulnerability: VulnerabilityRecord) -> str:
    identifiers = [vulnerability.id, *vulnerability.aliases]
    title = next((item for item in identifiers if item.startswith("CVE-")), vulnerability.id)
    if vulnerability.summary:
        return f"{title}: {vulnerability.summary}"
    return title


def _finding_sort_key(finding: ImpactFinding) -> tuple[int, int, str, str]:
    priority_order = {
        "priority-1": 0,
        "review": 1,
        "manual-review": 2,
        "likely-unused": 3,
    }
    return (
        priority_order.get(finding.priority, 9),
        -_severity_rank(finding.vulnerability),
        canonicalize_name(finding.project),
        finding.vulnerability.id,
    )


def _import_sort_key(item: ImportEvidence) -> tuple[str, int, str, str]:
    return (item.path, item.line, item.root, item.module)


def _file_context(path: Path, root: Path) -> str:
    relative = path.relative_to(root) if _is_relative_to(path, root) else path
    parts = {part.lower() for part in relative.parts}
    name = path.name.lower()
    if parts.intersection(TEST_PARTS) or name.startswith("test_") or name.endswith("_test.py"):
        return "test"
    if name in {"conftest.py", "noxfile.py", "toxfile.py"}:
        return "test" if name == "conftest.py" else "development"
    if parts.intersection(DEVELOPMENT_PARTS):
        return "development"
    return "production"


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _json_dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def render_impact_json(report: ImpactReport) -> str:
    return _json_dumps(report.to_dict())
