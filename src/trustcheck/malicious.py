from __future__ import annotations

import ast
import math
import re
import statistics
import struct
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from urllib.parse import urlparse

from packaging.utils import canonicalize_name

from .models import (
    HeuristicFinding,
    MaliciousPackageAssessment,
    NativeBinaryInspection,
)

DEFAULT_TRUSTED_PROJECTS = frozenset(
    {
        "aiohttp",
        "attrs",
        "boto3",
        "build",
        "certifi",
        "cffi",
        "click",
        "cryptography",
        "django",
        "fastapi",
        "flask",
        "google-auth",
        "grpcio",
        "httpx",
        "idna",
        "jinja2",
        "jupyter",
        "keyring",
        "matplotlib",
        "mypy",
        "numpy",
        "opencv-python",
        "packaging",
        "pandas",
        "pillow",
        "pip",
        "pip-audit",
        "pip-tools",
        "poetry",
        "protobuf",
        "psutil",
        "pyarrow",
        "pydantic",
        "pyjwt",
        "pytest",
        "python-dateutil",
        "pyyaml",
        "requests",
        "rich",
        "ruff",
        "scikit-learn",
        "scipy",
        "setuptools",
        "sigstore",
        "sqlalchemy",
        "starlette",
        "tensorflow",
        "torch",
        "tqdm",
        "trustcheck",
        "tuf",
        "twine",
        "urllib3",
        "uv",
        "virtualenv",
        "wheel",
    }
)

_SENSITIVE_NAME = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|credential|password|passwd|"
    r"secret|private[_-]?key|aws_|azure_|gcp_|github_token|gitlab_token|"
    r"pypi_token|twine_password)",
    re.IGNORECASE,
)
_SENSITIVE_PATHS = (
    ".aws/credentials",
    ".config/gcloud",
    ".docker/config.json",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh/",
    "login data",
    "keychain",
)
_PERSISTENCE_PATHS = (
    ".bash_profile",
    ".bashrc",
    ".pth",
    ".profile",
    "authorized_keys",
    "crontab",
    "launchagents",
    "launchdaemons",
    "sitecustomize.py",
    "startup",
    "systemd/",
    "usercustomize.py",
)
_NETWORK_CALLS = {
    "aiohttp.client",
    "aiohttp.clientrequest",
    "aiohttp.clientresponse",
    "http.client.httpconnection",
    "http.client.httpsconnection",
    "httpx.delete",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "requests.delete",
    "requests.get",
    "requests.post",
    "requests.put",
    "socket.create_connection",
    "socket.socket",
    "urllib.request.urlopen",
    "urllib3.poolmanager",
}
_PROCESS_CALLS = {
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.popen",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.popen",
    "subprocess.run",
}
_DYNAMIC_CALLS = {
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "compile",
    "eval",
    "exec",
}
_DECODE_CALLS = {
    "base64.a85decode",
    "base64.b16decode",
    "base64.b32decode",
    "base64.b64decode",
    "base64.b85decode",
    "binascii.a2b_base64",
    "bz2.decompress",
    "gzip.decompress",
    "lzma.decompress",
    "marshal.loads",
    "pickle.loads",
    "zlib.decompress",
}
_PERSISTENCE_CALLS = {
    "os.startfile",
    "winreg.createkey",
    "winreg.createkeyex",
    "winreg.setvalue",
    "winreg.setvalueex",
}
_SUSPICIOUS_NATIVE_IMPORTS = (
    "advapi32",
    "crypt32",
    "curl",
    "keychain",
    "libsecret",
    "shell32",
    "urlmon",
    "winhttp",
    "wininet",
    "ws2_32",
)
_MACHO_DYLIB_COMMANDS = {
    0xC,
    0x18,
    0x18 | 0x80000000,
    0x1F,
    0x1F | 0x80000000,
    0x20,
    0x23,
    0x23 | 0x80000000,
}
DEFAULT_SCORE_THRESHOLDS = {
    "low": 1,
    "elevated": 25,
    "high": 50,
    "critical": 75,
}


@dataclass(frozen=True, slots=True)
class HeuristicRuleMetadata:
    false_positive_rate: float
    confidence: str
    rule_version: str
    score_threshold: int = 1


RULE_METADATA: dict[str, HeuristicRuleMetadata] = {
    "ast_credential_environment": HeuristicRuleMetadata(0.18, "high", "2026.06"),
    "ast_credential_file_access": HeuristicRuleMetadata(0.12, "medium", "2026.06"),
    "ast_credential_network_chain": HeuristicRuleMetadata(0.04, "medium", "2026.06"),
    "ast_custom_install_hook": HeuristicRuleMetadata(0.09, "high", "2026.06"),
    "ast_dynamic_execution": HeuristicRuleMetadata(0.16, "high", "2026.06"),
    "ast_install_time_execution_chain": HeuristicRuleMetadata(0.03, "high", "2026.06"),
    "ast_keyring_access": HeuristicRuleMetadata(0.06, "high", "2026.06"),
    "ast_network_call": HeuristicRuleMetadata(0.28, "high", "2026.06"),
    "ast_obfuscated_process_chain": HeuristicRuleMetadata(0.05, "medium", "2026.06"),
    "ast_payload_decode": HeuristicRuleMetadata(0.22, "high", "2026.06"),
    "ast_persistence": HeuristicRuleMetadata(0.08, "medium", "2026.06"),
    "ast_subprocess_call": HeuristicRuleMetadata(0.20, "high", "2026.06"),
    "declared_repository_change": HeuristicRuleMetadata(0.07, "high", "2026.06"),
    "dependency_confusion_index_collision": HeuristicRuleMetadata(0.03, "high", "2026.06"),
    "maintainer_identity_change": HeuristicRuleMetadata(0.25, "medium", "2026.06"),
    "native_embedded_payload": HeuristicRuleMetadata(0.10, "medium", "2026.06"),
    "native_high_entropy": HeuristicRuleMetadata(0.35, "low", "2026.06"),
    "native_payload_network_chain": HeuristicRuleMetadata(0.05, "medium", "2026.06"),
    "native_sensitive_import": HeuristicRuleMetadata(0.18, "medium", "2026.06"),
    "native_signature_absent": HeuristicRuleMetadata(0.42, "low", "2026.06"),
    "project_ownership_change": HeuristicRuleMetadata(0.10, "medium", "2026.06"),
    "release_after_dormancy": HeuristicRuleMetadata(0.20, "high", "2026.06"),
    "release_burst": HeuristicRuleMetadata(0.18, "high", "2026.06"),
    "release_cadence_acceleration": HeuristicRuleMetadata(0.23, "medium", "2026.06"),
    "typosquatting_name_similarity": HeuristicRuleMetadata(0.08, "medium", "2026.06"),
}


def analyze_python_source(
    path: str,
    payload: bytes,
    *,
    install_context: bool = False,
) -> tuple[list[HeuristicFinding], str | None]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [], f"{path}: source is not valid UTF-8: {exc}"
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError) as exc:
        return [], f"{path}: unable to parse Python AST: {exc}"

    visitor = _SourceVisitor(path, install_context=install_context)
    visitor.visit(tree)
    visitor.add_combination_findings()
    return _deduplicate_findings(visitor.findings), None


def inspect_native_binary(path: str, payload: bytes) -> NativeBinaryInspection:
    entropy = _shannon_entropy(payload)
    embedded = _embedded_payloads(payload)
    try:
        if payload.startswith(b"MZ"):
            result = _parse_pe(path, payload)
        elif payload.startswith(b"\x7fELF"):
            result = _parse_elf(path, payload)
        elif payload[:4] in {
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
        }:
            result = _parse_macho(path, payload)
        else:
            result = NativeBinaryInspection(
                path=path,
                parse_error="native file does not contain a recognized PE, ELF, or Mach-O header",
            )
    except (IndexError, OverflowError, struct.error, ValueError) as exc:
        result = NativeBinaryInspection(
            path=path,
            format=_native_format(payload),
            parse_error=f"unable to parse native binary: {exc}",
        )
    result.entropy = entropy
    result.embedded_payloads = embedded
    return result


def native_binary_findings(
    inspection: NativeBinaryInspection,
) -> list[HeuristicFinding]:
    findings: list[HeuristicFinding] = []
    location = inspection.path
    suspicious_imports = sorted(
        {
            imported
            for imported in inspection.imports
            if any(token in imported.lower() for token in _SUSPICIOUS_NATIVE_IMPORTS)
        }
    )
    if suspicious_imports:
        findings.append(
            _finding(
                "native_sensitive_import",
                "native-code",
                "medium",
                "medium",
                15,
                "Native code imports networking, credential, or operating-system APIs.",
                evidence=suspicious_imports[:10],
                location=location,
            )
        )
    if inspection.entropy is not None and inspection.entropy >= 7.2:
        findings.append(
            _finding(
                "native_high_entropy",
                "obfuscation",
                "medium",
                "low",
                12,
                "Native code has high byte entropy consistent with compression or packing.",
                evidence=[f"Shannon entropy: {inspection.entropy:.3f} bits/byte"],
                location=location,
            )
        )
    if inspection.embedded_payloads:
        findings.append(
            _finding(
                "native_embedded_payload",
                "embedded-payload",
                "high",
                "medium",
                30,
                "Native code contains one or more embedded executable or archive signatures.",
                evidence=inspection.embedded_payloads[:10],
                location=location,
            )
        )
    if (
        inspection.format in {"PE", "Mach-O"}
        and inspection.signature_present is False
    ):
        findings.append(
            _finding(
                "native_signature_absent",
                "native-code",
                "low",
                "low",
                5,
                "The native binary has no embedded platform signature.",
                evidence=[
                    "Unsigned extension modules are common; signature absence is only "
                    "a weak review signal."
                ],
                location=location,
            )
        )
    if suspicious_imports and inspection.embedded_payloads:
        findings.append(
            _finding(
                "native_payload_network_chain",
                "native-code",
                "high",
                "medium",
                42,
                "Native code combines sensitive imports with an embedded payload.",
                evidence=[*suspicious_imports[:5], *inspection.embedded_payloads[:5]],
                location=location,
            )
        )
    return findings


def assess_package(
    project: str,
    *,
    current_info: Mapping[str, object],
    current_ownership: Mapping[str, object],
    current_repositories: Sequence[str],
    project_payload: Mapping[str, object] | None = None,
    previous_payload: Mapping[str, object] | None = None,
    dependency_confusion_indexes: Sequence[str] = (),
    artifact_findings: Sequence[HeuristicFinding] = (),
    artifact_analysis: bool = False,
    trusted_projects: Iterable[str] = (),
    score_thresholds: Mapping[str, int] | None = None,
    rule_thresholds: Mapping[str, int] | None = None,
) -> MaliciousPackageAssessment:
    resolved_score_thresholds = normalize_score_thresholds(score_thresholds)
    resolved_rule_thresholds = normalize_rule_thresholds(rule_thresholds)
    trusted_names = {
        str(canonicalize_name(name))
        for name in (*DEFAULT_TRUSTED_PROJECTS, *trusted_projects)
        if name
    }
    findings = _typosquatting_findings(project, trusted_names)
    findings.extend(_dependency_confusion_findings(dependency_confusion_indexes))
    findings.extend(
        _metadata_anomaly_findings(
            current_info=current_info,
            current_ownership=current_ownership,
            current_repositories=current_repositories,
            previous_payload=previous_payload,
        )
    )
    findings.extend(
        _release_cadence_findings(
            project_payload=project_payload,
            current_version=str(current_info.get("version") or ""),
        )
    )
    findings.extend(artifact_findings)
    findings = _deduplicate_findings(findings)
    score = heuristic_score(findings, rule_thresholds=resolved_rule_thresholds)
    return MaliciousPackageAssessment(
        score=score,
        level=_score_level(score, thresholds=resolved_score_thresholds),
        artifact_analysis=artifact_analysis,
        trusted_name_count=len(trusted_names),
        findings=sorted(
            findings,
            key=lambda item: (-item.score, item.category, item.code, item.location or ""),
        ),
        score_thresholds=resolved_score_thresholds,
        rule_thresholds=resolved_rule_thresholds,
    )


def heuristic_score(
    findings: Sequence[HeuristicFinding],
    *,
    rule_thresholds: Mapping[str, int] | None = None,
) -> int:
    confidence_weight = {"low": 0.5, "medium": 0.75, "high": 1.0}
    thresholds = normalize_rule_thresholds(rule_thresholds)
    weighted = sorted(
        (
            finding.score * confidence_weight.get(finding.confidence, 0.5)
            for finding in findings
            if finding.score > 0
            and finding.score >= thresholds.get(finding.code, finding.score_threshold)
        ),
        reverse=True,
    )
    return min(
        100,
        round(
            sum(value * (0.65**index) for index, value in enumerate(weighted))
        ),
    )


def normalize_score_thresholds(
    thresholds: Mapping[str, int] | None,
) -> dict[str, int]:
    resolved = dict(DEFAULT_SCORE_THRESHOLDS)
    if thresholds is not None:
        unknown = sorted(set(thresholds) - set(DEFAULT_SCORE_THRESHOLDS))
        if unknown:
            raise ValueError(
                "unknown malicious-package score threshold(s): "
                + ", ".join(unknown)
            )
        resolved.update({key: int(value) for key, value in thresholds.items()})
    ordered = ["low", "elevated", "high", "critical"]
    for key in ordered:
        value = resolved[key]
        if value < 0 or value > 100:
            raise ValueError(
                "malicious-package score thresholds must be between 0 and 100"
            )
    if any(
        resolved[left] > resolved[right]
        for left, right in zip(ordered, ordered[1:])
    ):
        raise ValueError(
            "malicious-package score thresholds must be ordered "
            "low <= elevated <= high <= critical"
        )
    return resolved


def normalize_rule_thresholds(
    thresholds: Mapping[str, int] | None,
) -> dict[str, int]:
    if thresholds is None:
        return {}
    normalized: dict[str, int] = {}
    for code, raw_value in thresholds.items():
        value = int(raw_value)
        if value < 0 or value > 100:
            raise ValueError(
                "malicious-package rule thresholds must be between 0 and 100"
            )
        normalized[str(code)] = value
    return normalized


class _SourceVisitor(ast.NodeVisitor):
    def __init__(self, path: str, *, install_context: bool) -> None:
        self.path = path
        self.install_context = install_context
        self.aliases: dict[str, str] = {}
        self.findings: list[HeuristicFinding] = []
        self.categories: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", maxsplit=1)[0]
            self.aliases[local] = alias.name if alias.asname else local
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}".strip(".")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = self._qualified_name(node.value)
        key = _constant_text(node.slice)
        if name.lower() == "os.environ" and key and _SENSITIVE_NAME.search(key):
            self._add(
                node,
                "ast_credential_environment",
                "credential-access",
                "high",
                "high",
                28,
                "Python source reads a sensitive credential-like environment variable.",
                [f"environment variable: {key}"],
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._qualified_name(node.func).lower()
        arguments = _call_text_arguments(node)
        if _matches_call(name, _NETWORK_CALLS):
            self._add(
                node,
                "ast_network_call",
                "network",
                "medium" if self.install_context else "low",
                "high",
                22 if self.install_context else 8,
                "Python source can initiate an outbound network connection.",
                [name, *arguments[:2]],
            )
        if _matches_call(name, _PROCESS_CALLS):
            self._add(
                node,
                "ast_subprocess_call",
                "subprocess",
                "high" if self.install_context else "medium",
                "high",
                30 if self.install_context else 12,
                "Python source can start an external process.",
                [name, *arguments[:2]],
            )
        if name in _DYNAMIC_CALLS:
            self._add(
                node,
                "ast_dynamic_execution",
                "obfuscation",
                "high",
                "high",
                32 if self.install_context else 24,
                "Python source dynamically compiles or executes code.",
                [name],
            )
        if name in _DECODE_CALLS:
            self._add(
                node,
                "ast_payload_decode",
                "obfuscation",
                "medium",
                "high",
                18,
                "Python source decodes or deserializes an opaque payload.",
                [name],
            )
        if name == "keyring.get_password":
            self._add(
                node,
                "ast_keyring_access",
                "credential-access",
                "high",
                "high",
                30,
                "Python source requests a password from the system keyring.",
                [name, *arguments[:2]],
            )
        if name in {"os.getenv", "os.environ.get"}:
            sensitive = [value for value in arguments if _SENSITIVE_NAME.search(value)]
            if sensitive:
                self._add(
                    node,
                    "ast_credential_environment",
                    "credential-access",
                    "high",
                    "high",
                    28,
                    "Python source reads a sensitive credential-like environment variable.",
                    sensitive[:3],
                )
        sensitive_paths = [
            value
            for value in arguments
            if any(token in value.lower().replace("\\", "/") for token in _SENSITIVE_PATHS)
        ]
        if sensitive_paths and name in {
            "builtins.open",
            "io.open",
            "open",
            "pathlib.path",
            "pathlib.path.read_bytes",
            "pathlib.path.read_text",
        }:
            self._add(
                node,
                "ast_credential_file_access",
                "credential-access",
                "high",
                "medium",
                30,
                "Python source accesses a path commonly used to store credentials.",
                sensitive_paths[:3],
            )
        persistence_paths = [
            value
            for value in arguments
            if any(token in value.lower().replace("\\", "/") for token in _PERSISTENCE_PATHS)
        ]
        if name in _PERSISTENCE_CALLS or persistence_paths:
            evidence = [name, *persistence_paths[:3]]
            self._add(
                node,
                "ast_persistence",
                "persistence",
                "high",
                "medium",
                36,
                "Python source can modify an operating-system or Python startup location.",
                evidence,
            )
        if self.install_context and name in {"setuptools.setup", "distutils.core.setup", "setup"}:
            if any(keyword.arg == "cmdclass" for keyword in node.keywords):
                self._add(
                    node,
                    "ast_custom_install_hook",
                    "install-hook",
                    "high",
                    "high",
                    25,
                    "Package build metadata registers a custom install or build command.",
                    ["setup(..., cmdclass=...)"],
                )
        self.generic_visit(node)

    def add_combination_findings(self) -> None:
        if {"credential-access", "network"} <= self.categories:
            self.findings.append(
                _finding(
                    "ast_credential_network_chain",
                    "credential-access",
                    "critical",
                    "medium",
                    58,
                    "The same Python file combines credential access with network capability.",
                    evidence=["credential-access", "network"],
                    location=self.path,
                )
            )
        if {"obfuscation", "subprocess"} <= self.categories:
            self.findings.append(
                _finding(
                    "ast_obfuscated_process_chain",
                    "obfuscation",
                    "high",
                    "medium",
                    48,
                    "The same Python file combines opaque code handling with process execution.",
                    evidence=["obfuscation", "subprocess"],
                    location=self.path,
                )
            )
        if self.install_context and (
            {"network", "subprocess"} <= self.categories
            or {"obfuscation", "subprocess"} <= self.categories
        ):
            self.findings.append(
                _finding(
                    "ast_install_time_execution_chain",
                    "install-hook",
                    "critical",
                    "high",
                    65,
                    "Install-time source combines multiple capabilities that can execute "
                    "or retrieve code.",
                    evidence=sorted(self.categories),
                    location=self.path,
                )
            )

    def _qualified_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = self._qualified_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    def _add(
        self,
        node: ast.AST,
        code: str,
        category: str,
        severity: str,
        confidence: str,
        score: int,
        message: str,
        evidence: list[str],
    ) -> None:
        self.categories.add(category)
        line = getattr(node, "lineno", None)
        location = f"{self.path}:{line}" if line is not None else self.path
        self.findings.append(
            _finding(
                code,
                category,
                severity,
                confidence,
                score,
                message,
                evidence=[value for value in evidence if value],
                location=location,
            )
        )


def _typosquatting_findings(
    project: str,
    trusted_names: set[str],
) -> list[HeuristicFinding]:
    candidate = str(canonicalize_name(project))
    compact_candidate = candidate.replace("-", "")
    matches: list[tuple[int, float, str, str]] = []
    for trusted in trusted_names:
        if trusted == candidate:
            continue
        distance = _damerau_levenshtein(candidate, trusted)
        compact_distance = _damerau_levenshtein(
            compact_candidate,
            trusted.replace("-", ""),
        )
        effective_distance = min(distance, compact_distance)
        maximum = max(len(compact_candidate), len(trusted.replace("-", "")), 1)
        similarity = 1.0 - effective_distance / maximum
        threshold = 1 if maximum < 8 else 2
        if effective_distance <= threshold and similarity >= 0.72:
            relation = _name_relation(candidate, trusted)
            matches.append((effective_distance, similarity, trusted, relation))
    if not matches:
        return []
    distance, similarity, trusted, relation = min(
        matches,
        key=lambda item: (item[0], -item[1], item[2]),
    )
    score = 45 if distance == 1 else 32
    return [
        _finding(
            "typosquatting_name_similarity",
            "typosquatting",
            "high" if distance == 1 else "medium",
            "medium",
            score,
            "Project name is unusually similar to a trusted reference project.",
            evidence=[
                f"candidate={candidate}",
                f"trusted={trusted}",
                f"edit_distance={distance}",
                f"similarity={similarity:.3f}",
                f"relationship={relation}",
            ],
        )
    ]


def _dependency_confusion_findings(indexes: Sequence[str]) -> list[HeuristicFinding]:
    normalized = sorted({index for index in indexes if index})
    if len(normalized) < 2:
        return []
    public = any(
        hostname is not None
        and (
            hostname.lower() == "pypi.org"
            or hostname.lower().endswith(".pypi.org")
        )
        for hostname in (urlparse(index).hostname for index in normalized)
    )
    return [
        _finding(
            "dependency_confusion_index_collision",
            "dependency-confusion",
            "critical" if public else "high",
            "high",
            72 if public else 55,
            "The same normalized project name is available from multiple configured indexes.",
            evidence=[
                *normalized,
                "resolver_strategy=version-priority",
                "index_trust_order=not-enforced-by-pip",
                (
                    "pip selects candidates by version and compatibility across "
                    "configured indexes, not by a private-index trust order."
                ),
                (
                    "At least one colliding source is the public PyPI index."
                    if public
                    else "All observed colliding sources are non-PyPI indexes."
                ),
            ],
        )
    ]


def _metadata_anomaly_findings(
    *,
    current_info: Mapping[str, object],
    current_ownership: Mapping[str, object],
    current_repositories: Sequence[str],
    previous_payload: Mapping[str, object] | None,
) -> list[HeuristicFinding]:
    if previous_payload is None:
        return []
    raw_previous_info = previous_payload.get("info")
    previous_info = (
        raw_previous_info if isinstance(raw_previous_info, Mapping) else {}
    )
    findings: list[HeuristicFinding] = []
    current_maintainers = _maintainer_identities(current_info)
    previous_maintainers = _maintainer_identities(previous_info)
    if current_maintainers and previous_maintainers and current_maintainers != previous_maintainers:
        findings.append(
            _finding(
                "maintainer_identity_change",
                "ownership",
                "medium",
                "medium",
                24,
                "Maintainer or author identity metadata changed from the previous release.",
                evidence=[
                    f"previous={','.join(sorted(previous_maintainers))}",
                    f"current={','.join(sorted(current_maintainers))}",
                ],
            )
        )

    raw_previous_ownership = previous_info.get("ownership")
    previous_ownership = (
        raw_previous_ownership
        if isinstance(raw_previous_ownership, Mapping)
        else {}
    )
    current_owners = _ownership_identities(current_ownership)
    previous_owners = _ownership_identities(previous_ownership)
    if current_owners and previous_owners and current_owners != previous_owners:
        findings.append(
            _finding(
                "project_ownership_change",
                "ownership",
                "high",
                "medium",
                35,
                "Project ownership metadata changed from the previous release.",
                evidence=[
                    f"previous={','.join(sorted(previous_owners))}",
                    f"current={','.join(sorted(current_owners))}",
                ],
            )
        )

    previous_repositories = _repository_urls(previous_info)
    current = {_normalize_repository(url) for url in current_repositories if url}
    previous = {_normalize_repository(url) for url in previous_repositories if url}
    if current and previous and not current.intersection(previous):
        findings.append(
            _finding(
                "declared_repository_change",
                "repository",
                "high",
                "high",
                38,
                "Declared source repository changed to a non-overlapping location.",
                evidence=[
                    f"previous={','.join(sorted(previous))}",
                    f"current={','.join(sorted(current))}",
                ],
            )
        )
    return findings


def _release_cadence_findings(
    *,
    project_payload: Mapping[str, object] | None,
    current_version: str,
) -> list[HeuristicFinding]:
    if project_payload is None:
        return []
    raw_releases = project_payload.get("releases")
    if not isinstance(raw_releases, Mapping):
        return []
    uploads: list[tuple[datetime, str]] = []
    for version, raw_files in raw_releases.items():
        if not isinstance(raw_files, list):
            continue
        timestamps = [
            timestamp
            for item in raw_files
            if isinstance(item, Mapping)
            for timestamp in [_upload_time(item)]
            if timestamp is not None
        ]
        if timestamps:
            uploads.append((min(timestamps), str(version)))
    uploads.sort()
    current = next(
        (timestamp for timestamp, version in uploads if version == current_version),
        None,
    )
    if current is None:
        return []

    findings: list[HeuristicFinding] = []
    recent = [
        version
        for timestamp, version in uploads
        if 0 <= (current - timestamp).total_seconds() <= 24 * 60 * 60
    ]
    if len(recent) >= 5:
        findings.append(
            _finding(
                "release_burst",
                "release-cadence",
                "medium",
                "high",
                20,
                "The project published at least five releases within 24 hours.",
                evidence=[f"releases={','.join(recent[-10:])}"],
            )
        )

    relevant_uploads = [item for item in uploads if item[0] <= current]
    dormant_gaps = [
        (later[0] - earlier[0]).total_seconds() / (24 * 60 * 60)
        for earlier, later in zip(relevant_uploads, relevant_uploads[1:])
        if (current - later[0]).total_seconds() <= 24 * 60 * 60
        and (later[0] - earlier[0]).total_seconds() >= 365 * 24 * 60 * 60
    ]
    if dormant_gaps:
        findings.append(
            _finding(
                "release_after_dormancy",
                "release-cadence",
                "medium",
                "high",
                22,
                "The current release sequence follows at least one year without a release.",
                evidence=[f"dormancy_days={max(dormant_gaps):.1f}"],
            )
        )

    intervals = [
        (later[0] - earlier[0]).total_seconds()
        for earlier, later in zip(uploads, uploads[1:])
        if later[0] <= current and (later[0] - earlier[0]).total_seconds() > 0
    ]
    current_index = next(
        index for index, (_, version) in enumerate(uploads) if version == current_version
    )
    if current_index > 0 and len(intervals) >= 3:
        latest_interval = (
            uploads[current_index][0] - uploads[current_index - 1][0]
        ).total_seconds()
        baseline = statistics.median(intervals[:-1] or intervals)
        if latest_interval <= 60 * 60 and baseline >= 7 * 24 * 60 * 60:
            findings.append(
                _finding(
                    "release_cadence_acceleration",
                    "release-cadence",
                    "medium",
                    "medium",
                    18,
                    "The current release arrived much faster than the historical cadence.",
                    evidence=[
                        f"latest_interval_hours={latest_interval / 3600:.2f}",
                        f"median_interval_days={baseline / 86400:.2f}",
                    ],
                )
            )
    return findings


def _parse_pe(path: str, payload: bytes) -> NativeBinaryInspection:
    if len(payload) < 0x40:
        raise ValueError("truncated DOS header")
    pe_offset = _unpack("I", payload, 0x3C, "<")[0]
    if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe_offset + 4
    machine, section_count = _unpack("HH", payload, coff, "<")
    optional_size = _unpack("H", payload, coff + 16, "<")[0]
    optional = coff + 20
    magic = _unpack("H", payload, optional, "<")[0]
    if magic == 0x10B:
        data_directory = optional + 96
        number_offset = optional + 92
    elif magic == 0x20B:
        data_directory = optional + 112
        number_offset = optional + 108
    else:
        raise ValueError(f"unsupported optional-header magic 0x{magic:x}")
    directory_count = _unpack("I", payload, number_offset, "<")[0]
    import_rva = import_size = certificate_size = 0
    if directory_count > 1:
        import_rva, import_size = _unpack("II", payload, data_directory + 8, "<")
    if directory_count > 4:
        _, certificate_size = _unpack("II", payload, data_directory + 32, "<")

    sections: list[tuple[int, int, int, int]] = []
    section_offset = optional + optional_size
    for index in range(section_count):
        offset = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = _unpack(
            "IIII", payload, offset + 8, "<"
        )
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    imports: list[str] = []
    if import_rva and import_size:
        descriptor = _pe_rva_to_offset(import_rva, sections)
        limit = min(len(payload), descriptor + import_size)
        while descriptor + 20 <= limit:
            values = _unpack("IIIII", payload, descriptor, "<")
            if not any(values):
                break
            name_rva = values[3]
            if name_rva:
                name_offset = _pe_rva_to_offset(name_rva, sections)
                imports.append(_cstring(payload, name_offset))
            descriptor += 20
    architecture = {
        0x14C: "x86",
        0x8664: "x86-64",
        0x1C0: "ARM",
        0x1C4: "ARM Thumb-2",
        0xAA64: "ARM64",
        0x200: "Itanium",
        0x5064: "RISC-V 64",
    }.get(machine, f"machine-0x{machine:x}")
    return NativeBinaryInspection(
        path=path,
        format="PE",
        architecture=architecture,
        imports=sorted({item for item in imports if item}),
        signature_present=certificate_size > 0,
        signature_status=(
            "embedded-certificate-present"
            if certificate_size > 0
            else "no-embedded-certificate"
        ),
    )


def _parse_elf(path: str, payload: bytes) -> NativeBinaryInspection:
    if len(payload) < 52:
        raise ValueError("truncated ELF header")
    elf_class = payload[4]
    encoding = payload[5]
    endian = "<" if encoding == 1 else ">" if encoding == 2 else ""
    if not endian:
        raise ValueError("unsupported ELF byte order")
    machine = _unpack("H", payload, 18, endian)[0]
    if elf_class == 1:
        shoff = _unpack("I", payload, 32, endian)[0]
        shentsize, shnum = _unpack("HH", payload, 46, endian)
        section_format = "IIIIIIIIII"
        dynamic_format = "II"
    elif elf_class == 2:
        shoff = _unpack("Q", payload, 40, endian)[0]
        shentsize, shnum = _unpack("HH", payload, 58, endian)
        section_format = "IIQQQQIIQQ"
        dynamic_format = "QQ"
    else:
        raise ValueError("unsupported ELF class")

    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(shnum):
        values = _unpack(section_format, payload, shoff + index * shentsize, endian)
        if elf_class == 1:
            section_type, offset, size, link, entry_size = (
                values[1],
                values[4],
                values[5],
                values[6],
                values[9],
            )
        else:
            section_type, offset, size, link, entry_size = (
                values[1],
                values[4],
                values[5],
                values[6],
                values[9],
            )
        sections.append((section_type, offset, size, link, entry_size))

    imports: list[str] = []
    dynamic_entry_size = struct.calcsize(endian + dynamic_format)
    for section_type, offset, size, link, entry_size in sections:
        if section_type != 6 or link >= len(sections):
            continue
        _, string_offset, string_size, _, _ = sections[link]
        step = entry_size or dynamic_entry_size
        for dynamic_offset in range(offset, offset + size, step):
            tag, value = _unpack(dynamic_format, payload, dynamic_offset, endian)
            if tag == 0:
                break
            if tag == 1 and value < string_size:
                imports.append(_cstring(payload, string_offset + value))
    architecture = {
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        21: "PowerPC64",
        40: "ARM",
        62: "x86-64",
        183: "AArch64",
        243: "RISC-V",
    }.get(machine, f"machine-{machine}")
    return NativeBinaryInspection(
        path=path,
        format="ELF",
        architecture=architecture,
        imports=sorted({item for item in imports if item}),
        signature_present=None,
        signature_status="no-standard-embedded-signature",
    )


def _parse_macho(
    path: str,
    payload: bytes,
    *,
    allow_fat: bool = True,
) -> NativeBinaryInspection:
    magic = payload[:4]
    if allow_fat and magic in {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }:
        endian = ">" if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "<"
        is_64 = magic in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
        count = _unpack("I", payload, 4, endian)[0]
        entry_size = 32 if is_64 else 20
        slices: list[NativeBinaryInspection] = []
        for index in range(min(count, 32)):
            offset = 8 + index * entry_size
            if is_64:
                _, _, slice_offset, slice_size = _unpack(
                    "IIQQ", payload, offset, endian
                )
            else:
                _, _, slice_offset, slice_size = _unpack(
                    "IIII", payload, offset, endian
                )
            slices.append(
                _parse_macho(
                    path,
                    payload[slice_offset : slice_offset + slice_size],
                    allow_fat=False,
                )
            )
        if not slices:
            raise ValueError("fat Mach-O contains no architecture slices")
        return NativeBinaryInspection(
            path=path,
            format="Mach-O",
            architecture="universal(" + ",".join(
                sorted({item.architecture or "unknown" for item in slices})
            ) + ")",
            imports=sorted({value for item in slices for value in item.imports}),
            signature_present=all(item.signature_present is True for item in slices),
            signature_status=(
                "all-slices-code-signature-present"
                if all(item.signature_present is True for item in slices)
                else "one-or-more-slices-unsigned"
            ),
        )

    if magic in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
        endian = "<"
    elif magic in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"}:
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O magic")
    is_64 = magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}
    cpu_type = _unpack("I", payload, 4, endian)[0]
    command_count = _unpack("I", payload, 16, endian)[0]
    command_offset = 32 if is_64 else 28
    imports: list[str] = []
    signed = False
    for _ in range(command_count):
        command, command_size = _unpack("II", payload, command_offset, endian)
        if command_size < 8:
            raise ValueError("invalid Mach-O load-command size")
        if command in _MACHO_DYLIB_COMMANDS and command_size >= 24:
            name_offset = _unpack("I", payload, command_offset + 8, endian)[0]
            imports.append(_cstring(payload, command_offset + name_offset))
        if command == 0x1D:
            signed = True
        command_offset += command_size
    architecture = {
        7: "x86",
        0x01000007: "x86-64",
        12: "ARM",
        0x0100000C: "ARM64",
        18: "PowerPC",
        0x01000012: "PowerPC64",
    }.get(cpu_type, f"cpu-0x{cpu_type:x}")
    return NativeBinaryInspection(
        path=path,
        format="Mach-O",
        architecture=architecture,
        imports=sorted({item for item in imports if item}),
        signature_present=signed,
        signature_status=(
            "code-signature-load-command-present"
            if signed
            else "no-code-signature-load-command"
        ),
    )


def _finding(
    code: str,
    category: str,
    severity: str,
    confidence: str,
    score: int,
    message: str,
    *,
    evidence: Sequence[str] = (),
    location: str | None = None,
    artifact: str | None = None,
) -> HeuristicFinding:
    metadata = RULE_METADATA.get(
        code,
        HeuristicRuleMetadata(
            false_positive_rate=0.25,
            confidence=confidence,
            rule_version="1.0",
        ),
    )
    return HeuristicFinding(
        code=code,
        category=category,
        severity=severity,
        confidence=metadata.confidence,
        score=score,
        message=message,
        evidence=list(evidence),
        location=location,
        artifact=artifact,
        rule_version=metadata.rule_version,
        false_positive_rate=metadata.false_positive_rate,
        score_threshold=metadata.score_threshold,
    )


def finding_for_artifact(
    finding: HeuristicFinding,
    artifact: str,
) -> HeuristicFinding:
    return replace(finding, artifact=artifact)


def _deduplicate_findings(
    findings: Sequence[HeuristicFinding],
) -> list[HeuristicFinding]:
    deduplicated: dict[tuple[str, str | None, str | None], HeuristicFinding] = {}
    for finding in findings:
        key = (finding.code, finding.location, finding.artifact)
        existing = deduplicated.get(key)
        if existing is None or finding.score > existing.score:
            deduplicated[key] = finding
    return list(deduplicated.values())


def _score_level(
    score: int,
    *,
    thresholds: Mapping[str, int] | None = None,
) -> str:
    resolved = normalize_score_thresholds(thresholds)
    if score >= resolved["critical"]:
        return "critical"
    if score >= resolved["high"]:
        return "high"
    if score >= resolved["elevated"]:
        return "elevated"
    if score >= resolved["low"]:
        return "low"
    return "none"


def _matches_call(name: str, candidates: set[str]) -> bool:
    return name in candidates or any(name.startswith(f"{candidate}.") for candidate in candidates)


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return (
            node.value.decode("utf-8", errors="replace")
            if isinstance(node.value, bytes)
            else node.value
        )
    return None


def _call_text_arguments(node: ast.Call) -> list[str]:
    values = [
        value
        for argument in node.args
        for value in [_constant_text(argument)]
        if value is not None
    ]
    values.extend(
        value
        for keyword in node.keywords
        for value in [_constant_text(keyword.value)]
        if value is not None
    )
    return values


def _damerau_levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    matrix = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for index in range(len(left) + 1):
        matrix[index][0] = index
    for index in range(len(right) + 1):
        matrix[0][index] = index
    for left_index in range(1, len(left) + 1):
        for right_index in range(1, len(right) + 1):
            substitution = 0 if left[left_index - 1] == right[right_index - 1] else 1
            matrix[left_index][right_index] = min(
                matrix[left_index - 1][right_index] + 1,
                matrix[left_index][right_index - 1] + 1,
                matrix[left_index - 1][right_index - 1] + substitution,
            )
            if (
                left_index > 1
                and right_index > 1
                and left[left_index - 1] == right[right_index - 2]
                and left[left_index - 2] == right[right_index - 1]
            ):
                matrix[left_index][right_index] = min(
                    matrix[left_index][right_index],
                    matrix[left_index - 2][right_index - 2] + substitution,
                )
    return matrix[-1][-1]


def _name_relation(candidate: str, trusted: str) -> str:
    if candidate.replace("-", "") == trusted.replace("-", ""):
        return "separator substitution"
    if len(candidate) == len(trusted):
        difference = [
            index
            for index, (left, right) in enumerate(zip(candidate, trusted))
            if left != right
        ]
        if len(difference) == 2 and difference[1] == difference[0] + 1:
            return "adjacent transposition or substitution"
    if len(candidate) != len(trusted):
        return "character insertion or deletion"
    return "character substitution"


def _maintainer_identities(info: Mapping[str, object]) -> set[str]:
    identities: set[str] = set()
    for key in ("author", "author_email", "maintainer", "maintainer_email"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            identities.add(value.strip().casefold())
    return identities


def _ownership_identities(ownership: Mapping[str, object]) -> set[str]:
    identities: set[str] = set()

    def collect(value: object) -> None:
        if isinstance(value, str) and value.strip():
            identities.add(value.strip().casefold())
        elif isinstance(value, Mapping):
            for key, nested in value.items():
                if str(key).lower() in {
                    "organization",
                    "owner",
                    "user",
                    "username",
                }:
                    collect(nested)
                elif isinstance(nested, (Mapping, list, tuple)):
                    collect(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                collect(nested)

    collect(ownership)
    return identities


def _repository_urls(info: Mapping[str, object]) -> list[str]:
    raw_urls = info.get("project_urls")
    if not isinstance(raw_urls, Mapping):
        return []
    return [
        value
        for key, value in raw_urls.items()
        if isinstance(value, str)
        and any(
            token in str(key).lower()
            for token in ("code", "github", "homepage", "repository", "source")
        )
    ]


def _normalize_repository(value: str) -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value.strip().casefold().rstrip("/")
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return f"{parsed.netloc.casefold()}{path.casefold()}"


def _upload_time(item: Mapping[str, object]) -> datetime | None:
    value = item.get("upload_time_iso_8601") or item.get("upload_time")
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _shannon_entropy(payload: bytes) -> float | None:
    if not payload:
        return None
    counts = [0] * 256
    for value in payload:
        counts[value] += 1
    length = len(payload)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def _embedded_payloads(payload: bytes) -> list[str]:
    signatures = {
        "ELF": b"\x7fELF",
        "Mach-O": b"\xcf\xfa\xed\xfe",
        "PE": b"MZ",
        "gzip": b"\x1f\x8b\x08",
        "zip": b"PK\x03\x04",
    }
    findings: list[str] = []
    for label, signature in signatures.items():
        start = 1 if payload.startswith(signature) else 0
        offset = payload.find(signature, start)
        if offset > 0:
            findings.append(f"{label} signature at byte offset {offset}")
    return findings


def _native_format(payload: bytes) -> str:
    if payload.startswith(b"MZ"):
        return "PE"
    if payload.startswith(b"\x7fELF"):
        return "ELF"
    if payload[:4] in {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }:
        return "Mach-O"
    return "unknown"


def _unpack(
    format_string: str,
    payload: bytes,
    offset: int,
    endian: str,
) -> tuple[int, ...]:
    size = struct.calcsize(endian + format_string)
    if offset < 0 or offset + size > len(payload):
        raise ValueError("binary structure extends beyond the file")
    return tuple(
        int(value)
        for value in struct.unpack_from(endian + format_string, payload, offset)
    )


def _cstring(payload: bytes, offset: int, *, limit: int = 4096) -> str:
    if offset < 0 or offset >= len(payload):
        raise ValueError("string offset is outside the file")
    end = payload.find(b"\0", offset, min(len(payload), offset + limit))
    if end < 0:
        end = min(len(payload), offset + limit)
    return payload[offset:end].decode("utf-8", errors="replace")


def _pe_rva_to_offset(
    rva: int,
    sections: Sequence[tuple[int, int, int, int]],
) -> int:
    for virtual_address, virtual_size, raw_offset, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_offset + (rva - virtual_address)
    raise ValueError(f"PE RVA 0x{rva:x} does not map to a section")
