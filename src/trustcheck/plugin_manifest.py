from __future__ import annotations

import base64
import configparser
import copy
import csv
import hashlib
import io
import json
import os
import tempfile
import time
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from .artifacts import (
    ENTRY_POINT_NAME_PATTERN,
    ENTRY_POINT_TARGET_PATTERN,
    MAX_ARCHIVE_MEMBERS,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    MAX_ARTIFACT_BYTES,
    MAX_COMPRESSION_RATIO,
    MIN_COMPRESSION_RATIO_BYTES,
)
from .plugins import (
    PLUGIN_API_VERSION,
    PLUGIN_EMPTY_CONFIGURATION_SCHEMA_SHA256,
    PLUGIN_GROUPS,
    PLUGIN_IPC_PROTOCOL_VERSION,
    PLUGIN_KIND_CAPABILITIES,
    PLUGIN_MANIFEST_NAME,
    PLUGIN_MANIFEST_SCHEMA,
    PLUGIN_SIGNED_STATEMENT_SCHEMA,
    PluginError,
    _canonical_json,
    _record_rows,
    _require_rsa_key_strength,
    _verified_manifest,
)


@dataclass(frozen=True, slots=True)
class PluginManifestSummary:
    path: Path
    name: str
    kind: str
    entry_point: str
    distribution: str
    distribution_version: str
    wheel_sha256: str
    record_sha256: str
    signer_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class _PluginEntryPoint:
    name: str
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class _WheelRecord:
    wheel_sha256: str
    record_sha256: str
    record_bytes: bytes


@dataclass(frozen=True, slots=True)
class _WheelProject:
    path: Path
    entries: Mapping[str, bytes]
    infos: Mapping[str, zipfile.ZipInfo]
    dist_info_dir: str
    record_path: str
    distribution: str
    distribution_version: str
    dependencies: list[str]
    plugin: _PluginEntryPoint


class _PathDistribution:
    def __init__(self, root: Path, dist_info_dir: str) -> None:
        self.root = root
        self.dist_info_dir = dist_info_dir
        metadata = Parser().parsestr(
            (root / dist_info_dir / "METADATA").read_text(encoding="utf-8")
        )
        self.metadata = metadata
        self.name = _required_metadata(metadata, "Name")
        self.version = _required_metadata(metadata, "Version")
        self._requires = sorted(
            item.strip()
            for item in metadata.get_all("Requires-Dist") or []
            if item.strip()
        )

    @property
    def files(self) -> tuple[str, ...]:
        record = self.root / self.dist_info_dir / "RECORD"
        try:
            rows = _record_rows(record.read_bytes(), record)
        except OSError as exc:
            raise PluginError(f"unable to read plugin RECORD {record}: {exc}") from exc
        return tuple(row[0] for row in rows)

    @property
    def requires(self) -> list[str]:
        return list(self._requires)

    def locate_file(self, name: str) -> Path:
        return self.root / name


@dataclass(frozen=True, slots=True)
class _DistributionEntryPoint:
    name: str
    value: str
    dist: _PathDistribution


def build_plugin_manifest_draft(
    wheel: str | Path,
    *,
    configuration_schema: str | Path | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return an unsigned v2 plugin manifest envelope draft for a wheel."""
    project = _read_plugin_wheel(Path(wheel))
    schema = _load_configuration_schema(configuration_schema)
    statement, _ = _build_statement(project, schema)
    envelope: dict[str, object] = {
        "schema": PLUGIN_MANIFEST_SCHEMA,
        "manifest": statement,
    }
    if schema is not None:
        envelope["configuration_schema"] = schema
    return envelope


def sign_plugin_wheel(
    wheel: str | Path,
    *,
    key: str | Path,
    output: str | Path | None = None,
    configuration_schema: str | Path | Mapping[str, object] | None = None,
) -> PluginManifestSummary:
    """Insert a signed v2 plugin manifest into *wheel* and revalidate it."""
    wheel_path = Path(wheel)
    output_path = Path(output) if output is not None else wheel_path
    _validate_signing_output_path(wheel_path, output_path)
    project = _read_plugin_wheel(wheel_path)
    schema = _load_configuration_schema(configuration_schema)
    statement, record = _build_statement(project, schema)
    private_key = _load_private_key(Path(key))
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signature = private_key.sign(
        _canonical_json(statement),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    envelope: dict[str, object] = {
        "schema": PLUGIN_MANIFEST_SCHEMA,
        "manifest": statement,
        "public_key": public_key_pem,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    if schema is not None:
        envelope["configuration_schema"] = schema
    _write_signed_wheel(project, envelope, record.record_bytes, output_path)
    summary = verify_plugin_manifest(output_path)
    if summary.signer_sha256 != fingerprint_public_key(public_key):
        raise PluginError("signed plugin manifest did not verify with the expected key")
    return summary


def verify_plugin_manifest(path: str | Path) -> PluginManifestSummary:
    """Verify a signed plugin manifest in a wheel or extracted distribution."""
    target = Path(path)
    if target.is_file() and target.suffix == ".whl":
        with tempfile.TemporaryDirectory(prefix="trustcheck-plugin-manifest-") as temp:
            root = Path(temp)
            _extract_wheel(target, root)
            return _verify_distribution_tree(root, target)
    if target.is_dir():
        return _verify_distribution_tree(target, target)
    raise PluginError(f"plugin manifest target {target} is not a wheel or directory")


def fingerprint_public_key_file(path: str | Path) -> str:
    try:
        public_key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise PluginError(f"unable to read plugin public key {path}: {exc}") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PluginError("plugin manifests require an RSA public key")
    return fingerprint_public_key(public_key)


def fingerprint_public_key(public_key: rsa.RSAPublicKey) -> str:
    _require_rsa_key_strength(public_key)
    return hashlib.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


def _read_plugin_wheel(path: Path) -> _WheelProject:
    if not path.is_file() or path.suffix != ".whl":
        raise PluginError(f"plugin manifest signing requires a wheel file: {path}")
    _parse_wheel_basename(path.name, "input")
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise PluginError(
                f"plugin wheel exceeds the {MAX_ARTIFACT_BYTES}-byte artifact limit"
            )
    except OSError as exc:
        raise PluginError(f"unable to read plugin wheel {path}: {exc}") from exc
    entries: dict[str, bytes] = {}
    infos: dict[str, zipfile.ZipInfo] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            _validate_wheel_members(path, archive.infolist())
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = _safe_wheel_path(info.filename)
                if name in entries:
                    raise PluginError(f"wheel {path} contains duplicate entry {name}")
                entries[name] = archive.read(info)
                infos[name] = _copy_zip_info(info, name)
    except zipfile.BadZipFile as exc:
        raise PluginError(f"plugin wheel {path} is not a valid zip archive") from exc

    metadata_paths = sorted(
        name for name in entries if name.endswith(".dist-info/METADATA")
    )
    if len(metadata_paths) != 1:
        raise PluginError("plugin wheel must contain exactly one METADATA file")
    dist_info_dir = metadata_paths[0].rsplit("/", 1)[0]
    record_path = f"{dist_info_dir}/RECORD"
    if record_path not in entries:
        raise PluginError("plugin wheel must contain a dist-info RECORD")
    _reject_existing_record_signatures(entries, dist_info_dir)

    metadata = Parser().parsestr(entries[metadata_paths[0]].decode("utf-8"))
    entry_points_path = f"{dist_info_dir}/entry_points.txt"
    plugin = _read_plugin_entry_point(entries.get(entry_points_path, b""))
    dependencies = sorted(
        item.strip()
        for item in metadata.get_all("Requires-Dist") or []
        if item.strip()
    )
    return _WheelProject(
        path=path,
        entries=entries,
        infos=infos,
        dist_info_dir=dist_info_dir,
        record_path=record_path,
        distribution=_required_metadata(metadata, "Name"),
        distribution_version=_required_metadata(metadata, "Version"),
        dependencies=dependencies,
        plugin=plugin,
    )


def _read_plugin_entry_point(payload: bytes) -> _PluginEntryPoint:
    if not payload:
        raise PluginError("plugin wheel does not declare Trustcheck entry points")
    parser = configparser.ConfigParser()
    parser.optionxform = str  # type: ignore[assignment]
    try:
        parser.read_string(payload.decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise PluginError("plugin wheel has invalid entry point metadata") from exc
    candidates: list[_PluginEntryPoint] = []
    for kind, group in PLUGIN_GROUPS.items():
        if not parser.has_section(group):
            continue
        for name, value in parser.items(group):
            normalized_value = value.strip()
            if (
                ENTRY_POINT_NAME_PATTERN.fullmatch(name) is None
                or ENTRY_POINT_TARGET_PATTERN.fullmatch(normalized_value) is None
            ):
                raise PluginError("plugin wheel has invalid Trustcheck entry point metadata")
            candidates.append(_PluginEntryPoint(name=name, kind=kind, value=normalized_value))
    script_sections = [
        section
        for section in ("console_scripts", "gui_scripts")
        if parser.has_section(section)
    ]
    if script_sections:
        raise PluginError(
            "plugin wheels with console_scripts or gui_scripts are not supported; "
            "remove "
            + ", ".join(script_sections)
            + " before signing"
        )
    if len(candidates) != 1:
        raise PluginError(
            "plugin wheel must declare exactly one Trustcheck plugin entry point"
        )
    return candidates[0]


def _build_statement(
    project: _WheelProject,
    configuration_schema: Mapping[str, object] | None,
) -> tuple[dict[str, object], _WheelRecord]:
    record = _build_record(project.entries, project.record_path)
    statement: dict[str, object] = {
        "schema": PLUGIN_SIGNED_STATEMENT_SCHEMA,
        "name": project.plugin.name,
        "kind": project.plugin.kind,
        "entry_point": project.plugin.value,
        "api_version": PLUGIN_API_VERSION,
        "distribution": project.distribution,
        "distribution_version": project.distribution_version,
        "wheel_sha256": record.wheel_sha256,
        "record_sha256": record.record_sha256,
        "configuration_schema_sha256": (
            hashlib.sha256(_canonical_json(configuration_schema)).hexdigest()
            if configuration_schema is not None
            else PLUGIN_EMPTY_CONFIGURATION_SCHEMA_SHA256
        ),
        "protocol_version": PLUGIN_IPC_PROTOCOL_VERSION,
        "capabilities": sorted(PLUGIN_KIND_CAPABILITIES[project.plugin.kind]),
        "dependencies": project.dependencies,
    }
    return statement, record


def _build_record(entries: Mapping[str, bytes], record_path: str) -> _WheelRecord:
    wheel_rows: list[tuple[str, str, str]] = []
    runtime_rows: list[tuple[str, str, str]] = []
    canonical_entries: list[str] = []
    installed_paths: set[str] = set()
    for name in sorted(entries):
        if name in {PLUGIN_MANIFEST_NAME, record_path}:
            continue
        payload = entries[name]
        digest = hashlib.sha256(payload).digest()
        digest_text = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )
        installed_name = _installed_wheel_path(name)
        if installed_name in {PLUGIN_MANIFEST_NAME, record_path}:
            raise PluginError(f"plugin wheel installs reserved path {installed_name}")
        if installed_name in installed_paths:
            raise PluginError(f"plugin wheel installs duplicate path {installed_name}")
        installed_paths.add(installed_name)
        wheel_rows.append((name, f"sha256={digest_text}", str(len(payload))))
        runtime_rows.append((installed_name, f"sha256={digest_text}", str(len(payload))))
        canonical_entries.append(f"{installed_name}\0{digest.hex()}\0{len(payload)}")
    wheel_rows.append((PLUGIN_MANIFEST_NAME, "", ""))
    wheel_rows.append((record_path, "", ""))
    runtime_record_bytes = _render_record(
        [*sorted(runtime_rows), (PLUGIN_MANIFEST_NAME, "", ""), (record_path, "", "")]
    )
    record_bytes = _render_record(wheel_rows)
    wheel_sha256 = hashlib.sha256(
        "\n".join(sorted(canonical_entries)).encode("utf-8")
    ).hexdigest()
    return _WheelRecord(
        wheel_sha256=wheel_sha256,
        record_sha256=hashlib.sha256(runtime_record_bytes).hexdigest(),
        record_bytes=record_bytes,
    )


def _write_signed_wheel(
    project: _WheelProject,
    envelope: Mapping[str, object],
    record_bytes: bytes,
    output: Path,
) -> None:
    manifest_bytes = (
        json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.resolve() == project.path.resolve():
        temporary = output.with_name(output.name + ".tmp")
        _write_wheel_archive(project, manifest_bytes, record_bytes, temporary)
        temporary.replace(output)
        return
    _write_wheel_archive(project, manifest_bytes, record_bytes, output)


def _write_wheel_archive(
    project: _WheelProject,
    manifest_bytes: bytes,
    record_bytes: bytes,
    output: Path,
) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(project.entries):
            if name in {PLUGIN_MANIFEST_NAME, project.record_path}:
                continue
            archive.writestr(project.infos[name], project.entries[name])
        archive.writestr(_new_zip_info(PLUGIN_MANIFEST_NAME), manifest_bytes)
        archive.writestr(_new_zip_info(project.record_path), record_bytes)


def _verify_distribution_tree(root: Path, display_path: Path) -> PluginManifestSummary:
    distribution_root = root.parent if root.name.endswith(".dist-info") else root
    dist_info_dir = _find_dist_info_dir(root)
    manifest_path = distribution_root / PLUGIN_MANIFEST_NAME
    try:
        envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PluginError(
            f"unable to read signed plugin manifest {manifest_path}: {exc}"
        ) from exc
    if not isinstance(envelope, dict):
        raise PluginError(f"plugin manifest {manifest_path} is invalid")
    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict):
        raise PluginError(f"plugin manifest {manifest_path} is incomplete")
    public_key_pem = envelope.get("public_key")
    if not isinstance(public_key_pem, str):
        raise PluginError(f"plugin manifest {manifest_path} is incomplete")
    signer = fingerprint_public_key_pem(public_key_pem)
    entry = _DistributionEntryPoint(
        name=cast(str, manifest.get("name")),
        value=cast(str, manifest.get("entry_point")),
        dist=_PathDistribution(distribution_root, dist_info_dir),
    )
    verified, _, verified_signer, wheel_sha256, record_sha256 = _verified_manifest(
        cast(Any, entry),
        kind=cast(str, manifest.get("kind")),
        trusted_signers=(signer,),
    )
    return PluginManifestSummary(
        path=display_path,
        name=str(verified["name"]),
        kind=str(verified["kind"]),
        entry_point=str(verified["entry_point"]),
        distribution=str(verified["distribution"]),
        distribution_version=str(verified["distribution_version"]),
        wheel_sha256=wheel_sha256,
        record_sha256=record_sha256,
        signer_sha256=verified_signer,
    )


def fingerprint_public_key_pem(public_key_pem: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PluginError(f"plugin manifest has invalid public key data: {exc}") from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PluginError("plugin manifests require an RSA public key")
    return fingerprint_public_key(public_key)


def _find_dist_info_dir(root: Path) -> str:
    if root.name.endswith(".dist-info"):
        return root.name
    candidates = sorted(
        path.name for path in root.iterdir() if path.name.endswith(".dist-info")
    )
    if len(candidates) != 1:
        raise PluginError(
            f"plugin distribution {root} must contain exactly one dist-info directory"
        )
    return candidates[0]


def _load_private_key(path: Path) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise PluginError(f"unable to read plugin private key {path}: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise PluginError("plugin manifests require an RSA private key")
    _require_rsa_key_strength(key)
    return key


def _load_configuration_schema(
    value: str | Path | Mapping[str, object] | None,
) -> Mapping[str, object] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PluginError(f"unable to read plugin configuration schema {value}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PluginError("plugin configuration schema must be a JSON object")
    return cast(Mapping[str, object], payload)


def _required_metadata(metadata: Any, name: str) -> str:
    value = metadata.get(name)
    if not isinstance(value, str) or not value:
        raise PluginError(f"plugin distribution metadata is missing {name}")
    return value


def _safe_wheel_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise PluginError(f"wheel contains unsafe path {value!r}")
    return path.as_posix()


def _extract_wheel(path: Path, root: Path) -> None:
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise PluginError(
                f"plugin wheel exceeds the {MAX_ARTIFACT_BYTES}-byte artifact limit"
            )
    except OSError as exc:
        raise PluginError(f"unable to read plugin wheel {path}: {exc}") from exc
    try:
        with zipfile.ZipFile(path) as archive:
            _validate_wheel_members(path, archive.infolist())
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = _safe_wheel_path(info.filename)
                destination_name = _installed_wheel_path(name)
                payload = archive.read(info)
                if name.endswith(".dist-info/RECORD"):
                    payload = _installed_record_payload(payload, Path(name))
                destination = root / destination_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
    except zipfile.BadZipFile as exc:
        raise PluginError(f"plugin wheel {path} is not a valid zip archive") from exc


def _validate_wheel_members(path: Path, infos: Sequence[zipfile.ZipInfo]) -> None:
    files = [info for info in infos if not info.is_dir()]
    if len(files) > MAX_ARCHIVE_MEMBERS:
        raise PluginError(
            f"plugin wheel contains {len(files)} members; limit is {MAX_ARCHIVE_MEMBERS}"
        )
    total = 0
    raw_names: set[str] = set()
    installed_names: set[str] = set()
    for info in files:
        name = _safe_wheel_path(info.filename)
        if name in raw_names:
            raise PluginError(f"wheel {path} contains duplicate entry {name}")
        raw_names.add(name)
        installed_name = _installed_wheel_path(name)
        if installed_name in installed_names:
            raise PluginError(f"wheel {path} installs duplicate path {installed_name}")
        installed_names.add(installed_name)
        total += info.file_size
        if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise PluginError(
                "plugin wheel expanded size exceeds the "
                f"{MAX_ARCHIVE_UNCOMPRESSED_BYTES}-byte limit"
            )
        if info.file_size >= MIN_COMPRESSION_RATIO_BYTES and info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise PluginError(
                    f"plugin wheel member {info.filename!r} compression ratio "
                    f"{ratio:.1f} exceeds limit {MAX_COMPRESSION_RATIO:g}"
                )
    if not files:
        raise PluginError(f"plugin wheel {path} contains no files")


def _validate_signing_output_path(input_path: Path, output_path: Path) -> None:
    if output_path.suffix != ".whl":
        raise PluginError(f"plugin manifest output must be a .whl file: {output_path}")
    input_parts = _parse_wheel_basename(input_path.name, "input")
    output_parts = _parse_wheel_basename(output_path.name, "output")
    if output_parts != input_parts or output_path.name != input_path.name:
        raise PluginError(
            "plugin manifest output wheel filename must match the input wheel "
            f"filename {input_path.name!r}; choose a different directory for "
            "separate signed output"
        )


def _parse_wheel_basename(filename: str, label: str) -> tuple[object, object, object, object]:
    try:
        return parse_wheel_filename(filename)
    except InvalidWheelFilename as exc:
        raise PluginError(
            f"plugin manifest {label} must use a valid wheel filename: {filename}"
        ) from exc


def _reject_existing_record_signatures(
    entries: Mapping[str, bytes],
    dist_info_dir: str,
) -> None:
    for name in (f"{dist_info_dir}/RECORD.jws", f"{dist_info_dir}/RECORD.p7s"):
        if name in entries:
            raise PluginError(
                f"plugin wheel contains existing RECORD signature {name}; "
                "rewriting RECORD would invalidate it"
            )


def _installed_wheel_path(name: str) -> str:
    parts = name.split("/")
    if not parts or not parts[0].endswith(".data"):
        return name
    if len(parts) < 3 or not parts[1]:
        raise PluginError(f"plugin wheel contains malformed .data member {name}")
    scheme = parts[1]
    if scheme in {"purelib", "platlib"}:
        installed = "/".join(parts[2:])
        if not installed:
            raise PluginError(f"plugin wheel contains malformed .data member {name}")
        return installed
    if scheme in {"scripts", "headers", "data"}:
        raise PluginError(
            f"plugin wheels with .data/{scheme} entries are not supported; "
            "those files install outside the verified distribution root"
        )
    raise PluginError(
        f"plugin wheel uses unsupported .data scheme {scheme!r}; "
        "only purelib and platlib are supported"
    )


def _installed_record_payload(record_bytes: bytes, record_path: Path) -> bytes:
    rows = [
        (_installed_wheel_path(_safe_wheel_path(relative_path)), hash_spec, size_text)
        for relative_path, hash_spec, size_text in _record_rows(record_bytes, record_path)
    ]
    return _render_record(rows)


def _copy_zip_info(info: zipfile.ZipInfo, filename: str) -> zipfile.ZipInfo:
    copied = copy.copy(info)
    copied.filename = filename
    return copied


def _new_zip_info(filename: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename, date_time=_zip_timestamp())
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _zip_timestamp() -> tuple[int, int, int, int, int, int]:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return (1980, 1, 1, 0, 0, 0)
    try:
        epoch = max(315532800, int(raw))
    except ValueError:
        epoch = 315532800
    timestamp = time.gmtime(epoch)
    return (
        timestamp.tm_year,
        timestamp.tm_mon,
        timestamp.tm_mday,
        timestamp.tm_hour,
        timestamp.tm_min,
        timestamp.tm_sec,
    )


def _render_record(rows: Sequence[tuple[str, str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")
