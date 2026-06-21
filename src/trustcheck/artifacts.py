from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import io
import math
import multiprocessing
import os
import re
import tarfile
import zipfile
from email.parser import BytesParser
from email.policy import default
from multiprocessing.connection import Connection
from pathlib import PurePosixPath
from typing import IO, Callable, Iterable, Sequence, TypeVar

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .malicious import (
    analyze_python_source,
    inspect_native_binary,
    native_binary_findings,
)
from .models import ArtifactInspection

MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_SAMPLE_BYTES = 256 * 1024
MAX_SOURCE_AST_BYTES = 512 * 1024
MAX_NATIVE_ANALYSIS_BYTES = 32 * 1024 * 1024
MAX_DEEP_INSPECTION_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200.0
MIN_COMPRESSION_RATIO_BYTES = 10 * 1024 * 1024
MAX_INSPECTION_SECONDS = 20.0
MAX_INSPECTION_CPU_SECONDS = 15
MAX_INSPECTION_MEMORY_BYTES = 512 * 1024 * 1024
OVERSIZED_FILE_BYTES = 20 * 1024 * 1024
NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
SCRIPT_SUFFIXES = (".sh", ".bash", ".bat", ".cmd", ".ps1")
UNUSUAL_SUFFIXES = (
    ".class",
    ".db",
    ".jar",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
)
SAFE_ROOT_FILE_SUFFIXES = (".py", ".pyi", *NATIVE_SUFFIXES)
SUSPICIOUS_SCRIPT_PATTERNS = {
    "network download": re.compile(
        r"\b(curl|wget|invoke-webrequest|urlopen|requests\.(get|post))\b",
        re.IGNORECASE,
    ),
    "process execution": re.compile(
        r"\b(os\.system|subprocess\.|powershell|cmd\.exe|/bin/sh)\b",
        re.IGNORECASE,
    ),
    "dynamic execution": re.compile(
        r"\b(eval|exec)\s*\(",
        re.IGNORECASE,
    ),
}
ENTRY_POINT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ENTRY_POINT_TARGET_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r":[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"(?:\s*\[[^\]]+\])?$"
)
DANGEROUS_ENTRY_POINT_TARGETS = {
    "builtins:eval",
    "builtins:exec",
    "os:popen",
    "os:system",
    "subprocess:call",
    "subprocess:check_call",
    "subprocess:check_output",
    "subprocess:run",
}
MemberT = TypeVar("MemberT")


class ArtifactLimitError(ValueError):
    """Raised when an artifact exceeds a static-inspection safety bound."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def inspect_artifact(
    filename: str,
    payload: bytes,
    *,
    expected_project: str,
    expected_version: str,
    expected_requires_dist: Iterable[str] | None = None,
) -> ArtifactInspection:
    if len(payload) > MAX_ARTIFACT_BYTES:
        return _limit_failure(
            filename,
            f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte download limit",
        )
    if filename.endswith(".whl"):
        result = _inspect_wheel(payload)
    elif filename.endswith((".tar.gz", ".tgz", ".zip")):
        result = _inspect_sdist(filename, payload)
    else:
        return ArtifactInspection(
            inspected=True,
            kind="unsupported",
            archive_valid=None,
            error="artifact format is not supported for static inspection",
        )

    _compare_expected_metadata(
        result,
        expected_project=expected_project,
        expected_version=expected_version,
        expected_requires_dist=expected_requires_dist,
    )
    return result


def inspect_artifact_isolated(
    filename: str,
    payload: bytes,
    *,
    expected_project: str,
    expected_version: str,
    expected_requires_dist: Iterable[str] | None = None,
    timeout: float = MAX_INSPECTION_SECONDS,
) -> ArtifactInspection:
    """Inspect an artifact in a resource-bounded spawned process."""
    if len(payload) > MAX_ARTIFACT_BYTES:
        return _limit_failure(
            filename,
            f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte download limit",
        )
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_inspection_worker,
        args=(
            sender,
            filename,
            payload,
            expected_project,
            expected_version,
            tuple(expected_requires_dist or ()),
        ),
        name="trustcheck-artifact-inspection",
        daemon=True,
    )
    try:
        process.start()
        sender.close()
        if not receiver.poll(timeout):
            process.terminate()
            process.join(timeout=1.0)
            return _limit_failure(
                filename,
                f"artifact inspection exceeded the {timeout:g}-second time limit",
            )
        try:
            result = receiver.recv()
        except EOFError:
            result = _limit_failure(
                filename,
                "artifact inspection worker exited without a result",
            )
        process.join(timeout=1.0)
        if not isinstance(result, ArtifactInspection):
            return _limit_failure(filename, "artifact inspection worker returned invalid data")
        return result
    except (OSError, RuntimeError) as exc:
        return _limit_failure(filename, f"unable to isolate artifact inspection: {exc}")
    finally:
        receiver.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)


def _inspection_worker(
    sender: Connection,
    filename: str,
    payload: bytes,
    expected_project: str,
    expected_version: str,
    expected_requires_dist: tuple[str, ...],
) -> None:  # pragma: no cover - exercised in the spawned integration test
    try:
        _apply_worker_limits()
        result = inspect_artifact(
            filename,
            payload,
            expected_project=expected_project,
            expected_version=expected_version,
            expected_requires_dist=expected_requires_dist,
        )
        sender.send(result)
    except BaseException as exc:
        sender.send(
            _limit_failure(filename, f"artifact inspection worker failed: {exc}")
        )
    finally:
        sender.close()


def _apply_worker_limits() -> None:  # pragma: no cover - OS-specific child bootstrap
    try:
        import resource
    except ImportError:
        return
    cpu_limit = max(1, math.ceil(MAX_INSPECTION_CPU_SECONDS))
    setrlimit = getattr(resource, "setrlimit", None)
    getrlimit = getattr(resource, "getrlimit", None)
    rlimit_cpu = getattr(resource, "RLIMIT_CPU", None)
    if setrlimit is None or getrlimit is None or rlimit_cpu is None:
        return
    infinity = getattr(resource, "RLIM_INFINITY", -1)

    def set_soft_limit(kind: int, requested: int) -> None:
        try:
            _, hard_limit = getrlimit(kind)
            effective = requested if hard_limit == infinity else min(requested, hard_limit)
            setrlimit(kind, (effective, effective))
        except (OSError, ValueError):
            return

    set_soft_limit(rlimit_cpu, cpu_limit)
    rlimit_as = getattr(resource, "RLIMIT_AS", None)
    if rlimit_as is not None:
        set_soft_limit(rlimit_as, MAX_INSPECTION_MEMORY_BYTES)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        import pwd

        nobody = getattr(pwd, "getpwnam")("nobody")
        getattr(os, "setgroups")([])
        getattr(os, "setgid")(nobody.pw_gid)
        getattr(os, "setuid")(nobody.pw_uid)


def _limit_failure(filename: str, message: str) -> ArtifactInspection:
    kind = "wheel" if filename.endswith(".whl") else "sdist"
    return ArtifactInspection(
        inspected=True,
        kind=kind,
        archive_valid=False,
        record_valid=False if kind == "wheel" else None,
        error=message,
    )


def compare_artifact_metadata(inspections: Iterable[ArtifactInspection]) -> None:
    comparable = [
        item
        for item in inspections
        if item.inspected and item.metadata_name and item.metadata_version
    ]
    wheels = [item for item in comparable if item.kind == "wheel"]
    sdists = [item for item in comparable if item.kind == "sdist"]
    if not wheels or not sdists:
        return

    for wheel in wheels:
        for sdist in sdists:
            differences: list[str] = []
            if canonicalize_name(wheel.metadata_name or "") != canonicalize_name(
                sdist.metadata_name or ""
            ):
                differences.append(
                    "wheel and sdist metadata names differ: "
                    f"{wheel.metadata_name!r} != {sdist.metadata_name!r}"
                )
            if wheel.metadata_version != sdist.metadata_version:
                differences.append(
                    "wheel and sdist metadata versions differ: "
                    f"{wheel.metadata_version!r} != {sdist.metadata_version!r}"
                )
            wheel_dependencies = _canonical_requirements(wheel.metadata_requires_dist)
            sdist_dependencies = _canonical_requirements(sdist.metadata_requires_dist)
            if wheel_dependencies != sdist_dependencies:
                differences.append("wheel and sdist Requires-Dist metadata differ")
            for difference in differences:
                if difference not in wheel.metadata_mismatches:
                    wheel.metadata_mismatches.append(difference)
                if difference not in sdist.metadata_mismatches:
                    sdist.metadata_mismatches.append(difference)


def _inspect_wheel(payload: bytes) -> ArtifactInspection:
    result = ArtifactInspection(inspected=True, kind="wheel")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            _validate_zip_limits(members, len(payload))
            result.archive_valid = True
            result.file_count = sum(1 for member in members if not member.is_dir())
            result.total_uncompressed_size = sum(
                member.file_size for member in members if not member.is_dir()
            )
            _inspect_zip_structure(members, result)
            _inspect_wheel_record(archive, members, result)
            _inspect_wheel_metadata(archive, members, result)
            _inspect_wheel_file_metadata(archive, members, result)
            _inspect_entry_points(archive, members, result)
            _inspect_wheel_contents(members, result)
            _inspect_zip_payloads(archive, members, result)
    except (
        NotImplementedError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        result.archive_valid = False
        result.record_valid = False
        result.error = f"invalid wheel archive: {exc}"
        result.record_errors.append(result.error)
    return result


def _inspect_sdist(filename: str, payload: bytes) -> ArtifactInspection:
    result = ArtifactInspection(inspected=True, kind="sdist")
    try:
        if filename.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                zip_members = archive.infolist()
                _validate_zip_limits(zip_members, len(payload))
                result.archive_valid = True
                result.file_count = sum(
                    1 for member in zip_members if not member.is_dir()
                )
                result.total_uncompressed_size = sum(
                    member.file_size
                    for member in zip_members
                    if not member.is_dir()
                )
                _inspect_zip_structure(zip_members, result)
                _inspect_sdist_zip(archive, zip_members, result)
        else:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                tar_members = _bounded_tar_members(archive, len(payload))
                result.archive_valid = True
                result.file_count = sum(
                    1 for member in tar_members if member.isfile()
                )
                result.total_uncompressed_size = sum(
                    member.size for member in tar_members if member.isfile()
                )
                _inspect_sdist_tar(archive, tar_members, result)
    except (
        NotImplementedError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        result.archive_valid = False
        result.error = f"invalid sdist archive: {exc}"
    return result


def _validate_zip_limits(
    members: Sequence[zipfile.ZipInfo],
    compressed_bytes: int,
) -> None:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ArtifactLimitError(
            f"archive contains {len(members)} members; limit is {MAX_ARCHIVE_MEMBERS}"
        )
    files = [member for member in members if not member.is_dir()]
    total = sum(member.file_size for member in files)
    if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        raise ArtifactLimitError(
            f"archive expands to {total} bytes; limit is "
            f"{MAX_ARCHIVE_UNCOMPRESSED_BYTES}"
        )
    for member in files:
        ratio = member.file_size / max(1, member.compress_size)
        if member.file_size >= MIN_COMPRESSION_RATIO_BYTES and ratio > MAX_COMPRESSION_RATIO:
            raise ArtifactLimitError(
                f"{member.filename} has compression ratio {ratio:.1f}; "
                f"limit is {MAX_COMPRESSION_RATIO:g}"
            )
    _validate_aggregate_ratio(total, compressed_bytes)


def _bounded_tar_members(
    archive: tarfile.TarFile,
    compressed_bytes: int,
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    total = 0
    for member in archive:
        members.append(member)
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ArtifactLimitError(
                f"archive contains more than {MAX_ARCHIVE_MEMBERS} members"
            )
        if member.isfile():
            if member.size < 0:
                raise ArtifactLimitError(f"{member.name} declares a negative size")
            total += member.size
            if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ArtifactLimitError(
                    f"archive expands beyond the "
                    f"{MAX_ARCHIVE_UNCOMPRESSED_BYTES}-byte limit"
                )
    _validate_aggregate_ratio(total, compressed_bytes)
    return members


def _validate_aggregate_ratio(uncompressed_bytes: int, compressed_bytes: int) -> None:
    ratio = uncompressed_bytes / max(1, compressed_bytes)
    if (
        uncompressed_bytes >= MIN_COMPRESSION_RATIO_BYTES
        and ratio > MAX_COMPRESSION_RATIO
    ):
        raise ArtifactLimitError(
            f"archive aggregate compression ratio is {ratio:.1f}; "
            f"limit is {MAX_COMPRESSION_RATIO:g}"
        )


def _inspect_wheel_record(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    files_by_name: dict[str, zipfile.ZipInfo] = {
        member.filename: member for member in members if not member.is_dir()
    }
    record_names = [
        name for name in files_by_name if name.endswith(".dist-info/RECORD")
    ]
    if len(record_names) != 1:
        result.record_valid = False
        result.record_errors.append(
            f"wheel must contain exactly one .dist-info/RECORD file; found {len(record_names)}"
        )
        return

    record_name = record_names[0]
    try:
        record_bytes = _read_zip_member(
            archive,
            files_by_name[record_name],
            limit=MAX_METADATA_BYTES,
        )
        rows = list(csv.reader(io.StringIO(record_bytes.decode("utf-8"))))
    except (csv.Error, UnicodeError, ValueError) as exc:
        result.record_valid = False
        result.record_errors.append(f"unable to parse {record_name}: {exc}")
        return

    listed_paths: set[str] = set()
    for row_number, row in enumerate(rows, start=1):
        if len(row) != 3:
            result.record_errors.append(
                f"{record_name} row {row_number} must contain path, hash, and size"
            )
            continue
        path, hash_value, size_value = row
        if not path or path in listed_paths:
            result.record_errors.append(
                f"{record_name} row {row_number} has an empty or duplicate path"
            )
            continue
        listed_paths.add(path)
        member = files_by_name.get(path)
        if member is None:
            result.record_errors.append(f"{path} is listed in RECORD but missing from the wheel")
            continue
        if path == record_name:
            continue
        if not hash_value or not size_value:
            result.record_errors.append(f"{path} is missing a required RECORD hash or size")
            continue
        try:
            algorithm, encoded_digest = hash_value.split("=", maxsplit=1)
        except ValueError:
            result.record_errors.append(f"{path} has a malformed RECORD hash")
            continue
        algorithm = algorithm.lower()
        try:
            digest = hashlib.new(algorithm)
        except (TypeError, ValueError):
            result.record_errors.append(
                f"{path} uses insecure or unsupported RECORD hash algorithm {algorithm!r}"
            )
            continue
        if digest.digest_size < 32 or algorithm.startswith("shake_"):
            result.record_errors.append(
                f"{path} uses RECORD hash algorithm {algorithm!r}, which is weaker "
                "than sha256 or has variable output"
            )
            continue
        try:
            expected_size = int(size_value)
        except ValueError:
            result.record_errors.append(f"{path} has a non-integer RECORD size")
            continue
        if expected_size != member.file_size:
            result.record_errors.append(
                f"{path} size mismatch: RECORD={expected_size} archive={member.file_size}"
            )
        observed_digest = _hash_zip_member(archive, member, algorithm)
        if observed_digest != encoded_digest.rstrip("="):
            result.record_errors.append(f"{path} hash does not match RECORD")

    signature_files = {
        f"{record_name}.jws",
        f"{record_name}.p7s",
    }
    missing_from_record = sorted(
        set(files_by_name) - listed_paths - signature_files
    )
    result.record_errors.extend(
        f"{path} is present in the wheel but missing from RECORD"
        for path in missing_from_record
    )
    result.record_valid = not result.record_errors


def _inspect_wheel_metadata(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    metadata_members = [
        member
        for member in members
        if not member.is_dir() and member.filename.endswith(".dist-info/METADATA")
    ]
    if len(metadata_members) != 1:
        result.metadata_mismatches.append(
            "wheel must contain exactly one .dist-info/METADATA file"
        )
        return
    _populate_metadata(
        _read_zip_member(archive, metadata_members[0], limit=MAX_METADATA_BYTES),
        result,
    )


def _inspect_wheel_file_metadata(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    wheel_members = [
        member
        for member in members
        if not member.is_dir() and member.filename.endswith(".dist-info/WHEEL")
    ]
    if len(wheel_members) != 1:
        result.metadata_mismatches.append(
            "wheel must contain exactly one .dist-info/WHEEL metadata file"
        )
        return
    payload = _read_zip_member(
        archive,
        wheel_members[0],
        limit=MAX_METADATA_BYTES,
    )
    message = BytesParser(policy=default).parsebytes(payload)
    result.wheel_version = message.get("Wheel-Version")
    root_is_purelib = message.get("Root-Is-Purelib")
    if isinstance(root_is_purelib, str):
        normalized = root_is_purelib.strip().lower()
        if normalized in {"true", "false"}:
            result.wheel_root_is_purelib = normalized == "true"
        else:
            result.metadata_mismatches.append(
                f"wheel Root-Is-Purelib has invalid value {root_is_purelib!r}"
            )
    else:
        result.metadata_mismatches.append("wheel metadata does not declare Root-Is-Purelib")
    result.wheel_tags = list(message.get_all("Tag", []))
    if not result.wheel_version:
        result.metadata_mismatches.append("wheel metadata does not declare Wheel-Version")
    if not result.wheel_tags:
        result.metadata_mismatches.append("wheel metadata does not declare any compatibility Tag")


def _inspect_entry_points(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    entry_point_members = [
        member
        for member in members
        if not member.is_dir() and member.filename.endswith(".dist-info/entry_points.txt")
    ]
    for member in entry_point_members:
        try:
            payload = _read_zip_member(archive, member, limit=MAX_METADATA_BYTES)
            _parse_entry_points(payload, result)
        except (configparser.Error, UnicodeError, ValueError) as exc:
            result.suspicious_entry_points.append(
                f"{member.filename}: unable to parse entry points: {exc}"
            )


def _inspect_wheel_contents(
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    for member in members:
        if member.is_dir():
            continue
        name = member.filename
        lowered = name.lower()
        if lowered.endswith(NATIVE_SUFFIXES):
            result.native_files.append(name)
        if member.file_size > OVERSIZED_FILE_BYTES:
            result.oversized_files.append(name)
        if _is_unsafe_archive_path(name):
            result.unusual_files.append(f"{name} (unsafe archive path)")
        if "/" not in name.rstrip("/"):
            if name == "py.typed" or lowered.endswith(SAFE_ROOT_FILE_SUFFIXES):
                continue
            result.unexpected_top_level_files.append(name)
            if lowered.endswith((".pth", *SCRIPT_SUFFIXES, ".exe")):
                result.suspicious_files.append(name)
    if result.native_files and result.wheel_root_is_purelib is True:
        result.metadata_mismatches.append(
            "wheel contains native extensions but Root-Is-Purelib is true"
        )


def _inspect_sdist_zip(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    files = [member for member in members if not member.is_dir()]
    metadata = _select_metadata_member(files, lambda member: member.filename)
    if metadata is not None:
        _populate_metadata(
            _read_zip_member(archive, metadata, limit=MAX_METADATA_BYTES),
            result,
        )
    for member in files:
        name = member.filename
        _record_sdist_file_findings(name, member.file_size, result)
        if _is_script_candidate(name):
            sample = _read_zip_member(archive, member, limit=MAX_SCRIPT_SAMPLE_BYTES)
            _inspect_script_sample(name, sample, result)
    _inspect_zip_payloads(archive, files, result)


def _inspect_sdist_tar(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    result: ArtifactInspection,
) -> None:
    files = [member for member in members if member.isfile()]
    metadata = _select_metadata_member(files, lambda member: member.name)
    if metadata is not None:
        _populate_metadata(
            _read_tar_member(archive, metadata, limit=MAX_METADATA_BYTES),
            result,
        )
    for member in members:
        name = member.name
        if member.issym() or member.islnk() or member.isdev():
            result.unusual_files.append(f"{name} (special archive member)")
        if not member.isfile():
            continue
        _record_sdist_file_findings(name, member.size, result)
        if _is_script_candidate(name) or member.mode & 0o111:
            sample = _read_tar_member(archive, member, limit=MAX_SCRIPT_SAMPLE_BYTES)
            _inspect_script_sample(name, sample, result)
    _inspect_tar_payloads(archive, files, result)


def _inspect_zip_payloads(
    archive: zipfile.ZipFile,
    members: Sequence[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    remaining = MAX_DEEP_INSPECTION_BYTES
    for member in members:
        if member.is_dir() or member.flag_bits & 0x1:
            continue
        name = member.filename
        lowered = name.lower()
        if lowered.endswith(".py"):
            if member.file_size > MAX_SOURCE_AST_BYTES:
                result.source_parse_errors.append(
                    f"{name}: source exceeds the {MAX_SOURCE_AST_BYTES}-byte AST limit"
                )
                continue
            if member.file_size > remaining:
                result.source_parse_errors.append(
                    f"{name}: deep-inspection byte budget exhausted"
                )
                continue
            payload = _read_zip_member(archive, member, limit=MAX_SOURCE_AST_BYTES)
            remaining -= len(payload)
            _record_python_findings(name, payload, result)
        elif lowered.endswith(NATIVE_SUFFIXES):
            if member.file_size > MAX_NATIVE_ANALYSIS_BYTES:
                result.source_parse_errors.append(
                    f"{name}: native binary exceeds the "
                    f"{MAX_NATIVE_ANALYSIS_BYTES}-byte analysis limit"
                )
                continue
            if member.file_size > remaining:
                result.source_parse_errors.append(
                    f"{name}: deep-inspection byte budget exhausted"
                )
                continue
            payload = _read_zip_member(
                archive,
                member,
                limit=MAX_NATIVE_ANALYSIS_BYTES,
            )
            remaining -= len(payload)
            _record_native_findings(name, payload, result)


def _inspect_tar_payloads(
    archive: tarfile.TarFile,
    members: Sequence[tarfile.TarInfo],
    result: ArtifactInspection,
) -> None:
    remaining = MAX_DEEP_INSPECTION_BYTES
    for member in members:
        if not member.isfile():
            continue
        name = member.name
        lowered = name.lower()
        if lowered.endswith(".py"):
            if member.size > MAX_SOURCE_AST_BYTES:
                result.source_parse_errors.append(
                    f"{name}: source exceeds the {MAX_SOURCE_AST_BYTES}-byte AST limit"
                )
                continue
            if member.size > remaining:
                result.source_parse_errors.append(
                    f"{name}: deep-inspection byte budget exhausted"
                )
                continue
            payload = _read_tar_member(archive, member, limit=MAX_SOURCE_AST_BYTES)
            remaining -= len(payload)
            _record_python_findings(name, payload, result)
        elif lowered.endswith(NATIVE_SUFFIXES):
            if member.size > MAX_NATIVE_ANALYSIS_BYTES:
                result.source_parse_errors.append(
                    f"{name}: native binary exceeds the "
                    f"{MAX_NATIVE_ANALYSIS_BYTES}-byte analysis limit"
                )
                continue
            if member.size > remaining:
                result.source_parse_errors.append(
                    f"{name}: deep-inspection byte budget exhausted"
                )
                continue
            payload = _read_tar_member(
                archive,
                member,
                limit=MAX_NATIVE_ANALYSIS_BYTES,
            )
            remaining -= len(payload)
            _record_native_findings(name, payload, result)


def _record_python_findings(
    name: str,
    payload: bytes,
    result: ArtifactInspection,
) -> None:
    findings, error = analyze_python_source(
        name,
        payload,
        install_context=_is_install_context(name),
    )
    if error is not None:
        result.source_parse_errors.append(error)
        return
    result.source_files_analyzed += 1
    result.heuristic_findings.extend(findings)


def _record_native_findings(
    name: str,
    payload: bytes,
    result: ArtifactInspection,
) -> None:
    inspection = inspect_native_binary(name, payload)
    result.native_binaries.append(inspection)
    result.heuristic_findings.extend(native_binary_findings(inspection))


def _inspect_zip_structure(
    members: list[zipfile.ZipInfo],
    result: ArtifactInspection,
) -> None:
    seen: set[str] = set()
    for member in members:
        if member.filename in seen:
            result.unusual_files.append(f"{member.filename} (duplicate archive member)")
            if result.kind == "wheel":
                result.record_errors.append(
                    f"{member.filename} appears more than once in the wheel"
                )
        seen.add(member.filename)
        if member.flag_bits & 0x1:
            result.unusual_files.append(f"{member.filename} (encrypted archive member)")
            if result.kind == "wheel":
                result.record_errors.append(
                    f"{member.filename} is encrypted and cannot be validated safely"
                )
        if _is_unsafe_archive_path(member.filename) and result.kind == "wheel":
            result.record_errors.append(
                f"{member.filename} uses an unsafe archive path"
            )


def _record_sdist_file_findings(
    name: str,
    size: int,
    result: ArtifactInspection,
) -> None:
    lowered = name.lower()
    if _is_unsafe_archive_path(name):
        result.unusual_files.append(f"{name} (unsafe archive path)")
    if size > OVERSIZED_FILE_BYTES:
        result.oversized_files.append(name)
    if lowered.endswith(UNUSUAL_SUFFIXES) or _has_nested_archive_suffix(lowered):
        result.unusual_files.append(name)
    if lowered.endswith(NATIVE_SUFFIXES):
        result.native_files.append(name)


def _inspect_script_sample(
    name: str,
    payload: bytes,
    result: ArtifactInspection,
) -> None:
    lowered = name.lower()
    if lowered.endswith(SCRIPT_SUFFIXES):
        result.suspicious_files.append(f"{name} (executable script)")
    text = payload.decode("utf-8", errors="replace")
    for label, pattern in SUSPICIOUS_SCRIPT_PATTERNS.items():
        if pattern.search(text):
            finding = f"{name} ({label})"
            if finding not in result.suspicious_files:
                result.suspicious_files.append(finding)


def _parse_entry_points(payload: bytes, result: ArtifactInspection) -> None:
    parser = _CaseSensitiveConfigParser(interpolation=None, strict=False)
    parser.read_string(payload.decode("utf-8"))
    if not parser.has_section("console_scripts"):
        return
    for name, target in parser.items("console_scripts"):
        display = f"{name} = {target}"
        result.console_scripts.append(display)
        normalized_target = target.split("[", maxsplit=1)[0].strip()
        if (
            not ENTRY_POINT_NAME_PATTERN.fullmatch(name)
            or not ENTRY_POINT_TARGET_PATTERN.fullmatch(target.strip())
            or normalized_target in DANGEROUS_ENTRY_POINT_TARGETS
        ):
            result.suspicious_entry_points.append(display)


def _populate_metadata(payload: bytes, result: ArtifactInspection) -> None:
    message = BytesParser(policy=default).parsebytes(payload)
    result.metadata_name = message.get("Name")
    result.metadata_version = message.get("Version")
    result.metadata_requires_dist = list(message.get_all("Requires-Dist", []))


def _compare_expected_metadata(
    result: ArtifactInspection,
    *,
    expected_project: str,
    expected_version: str,
    expected_requires_dist: Iterable[str] | None,
) -> None:
    if result.metadata_name is None:
        result.metadata_mismatches.append("artifact package metadata does not declare Name")
    elif canonicalize_name(result.metadata_name) != canonicalize_name(expected_project):
        result.metadata_mismatches.append(
            f"artifact metadata Name {result.metadata_name!r} does not match "
            f"project {expected_project!r}"
        )
    if result.metadata_version is None:
        result.metadata_mismatches.append("artifact package metadata does not declare Version")
    elif result.metadata_version != expected_version:
        result.metadata_mismatches.append(
            f"artifact metadata Version {result.metadata_version!r} does not match "
            f"release {expected_version!r}"
        )
    if expected_requires_dist is not None:
        expected_dependencies = _canonical_requirements(list(expected_requires_dist))
        artifact_dependencies = _canonical_requirements(result.metadata_requires_dist)
        if artifact_dependencies != expected_dependencies:
            result.metadata_mismatches.append(
                "artifact Requires-Dist metadata does not match selected release metadata"
            )


def _canonical_requirements(requirements: list[str]) -> list[str]:
    normalized: list[str] = []
    for requirement_text in requirements:
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            normalized.append(requirement_text.strip())
            continue
        extras = (
            f"[{','.join(sorted(canonicalize_name(extra) for extra in requirement.extras))}]"
            if requirement.extras
            else ""
        )
        url = f" @ {requirement.url}" if requirement.url else ""
        marker = f"; {requirement.marker}" if requirement.marker else ""
        normalized.append(
            f"{canonicalize_name(requirement.name)}{extras}{url}"
            f"{requirement.specifier}{marker}"
        )
    return sorted(normalized)


def _select_metadata_member(
    members: Sequence[MemberT],
    name_for: Callable[[MemberT], str],
) -> MemberT | None:
    candidates = [
        member
        for member in members
        if name_for(member).endswith(("/PKG-INFO", ".dist-info/METADATA"))
        or name_for(member) == "PKG-INFO"
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda member: (name_for(member).count("/"), name_for(member)))


def _read_zip_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    *,
    limit: int,
) -> bytes:
    if member.file_size > limit:
        raise ValueError(f"{member.filename} exceeds the {limit}-byte inspection limit")
    with archive.open(member) as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{member.filename} exceeds the {limit}-byte inspection limit")
    return payload


def _read_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    limit: int,
) -> bytes:
    if member.size > limit:
        raise ValueError(f"{member.name} exceeds the {limit}-byte inspection limit")
    stream = archive.extractfile(member)
    if stream is None:
        return b""
    with stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{member.name} exceeds the {limit}-byte inspection limit")
    return payload


def _hash_zip_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    algorithm: str,
) -> str:
    digest = hashlib.new(algorithm)
    with archive.open(member) as stream:
        _update_digest(stream, digest.update)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")


def _update_digest(stream: IO[bytes], update: Callable[[bytes], None]) -> None:
    while chunk := stream.read(1024 * 1024):
        update(chunk)


def _is_unsafe_archive_path(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or ".." in path.parts or "\\" in name


def _is_script_candidate(name: str) -> bool:
    lowered = name.lower()
    basename = lowered.rsplit("/", maxsplit=1)[-1]
    return lowered.endswith((*SCRIPT_SUFFIXES, ".py")) and (
        basename in {"setup.py", "install.py"}
        or "/scripts/" in f"/{lowered}"
        or lowered.endswith(SCRIPT_SUFFIXES)
    )


def _is_install_context(name: str) -> bool:
    lowered = name.lower().replace("\\", "/")
    basename = lowered.rsplit("/", maxsplit=1)[-1]
    return (
        basename in {"setup.py", "install.py"}
        or "/scripts/" in f"/{lowered}"
        or "/build_backend/" in f"/{lowered}"
    )


def _has_nested_archive_suffix(name: str) -> bool:
    return name.endswith((".tar", ".tar.gz", ".tgz", ".whl", ".zip"))
