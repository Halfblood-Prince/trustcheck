from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from packaging.utils import canonicalize_name

from .models import VulnerabilityRecord, VulnerabilitySuppression

ADVISORY_SNAPSHOT_SCHEMA = "urn:trustcheck:advisory-snapshot:2.0.0"
LEGACY_ADVISORY_SNAPSHOT_SCHEMA = "urn:trustcheck:advisory-snapshot:1.0.0"
DEFAULT_MAX_ADVISORY_AGE_HOURS = 168
Clock = Callable[[], datetime]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
_SIGSTORE_EXPORTS = {
    "Bundle": ("sigstore.models", "Bundle"),
    "SigstoreError": ("sigstore.errors", "Error"),
    "Verifier": ("sigstore.verify", "Verifier"),
    "policy": ("sigstore.verify", "policy"),
}


class AdvisorySnapshotError(ValueError):
    """Raised when an advisory snapshot is malformed or cannot be written."""


class AdvisorySnapshotStore:
    def __init__(
        self,
        *,
        inputs: Iterable[str | Path] = (),
        output: str | Path | None = None,
        source_urls: Iterable[str] = (),
        max_age: timedelta = timedelta(hours=DEFAULT_MAX_ADVISORY_AGE_HOURS),
        sigstore_identity: str | None = None,
        sigstore_issuer: str | None = None,
        allow_unsigned: bool = False,
        sign_output: bool = False,
        offline: bool = False,
        clock: Clock = lambda: datetime.now(timezone.utc),
        runner: CommandRunner = subprocess.run,
    ) -> None:
        if max_age <= timedelta(0):
            raise AdvisorySnapshotError("maximum advisory snapshot age must be positive")
        self.output = Path(output) if output is not None else None
        self.max_age = max_age
        self.sigstore_identity = sigstore_identity
        self.sigstore_issuer = sigstore_issuer
        self.allow_unsigned = allow_unsigned
        self.sign_output = sign_output
        self.offline = offline
        self._clock = clock
        self._runner = runner
        self._records: dict[str, list[VulnerabilityRecord]] = {}
        self._sources: list[str] = []
        self._source_urls = list(dict.fromkeys(url for url in source_urls if url))
        self._lock = threading.RLock()
        for path in inputs:
            self._load(Path(path))

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(self._sources)

    def get(
        self,
        project: str,
        version: str,
    ) -> list[VulnerabilityRecord] | None:
        key = _snapshot_key(project, version)
        with self._lock:
            records = self._records.get(key)
            if records is None:
                return None
            return [_copy_record(record) for record in records]

    def put(
        self,
        project: str,
        version: str,
        records: Iterable[VulnerabilityRecord],
    ) -> None:
        key = _snapshot_key(project, version)
        normalized = [_copy_record(record) for record in records]
        with self._lock:
            self._records[key] = normalized

    def write(self) -> Path | None:
        if self.output is None:
            return None
        if not self.sign_output and not self.allow_unsigned:
            raise AdvisorySnapshotError(
                "advisory snapshot output must be Sigstore-signed; enable signing "
                "or explicitly allow unsigned compatibility output"
            )
        with self._lock:
            generated_at = _utc(self._clock())
            records = {
                key: [asdict(record) for record in records]
                for key, records in sorted(self._records.items())
            }
            records_digest = _records_digest(records)
            payload = {
                "schema": ADVISORY_SNAPSHOT_SCHEMA,
                "generated_at": generated_at.isoformat(),
                "expires_at": (generated_at + self.max_age).isoformat(),
                "source_manifest": {
                    "sources": [
                        {"url": url}
                        for url in sorted(dict.fromkeys(self._source_urls))
                    ],
                    "records_sha256": records_digest,
                },
                "digests": {
                    "records_sha256": records_digest,
                },
                "records": records,
            }
            self.output.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(self.output, payload)
            if self.sign_output:
                _sign_snapshot(
                    self.output,
                    runner=self._runner,
                )
            return self.output

    def _load(self, path: Path) -> None:
        try:
            contents = path.read_bytes()
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AdvisorySnapshotError(
                f"unable to read advisory snapshot {path}: {exc}"
            ) from exc
        self._verify_signature(path, contents)
        try:
            payload = json.loads(contents)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AdvisorySnapshotError(
                f"unable to read advisory snapshot {path}: {exc}"
            ) from exc
        schema = payload.get("schema") if isinstance(payload, dict) else None
        legacy = schema == LEGACY_ADVISORY_SNAPSHOT_SCHEMA and self.allow_unsigned
        if schema != ADVISORY_SNAPSHOT_SCHEMA and not legacy:
            raise AdvisorySnapshotError(
                f"unsupported advisory snapshot schema in {path}"
            )
        if not legacy:
            generated_at = _snapshot_datetime(
                payload.get("generated_at"), path, "generated_at"
            )
            expires_at = _snapshot_datetime(
                payload.get("expires_at"), path, "expires_at"
            )
            now = _utc(self._clock())
            if generated_at > now + timedelta(minutes=5):
                raise AdvisorySnapshotError(
                    f"advisory snapshot generation time is in the future in {path}"
                )
            if expires_at <= generated_at or now > expires_at:
                raise AdvisorySnapshotError(f"advisory snapshot has expired: {path}")
            if now - generated_at > self.max_age:
                raise AdvisorySnapshotError(
                    f"advisory snapshot exceeds the configured maximum age: {path}"
                )
        raw_records = payload.get("records")
        if not isinstance(raw_records, dict):
            raise AdvisorySnapshotError(
                f"advisory snapshot records must be an object in {path}"
            )
        if not legacy:
            digests = payload.get("digests")
            expected_digest = (
                digests.get("records_sha256")
                if isinstance(digests, dict)
                else None
            )
            if (
                not isinstance(expected_digest, str)
                or expected_digest != _records_digest(raw_records)
            ):
                raise AdvisorySnapshotError(
                    f"advisory snapshot records SHA-256 digest mismatch in {path}"
                )
            source_manifest = payload.get("source_manifest")
            sources = (
                source_manifest.get("sources")
                if isinstance(source_manifest, dict)
                else None
            )
            manifest_digest = (
                source_manifest.get("records_sha256")
                if isinstance(source_manifest, dict)
                else None
            )
            if not isinstance(sources, list):
                raise AdvisorySnapshotError(
                    f"advisory snapshot sources must be an array in {path}"
                )
            if manifest_digest != expected_digest:
                raise AdvisorySnapshotError(
                    f"advisory snapshot source manifest digest mismatch in {path}"
                )
            for source in sources:
                url = source.get("url") if isinstance(source, dict) else None
                if not isinstance(url, str) or not url:
                    raise AdvisorySnapshotError(
                        f"invalid advisory snapshot source URL in {path}"
                    )
                if url not in self._source_urls:
                    self._source_urls.append(url)
        for key, items in raw_records.items():
            if not isinstance(key, str) or not isinstance(items, list):
                raise AdvisorySnapshotError(
                    f"invalid advisory snapshot record collection in {path}"
                )
            parsed = [_record_from_mapping(item, path=path) for item in items]
            existing = self._records.setdefault(key, [])
            _merge_snapshot_records(existing, parsed)
        self._sources.append(str(path.resolve()))

    def _verify_signature(self, path: Path, contents: bytes) -> None:
        bundle_path = _snapshot_bundle_path(path)
        if not bundle_path.is_file():
            if self.allow_unsigned:
                return
            raise AdvisorySnapshotError(
                f"Sigstore bundle not found for advisory snapshot: {bundle_path}"
            )
        if not self.sigstore_identity:
            raise AdvisorySnapshotError(
                "a trusted Sigstore certificate identity is required for advisory snapshots"
            )
        try:
            bundle_type = _sigstore_symbol("Bundle")
            verifier_type = _sigstore_symbol("Verifier")
            policy_module = _sigstore_symbol("policy")
            sigstore_error = _sigstore_symbol("SigstoreError")
            bundle = bundle_type.from_json(bundle_path.read_text(encoding="utf-8"))
            verifier = verifier_type.production(offline=self.offline)
            verifier.verify_artifact(
                contents,
                bundle,
                policy_module.Identity(
                    identity=self.sigstore_identity,
                    issuer=self.sigstore_issuer,
                ),
            )
        except (OSError, UnicodeError, ValueError, ImportError) as exc:
            raise AdvisorySnapshotError(
                f"advisory snapshot Sigstore verification failed for {path}: {exc}"
            ) from exc
        except sigstore_error as exc:
            raise AdvisorySnapshotError(
                f"advisory snapshot Sigstore verification failed for {path}: {exc}"
            ) from exc


def _snapshot_key(project: str, version: str) -> str:
    return f"{canonicalize_name(project)}=={version}"


def _record_from_mapping(value: object, *, path: Path) -> VulnerabilityRecord:
    if not isinstance(value, dict):
        raise AdvisorySnapshotError(
            f"advisory snapshot record must be an object in {path}"
        )
    data: dict[str, Any] = dict(value)
    suppression = data.get("suppression")
    try:
        if suppression is not None:
            if not isinstance(suppression, dict):
                raise AdvisorySnapshotError(
                    f"advisory snapshot suppression must be an object in {path}"
                )
            data["suppression"] = VulnerabilitySuppression(**suppression)
        return VulnerabilityRecord(**data)
    except (TypeError, AdvisorySnapshotError) as exc:
        if isinstance(exc, AdvisorySnapshotError):
            raise
        raise AdvisorySnapshotError(
            f"invalid advisory snapshot vulnerability in {path}: {exc}"
        ) from exc


def _copy_record(record: VulnerabilityRecord) -> VulnerabilityRecord:
    payload = asdict(record)
    suppression = payload.get("suppression")
    if suppression is not None:
        payload["suppression"] = VulnerabilitySuppression(**suppression)
    return VulnerabilityRecord(**payload)


def _merge_snapshot_records(
    existing: list[VulnerabilityRecord],
    incoming: Iterable[VulnerabilityRecord],
) -> None:
    identities = {
        (record.id.upper(), tuple(sorted(alias.upper() for alias in record.aliases)))
        for record in existing
    }
    for record in incoming:
        identity = (
            record.id.upper(),
            tuple(sorted(alias.upper() for alias in record.aliases)),
        )
        if identity not in identities:
            existing.append(record)
            identities.add(identity)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AdvisorySnapshotError("advisory snapshot timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _snapshot_datetime(value: object, path: Path, field: str) -> datetime:
    if not isinstance(value, str):
        raise AdvisorySnapshotError(
            f"advisory snapshot {field} must be an ISO-8601 timestamp in {path}"
        )
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, AdvisorySnapshotError) as exc:
        raise AdvisorySnapshotError(
            f"invalid advisory snapshot {field} in {path}"
        ) from exc


def _records_digest(records: dict[str, Any]) -> str:
    canonical = json.dumps(
        records,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _snapshot_bundle_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.sigstore.json")


def __getattr__(name: str) -> Any:
    if name not in _SIGSTORE_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _SIGSTORE_EXPORTS[name]
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value


def _sigstore_symbol(name: str) -> Any:
    try:
        return globals()[name]
    except KeyError:
        return __getattr__(name)


def _sign_snapshot(path: Path, *, runner: CommandRunner) -> Path:
    bundle_path = _snapshot_bundle_path(path)
    command = [
        sys.executable,
        "-m",
        "sigstore",
        "sign",
        "--bundle",
        str(bundle_path),
        "--overwrite",
        str(path),
    ]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
    except OSError as exc:
        raise AdvisorySnapshotError(
            f"unable to start Sigstore snapshot signing: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise AdvisorySnapshotError(
            "Sigstore advisory snapshot signing failed"
            + (f": {detail}" if detail else "")
        )
    if not bundle_path.is_file():
        raise AdvisorySnapshotError(
            f"Sigstore did not create the advisory snapshot bundle: {bundle_path}"
        )
    return bundle_path


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:  # pragma: no cover - best-effort cleanup after write failure
            pass
        raise
