from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from packaging.utils import canonicalize_name

from .models import VulnerabilityRecord, VulnerabilitySuppression

ADVISORY_SNAPSHOT_SCHEMA = "urn:trustcheck:advisory-snapshot:1.0.0"


class AdvisorySnapshotError(ValueError):
    """Raised when an advisory snapshot is malformed or cannot be written."""


class AdvisorySnapshotStore:
    def __init__(
        self,
        *,
        inputs: Iterable[str | Path] = (),
        output: str | Path | None = None,
    ) -> None:
        self.output = Path(output) if output is not None else None
        self._records: dict[str, list[VulnerabilityRecord]] = {}
        self._sources: list[str] = []
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
        with self._lock:
            payload = {
                "schema": ADVISORY_SNAPSHOT_SCHEMA,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "records": {
                    key: [asdict(record) for record in records]
                    for key, records in sorted(self._records.items())
                },
            }
            self.output.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(self.output, payload)
            return self.output

    def _load(self, path: Path) -> None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AdvisorySnapshotError(
                f"unable to read advisory snapshot {path}: {exc}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("schema") != ADVISORY_SNAPSHOT_SCHEMA:
            raise AdvisorySnapshotError(
                f"unsupported advisory snapshot schema in {path}"
            )
        raw_records = payload.get("records")
        if not isinstance(raw_records, dict):
            raise AdvisorySnapshotError(
                f"advisory snapshot records must be an object in {path}"
            )
        for key, items in raw_records.items():
            if not isinstance(key, str) or not isinstance(items, list):
                raise AdvisorySnapshotError(
                    f"invalid advisory snapshot record collection in {path}"
                )
            parsed = [_record_from_mapping(item, path=path) for item in items]
            existing = self._records.setdefault(key, [])
            _merge_snapshot_records(existing, parsed)
        self._sources.append(str(path.resolve()))


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
