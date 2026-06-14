from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, cast

from .contract import deserialize_report
from .models import TrustReport

SCAN_STATE_SCHEMA = "urn:trustcheck:scan-state:1.0.0"


class ScanStateError(ValueError):
    """Raised when resumable state is invalid or belongs to another scan."""


class ScanState:
    def __init__(
        self,
        path: str | Path,
        *,
        fingerprint: str,
        target_keys: Iterable[str],
    ) -> None:
        self.path = Path(path)
        self.fingerprint = fingerprint
        self.target_keys = tuple(target_keys)
        self._reports: dict[str, TrustReport] = {}
        self._failures: dict[str, dict[str, str]] = {}
        self._lock = threading.RLock()
        if self.path.exists():
            self._load()

    def report(self, target_key: str) -> TrustReport | None:
        with self._lock:
            return self._reports.get(target_key)

    def failure(self, target_key: str) -> dict[str, str] | None:
        with self._lock:
            failure = self._failures.get(target_key)
            return dict(failure) if failure is not None else None

    def record_report(self, target_key: str, report: TrustReport) -> None:
        with self._lock:
            self._reports[target_key] = report
            self._failures.pop(target_key, None)
            self._write(status="running")

    def record_failure(
        self,
        target_key: str,
        *,
        requirement: str,
        message: str,
    ) -> None:
        with self._lock:
            self._failures[target_key] = {
                "requirement": requirement,
                "message": message,
            }
            self._reports.pop(target_key, None)
            self._write(status="running")

    def complete(self) -> None:
        with self._lock:
            self._write(status="complete")

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ScanStateError(
                f"unable to read scan state {self.path}: {exc}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("schema") != SCAN_STATE_SCHEMA:
            raise ScanStateError(f"unsupported scan state schema in {self.path}")
        if payload.get("fingerprint") != self.fingerprint:
            raise ScanStateError(
                f"scan state {self.path} does not match this scan configuration"
            )
        if payload.get("targets") != list(self.target_keys):
            raise ScanStateError(
                f"scan state {self.path} does not match the resolved target set"
            )
        raw_reports = payload.get("reports", {})
        raw_failures = payload.get("failures", {})
        if not isinstance(raw_reports, dict) or not isinstance(raw_failures, dict):
            raise ScanStateError(f"scan state collections are invalid in {self.path}")
        for key, value in raw_reports.items():
            if not isinstance(key, str) or not isinstance(value, Mapping):
                raise ScanStateError(f"scan state report is invalid in {self.path}")
            self._reports[key] = deserialize_report(value)
        for key, value in raw_failures.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, dict)
                or not isinstance(value.get("requirement"), str)
                or not isinstance(value.get("message"), str)
            ):
                raise ScanStateError(f"scan state failure is invalid in {self.path}")
            self._failures[key] = {
                "requirement": value["requirement"],
                "message": value["message"],
            }

    def _write(self, *, status: str) -> None:
        payload = {
            "schema": SCAN_STATE_SCHEMA,
            "fingerprint": self.fingerprint,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "targets": list(self.target_keys),
            "reports": {
                key: report.to_dict()["report"]
                for key, report in sorted(self._reports.items())
            },
            "failures": dict(sorted(self._failures.items())),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self.path, payload)


def scan_fingerprint(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def target_key(target: object) -> str:
    payload = (
        asdict(cast(Any, target))
        if hasattr(target, "__dataclass_fields__")
        else str(target)
    )
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_default(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "__dataclass_fields__"):
        return asdict(cast(Any, value))
    raise TypeError(f"value is not JSON serializable: {type(value).__name__}")


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
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
