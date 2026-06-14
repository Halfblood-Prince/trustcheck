from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CACHE_SCHEMA = "urn:trustcheck:cache-ref:1.0.0"


class CacheIntegrityError(RuntimeError):
    """Raised when a cached object does not match its recorded digest."""


@dataclass(frozen=True, slots=True)
class CacheObject:
    digest: str
    size: int
    path: Path


class ContentAddressedCache:
    """A request-keyed index backed by deduplicated SHA-256 objects."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects" / "sha256"
        self.refs = self.root / "refs"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.refs.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def get(self, namespace: str, key: str) -> bytes | None:
        ref_path = self._ref_path(namespace, key)
        with self._lock:
            if not ref_path.is_file():
                return None
            try:
                raw_ref = json.loads(ref_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise CacheIntegrityError(
                    f"cache reference is unreadable: {ref_path}"
                ) from exc
            if (
                not isinstance(raw_ref, dict)
                or raw_ref.get("schema") != CACHE_SCHEMA
                or raw_ref.get("key") != key
            ):
                raise CacheIntegrityError(
                    f"cache reference is invalid: {ref_path}"
                )
            digest = raw_ref.get("sha256")
            size = raw_ref.get("size")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or not isinstance(size, int)
                or size < 0
            ):
                raise CacheIntegrityError(
                    f"cache reference has invalid object metadata: {ref_path}"
                )
            object_path = self._object_path(digest)
            try:
                payload = object_path.read_bytes()
            except OSError as exc:
                raise CacheIntegrityError(
                    f"cache object is missing: {object_path}"
                ) from exc
            observed = hashlib.sha256(payload).hexdigest()
            if observed != digest or len(payload) != size:
                raise CacheIntegrityError(
                    f"cache object failed SHA-256 verification: {object_path}"
                )
            return payload

    def put(
        self,
        namespace: str,
        key: str,
        payload: bytes,
        *,
        media_type: str | None = None,
    ) -> CacheObject:
        digest = hashlib.sha256(payload).hexdigest()
        object_path = self._object_path(digest)
        ref_path = self._ref_path(namespace, key)
        reference: dict[str, Any] = {
            "schema": CACHE_SCHEMA,
            "key": key,
            "sha256": digest,
            "size": len(payload),
        }
        if media_type:
            reference["media_type"] = media_type
        with self._lock:
            object_path.parent.mkdir(parents=True, exist_ok=True)
            if not object_path.exists():
                _atomic_write_bytes(object_path, payload)
            else:
                existing = object_path.read_bytes()
                if hashlib.sha256(existing).hexdigest() != digest:
                    raise CacheIntegrityError(
                        f"existing cache object failed verification: {object_path}"
                    )
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_text(
                ref_path,
                json.dumps(reference, indent=2, sort_keys=True) + "\n",
            )
        return CacheObject(digest=digest, size=len(payload), path=object_path)

    def _object_path(self, digest: str) -> Path:
        return self.objects / digest[:2] / digest[2:]

    def _ref_path(self, namespace: str, key: str) -> Path:
        safe_namespace = _safe_namespace(namespace)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.refs / safe_namespace / f"{digest}.json"


def _safe_namespace(value: str) -> str:
    normalized = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in value.strip()
    )
    return normalized or "default"


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:  # pragma: no cover - best-effort cleanup after write failure
            pass
        raise


def _atomic_write_text(path: Path, payload: str) -> None:
    _atomic_write_bytes(path, payload.encode("utf-8"))
