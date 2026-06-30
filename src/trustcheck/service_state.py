from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from .models import (
    ArtifactDiagnostic,
    ReportDiagnostics,
    RequestFailureDiagnostic,
)
from .pypi import PackageClient, PypiClientError

ProgressCallback = Callable[[str, int, int], None]
DependencyProgressCallback = Callable[[str, int, int, bool], None]

_RECOMMENDATION_ORDER = {
    "verified": 0,
    "metadata-only": 1,
    "review-required": 2,
    "high-risk": 3,
}
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024

SCAN_PROFILE_NAMES = ("fast", "standard", "full")


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    collect_provenance: bool
    inspect_artifacts: bool
    release_history: bool
    heuristics: bool


SCAN_PROFILES = {
    "fast": ScanProfile(
        name="fast",
        collect_provenance=False,
        inspect_artifacts=False,
        release_history=False,
        heuristics=False,
    ),
    "standard": ScanProfile(
        name="standard",
        collect_provenance=True,
        inspect_artifacts=False,
        release_history=False,
        heuristics=False,
    ),
    "full": ScanProfile(
        name="full",
        collect_provenance=True,
        inspect_artifacts=True,
        release_history=True,
        heuristics=True,
    ),
}


class ArtifactDigestCache:
    """Share downloaded artifacts by digest and coalesce concurrent fetches."""

    def __init__(self, *, max_total_bytes: int = MAX_TOTAL_ARTIFACT_BYTES) -> None:
        self._payloads: dict[str, bytes] = {}
        self._pending: dict[str, Future[bytes]] = {}
        self._lock = Lock()
        self._max_total_bytes = max_total_bytes
        self._total_bytes = 0

    def fetch(
        self,
        url: str,
        expected_sha256: str | None,
        loader: Callable[[str], bytes],
    ) -> bytes:
        key = (
            f"sha256:{expected_sha256.lower()}"
            if expected_sha256
            else f"url:{url}"
        )
        with self._lock:
            cached = self._payloads.get(key)
            if cached is not None:
                return cached
            pending = self._pending.get(key)
            owner = pending is None
            if pending is None:
                pending = Future()
                self._pending[key] = pending
        if not owner:
            return pending.result()

        try:
            payload = loader(url)
            observed_digest = hashlib.new("sha256", payload).hexdigest()
            observed_key = f"sha256:{observed_digest}"
            with self._lock:
                if (
                    observed_key not in self._payloads
                    and self._total_bytes + len(payload) > self._max_total_bytes
                ):
                    raise PypiClientError(
                        "aggregate artifact downloads exceed the "
                        f"{self._max_total_bytes}-byte scan limit",
                        code="upstream",
                        subcode="response_too_large",
                    )
                if observed_key not in self._payloads:
                    self._total_bytes += len(payload)
                self._payloads[observed_key] = payload
                if not expected_sha256 or expected_sha256.lower() == observed_digest:
                    self._payloads[key] = payload
            pending.set_result(payload)
            return payload
        except BaseException as exc:
            pending.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(key, None)


@dataclass(slots=True)
class DependencyTraversalContext:
    seen: set[str] = field(default_factory=set)


@dataclass(slots=True)
class PackageHistoryContext:
    project_payload: Mapping[str, object] | None = None
    previous_version: str | None = None
    previous_payload: Mapping[str, object] | None = None


class DiagnosticsCollector:
    def __init__(self) -> None:
        self._lock = Lock()
        self.request_count = 0
        self.retry_count = 0
        self.cache_hit_count = 0
        self.request_failures: list[RequestFailureDiagnostic] = []
        self.artifact_failures: list[ArtifactDiagnostic] = []

    def on_request_event(self, event: str, payload: dict[str, Any]) -> None:
        with self._lock:
            if event == "request":
                self.request_count += 1
            elif event == "retry":
                self.retry_count += 1
            elif event == "cache_hit":
                self.cache_hit_count += 1
            elif event == "failure":
                self.request_failures.append(
                    RequestFailureDiagnostic(
                        url=str(payload.get("url") or ""),
                        attempt=int(payload.get("attempt") or 0),
                        code=str(payload.get("code") or "upstream"),
                        subcode=str(payload.get("subcode") or "unknown"),
                        message=str(payload.get("message") or ""),
                        transient=bool(payload.get("transient")),
                        status_code=(
                            int(payload["status_code"])
                            if payload.get("status_code") is not None
                            else None
                        ),
                    )
                )

    def add_artifact_failure(
        self,
        *,
        filename: str,
        stage: str,
        code: str,
        subcode: str,
        message: str,
    ) -> None:
        with self._lock:
            self.artifact_failures.append(
                ArtifactDiagnostic(
                    filename=filename,
                    stage=stage,
                    code=code,
                    subcode=subcode,
                    message=message,
                )
            )

    def to_report_diagnostics(self, client: PackageClient) -> ReportDiagnostics:
        return ReportDiagnostics(
            timeout=float(getattr(client, "timeout", 10.0)),
            max_retries=int(getattr(client, "max_retries", 2)),
            backoff_factor=float(getattr(client, "backoff_factor", 0.25)),
            offline=bool(getattr(client, "offline", False)),
            cache_dir=getattr(client, "cache_dir", None),
            request_count=self.request_count,
            retry_count=self.retry_count,
            cache_hit_count=self.cache_hit_count,
            request_failures=self.request_failures,
            artifact_failures=self.artifact_failures,
        )

