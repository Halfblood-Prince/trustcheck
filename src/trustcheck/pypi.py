from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable
from urllib import error, parse, request

from pydantic import ValidationError

from .schemas import ProjectResponsePayload, ProvenanceEnvelopePayload

PYPI_BASE_URL = "https://pypi.org"
JSON_ACCEPT = "application/json"
INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"
TRANSIENT_HTTP_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
TRANSIENT_OS_ERROR_CODES = {
    getattr(socket, "EAI_AGAIN", None),
}
TRANSIENT_ERROR_TEXT = (
    "temporary failure",
    "temporarily unavailable",
    "timed out",
    "timeout",
    "connection reset",
    "connection aborted",
    "remote end closed connection",
    "service unavailable",
    "try again",
)
PERMANENT_ERROR_TEXT = (
    "name or service not known",
    "nodename nor servname provided",
    "no address associated with hostname",
    "certificate verify failed",
    "wrong version number",
    "unknown ca",
    "handshake failure",
    "connection refused",
)
try:
    _PACKAGE_VERSION = version("trustcheck")
except PackageNotFoundError:
    _PACKAGE_VERSION = "0+unknown"
DEFAULT_USER_AGENT = f"trustcheck/{_PACKAGE_VERSION}"


class PypiClientError(RuntimeError):
    """Raised when PyPI cannot satisfy a request."""

    def __init__(
        self,
        message: str,
        *,
        transient: bool = False,
        status_code: int | None = None,
        url: str | None = None,
        code: str = "upstream",
        subcode: str = "unknown",
    ) -> None:
        super().__init__(message)
        self.transient = transient
        self.status_code = status_code
        self.url = url
        self.code = code
        self.subcode = subcode


@dataclass(slots=True)
class PypiClient:
    base_url: str = PYPI_BASE_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    enable_cache: bool = True
    cache_dir: str | None = None
    offline: bool = False
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _json_cache: dict[tuple[str, str], dict[str, Any]] | None = None
    _bytes_cache: dict[str, bytes] | None = None

    def __post_init__(self) -> None:
        if self.enable_cache:
            self._json_cache = {}
            self._bytes_cache = {}
        if self.cache_dir:
            Path(self.cache_dir).mkdir(parents=True, exist_ok=True)

    def get_project(self, project: str) -> dict[str, Any]:
        payload = self._get_json(f"/pypi/{parse.quote(project)}/json", accept=JSON_ACCEPT)
        return self._validate_project_payload(payload, f"/pypi/{parse.quote(project)}/json")

    def get_release(self, project: str, version: str) -> dict[str, Any]:
        project_q = parse.quote(project)
        version_q = parse.quote(version)
        path = f"/pypi/{project_q}/{version_q}/json"
        payload = self._get_json(path, accept=JSON_ACCEPT)
        return self._validate_project_payload(payload, path)

    def get_provenance(self, project: str, version: str, filename: str) -> dict[str, Any]:
        project_q = parse.quote(project)
        version_q = parse.quote(version)
        filename_q = parse.quote(filename)
        path = f"/integrity/{project_q}/{version_q}/{filename_q}/provenance"
        payload = self._get_json(path, accept=INTEGRITY_ACCEPT)
        return self._validate_provenance_payload(payload, path)

    def download_distribution(self, url: str) -> bytes:
        if self._bytes_cache is not None and url in self._bytes_cache:
            self._emit("cache_hit", url=url, kind="bytes")
            return self._bytes_cache[url]

        payload = self._request_bytes(url)
        if self._bytes_cache is not None:
            self._bytes_cache[url] = payload
        return payload

    def _get_json(self, path: str, *, accept: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        cache_key = (url, accept)
        if self._json_cache is not None and cache_key in self._json_cache:
            self._emit("cache_hit", url=url, kind="json")
            return self._json_cache[cache_key]
        disk_cached = self._read_disk_cache(url, accept=accept)
        if disk_cached is not None:
            payload = self._decode_json_payload(disk_cached, url)
            if self._json_cache is not None:
                self._json_cache[cache_key] = payload
            return payload

        payload_bytes = self._request_bytes(url, accept=accept)
        payload = self._decode_json_payload(payload_bytes, url)
        if self._json_cache is not None:
            self._json_cache[cache_key] = payload
        self._write_disk_cache(url, payload_bytes, accept=accept)
        return payload

    def _request_bytes(self, url: str, *, accept: str | None = None) -> bytes:
        if self.offline:
            cached = self._read_disk_cache(url, accept=accept)
            if cached is not None:
                return cached
            raise PypiClientError(
                f"offline mode enabled and no cached response is available for {url}",
                transient=False,
                url=url,
                code="upstream",
                subcode="offline_cache_miss",
            )

        headers = {"User-Agent": self.user_agent}
        if accept:
            headers["Accept"] = accept

        for attempt in range(self.max_retries + 1):
            self._emit("request", url=url, attempt=attempt + 1, accept=accept)
            req = request.Request(url, headers=headers)
            try:
                with request.urlopen(req, timeout=self.timeout) as response:
                    payload = bytes(response.read())
                    self._emit(
                        "response",
                        url=url,
                        attempt=attempt + 1,
                        status=getattr(response, "status", None),
                    )
                    self._write_disk_cache(url, payload, accept=accept)
                    return payload
            except (TimeoutError, socket.timeout) as exc:
                client_error = self._timeout_error(exc, url)
            except error.HTTPError as exc:
                client_error = self._http_error(exc, url)
            except error.URLError as exc:
                client_error = self._url_error(exc, url)

            self._emit(
                "failure",
                url=url,
                attempt=attempt + 1,
                transient=client_error.transient,
                message=str(client_error),
                code=client_error.code,
                subcode=client_error.subcode,
                status_code=client_error.status_code,
            )
            if not client_error.transient or attempt == self.max_retries:
                raise client_error
            backoff = self.backoff_factor * (2**attempt)
            self._emit("retry", url=url, attempt=attempt + 1, delay=backoff)
            self.sleep(backoff)

        raise AssertionError("unreachable")

    def _http_error(self, exc: error.HTTPError, url: str) -> PypiClientError:
        if exc.code == 404:
            return PypiClientError(
                f"resource not found: {url}; retrying is unlikely to help",
                transient=False,
                status_code=exc.code,
                url=url,
                code="upstream",
                subcode="http_not_found",
            )
        transient = exc.code in TRANSIENT_HTTP_STATUS_CODES
        retry_hint = "retrying may help" if transient else "retrying is unlikely to help"
        return PypiClientError(
            f"PyPI returned HTTP {exc.code} for {url}; {retry_hint}",
            transient=transient,
            status_code=exc.code,
            url=url,
            code="upstream",
            subcode="http_transient" if transient else "http_error",
        )

    def _timeout_error(self, exc: BaseException, url: str) -> PypiClientError:
        return PypiClientError(
            f"unable to reach PyPI: {exc}; retrying may help",
            transient=True,
            url=url,
            code="upstream",
            subcode="network_timeout",
        )

    def _url_error(self, exc: error.URLError, url: str) -> PypiClientError:
        reason = self._unwrap_url_error_reason(exc.reason)
        transient = self._is_transient_network_reason(reason)
        reason_text = self._format_network_reason(reason)
        subcode = self._network_subcode(reason, transient)
        return PypiClientError(
            (
                f"unable to reach PyPI: {reason_text}; "
                f"{'retrying may help' if transient else 'retrying is unlikely to help'}"
            ),
            transient=transient,
            url=url,
            code="upstream",
            subcode=subcode,
        )

    def _unwrap_url_error_reason(self, reason: object) -> object:
        current = reason
        seen: set[int] = set()
        while hasattr(current, "reason") and id(current) not in seen:
            seen.add(id(current))
            nested = getattr(current, "reason", None)
            if nested is None:
                break
            current = nested
        return current

    def _is_transient_network_reason(self, reason: object) -> bool:
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return True
        if isinstance(reason, ssl.SSLError):
            return False
        if isinstance(reason, socket.gaierror):
            return reason.errno in TRANSIENT_OS_ERROR_CODES
        if isinstance(reason, OSError):
            if reason.errno in TRANSIENT_OS_ERROR_CODES:
                return True
            return self._classify_reason_text(str(reason))
        if isinstance(reason, str):
            return self._classify_reason_text(reason)
        return False

    def _classify_reason_text(self, text: str) -> bool:
        normalized = text.strip().lower()
        if any(pattern in normalized for pattern in PERMANENT_ERROR_TEXT):
            return False
        return any(pattern in normalized for pattern in TRANSIENT_ERROR_TEXT)

    def _format_network_reason(self, reason: object) -> str:
        text = str(reason).strip()
        return text or reason.__class__.__name__

    def _network_subcode(self, reason: object, transient: bool) -> str:
        if isinstance(reason, ssl.SSLError):
            return "network_tls"
        if isinstance(reason, socket.gaierror):
            return "network_dns_temporary" if transient else "network_dns_failure"
        reason_text = str(reason).strip().lower()
        if "connection refused" in reason_text:
            return "network_connection_refused"
        return "network_transient" if transient else "network_error"

    def _emit(self, event: str, **payload: Any) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)

    def _decode_json_payload(self, payload_bytes: bytes, url: str) -> dict[str, Any]:
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError as exc:
            raise PypiClientError(
                f"PyPI returned malformed JSON for {url}; retrying is unlikely to help",
                transient=False,
                url=url,
                code="upstream",
                subcode="json_malformed",
            ) from exc
        if not isinstance(payload, dict):
            raise PypiClientError(
                f"PyPI returned a non-object JSON response for {url}; retrying is unlikely to help",
                transient=False,
                url=url,
                code="upstream",
                subcode="json_non_object",
            )
        return payload

    def _cache_path(self, url: str, *, accept: str | None) -> Path | None:
        if not self.cache_dir:
            return None
        digest = hashlib.sha256(f"{accept or ''}|{url}".encode("utf-8")).hexdigest()
        suffix = ".json" if accept else ".bin"
        return Path(self.cache_dir) / f"{digest}{suffix}"

    def _read_disk_cache(self, url: str, *, accept: str | None) -> bytes | None:
        cache_path = self._cache_path(url, accept=accept)
        if cache_path is None or not cache_path.exists():
            return None
        self._emit("cache_hit", url=url, kind="disk", cache_path=str(cache_path))
        return cache_path.read_bytes()

    def _write_disk_cache(self, url: str, payload: bytes, *, accept: str | None) -> None:
        cache_path = self._cache_path(url, accept=accept)
        if cache_path is None:
            return
        cache_path.write_bytes(payload)
        self._emit(
            "cache_store",
            url=url,
            kind="disk",
            cache_path=str(cache_path),
            size=len(payload),
        )

    def _validate_project_payload(self, payload: dict[str, Any], path: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            return ProjectResponsePayload.model_validate(payload).model_dump()
        except ValidationError as exc:
            raise PypiClientError(
                f"PyPI returned an unexpected project response shape for {url}; "
                "retrying is unlikely to help",
                transient=False,
                url=url,
                code="upstream",
                subcode="project_shape_invalid",
            ) from exc

    def _validate_provenance_payload(self, payload: dict[str, Any], path: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            return ProvenanceEnvelopePayload.model_validate(payload).model_dump()
        except ValidationError as exc:
            raise PypiClientError(
                f"PyPI returned an unexpected provenance response shape for {url}; "
                "retrying is unlikely to help",
                transient=False,
                url=url,
                code="upstream",
                subcode="provenance_shape_invalid",
            ) from exc
