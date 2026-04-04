from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Callable
from urllib import error, parse, request

from pydantic import ValidationError

from .schemas import ProjectResponsePayload, ProvenanceEnvelopePayload

PYPI_BASE_URL = "https://pypi.org"
JSON_ACCEPT = "application/json"
INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"
TRANSIENT_HTTP_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
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
    ) -> None:
        super().__init__(message)
        self.transient = transient
        self.status_code = status_code
        self.url = url


@dataclass(slots=True)
class PypiClient:
    base_url: str = PYPI_BASE_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    enable_cache: bool = True
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _json_cache: dict[tuple[str, str], dict[str, Any]] | None = None
    _bytes_cache: dict[str, bytes] | None = None

    def __post_init__(self) -> None:
        if self.enable_cache:
            self._json_cache = {}
            self._bytes_cache = {}

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

        payload_bytes = self._request_bytes(url, accept=accept)
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError as exc:
            raise PypiClientError(
                f"PyPI returned malformed JSON for {url}; retrying is unlikely to help",
                transient=False,
                url=url,
            ) from exc
        if not isinstance(payload, dict):
            raise PypiClientError(
                f"PyPI returned a non-object JSON response for {url}; retrying is unlikely to help",
                transient=False,
                url=url,
            )
        if self._json_cache is not None:
            self._json_cache[cache_key] = payload
        return payload

    def _request_bytes(self, url: str, *, accept: str | None = None) -> bytes:
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
                    return payload
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
            )
        transient = exc.code in TRANSIENT_HTTP_STATUS_CODES
        retry_hint = "retrying may help" if transient else "retrying is unlikely to help"
        return PypiClientError(
            f"PyPI returned HTTP {exc.code} for {url}; {retry_hint}",
            transient=transient,
            status_code=exc.code,
            url=url,
        )

    def _url_error(self, exc: error.URLError, url: str) -> PypiClientError:
        reason = exc.reason
        transient = isinstance(reason, (TimeoutError, socket.timeout, OSError, str))
        return PypiClientError(
            (
                f"unable to reach PyPI: {reason}; "
                f"{'retrying may help' if transient else 'retrying is unlikely to help'}"
            ),
            transient=transient,
            url=url,
        )

    def _emit(self, event: str, **payload: Any) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)

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
            ) from exc
