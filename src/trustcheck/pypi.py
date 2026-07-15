from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Protocol
from urllib import error, parse, request

import urllib3
from pydantic import ValidationError

from .cache import CacheIntegrityError, ContentAddressedCache
from .schemas import ProjectResponsePayload, ProvenanceEnvelopePayload

if TYPE_CHECKING:
    from .resolver import ArtifactReference

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
    from ._version import version as _PACKAGE_VERSION
except ImportError:
    try:
        _PACKAGE_VERSION = version("trustcheck")
    except PackageNotFoundError:
        _PACKAGE_VERSION = "0+unknown"
DEFAULT_USER_AGENT = f"trustcheck/{_PACKAGE_VERSION}"
DEFAULT_MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024


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


def _read_bounded_response(response: Any, *, limit: int, url: str) -> bytes:
    headers = getattr(response, "headers", None) or {}
    content_length = headers.get("Content-Length") if hasattr(headers, "get") else None
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except (TypeError, ValueError):
            declared_size = -1
        if declared_size > limit:
            raise _oversized_response_error(limit, url)

    payload = bytearray()
    while len(payload) <= limit:
        read_size = min(DOWNLOAD_CHUNK_BYTES, limit + 1 - len(payload))
        try:
            chunk = response.read(read_size)
        except TypeError:
            # Compatibility for simple test/plugin response wrappers. Standard HTTP
            # response objects always support bounded reads.
            chunk = response.read()
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > limit:
            raise _oversized_response_error(limit, url)
    return bytes(payload)


def _reject_oversized_payload(payload: bytes, limit: int, url: str) -> None:
    if len(payload) > limit:
        raise _oversized_response_error(limit, url)


def _oversized_response_error(limit: int, url: str) -> PypiClientError:
    return PypiClientError(
        f"response exceeds the {limit}-byte download limit: {url}",
        transient=False,
        url=url,
        code="upstream",
        subcode="response_too_large",
    )


class PackageClient(Protocol):
    timeout: float
    max_retries: int
    backoff_factor: float
    offline: bool
    request_hook: Callable[[str, dict[str, Any]], None] | None

    def get_project(self, project: str) -> dict[str, Any]: ...

    def get_release(self, project: str, version: str) -> dict[str, Any]: ...

    def get_provenance(
        self,
        project: str,
        version: str,
        filename: str,
    ) -> dict[str, Any]: ...

    def download_distribution(self, url: str) -> bytes: ...


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
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    http_pool: urllib3.PoolManager | None = None
    _json_cache: dict[tuple[str, str], dict[str, Any]] | None = None
    _bytes_cache: dict[str, bytes] | None = None
    _content_cache: ContentAddressedCache | None = None

    def __post_init__(self) -> None:
        if self.enable_cache:
            self._json_cache = {}
            self._bytes_cache = {}
        if self.cache_dir:
            Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
            self._content_cache = ContentAddressedCache(self.cache_dir)

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
        return payload

    def _request_bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self._validate_request_url(url)
        if self.offline:
            cached = self._read_disk_cache(url, accept=accept)
            if cached is not None:
                _reject_oversized_payload(cached, self.max_download_bytes, url)
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
            status: int | None
            try:
                if self.http_pool is not None:
                    payload, status = self._request_from_pool(url, headers)
                else:
                    req = request.Request(url, headers=headers)
                    # The URL scheme is constrained to HTTP(S) before the request is built.
                    # nosemgrep
                    with request.urlopen(  # nosec B310
                        req,
                        timeout=self.timeout,
                    ) as response:
                        payload = _read_bounded_response(
                            response,
                            limit=self.max_download_bytes,
                            url=url,
                        )
                        status = getattr(response, "status", None)
                self._emit(
                    "response",
                    url=url,
                    attempt=attempt + 1,
                    status=status,
                )
                self._write_disk_cache(url, payload, accept=accept)
                return payload
            except PypiClientError as exc:
                client_error = exc
            except urllib3.exceptions.HTTPError as exc:
                client_error = self._pool_error(exc, url)
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

    def _request_from_pool(
        self,
        url: str,
        headers: dict[str, str],
    ) -> tuple[bytes, int]:
        pool = self.http_pool
        if pool is None:
            raise RuntimeError("HTTP connection pool is not configured")
        response = pool.request(
            "GET",
            url,
            headers=headers,
            timeout=urllib3.Timeout(total=self.timeout),
            retries=False,
            preload_content=False,
        )
        try:
            status = int(response.status)
            if status >= 400:
                raise self._http_status_error(status, url)
            if hasattr(response, "read"):
                payload = _read_bounded_response(
                    response,
                    limit=self.max_download_bytes,
                    url=url,
                )
            else:
                payload = bytes(response.data)
                _reject_oversized_payload(payload, self.max_download_bytes, url)
            return payload, status
        finally:
            response.release_conn()

    def _validate_request_url(self, url: str) -> None:
        if parse.urlparse(url).scheme not in {"http", "https"}:
            raise PypiClientError(
                f"request URL must use HTTP or HTTPS: {url}",
                transient=False,
                url=url,
                code="upstream",
                subcode="url_scheme_invalid",
            )

    def _http_error(self, exc: error.HTTPError, url: str) -> PypiClientError:
        return self._http_status_error(exc.code, url)

    def _http_status_error(self, status: int, url: str) -> PypiClientError:
        if status == 404:
            return PypiClientError(
                f"resource not found: {url}; retrying is unlikely to help",
                transient=False,
                status_code=status,
                url=url,
                code="upstream",
                subcode="http_not_found",
            )
        transient = status in TRANSIENT_HTTP_STATUS_CODES
        retry_hint = "retrying may help" if transient else "retrying is unlikely to help"
        return PypiClientError(
            f"PyPI returned HTTP {status} for {url}; {retry_hint}",
            transient=transient,
            status_code=status,
            url=url,
            code="upstream",
            subcode="http_transient" if transient else "http_error",
        )

    def _pool_error(
        self,
        exc: urllib3.exceptions.HTTPError,
        url: str,
    ) -> PypiClientError:
        reason = getattr(exc, "reason", exc)
        if isinstance(
            reason,
            (urllib3.exceptions.TimeoutError, TimeoutError, socket.timeout),
        ):
            return self._timeout_error(reason, url)
        transient = not isinstance(reason, urllib3.exceptions.SSLError)
        return PypiClientError(
            (
                f"unable to reach PyPI: {reason}; "
                f"{'retrying may help' if transient else 'retrying is unlikely to help'}"
            ),
            transient=transient,
            url=url,
            code="upstream",
            subcode="network_transient" if transient else "network_tls",
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
        key = self._content_cache_key(url, accept=accept)
        if self._content_cache is not None:
            try:
                payload = self._content_cache.get("http", key)
            except CacheIntegrityError as exc:
                raise PypiClientError(
                    f"cached response failed integrity verification for {url}: {exc}",
                    transient=False,
                    url=url,
                    code="upstream",
                    subcode="cache_integrity_failed",
                ) from exc
            if payload is not None:
                self._emit(
                    "cache_hit",
                    url=url,
                    kind="content-addressed",
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
                return payload
        cache_path = self._cache_path(url, accept=accept)
        if cache_path is None or not cache_path.exists():
            return None
        self._emit("cache_hit", url=url, kind="disk", cache_path=str(cache_path))
        return cache_path.read_bytes()

    def _write_disk_cache(self, url: str, payload: bytes, *, accept: str | None) -> None:
        if self._content_cache is None:
            return
        cache_object = self._content_cache.put(
            "http",
            self._content_cache_key(url, accept=accept),
            payload,
            media_type=accept,
        )
        self._emit(
            "cache_store",
            url=url,
            kind="content-addressed",
            cache_path=str(cache_object.path),
            sha256=cache_object.digest,
            size=len(payload),
        )

    def _content_cache_key(self, url: str, *, accept: str | None) -> str:
        return f"{accept or ''}|{url}"

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


@dataclass(slots=True)
class IndexBackedPackageClient:
    base_client: PypiClient
    project: str
    version: str
    index_url: str
    artifacts: tuple[ArtifactReference, ...] = ()
    requires_dist: tuple[str, ...] = ()
    allow_insecure_index: bool = False
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    repository_client: Any = None

    def __post_init__(self) -> None:
        if self.repository_client is None:
            from .indexes import IndexURLPolicy, SimpleRepositoryClient

            self.repository_client = SimpleRepositoryClient(
                timeout=self.base_client.timeout,
                max_response_bytes=self.base_client.max_download_bytes,
                url_policy=IndexURLPolicy(
                    allow_insecure_index=self.allow_insecure_index,
                ),
            )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.base_client, name)

    def get_project(self, project: str) -> dict[str, Any]:
        self._validate_project(project)
        payload = self._release_payload()
        payload["releases"] = {self.version: payload["urls"]}
        return payload

    def get_release(self, project: str, version: str) -> dict[str, Any]:
        self._validate_project(project)
        if version != self.version:
            raise PypiClientError(
                f"index-backed package only provides locked version {self.version}",
                code="upstream",
                subcode="release_not_locked",
            )
        return self._release_payload()

    def get_provenance(
        self,
        project: str,
        version: str,
        filename: str,
    ) -> dict[str, Any]:
        del filename
        self._validate_project(project)
        if version != self.version:
            raise PypiClientError(
                f"index-backed package only provides locked version {self.version}",
                code="upstream",
                subcode="release_not_locked",
            )
        return {"version": 1, "attestation_bundles": []}

    def download_distribution(self, url: str) -> bytes:
        parsed = parse.urlsplit(url)
        if parsed.scheme == "file":
            if not self._allows_local_artifact(url):
                raise PypiClientError(
                    "local file artifact URLs are only allowed for explicitly "
                    "local lockfile or direct artifacts",
                    url=url,
                    code="upstream",
                    subcode="local_artifact_not_allowed",
                )
            try:
                path = _local_file_url_path(url)
                if path.stat().st_size > self.base_client.max_download_bytes:
                    raise PypiClientError(
                        f"artifact exceeds the {self.base_client.max_download_bytes}-byte "
                        f"download limit: {url}",
                        url=url,
                        code="upstream",
                        subcode="response_too_large",
                    )
                with path.open("rb") as stream:
                    return _read_bounded_response(
                        stream,
                        limit=self.base_client.max_download_bytes,
                        url=url,
                    )
            except OSError as exc:
                raise PypiClientError(
                    f"unable to read locked artifact {url}: {exc}",
                    code="upstream",
                    subcode="artifact_read_failed",
                ) from exc
        try:
            payload = bytes(self.repository_client.download(
                url,
                index_url=self.index_url,
            ))
            _reject_oversized_payload(
                payload,
                self.base_client.max_download_bytes,
                url,
            )
            return payload
        except Exception as exc:
            raise PypiClientError(
                str(exc),
                code="upstream",
                subcode="artifact_download_failed",
            ) from exc

    def package_url(self, project: str, version: str) -> str:
        from .indexes import normalize_index_url, redact_url_credentials

        base = redact_url_credentials(normalize_index_url(self.index_url))
        return parse.urljoin(base, f"{parse.quote(project)}/{parse.quote(version)}/")

    def _validate_project(self, project: str) -> None:
        from packaging.utils import canonicalize_name

        if canonicalize_name(project) != canonicalize_name(self.project):
            raise PypiClientError(
                f"index-backed client is scoped to {self.project!r}",
                code="upstream",
                subcode="project_scope_mismatch",
            )

    def _release_payload(self) -> dict[str, Any]:
        from .indexes import files_for_version

        artifacts = list(self.artifacts)
        if not any(item.url for item in artifacts):
            project = self.repository_client.get_project(
                self.index_url,
                self.project,
            )
            if project is None:
                raise PypiClientError(
                    f"project {self.project!r} was not found on the configured index",
                    code="upstream",
                    subcode="index_project_not_found",
                )
            expected_hashes = {
                hash_value
                for artifact in artifacts
                for hash_value in artifact.hashes
            }
            for item in files_for_version(project, self.version):
                if expected_hashes and not expected_hashes.intersection(item.hashes):
                    continue
                from .resolver import ArtifactReference

                artifacts.append(
                    ArtifactReference(
                        filename=item.filename,
                        url=item.url,
                        hashes=item.hashes,
                        size=item.size,
                        kind="index",
                    )
                )

        urls = []
        for artifact in artifacts:
            if not artifact.url:
                continue
            hashes = dict(artifact.hashes)
            urls.append(
                {
                    "filename": artifact.filename
                    or Path(parse.urlsplit(artifact.url).path).name,
                    "url": artifact.url,
                    "digests": {"sha256": hashes.get("sha256")},
                }
            )
        if not urls:
            raise PypiClientError(
                f"no locked artifacts for {self.project}=={self.version} "
                "were available from the configured index",
                code="upstream",
                subcode="locked_artifact_missing",
            )
        return {
            "info": {
                "version": self.version,
                "summary": None,
                "project_urls": {},
                "ownership": {},
                "requires_dist": list(self.requires_dist),
            },
            "releases": {},
            "urls": urls,
            "vulnerabilities": [],
        }

    def _allows_local_artifact(self, url: str) -> bool:
        try:
            requested_path = _local_file_url_path(url).resolve()
        except PypiClientError:
            return False
        for artifact in self.artifacts:
            if artifact.kind == "index":
                continue
            candidates: list[Path] = []
            if artifact.url:
                try:
                    candidates.append(_local_file_url_path(artifact.url).resolve())
                except PypiClientError:
                    pass
            if artifact.path:
                try:
                    candidates.append(Path(artifact.path).resolve())
                except OSError:
                    pass
            if requested_path in candidates:
                return True
        return False


def _local_file_url_path(url: str) -> Path:
    parsed = parse.urlsplit(url)
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise PypiClientError(
            f"unsupported local artifact URL: {url}",
            url=url,
            code="upstream",
            subcode="local_artifact_url_invalid",
        )
    return Path(request.url2pathname(parsed.path))
