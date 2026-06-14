from __future__ import annotations

import json
import math
import re
import socket
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib import error, parse, request

from packaging.utils import canonicalize_name

from .models import VulnerabilityRecord
from .pypi import DEFAULT_USER_AGENT, TRANSIENT_HTTP_STATUS_CODES, PypiClientError
from .snapshots import AdvisorySnapshotStore

OSV_BASE_URL = "https://api.osv.dev"
OSV_SOURCE = "OSV"
ECOSYSTEMS_OSV_BASE_URL = "https://advisories.ecosyste.ms"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class OsvQueryClient(Protocol):
    request_hook: Callable[[str, dict[str, Any]], None] | None

    def query(self, project: str, version: str) -> list[dict[str, Any]]: ...

    def query_batch(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[dict[str, Any]]]: ...


class AdvisorySourceClient(Protocol):
    name: str

    def query(
        self,
        project: str,
        version: str,
    ) -> Sequence[VulnerabilityRecord]: ...


@dataclass(slots=True)
class OsvClient:
    base_url: str = OSV_BASE_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    max_workers: int = 8
    batch_size: int = 1000
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _cache: dict[tuple[str, str], list[dict[str, Any]]] = field(
        default_factory=dict,
        init=False,
    )
    _vulnerability_cache: dict[str, dict[str, Any]] = field(
        default_factory=dict,
        init=False,
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    def query(self, project: str, version: str) -> list[dict[str, Any]]:
        cache_key = (canonicalize_name(project), version)
        with self._lock:
            cached = self._cache.get(cache_key)
        if cached is not None:
            self._emit("cache_hit", url=f"{self.base_url}/v1/query", kind="json")
            return deepcopy(cached)
        if self.offline:
            raise PypiClientError(
                "offline mode enabled and OSV queries are unavailable",
                transient=False,
                url=f"{self.base_url}/v1/query",
                code="advisory",
                subcode="offline_unavailable",
            )

        vulnerabilities: list[dict[str, Any]] = []
        page_token: str | None = None
        seen_page_tokens: set[str] = set()
        while True:
            payload: dict[str, Any] = {
                "package": {"name": project, "ecosystem": "PyPI"},
                "version": version,
            }
            if page_token:
                payload["page_token"] = page_token
            response = self._post_json("/v1/query", payload)
            items = response.get("vulns")
            if items is None:
                items = []
            if not isinstance(items, list):
                raise PypiClientError(
                    "OSV returned an unexpected response shape",
                    transient=False,
                    url=f"{self.base_url}/v1/query",
                    code="advisory",
                    subcode="response_shape_invalid",
                )
            vulnerabilities.extend(item for item in items if isinstance(item, dict))

            next_page_token = response.get("next_page_token")
            if not isinstance(next_page_token, str) or not next_page_token:
                break
            if next_page_token in seen_page_tokens:
                raise PypiClientError(
                    "OSV returned a repeated pagination token",
                    transient=False,
                    url=f"{self.base_url}/v1/query",
                    code="advisory",
                    subcode="pagination_invalid",
                )
            seen_page_tokens.add(next_page_token)
            page_token = next_page_token

        with self._lock:
            self._cache[cache_key] = deepcopy(vulnerabilities)
        return vulnerabilities

    def query_batch(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        ordered: list[tuple[str, str]] = list(
            dict.fromkeys(
                (str(canonicalize_name(project)), version)
                for project, version in packages
            )
        )
        if not ordered:
            return {}
        results: dict[tuple[str, str], list[dict[str, Any]]] = {}
        missing: list[tuple[str, str]] = []
        with self._lock:
            for key in ordered:
                cached = self._cache.get(key)
                if cached is None:
                    missing.append(key)
                else:
                    results[key] = deepcopy(cached)
        if missing and self.offline:
            raise PypiClientError(
                "offline mode enabled and OSV batch queries are unavailable",
                transient=False,
                url=f"{self.base_url}/v1/querybatch",
                code="advisory",
                subcode="offline_unavailable",
            )

        for offset in range(0, len(missing), self.batch_size):
            chunk = missing[offset : offset + self.batch_size]
            try:
                identifiers = self._query_batch_identifiers(chunk)
            except PypiClientError as exc:
                if exc.status_code not in {404, 405}:
                    raise
                fallback_records = self._fallback_query_records(chunk)
                for key, records in fallback_records.items():
                    with self._lock:
                        self._cache[key] = deepcopy(records)
                    results[key] = records
                continue
            unique_ids = sorted(
                {
                    identifier
                    for values in identifiers.values()
                    for identifier in values
                }
            )
            full_records = self._load_vulnerabilities(unique_ids)
            for key in chunk:
                records = [
                    deepcopy(full_records[identifier])
                    for identifier in identifiers.get(key, [])
                    if identifier in full_records
                ]
                with self._lock:
                    self._cache[key] = deepcopy(records)
                results[key] = records

        return {key: results.get(key, []) for key in ordered}

    def _query_batch_identifiers(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[str]]:
        identifiers: dict[tuple[str, str], list[str]] = {
            package: [] for package in packages
        }
        pending: list[tuple[tuple[str, str], str | None]] = [
            (package, None) for package in packages
        ]
        seen_tokens: dict[tuple[str, str], set[str]] = {
            package: set() for package in packages
        }
        while pending:
            query_payload = []
            for (project, version), page_token in pending:
                query: dict[str, Any] = {
                    "package": {"name": project, "ecosystem": "PyPI"},
                    "version": version,
                }
                if page_token:
                    query["page_token"] = page_token
                query_payload.append(query)
            response = self._post_json(
                "/v1/querybatch",
                {"queries": query_payload},
            )
            raw_results = response.get("results")
            if not isinstance(raw_results, list) or len(raw_results) != len(pending):
                raise _response_shape_error(
                    f"{self.base_url}/v1/querybatch",
                    source="OSV",
                )
            next_pending: list[tuple[tuple[str, str], str | None]] = []
            for (package, _), raw_result in zip(pending, raw_results, strict=True):
                if not isinstance(raw_result, dict):
                    raise _response_shape_error(
                        f"{self.base_url}/v1/querybatch",
                        source="OSV",
                    )
                raw_vulnerabilities = raw_result.get("vulns", [])
                if not isinstance(raw_vulnerabilities, list):
                    raise _response_shape_error(
                        f"{self.base_url}/v1/querybatch",
                        source="OSV",
                    )
                for item in raw_vulnerabilities:
                    if not isinstance(item, dict):
                        continue
                    identifier = item.get("id")
                    if (
                        isinstance(identifier, str)
                        and identifier not in identifiers[package]
                    ):
                        identifiers[package].append(identifier)
                next_token = raw_result.get("next_page_token")
                if isinstance(next_token, str) and next_token:
                    if next_token in seen_tokens[package]:
                        raise PypiClientError(
                            "OSV returned a repeated batch pagination token",
                            transient=False,
                            url=f"{self.base_url}/v1/querybatch",
                            code="advisory",
                            subcode="pagination_invalid",
                        )
                    seen_tokens[package].add(next_token)
                    next_pending.append((package, next_token))
            pending = next_pending
        return identifiers

    def _fallback_query_records(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
        workers = min(max(1, self.max_workers), len(packages))
        results: dict[tuple[str, str], list[dict[str, Any]]] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.query, project, version): (project, version)
                for project, version in packages
            }
            for future in as_completed(futures):
                key = futures[future]
                results[key] = future.result()
        return results

    def _load_vulnerabilities(
        self,
        identifiers: Sequence[str],
    ) -> dict[str, dict[str, Any]]:
        missing: list[str] = []
        with self._lock:
            for identifier in identifiers:
                if identifier not in self._vulnerability_cache:
                    missing.append(identifier)
        if missing:
            workers = min(max(1, self.max_workers), len(missing))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._get_vulnerability, identifier): identifier
                    for identifier in missing
                }
                for future in as_completed(futures):
                    identifier = futures[future]
                    record = future.result()
                    with self._lock:
                        self._vulnerability_cache[identifier] = record
        with self._lock:
            return {
                identifier: deepcopy(self._vulnerability_cache[identifier])
                for identifier in identifiers
                if identifier in self._vulnerability_cache
            }

    def _get_vulnerability(self, identifier: str) -> dict[str, Any]:
        encoded = parse.quote(identifier, safe="")
        return self._get_json(f"/v1/vulns/{encoded}")

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        _require_http_url(url, source="OSV")
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }

        for attempt in range(self.max_retries + 1):
            self._emit("request", url=url, attempt=attempt + 1, method="POST")
            req = request.Request(url, data=body, headers=headers, method="POST")
            try:
                # The URL scheme is constrained to HTTP(S) before the request is built.
                # nosemgrep
                with request.urlopen(  # nosec B310
                    req,
                    timeout=self.timeout,
                ) as response:
                    response_bytes = bytes(response.read())
                    self._emit(
                        "response",
                        url=url,
                        attempt=attempt + 1,
                        status=getattr(response, "status", None),
                    )
                    return self._decode_json(response_bytes, url)
            except (TimeoutError, socket.timeout) as exc:
                client_error = PypiClientError(
                    f"unable to reach OSV: {exc}; retrying may help",
                    transient=True,
                    url=url,
                    code="advisory",
                    subcode="network_timeout",
                )
            except error.HTTPError as exc:
                transient = exc.code in TRANSIENT_HTTP_STATUS_CODES
                client_error = PypiClientError(
                    f"OSV returned HTTP {exc.code} for {url}",
                    transient=transient,
                    status_code=exc.code,
                    url=url,
                    code="advisory",
                    subcode="http_transient" if transient else "http_error",
                )
            except error.URLError as exc:
                client_error = PypiClientError(
                    f"unable to reach OSV: {exc.reason}; retrying may help",
                    transient=True,
                    url=url,
                    code="advisory",
                    subcode="network_error",
                )

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
            delay = self.backoff_factor * (2**attempt)
            self._emit("retry", url=url, attempt=attempt + 1, delay=delay)
            self.sleep(delay)

        raise AssertionError("unreachable")

    def _get_json(self, path: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        _require_http_url(url, source="OSV")
        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        for attempt in range(self.max_retries + 1):
            self._emit("request", url=url, attempt=attempt + 1, method="GET")
            req = request.Request(url, headers=headers, method="GET")
            try:
                # The URL scheme is constrained to HTTP(S) before the request is built.
                # nosemgrep
                with request.urlopen(  # nosec B310
                    req,
                    timeout=self.timeout,
                ) as response:
                    response_bytes = bytes(response.read())
                    self._emit(
                        "response",
                        url=url,
                        attempt=attempt + 1,
                        status=getattr(response, "status", None),
                    )
                    return self._decode_json(response_bytes, url)
            except (TimeoutError, socket.timeout) as exc:
                client_error = PypiClientError(
                    f"unable to reach OSV: {exc}; retrying may help",
                    transient=True,
                    url=url,
                    code="advisory",
                    subcode="network_timeout",
                )
            except error.HTTPError as exc:
                transient = exc.code in TRANSIENT_HTTP_STATUS_CODES
                client_error = PypiClientError(
                    f"OSV returned HTTP {exc.code} for {url}",
                    transient=transient,
                    status_code=exc.code,
                    url=url,
                    code="advisory",
                    subcode="http_transient" if transient else "http_error",
                )
            except error.URLError as exc:
                client_error = PypiClientError(
                    f"unable to reach OSV: {exc.reason}; retrying may help",
                    transient=True,
                    url=url,
                    code="advisory",
                    subcode="network_error",
                )
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
            delay = self.backoff_factor * (2**attempt)
            self._emit("retry", url=url, attempt=attempt + 1, delay=delay)
            self.sleep(delay)
        raise AssertionError("unreachable")

    def _decode_json(self, payload: bytes, url: str) -> dict[str, Any]:
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise PypiClientError(
                f"OSV returned malformed JSON for {url}",
                transient=False,
                url=url,
                code="advisory",
                subcode="json_malformed",
            ) from exc
        if not isinstance(decoded, dict):
            raise PypiClientError(
                f"OSV returned a non-object JSON response for {url}",
                transient=False,
                url=url,
                code="advisory",
                subcode="json_non_object",
            )
        return decoded

    def _emit(self, event: str, **payload: Any) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)


@dataclass(slots=True)
class CisaKevClient:
    url: str = CISA_KEV_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _catalog: dict[str, dict[str, Any]] | None = field(
        default=None,
        init=False,
    )

    def query(self, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        requested = {
            identifier.strip().upper()
            for identifier in cve_ids
            if CVE_PATTERN.fullmatch(identifier.strip())
        }
        if not requested:
            return {}
        if self._catalog is None:
            if self.offline:
                raise _offline_error(self.url, source="CISA KEV")
            payload = _get_json(self, self.url, source="CISA KEV")
            vulnerabilities = payload.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise _response_shape_error(self.url, source="CISA KEV")
            catalog: dict[str, dict[str, Any]] = {}
            for item in vulnerabilities:
                if not isinstance(item, dict):
                    continue
                identifier = item.get("cveID")
                if (
                    isinstance(identifier, str)
                    and CVE_PATTERN.fullmatch(identifier)
                ):
                    catalog[identifier.upper()] = item
            self._catalog = catalog
        else:
            self._emit("cache_hit", url=self.url, kind="json")
        return {
            identifier: self._catalog[identifier]
            for identifier in sorted(requested)
            if identifier in self._catalog
        }

    def _emit(self, event: str, **payload: Any) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)


@dataclass(slots=True)
class EpssClient:
    base_url: str = EPSS_BASE_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _cache: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)

    def query(self, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        requested = sorted(
            {
                identifier.strip().upper()
                for identifier in cve_ids
                if CVE_PATTERN.fullmatch(identifier.strip())
            }
        )
        if not requested:
            return {}
        missing = [
            identifier
            for identifier in requested
            if identifier not in self._cache
        ]
        if missing and self.offline:
            raise _offline_error(self.base_url, source="FIRST EPSS")
        for offset in range(0, len(missing), 100):
            batch = missing[offset : offset + 100]
            url = self.base_url + "?" + parse.urlencode(
                {"cve": ",".join(batch)}
            )
            payload = _get_json(self, url, source="FIRST EPSS")
            data = payload.get("data")
            if not isinstance(data, list):
                raise _response_shape_error(url, source="FIRST EPSS")
            returned: set[str] = set()
            for item in data:
                if not isinstance(item, dict):
                    continue
                identifier = item.get("cve")
                if not isinstance(identifier, str):
                    continue
                normalized = identifier.upper()
                if normalized not in batch:
                    continue
                score = _optional_float(item.get("epss"))
                percentile = _optional_float(item.get("percentile"))
                self._cache[normalized] = {
                    "cve": normalized,
                    "epss": score,
                    "percentile": percentile,
                    "date": _optional_string(item.get("date")),
                }
                returned.add(normalized)
            for identifier in set(batch) - returned:
                self._cache[identifier] = {}
        for identifier in requested:
            if identifier in self._cache and identifier not in missing:
                self._emit("cache_hit", url=self.base_url, kind="json")
        return {
            identifier: self._cache[identifier]
            for identifier in requested
            if self._cache.get(identifier)
        }

    def _emit(self, event: str, **payload: Any) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)


@dataclass(frozen=True, slots=True)
class OsvProvider:
    name: str
    client: OsvQueryClient


@dataclass(slots=True)
class VulnerabilityIntelligenceClient:
    providers: tuple[OsvProvider, ...] = ()
    advisory_sources: tuple[AdvisorySourceClient, ...] = ()
    kev_client: CisaKevClient | None = None
    epss_client: EpssClient | None = None
    snapshot_store: AdvisorySnapshotStore | None = None
    max_workers: int = 8
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    _cache: dict[tuple[str, str], list[VulnerabilityRecord]] = field(
        default_factory=dict,
        init=False,
    )
    _enriched: set[tuple[str, str]] = field(default_factory=set, init=False)
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    def query(
        self,
        project: str,
        version: str,
        pypi_vulnerabilities: Sequence[VulnerabilityRecord] = (),
    ) -> list[VulnerabilityRecord]:
        provider_records, enriched = self._cached_provider_records(
            project,
            version,
        )
        vulnerabilities = merge_vulnerabilities(
            deepcopy(list(pypi_vulnerabilities)),
            provider_records,
        )
        if not enriched or pypi_vulnerabilities:
            self._enrich(vulnerabilities)
        return sorted(
            vulnerabilities,
            key=lambda item: (
                item.withdrawn,
                item.id.upper(),
            ),
        )

    def prefetch(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> None:
        ordered: list[tuple[str, str]] = list(
            dict.fromkeys(
                (str(canonicalize_name(project)), version)
                for project, version in packages
            )
        )
        missing = []
        for project, version in ordered:
            key = (project, version)
            with self._lock:
                if key in self._cache:
                    continue
            snapshot = (
                self.snapshot_store.get(project, version)
                if self.snapshot_store is not None
                else None
            )
            if snapshot is not None:
                with self._lock:
                    self._cache[key] = snapshot
                    self._enriched.add(key)
                self._emit(
                    "cache_hit",
                    {
                        "kind": "advisory-snapshot",
                        "project": project,
                        "version": version,
                    },
                )
                continue
            missing.append(key)
        if not missing:
            return

        grouped: dict[tuple[str, str], list[VulnerabilityRecord]] = {
            key: [] for key in missing
        }
        provider_results = self._query_providers_batch(missing)
        for key, records in provider_results.items():
            grouped[key].extend(records)
        source_results = self._query_sources_batch(missing)
        for key, records in source_results.items():
            grouped[key].extend(records)

        merged_by_key = {
            key: merge_vulnerabilities(records)
            for key, records in grouped.items()
        }
        all_records = [
            record
            for records in merged_by_key.values()
            for record in records
        ]
        self._enrich(all_records)
        with self._lock:
            for key, records in merged_by_key.items():
                self._cache[key] = deepcopy(records)
                self._enriched.add(key)
                if self.snapshot_store is not None:
                    self.snapshot_store.put(key[0], key[1], records)

    def flush_snapshots(self) -> None:
        if self.snapshot_store is not None:
            self.snapshot_store.write()

    def _cached_provider_records(
        self,
        project: str,
        version: str,
    ) -> tuple[list[VulnerabilityRecord], bool]:
        key = (canonicalize_name(project), version)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                return deepcopy(cached), key in self._enriched
        self.prefetch([key])
        with self._lock:
            return deepcopy(self._cache.get(key, [])), key in self._enriched

    def _query_providers_batch(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[VulnerabilityRecord]]:
        combined: dict[tuple[str, str], list[VulnerabilityRecord]] = {
            package: [] for package in packages
        }
        if not self.providers:
            return combined
        workers = min(max(1, self.max_workers), len(self.providers))
        provider_results: dict[
            int,
            dict[tuple[str, str], list[VulnerabilityRecord]],
        ] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._query_provider_batch,
                    provider,
                    packages,
                ): index
                for index, provider in enumerate(self.providers)
            }
            for future in as_completed(futures):
                provider_results[futures[future]] = future.result()
        for index in range(len(self.providers)):
            for key, records in provider_results[index].items():
                combined[key].extend(records)
        return combined

    def _query_provider_batch(
        self,
        provider: OsvProvider,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[VulnerabilityRecord]]:
        with _instrument_request_hook(provider.client, self._emit):
            query_batch = getattr(provider.client, "query_batch", None)
            if callable(query_batch):
                raw_results = query_batch(packages)
            else:
                raw_results = {
                    package: provider.client.query(*package)
                    for package in packages
                }
        return {
            package: parse_osv_vulnerabilities(
                raw_results.get(package, []),
                project=package[0],
                source=provider.name,
            )
            for package in packages
        }

    def _query_sources_batch(
        self,
        packages: Sequence[tuple[str, str]],
    ) -> dict[tuple[str, str], list[VulnerabilityRecord]]:
        combined: dict[tuple[str, str], list[VulnerabilityRecord]] = {
            package: [] for package in packages
        }
        tasks = [
            (source, package)
            for source in self.advisory_sources
            for package in packages
        ]
        if not tasks:
            return combined
        workers = min(max(1, self.max_workers), len(tasks))
        ordered_results: dict[
            int,
            tuple[AdvisorySourceClient, tuple[str, str], Sequence[VulnerabilityRecord]],
        ] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(source.query, *package): (index, source, package)
                for index, (source, package) in enumerate(tasks)
            }
            for future in as_completed(futures):
                index, source, package = futures[future]
                ordered_results[index] = (source, package, future.result())
        for index in range(len(tasks)):
            source, package, values = ordered_results[index]
            for record in values:
                if not isinstance(record, VulnerabilityRecord):
                    raise TypeError(
                        f"advisory plugin {source.name!r} returned "
                        f"{type(record).__name__}, expected VulnerabilityRecord"
                    )
                combined[package].append(deepcopy(record))
        return combined

    def _enrich(self, vulnerabilities: list[VulnerabilityRecord]) -> None:
        if self.kev_client is None and self.epss_client is None:
            return
        cve_ids = sorted(
            {
                identifier
                for vulnerability in vulnerabilities
                for identifier in _cve_identifiers(vulnerability)
            }
        )
        if not cve_ids:
            return
        tasks = []
        workers = min(
            max(1, self.max_workers),
            int(self.kev_client is not None) + int(self.epss_client is not None),
        )
        with ThreadPoolExecutor(max_workers=workers) as executor:
            if self.kev_client is not None:
                tasks.append(
                    (
                        "kev",
                        executor.submit(
                            self._query_enricher,
                            self.kev_client,
                            cve_ids,
                        ),
                    )
                )
            if self.epss_client is not None:
                tasks.append(
                    (
                        "epss",
                        executor.submit(
                            self._query_enricher,
                            self.epss_client,
                            cve_ids,
                        ),
                    )
                )
            results = {
                name: future.result()
                for name, future in tasks
            }
        _apply_enrichment(
            vulnerabilities,
            kev=results.get("kev", {}),
            epss=results.get("epss", {}),
        )

    def _query_enricher(
        self,
        client: CisaKevClient | EpssClient,
        cve_ids: Sequence[str],
    ) -> dict[str, dict[str, Any]]:
        with _instrument_request_hook(client, self._emit):
            return client.query(cve_ids)

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.request_hook is not None:
            self.request_hook(event, payload)


@contextmanager
def _instrument_request_hook(
    client: Any,
    hook: Callable[[str, dict[str, Any]], None],
) -> Any:
    previous_hook = getattr(client, "request_hook", None)

    def combined(event: str, payload: dict[str, Any]) -> None:
        hook(event, payload)
        if previous_hook is not None:
            previous_hook(event, payload)

    client.request_hook = combined
    try:
        yield
    finally:
        client.request_hook = previous_hook


def _get_json(
    client: CisaKevClient | EpssClient,
    url: str,
    *,
    source: str,
) -> dict[str, Any]:
    _require_http_url(url, source=source)
    headers = {
        "Accept": "application/json",
        "User-Agent": client.user_agent,
    }
    for attempt in range(client.max_retries + 1):
        client._emit("request", url=url, attempt=attempt + 1, method="GET")
        req = request.Request(url, headers=headers, method="GET")
        try:
            # The URL scheme is constrained to HTTP(S) before the request is built.
            # nosemgrep
            with request.urlopen(  # nosec B310
                req,
                timeout=client.timeout,
            ) as response:
                response_bytes = bytes(response.read())
                client._emit(
                    "response",
                    url=url,
                    attempt=attempt + 1,
                    status=getattr(response, "status", None),
                )
                return _decode_json_object(response_bytes, url, source=source)
        except (TimeoutError, socket.timeout) as exc:
            client_error = PypiClientError(
                f"unable to reach {source}: {exc}; retrying may help",
                transient=True,
                url=url,
                code="advisory",
                subcode="network_timeout",
            )
        except error.HTTPError as exc:
            transient = exc.code in TRANSIENT_HTTP_STATUS_CODES
            client_error = PypiClientError(
                f"{source} returned HTTP {exc.code} for {url}",
                transient=transient,
                status_code=exc.code,
                url=url,
                code="advisory",
                subcode="http_transient" if transient else "http_error",
            )
        except error.URLError as exc:
            client_error = PypiClientError(
                f"unable to reach {source}: {exc.reason}; retrying may help",
                transient=True,
                url=url,
                code="advisory",
                subcode="network_error",
            )

        client._emit(
            "failure",
            url=url,
            attempt=attempt + 1,
            transient=client_error.transient,
            message=str(client_error),
            code=client_error.code,
            subcode=client_error.subcode,
            status_code=client_error.status_code,
        )
        if not client_error.transient or attempt == client.max_retries:
            raise client_error
        delay = client.backoff_factor * (2**attempt)
        client._emit("retry", url=url, attempt=attempt + 1, delay=delay)
        client.sleep(delay)
    raise AssertionError("unreachable")


def _decode_json_object(
    payload: bytes,
    url: str,
    *,
    source: str,
) -> dict[str, Any]:
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PypiClientError(
            f"{source} returned malformed JSON for {url}",
            transient=False,
            url=url,
            code="advisory",
            subcode="json_malformed",
        ) from exc
    if not isinstance(decoded, dict):
        raise PypiClientError(
            f"{source} returned a non-object JSON response for {url}",
            transient=False,
            url=url,
            code="advisory",
            subcode="json_non_object",
        )
    return decoded


def _offline_error(url: str, *, source: str) -> PypiClientError:
    return PypiClientError(
        f"offline mode enabled and {source} queries are unavailable",
        transient=False,
        url=url,
        code="advisory",
        subcode="offline_unavailable",
    )


def _response_shape_error(url: str, *, source: str) -> PypiClientError:
    return PypiClientError(
        f"{source} returned an unexpected response shape",
        transient=False,
        url=url,
        code="advisory",
        subcode="response_shape_invalid",
    )


def _require_http_url(url: str, *, source: str) -> None:
    if parse.urlparse(url).scheme not in {"http", "https"}:
        raise PypiClientError(
            f"{source} URL must use HTTP or HTTPS: {url}",
            transient=False,
            url=url,
            code="advisory",
            subcode="url_scheme_invalid",
        )


def parse_osv_vulnerabilities(
    items: list[dict[str, Any]],
    *,
    project: str,
    source: str = OSV_SOURCE,
) -> list[VulnerabilityRecord]:
    vulnerabilities: list[VulnerabilityRecord] = []
    for item in items:
        vulnerability_id = str(item.get("id") or "unknown")
        cvss_score, cvss_vector, cvss_version = _extract_osv_cvss(
            item,
            project=project,
        )
        withdrawn_at = _optional_string(item.get("withdrawn"))
        vulnerabilities.append(
            VulnerabilityRecord(
                id=vulnerability_id,
                summary=str(
                    item.get("summary")
                    or item.get("details")
                    or "No summary provided."
                ),
                aliases=_string_list(item.get("aliases")),
                source=source,
                severity=_extract_osv_severity(
                    item,
                    project=project,
                    cvss_score=cvss_score,
                ),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                cwes=_extract_osv_cwes(item, project=project),
                fixed_in=_extract_osv_fixed_versions(item, project=project),
                link=_extract_osv_link(item, vulnerability_id),
                withdrawn=withdrawn_at is not None,
                withdrawn_at=withdrawn_at,
            )
        )
    return vulnerabilities


def parse_pypi_vulnerabilities(
    items: Iterable[dict[str, Any]],
) -> list[VulnerabilityRecord]:
    vulnerabilities: list[VulnerabilityRecord] = []
    for item in items:
        score = _optional_float(item.get("cvss_score"))
        vector = _optional_string(item.get("cvss_vector"))
        version = _cvss_version(vector)
        severity = normalize_severity(item.get("severity"), score=score)
        withdrawn_at = _optional_string(item.get("withdrawn_at"))
        vulnerabilities.append(
            VulnerabilityRecord(
                id=str(item.get("id") or "unknown"),
                summary=str(
                    item.get("summary")
                    or item.get("details")
                    or "No summary provided."
                ),
                aliases=_string_list(item.get("aliases")),
                source=str(item.get("source") or "PyPI"),
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                cvss_version=version,
                cwes=_normalize_cwes(item.get("cwes")),
                fixed_in=_string_list(item.get("fixed_in")),
                link=_optional_string(item.get("link")),
                withdrawn=bool(item.get("withdrawn") or withdrawn_at),
                withdrawn_at=withdrawn_at,
            )
        )
    return vulnerabilities


def merge_vulnerabilities(
    *groups: list[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    merged: list[VulnerabilityRecord] = []
    for group in groups:
        for vulnerability in group:
            identifiers = _vulnerability_identifiers(vulnerability)
            matching_indexes = [
                index
                for index, candidate in enumerate(merged)
                if identifiers & _vulnerability_identifiers(candidate)
            ]
            if not matching_indexes:
                merged.append(vulnerability)
                continue
            existing = merged[matching_indexes[0]]
            _merge_vulnerability(existing, vulnerability)
            for index in reversed(matching_indexes[1:]):
                _merge_vulnerability(existing, merged[index])
                del merged[index]
    return merged


def _merge_vulnerability(
    existing: VulnerabilityRecord,
    incoming: VulnerabilityRecord,
) -> None:
    identifiers = (
        {existing.id, incoming.id}
        | set(existing.aliases)
        | set(incoming.aliases)
    )
    existing.aliases = sorted(
        identifier for identifier in identifiers if identifier != existing.id
    )
    existing.source = _merge_sources(existing.source, incoming.source)
    existing.severity = _higher_severity(existing.severity, incoming.severity)
    if (
        incoming.cvss_score is not None
        and (
            existing.cvss_score is None
            or incoming.cvss_score > existing.cvss_score
        )
    ):
        existing.cvss_score = incoming.cvss_score
        existing.cvss_vector = incoming.cvss_vector
        existing.cvss_version = incoming.cvss_version
    elif existing.cvss_vector is None and incoming.cvss_vector is not None:
        existing.cvss_vector = incoming.cvss_vector
        existing.cvss_version = incoming.cvss_version
    existing.cwes = sorted(set(existing.cwes) | set(incoming.cwes))
    existing.fixed_in = sorted(set(existing.fixed_in) | set(incoming.fixed_in))
    existing.link = existing.link or incoming.link
    existing.withdrawn = existing.withdrawn and incoming.withdrawn
    if existing.withdrawn:
        existing.withdrawn_at = _latest_timestamp(
            existing.withdrawn_at,
            incoming.withdrawn_at,
        )
    else:
        existing.withdrawn_at = None
    if incoming.kev:
        existing.kev = True
        existing.kev_date_added = (
            existing.kev_date_added or incoming.kev_date_added
        )
        existing.kev_due_date = existing.kev_due_date or incoming.kev_due_date
        existing.kev_required_action = (
            existing.kev_required_action or incoming.kev_required_action
        )
        existing.kev_known_ransomware_campaign_use = (
            existing.kev_known_ransomware_campaign_use
            or incoming.kev_known_ransomware_campaign_use
        )
    if (
        incoming.epss_score is not None
        and (
            existing.epss_score is None
            or incoming.epss_score > existing.epss_score
        )
    ):
        existing.epss_score = incoming.epss_score
        existing.epss_percentile = incoming.epss_percentile
        existing.epss_date = incoming.epss_date
    if existing.summary == "No summary provided.":
        existing.summary = incoming.summary


def _vulnerability_identifiers(vulnerability: VulnerabilityRecord) -> set[str]:
    return {
        identifier.strip().upper()
        for identifier in [vulnerability.id, *vulnerability.aliases]
        if identifier.strip()
    }


def _merge_sources(first: str | None, second: str | None) -> str | None:
    sources: list[str] = []
    for value in (first, second):
        if not value:
            continue
        for source in value.split(","):
            normalized = source.strip()
            if normalized and normalized not in sources:
                sources.append(normalized)
    return ", ".join(sources) or None


def _higher_severity(first: str | None, second: str | None) -> str | None:
    if not first:
        return second
    if not second:
        return first
    ranking = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MODERATE": 2,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    first_rank = ranking.get(first.upper())
    second_rank = ranking.get(second.upper())
    if first_rank is None or second_rank is None:
        return first
    return second if second_rank > first_rank else first


def _extract_osv_severity(
    item: dict[str, Any],
    *,
    project: str,
    cvss_score: float | None = None,
) -> str | None:
    database_specific = item.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return normalize_severity(severity, score=cvss_score)

    for affected in _matching_affected_items(item, project=project):
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if not isinstance(container, dict):
                continue
            severity = container.get("severity")
            if isinstance(severity, str) and severity:
                return normalize_severity(severity, score=cvss_score)

    return normalize_severity(None, score=cvss_score)


def _severity_score(severity_items: object) -> str | None:
    if isinstance(severity_items, list):
        for severity_item in severity_items:
            if not isinstance(severity_item, dict):
                continue
            severity_type = severity_item.get("type")
            score = severity_item.get("score")
            if isinstance(score, str) and score:
                if isinstance(severity_type, str) and severity_type:
                    return f"{severity_type}: {score}"
                return score
    return None


def normalize_severity(
    value: object,
    *,
    score: float | None = None,
) -> str | None:
    if isinstance(value, str):
        normalized = value.strip().upper()
        aliases = {
            "MODERATE": "MEDIUM",
            "IMPORTANT": "HIGH",
            "NONE": "NONE",
            "UNKNOWN": "UNKNOWN",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        if normalized in aliases:
            return aliases[normalized]
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _extract_osv_cvss(
    item: dict[str, Any],
    *,
    project: str,
) -> tuple[float | None, str | None, str | None]:
    candidates: list[tuple[float | None, str | None, str | None]] = []
    candidates.extend(_cvss_candidates(item.get("severity")))
    database_specific = item.get("database_specific")
    if isinstance(database_specific, dict):
        candidates.extend(_cvss_candidates_from_mapping(database_specific))
    for affected in _matching_affected_items(item, project=project):
        candidates.extend(_cvss_candidates(affected.get("severity")))
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if isinstance(container, dict):
                candidates.extend(_cvss_candidates_from_mapping(container))
    if not candidates:
        return None, None, None
    return max(
        candidates,
        key=lambda candidate: (
            candidate[0] is not None,
            candidate[0] if candidate[0] is not None else -1.0,
            candidate[1] is not None,
        ),
    )


def _cvss_candidates(
    value: object,
) -> list[tuple[float | None, str | None, str | None]]:
    if not isinstance(value, list):
        return []
    candidates: list[tuple[float | None, str | None, str | None]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        raw_score = item.get("score")
        severity_type = _optional_string(item.get("type"))
        if isinstance(raw_score, str) and (
            raw_score.upper().startswith("CVSS:")
            or "/" in raw_score
            and (severity_type or "").upper().startswith("CVSS")
        ):
            vector = _normalize_cvss_vector(raw_score, severity_type)
            candidates.append(
                (
                    _score_cvss_vector(vector),
                    vector,
                    _cvss_version(vector) or severity_type,
                )
            )
            continue
        score = _optional_float(raw_score)
        if score is not None:
            candidates.append((score, None, severity_type))
    return candidates


def _cvss_candidates_from_mapping(
    value: dict[str, Any],
) -> list[tuple[float | None, str | None, str | None]]:
    candidates: list[tuple[float | None, str | None, str | None]] = []
    for key in ("cvss", "cvss_vector", "cvss_v3", "cvss_v4"):
        vector = value.get(key)
        if isinstance(vector, str) and vector.upper().startswith("CVSS:"):
            candidates.append(
                (
                    _score_cvss_vector(vector),
                    vector,
                    _cvss_version(vector),
                )
            )
    for key in ("cvss_score", "score"):
        score = _optional_float(value.get(key))
        if score is not None:
            candidates.append((score, None, None))
    return candidates


def _score_cvss_vector(vector: str) -> float | None:
    version = _cvss_version(vector)
    if version in {"3.0", "3.1"}:
        return _score_cvss_v3(vector)
    if version == "2.0":
        return _score_cvss_v2(vector)
    return None


def _cvss_version(vector: str | None) -> str | None:
    if not vector:
        return None
    match = re.match(r"^CVSS:(\d+\.\d+)/", vector, re.IGNORECASE)
    return match.group(1) if match else None


def _normalize_cvss_vector(
    vector: str,
    severity_type: str | None,
) -> str:
    if vector.upper().startswith("CVSS:"):
        return vector
    versions = {
        "CVSS_V2": "2.0",
        "CVSS_V3": "3.1",
        "CVSS_V4": "4.0",
    }
    version = versions.get((severity_type or "").upper())
    return f"CVSS:{version}/{vector}" if version else vector


def _score_cvss_v3(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    try:
        scope = metrics["S"]
        confidentiality = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["C"]]
        integrity = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["I"]]
        availability = {"N": 0.0, "L": 0.22, "H": 0.56}[metrics["A"]]
        impact_subscore = 1 - (
            (1 - confidentiality)
            * (1 - integrity)
            * (1 - availability)
        )
        if scope == "U":
            impact = 6.42 * impact_subscore
        else:
            impact = (
                7.52 * (impact_subscore - 0.029)
                - 3.25 * ((impact_subscore - 0.02) ** 15)
            )
        privileges = (
            {
                "N": 0.85,
                "L": 0.62,
                "H": 0.27,
            }
            if scope == "U"
            else {
                "N": 0.85,
                "L": 0.68,
                "H": 0.50,
            }
        )[metrics["PR"]]
        exploitability = (
            8.22
            * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
            * {"L": 0.77, "H": 0.44}[metrics["AC"]]
            * privileges
            * {"N": 0.85, "R": 0.62}[metrics["UI"]]
        )
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    base = impact + exploitability
    if scope == "C":
        base *= 1.08
    return _round_up_tenth(min(base, 10.0))


def _score_cvss_v2(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    try:
        confidentiality = {"N": 0.0, "P": 0.275, "C": 0.660}[metrics["C"]]
        integrity = {"N": 0.0, "P": 0.275, "C": 0.660}[metrics["I"]]
        availability = {"N": 0.0, "P": 0.275, "C": 0.660}[metrics["A"]]
        impact = 10.41 * (
            1
            - (1 - confidentiality)
            * (1 - integrity)
            * (1 - availability)
        )
        exploitability = (
            20
            * {"L": 0.395, "A": 0.646, "N": 1.0}[metrics["AV"]]
            * {"H": 0.35, "M": 0.61, "L": 0.71}[metrics["AC"]]
            * {"M": 0.45, "S": 0.56, "N": 0.704}[metrics["AU"]]
        )
    except KeyError:
        return None
    impact_factor = 0.0 if impact == 0 else 1.176
    return round(
        ((0.6 * impact) + (0.4 * exploitability) - 1.5)
        * impact_factor,
        1,
    )


def _cvss_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for component in vector.split("/")[1:]:
        key, separator, value = component.partition(":")
        if separator and key and value:
            metrics[key.upper()] = value.upper()
    return metrics


def _round_up_tenth(value: float) -> float:
    return math.ceil((value * 10) - 1e-10) / 10.0


def _extract_osv_fixed_versions(item: dict[str, Any], *, project: str) -> list[str]:
    versions: set[str] = set()
    for affected in _matching_affected_items(item, project=project):
        ranges = affected.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_item in ranges:
            if not isinstance(range_item, dict):
                continue
            if str(range_item.get("type") or "").upper() == "GIT":
                continue
            events = range_item.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed:
                    versions.add(fixed)
    return sorted(versions)


def _extract_osv_cwes(
    item: dict[str, Any],
    *,
    project: str,
) -> list[str]:
    values: list[object] = []
    database_specific = item.get("database_specific")
    if isinstance(database_specific, dict):
        values.extend(
            database_specific.get(key)
            for key in ("cwe", "cwes", "cwe_ids")
        )
    for affected in _matching_affected_items(item, project=project):
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if not isinstance(container, dict):
                continue
            values.extend(
                container.get(key)
                for key in ("cwe", "cwes", "cwe_ids")
            )
    return sorted(
        {
            cwe
            for value in values
            for cwe in _normalize_cwes(value)
        }
    )


def _normalize_cwes(value: object) -> list[str]:
    candidates: list[str] = []
    if isinstance(value, str):
        candidates.extend(re.split(r"[\s,;]+", value))
    elif isinstance(value, list):
        candidates.extend(str(item) for item in value)
    elif isinstance(value, dict):
        candidates.extend(str(item) for item in value.values())
    return sorted(
        {
            match.group(0).upper()
            for candidate in candidates
            for match in re.finditer(
                r"CWE-\d+",
                candidate,
                re.IGNORECASE,
            )
        }
    )


def _matching_affected_items(
    item: dict[str, Any],
    *,
    project: str,
) -> list[dict[str, Any]]:
    affected_items = item.get("affected")
    if not isinstance(affected_items, list):
        return []
    project_key = canonicalize_name(project)
    matches: list[dict[str, Any]] = []
    for affected in affected_items:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        ecosystem = package.get("ecosystem")
        if (
            isinstance(name, str)
            and canonicalize_name(name) == project_key
            and (not isinstance(ecosystem, str) or ecosystem == "PyPI")
        ):
            matches.append(affected)
    return matches


def _extract_osv_link(item: dict[str, Any], vulnerability_id: str) -> str:
    references = item.get("references")
    if isinstance(references, list):
        for preferred_type in ("ADVISORY", "WEB", "REPORT"):
            for reference in references:
                if not isinstance(reference, dict):
                    continue
                if str(reference.get("type") or "").upper() != preferred_type:
                    continue
                url = reference.get("url")
                if isinstance(url, str) and url.startswith(("https://", "http://")):
                    return url
    return f"https://osv.dev/vulnerability/{vulnerability_id}"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _cve_identifiers(
    vulnerability: VulnerabilityRecord,
) -> list[str]:
    return sorted(
        {
            identifier.strip().upper()
            for identifier in [vulnerability.id, *vulnerability.aliases]
            if CVE_PATTERN.fullmatch(identifier.strip())
        }
    )


def _apply_enrichment(
    vulnerabilities: list[VulnerabilityRecord],
    *,
    kev: dict[str, dict[str, Any]],
    epss: dict[str, dict[str, Any]],
) -> None:
    for vulnerability in vulnerabilities:
        identifiers = _cve_identifiers(vulnerability)
        kev_entries = [
            kev[identifier]
            for identifier in identifiers
            if identifier in kev
        ]
        if kev_entries:
            entry = min(
                kev_entries,
                key=lambda item: str(item.get("dateAdded") or ""),
            )
            vulnerability.kev = True
            vulnerability.kev_date_added = _optional_string(
                entry.get("dateAdded")
            )
            vulnerability.kev_due_date = _optional_string(
                entry.get("dueDate")
            )
            vulnerability.kev_required_action = _optional_string(
                entry.get("requiredAction")
            )
            vulnerability.kev_known_ransomware_campaign_use = _optional_string(
                entry.get("knownRansomwareCampaignUse")
            )
        epss_entries = [
            epss[identifier]
            for identifier in identifiers
            if identifier in epss
        ]
        if epss_entries:
            entry = max(
                epss_entries,
                key=lambda item: _optional_float(item.get("epss")) or -1.0,
            )
            vulnerability.epss_score = _optional_float(entry.get("epss"))
            vulnerability.epss_percentile = _optional_float(
                entry.get("percentile")
            )
            vulnerability.epss_date = _optional_string(entry.get("date"))


def _optional_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _latest_timestamp(
    first: str | None,
    second: str | None,
) -> str | None:
    values = [value for value in (first, second) if value]
    return max(values) if values else None
