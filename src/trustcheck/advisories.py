from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib import error, parse, request

from packaging.utils import canonicalize_name

from .models import VulnerabilityRecord
from .pypi import DEFAULT_USER_AGENT, TRANSIENT_HTTP_STATUS_CODES, PypiClientError

OSV_BASE_URL = "https://api.osv.dev"
OSV_SOURCE = "OSV"


@dataclass(slots=True)
class OsvClient:
    base_url: str = OSV_BASE_URL
    timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    max_retries: int = 2
    backoff_factor: float = 0.25
    offline: bool = False
    request_hook: Callable[[str, dict[str, Any]], None] | None = None
    sleep: Callable[[float], None] = time.sleep
    _cache: dict[tuple[str, str], list[dict[str, Any]]] = field(
        default_factory=dict,
        init=False,
    )

    def query(self, project: str, version: str) -> list[dict[str, Any]]:
        cache_key = (canonicalize_name(project), version)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._emit("cache_hit", url=f"{self.base_url}/v1/query", kind="json")
            return cached
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

        self._cache[cache_key] = vulnerabilities
        return vulnerabilities

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
) -> list[VulnerabilityRecord]:
    vulnerabilities: list[VulnerabilityRecord] = []
    for item in items:
        vulnerability_id = str(item.get("id") or "unknown")
        vulnerabilities.append(
            VulnerabilityRecord(
                id=vulnerability_id,
                summary=str(
                    item.get("summary")
                    or item.get("details")
                    or "No summary provided."
                ),
                aliases=_string_list(item.get("aliases")),
                source=OSV_SOURCE,
                severity=_extract_osv_severity(item, project=project),
                fixed_in=_extract_osv_fixed_versions(item, project=project),
                link=_extract_osv_link(item, vulnerability_id),
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
            existing = next(
                (
                    candidate
                    for candidate in merged
                    if identifiers & _vulnerability_identifiers(candidate)
                ),
                None,
            )
            if existing is None:
                merged.append(vulnerability)
                continue
            _merge_vulnerability(existing, vulnerability)
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
    existing.fixed_in = sorted(set(existing.fixed_in) | set(incoming.fixed_in))
    existing.link = existing.link or incoming.link
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


def _extract_osv_severity(item: dict[str, Any], *, project: str) -> str | None:
    database_specific = item.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity.upper()

    for affected in _matching_affected_items(item, project=project):
        affected_severity = _severity_score(affected.get("severity"))
        if affected_severity:
            return affected_severity
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if not isinstance(container, dict):
                continue
            severity = container.get("severity")
            if isinstance(severity, str) and severity:
                return severity.upper()

    return _severity_score(item.get("severity"))


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
