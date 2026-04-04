from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


PYPI_BASE_URL = "https://pypi.org"
JSON_ACCEPT = "application/json"
INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"


class PypiClientError(RuntimeError):
    """Raised when PyPI cannot satisfy a request."""


@dataclass(slots=True)
class PypiClient:
    base_url: str = PYPI_BASE_URL
    timeout: float = 10.0

    def get_project(self, project: str) -> dict[str, Any]:
        return self._get_json(f"/pypi/{parse.quote(project)}/json", accept=JSON_ACCEPT)

    def get_release(self, project: str, version: str) -> dict[str, Any]:
        project_q = parse.quote(project)
        version_q = parse.quote(version)
        return self._get_json(f"/pypi/{project_q}/{version_q}/json", accept=JSON_ACCEPT)

    def get_provenance(self, project: str, version: str, filename: str) -> dict[str, Any]:
        project_q = parse.quote(project)
        version_q = parse.quote(version)
        filename_q = parse.quote(filename)
        path = f"/integrity/{project_q}/{version_q}/{filename_q}/provenance"
        return self._get_json(path, accept=INTEGRITY_ACCEPT)

    def download_distribution(self, url: str) -> bytes:
        req = request.Request(url, headers={"User-Agent": "trustcheck/0.1"})

        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                return response.read()
        except error.HTTPError as exc:
            raise PypiClientError(f"artifact download failed with HTTP {exc.code} for {url}") from exc
        except error.URLError as exc:
            raise PypiClientError(f"unable to download artifact: {exc.reason}") from exc

    def _get_json(self, path: str, *, accept: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        req = request.Request(url, headers={"Accept": accept, "User-Agent": "trustcheck/0.1"})

        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                return json.load(response)
        except error.HTTPError as exc:
            if exc.code == 404:
                raise PypiClientError(f"resource not found: {url}") from exc
            raise PypiClientError(f"PyPI returned HTTP {exc.code} for {url}") from exc
        except error.URLError as exc:
            raise PypiClientError(f"unable to reach PyPI: {exc.reason}") from exc
