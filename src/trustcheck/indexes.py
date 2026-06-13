from __future__ import annotations

import base64
import json
import netrc
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

SIMPLE_JSON_ACCEPT = (
    "application/vnd.pypi.simple.v1+json, "
    "application/vnd.pypi.simple.latest+json;q=0.9, text/html;q=0.1"
)
DEFAULT_INDEX_URL = "https://pypi.org/simple"
KEYRING_PROVIDERS = {"auto", "disabled", "import", "subprocess"}
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
UrlOpener = Callable[..., Any]


class IndexError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class IndexConfiguration:
    index_url: str = DEFAULT_INDEX_URL
    extra_index_urls: tuple[str, ...] = ()
    keyring_provider: str = "auto"

    def __post_init__(self) -> None:
        if self.keyring_provider not in KEYRING_PROVIDERS:
            raise ValueError(
                "keyring provider must be auto, disabled, import, or subprocess"
            )
        _validate_index_url(self.index_url)
        for index_url in self.extra_index_urls:
            _validate_index_url(index_url)

    @property
    def all_urls(self) -> tuple[str, ...]:
        urls: list[str] = []
        seen: set[str] = set()
        for raw_url in (self.index_url, *self.extra_index_urls):
            normalized = normalize_index_url(raw_url)
            redacted = redact_url_credentials(normalized)
            if redacted not in seen:
                urls.append(normalized)
                seen.add(redacted)
        return tuple(urls)

    @property
    def has_multiple_indexes(self) -> bool:
        return len(self.all_urls) > 1

    def pip_arguments(self) -> list[str]:
        arguments = ["--index-url", self.index_url]
        for index_url in self.extra_index_urls:
            arguments.extend(["--extra-index-url", index_url])
        arguments.extend(["--keyring-provider", self.keyring_provider])
        return arguments

    def redacted(self) -> dict[str, object]:
        return {
            "index_url": redact_url_credentials(self.index_url),
            "extra_index_urls": [
                redact_url_credentials(url) for url in self.extra_index_urls
            ],
            "keyring_provider": self.keyring_provider,
        }


@dataclass(frozen=True, slots=True)
class IndexFile:
    filename: str
    url: str
    hashes: tuple[tuple[str, str], ...] = ()
    requires_python: str | None = None
    yanked: bool | str = False
    size: int | None = None
    upload_time: str | None = None
    metadata_url: str | None = None
    metadata_hashes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class IndexProject:
    name: str
    index_url: str
    files: tuple[IndexFile, ...] = ()
    api_version: str | None = None


@dataclass(frozen=True, slots=True)
class DependencyConfusionFinding:
    project: str
    indexes: tuple[str, ...]


@dataclass(slots=True)
class SimpleRepositoryClient:
    timeout: float = 15.0
    keyring_provider: str = "auto"
    opener: UrlOpener = request.urlopen
    runner: CommandRunner = subprocess.run
    python_executable: str = sys.executable
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    _cache: dict[tuple[str, str], IndexProject | None] = field(default_factory=dict)

    def get_project(self, index_url: str, project: str) -> IndexProject | None:
        normalized_index = normalize_index_url(index_url)
        normalized_name = canonicalize_name(project)
        cache_key = (redact_url_credentials(normalized_index), normalized_name)
        if cache_key in self._cache:
            return self._cache[cache_key]

        project_url = parse.urljoin(
            normalized_index,
            f"{parse.quote(normalized_name)}/",
        )
        try:
            payload, content_type, final_url = self._request(
                project_url,
                accept=SIMPLE_JSON_ACCEPT,
            )
        except error.HTTPError as exc:
            if exc.code == 404:
                self._cache[cache_key] = None
                return None
            raise IndexError(
                f"index returned HTTP {exc.code} for "
                f"{redact_url_credentials(project_url)}"
            ) from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise IndexError(
                f"unable to query package index "
                f"{redact_url_credentials(project_url)}: {exc}"
            ) from exc

        try:
            if "json" in content_type.lower() or payload.lstrip().startswith(b"{"):
                result = parse_simple_json(
                    payload,
                    project=project,
                    index_url=normalized_index,
                    response_url=final_url,
                )
            else:
                result = parse_simple_html(
                    payload,
                    project=project,
                    index_url=normalized_index,
                    response_url=final_url,
                )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise IndexError(
                f"invalid Simple Repository response from "
                f"{redact_url_credentials(project_url)}: {exc}"
            ) from exc
        self._cache[cache_key] = result
        return result

    def download(self, url: str, *, index_url: str | None = None) -> bytes:
        try:
            payload, _, _ = self._request(url, index_url=index_url)
        except (error.HTTPError, error.URLError, TimeoutError, OSError) as exc:
            raise IndexError(
                f"unable to download artifact from {redact_url_credentials(url)}: {exc}"
            ) from exc
        return payload

    def find_dependency_confusion(
        self,
        projects: Iterable[str],
        indexes: Sequence[str],
    ) -> tuple[DependencyConfusionFinding, ...]:
        if len(indexes) < 2:
            return ()
        findings: list[DependencyConfusionFinding] = []
        for project in sorted(set(projects), key=canonicalize_name):
            matches = [
                redact_url_credentials(index_url)
                for index_url in indexes
                if self.get_project(index_url, project) is not None
            ]
            if len(matches) > 1:
                findings.append(
                    DependencyConfusionFinding(
                        project=project,
                        indexes=tuple(matches),
                    )
                )
        return tuple(findings)

    def locate_artifact_index(
        self,
        project: str,
        artifact_url: str | None,
        indexes: Sequence[str],
    ) -> str | None:
        if len(indexes) == 1:
            return redact_url_credentials(indexes[0])
        if not artifact_url:
            return None
        normalized_artifact = redact_url_credentials(artifact_url)
        for index_url in indexes:
            index_project = self.get_project(index_url, project)
            if index_project is None:
                continue
            if any(
                redact_url_credentials(item.url) == normalized_artifact
                for item in index_project.files
            ):
                return redact_url_credentials(index_url)
        return None

    def _request(
        self,
        url: str,
        *,
        accept: str | None = None,
        index_url: str | None = None,
    ) -> tuple[bytes, str, str]:
        request_url, headers = self._authenticated_request(url, index_url=index_url)
        if accept:
            headers["Accept"] = accept
        req = request.Request(request_url, headers=headers)
        with self.opener(req, timeout=self.timeout) as response:
            payload = bytes(response.read())
            response_headers = getattr(response, "headers", {})
            content_type = (
                response_headers.get("Content-Type", "")
                if hasattr(response_headers, "get")
                else ""
            )
            final_url = (
                str(response.geturl())
                if hasattr(response, "geturl")
                else request_url
            )
            return payload, str(content_type), final_url

    def _authenticated_request(
        self,
        url: str,
        *,
        index_url: str | None,
    ) -> tuple[str, dict[str, str]]:
        parsed_request = parse.urlsplit(url)
        parsed_index = parse.urlsplit(index_url) if index_url else None
        credential_source = (
            index_url
            if index_url
            and parsed_index is not None
            and _same_origin(parsed_index, parsed_request)
            else url
        )
        parsed_credentials = parse.urlsplit(credential_source)
        username = (
            parse.unquote(parsed_credentials.username)
            if parsed_credentials.username is not None
            else None
        )
        password = (
            parse.unquote(parsed_credentials.password)
            if parsed_credentials.password is not None
            else None
        )
        hostname = parsed_credentials.hostname or parsed_request.hostname
        if username is None and hostname:
            username, password = self._netrc_credentials(hostname)
        if username is not None and password is None and hostname:
            password = self._keyring_password(hostname, username)

        clean_url = _without_url_credentials(url)
        headers = {"User-Agent": "trustcheck/simple-index"}
        if username is not None and password is not None:
            token = base64.b64encode(
                f"{username}:{password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        return clean_url, headers

    def _netrc_credentials(self, hostname: str) -> tuple[str | None, str | None]:
        try:
            authenticators = netrc.netrc().authenticators(hostname)
        except (FileNotFoundError, netrc.NetrcParseError, OSError):
            return None, None
        if authenticators is None:
            return None, None
        login, _, password = authenticators
        return login, password

    def _keyring_password(self, service: str, username: str) -> str | None:
        provider = self.keyring_provider
        if provider == "disabled":
            return None
        if provider in {"auto", "import"}:
            try:
                import keyring
            except ImportError as exc:
                if provider == "import":
                    raise IndexError(
                        "keyring provider 'import' requested but keyring is not installed"
                    ) from exc
                return self._subprocess_keyring_password(
                    service,
                    username,
                    required=False,
                )
            try:
                return keyring.get_password(service, username)
            except Exception as exc:
                if provider == "import":
                    raise IndexError(
                        f"keyring credential lookup failed: {exc}"
                    ) from exc
                return None

        return self._subprocess_keyring_password(
            service,
            username,
            required=True,
        )

    def _subprocess_keyring_password(
        self,
        service: str,
        username: str,
        *,
        required: bool,
    ) -> str | None:
        try:
            completed = self.runner(
                ["keyring", "get", service, username],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            if not required:
                return None
            raise IndexError(
                "keyring provider 'subprocess' requested but keyring is unavailable"
            ) from exc
        if completed.returncode != 0:
            if not required:
                return None
            detail = completed.stderr.strip()
            raise IndexError(
                "keyring credential lookup failed"
                + (f": {detail}" if detail else "")
            )
        password = completed.stdout.rstrip("\r\n")
        return password or None


def parse_simple_json(
    payload: bytes,
    *,
    project: str,
    index_url: str,
    response_url: str,
) -> IndexProject:
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("JSON response must be an object")
    meta = raw.get("meta")
    api_version = (
        str(meta.get("api-version"))
        if isinstance(meta, dict) and meta.get("api-version") is not None
        else None
    )
    if api_version is not None and api_version.split(".", 1)[0] != "1":
        raise ValueError(f"unsupported Simple Repository API version {api_version!r}")
    raw_files = raw.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("JSON response is missing the files array")

    files: list[IndexFile] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            continue
        filename = raw_file.get("filename")
        raw_url = raw_file.get("url")
        if not isinstance(filename, str) or not filename:
            continue
        if not isinstance(raw_url, str) or not raw_url:
            continue
        metadata_value = raw_file.get("core-metadata")
        if metadata_value is None:
            metadata_value = raw_file.get("dist-info-metadata")
        metadata_hashes = _metadata_hashes(metadata_value)
        file_url = parse.urljoin(response_url, raw_url)
        files.append(
            IndexFile(
                filename=filename,
                url=redact_url_credentials(file_url),
                hashes=_hash_mapping(raw_file.get("hashes")),
                requires_python=_optional_string(raw_file.get("requires-python")),
                yanked=_yanked_value(raw_file.get("yanked")),
                size=_optional_int(raw_file.get("size")),
                upload_time=_optional_string(raw_file.get("upload-time")),
                metadata_url=(
                    f"{redact_url_credentials(file_url)}.metadata"
                    if metadata_value not in (None, False)
                    else None
                ),
                metadata_hashes=metadata_hashes,
            )
        )
    return IndexProject(
        name=project,
        index_url=redact_url_credentials(index_url),
        files=tuple(files),
        api_version=api_version,
    )


class _SimpleHTMLParser(HTMLParser):
    def __init__(self, response_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.response_url = response_url
        self.files: list[IndexFile] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return
        attributes = {key.lower(): value for key, value in attrs}
        href = attributes.get("href")
        if not href:
            return
        file_url = parse.urljoin(self.response_url, href)
        parsed = parse.urlsplit(file_url)
        filename = Path(parse.unquote(parsed.path)).name
        if not filename:
            return
        hashes = _hash_fragment(parsed.fragment)
        clean_url = parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
        )
        metadata_value = attributes.get("data-core-metadata")
        if metadata_value is None:
            metadata_value = attributes.get("data-dist-info-metadata")
        self.files.append(
            IndexFile(
                filename=filename,
                url=redact_url_credentials(clean_url),
                hashes=hashes,
                requires_python=attributes.get("data-requires-python"),
                yanked=_yanked_value(attributes.get("data-yanked")),
                metadata_url=(
                    f"{redact_url_credentials(clean_url)}.metadata"
                    if metadata_value not in (None, "false")
                    else None
                ),
                metadata_hashes=_metadata_hashes(metadata_value),
            )
        )


def parse_simple_html(
    payload: bytes,
    *,
    project: str,
    index_url: str,
    response_url: str,
) -> IndexProject:
    parser = _SimpleHTMLParser(response_url)
    parser.feed(payload.decode("utf-8"))
    parser.close()
    return IndexProject(
        name=project,
        index_url=redact_url_credentials(index_url),
        files=tuple(parser.files),
        api_version=None,
    )


def normalize_index_url(url: str) -> str:
    normalized = url.strip()
    if not normalized:
        raise ValueError("package index URL cannot be empty")
    return normalized.rstrip("/") + "/"


def redact_url_credentials(url: str) -> str:
    if "://" in url and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        return re.sub(
            r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@",
            r"\g<scheme><redacted>@",
            url,
        )
    parsed = parse.urlsplit(url)
    if parsed.username is None:
        return url
    hostname = parsed.hostname or ""
    if parsed.port is not None:
        hostname = f"{hostname}:{parsed.port}"
    return parse.urlunsplit(
        (parsed.scheme, f"<redacted>@{hostname}", parsed.path, parsed.query, parsed.fragment)
    )


def files_for_version(
    project: IndexProject,
    version: str,
) -> tuple[IndexFile, ...]:
    selected: list[IndexFile] = []
    for item in project.files:
        try:
            if item.filename.endswith(".whl"):
                _, parsed_version, _, _ = parse_wheel_filename(item.filename)
            else:
                _, parsed_version = parse_sdist_filename(item.filename)
        except (InvalidWheelFilename, InvalidSdistFilename):
            continue
        if str(parsed_version) == version:
            selected.append(item)
    return tuple(selected)


def _without_url_credentials(url: str) -> str:
    parsed = parse.urlsplit(url)
    if parsed.username is None:
        return url
    hostname = parsed.hostname or ""
    if parsed.port is not None:
        hostname = f"{hostname}:{parsed.port}"
    return parse.urlunsplit(
        (parsed.scheme, hostname, parsed.path, parsed.query, parsed.fragment)
    )


def _same_origin(
    first: parse.SplitResult,
    second: parse.SplitResult,
) -> bool:
    default_ports = {"http": 80, "https": 443}
    first_scheme = first.scheme.lower()
    second_scheme = second.scheme.lower()
    return (
        first_scheme == second_scheme
        and first.hostname == second.hostname
        and (first.port or default_ports.get(first_scheme))
        == (second.port or default_ports.get(second_scheme))
    )


def _validate_index_url(url: str) -> None:
    parsed = parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"package index URL must use HTTP or HTTPS: {url!r}")


def _hash_mapping(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        return ()
    hashes: list[tuple[str, str]] = []
    for algorithm, digest in value.items():
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            continue
        normalized_algorithm = algorithm.strip().lower()
        normalized_digest = digest.strip().lower()
        if normalized_algorithm and re.fullmatch(r"[0-9a-f]+", normalized_digest):
            hashes.append((normalized_algorithm, normalized_digest))
    return tuple(sorted(hashes))


def _hash_fragment(fragment: str) -> tuple[tuple[str, str], ...]:
    if not fragment or "=" not in fragment:
        return ()
    algorithm, digest = fragment.split("=", 1)
    return _hash_mapping({algorithm: digest})


def _metadata_hashes(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, str) or "=" not in value:
        return ()
    algorithm, digest = value.split("=", 1)
    return _hash_mapping({algorithm: digest})


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _yanked_value(value: object) -> bool | str:
    if value is True:
        return True
    if isinstance(value, str):
        return value
    return False
