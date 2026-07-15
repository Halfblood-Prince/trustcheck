from __future__ import annotations

import base64
import configparser
import importlib
import io
import json
import netrc
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterator, Protocol, cast
from urllib import error, parse, request

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

# Subprocess calls use fixed argv lists and explicitly disable the shell.
SIMPLE_JSON_ACCEPT = (
    "application/vnd.pypi.simple.v1+json, "
    "application/vnd.pypi.simple.latest+json;q=0.9, text/html;q=0.1"
)
DEFAULT_INDEX_URL = "https://pypi.org/simple"
DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024 * 1024
RESPONSE_CHUNK_BYTES = 1024 * 1024
KEYRING_PROVIDERS = {"auto", "disabled", "import", "subprocess"}
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
UrlOpener = Callable[..., Any]
AUTHORIZATION_HEADERS = {"authorization", "proxy-authorization"}


class _KeyringModule(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...


class IndexError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class IndexURLPolicy:
    allow_insecure_index: bool = False
    max_redirects: int = 10

    def validate_index_url(self, url: str) -> None:
        self._validated_remote_url(url, context="package index URL")

    def validate_remote_artifact_url(
        self,
        url: str,
        *,
        context: str = "remote index artifact URL",
    ) -> None:
        self._validated_remote_url(url, context=context)

    def validate_request_url(self, url: str, *, context: str = "request URL") -> None:
        self._validated_remote_url(url, context=context)

    def validate_redirect(self, source_url: str, target_url: str) -> str:
        resolved = parse.urljoin(source_url, target_url)
        source = self._validated_remote_url(
            source_url,
            context="redirect source URL",
        )
        target = _split_url(resolved, context="redirect target URL")
        if source.scheme.lower() == "https" and target.scheme.lower() == "http":
            raise ValueError(
                "refusing HTTPS-to-HTTP redirect from "
                f"{redact_url_credentials(source_url)} to "
                f"{redact_url_credentials(resolved)}"
            )
        self._validated_remote_url(
            resolved,
            context="redirect target URL",
        )
        return resolved

    def validate_final_url(
        self,
        source_url: str,
        final_url: str,
        *,
        context: str = "final response URL",
    ) -> None:
        if final_url != source_url:
            self.validate_redirect(source_url, final_url)
        else:
            self._validated_remote_url(final_url, context=context)

    def _validated_remote_url(
        self,
        url: str,
        *,
        context: str,
    ) -> parse.SplitResult:
        parsed = _split_url(url, context=context)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError(
                f"{context} must use HTTPS"
                + (" or explicitly allowed HTTP" if self.allow_insecure_index else "")
                + f": {redact_url_credentials(url)!r}"
            )
        if scheme == "http" and not self.allow_insecure_index:
            raise ValueError(
                f"{context} must use HTTPS unless --allow-insecure-index is set: "
                f"{redact_url_credentials(url)!r}"
            )
        return parsed


class _PolicyRedirectHandler(request.HTTPRedirectHandler):
    def __init__(self, policy: IndexURLPolicy) -> None:
        super().__init__()
        self.policy = policy
        self.max_redirections = policy.max_redirects

    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> request.Request | None:
        try:
            target_url = self.policy.validate_redirect(req.full_url, newurl)
        except ValueError as exc:
            raise error.URLError(str(exc)) from exc
        redirected = super().redirect_request(req, fp, code, msg, headers, target_url)
        if redirected is not None and not _same_origin(
            parse.urlsplit(req.full_url),
            parse.urlsplit(target_url),
        ):
            _remove_request_headers(redirected, AUTHORIZATION_HEADERS)
        return redirected


def _safe_urlopen(
    req: request.Request,
    *,
    timeout: float,
    policy: IndexURLPolicy,
) -> Any:
    opener = request.build_opener(_PolicyRedirectHandler(policy))
    return opener.open(req, timeout=timeout)


def _read_bounded_response(response: Any, *, limit: int, url: str) -> bytes:
    headers = getattr(response, "headers", None) or {}
    content_length = headers.get("Content-Length") if hasattr(headers, "get") else None
    if content_length is not None:
        try:
            if int(content_length) > limit:
                raise IndexError(f"response exceeds the {limit}-byte limit: {url}")
        except (TypeError, ValueError):
            pass
    payload = bytearray()
    while len(payload) <= limit:
        read_size = min(RESPONSE_CHUNK_BYTES, limit + 1 - len(payload))
        try:
            chunk = response.read(read_size)
        except TypeError:
            chunk = response.read()
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > limit:
            raise IndexError(f"response exceeds the {limit}-byte limit: {url}")
    return bytes(payload)


@dataclass(frozen=True, slots=True)
class IndexConfiguration:
    index_url: str = DEFAULT_INDEX_URL
    extra_index_urls: tuple[str, ...] = ()
    keyring_provider: str = "auto"
    allow_insecure_index: bool = False

    def __post_init__(self) -> None:
        if self.keyring_provider not in KEYRING_PROVIDERS:
            raise ValueError(
                "keyring provider must be auto, disabled, import, or subprocess"
            )
        _validate_index_url(
            self.index_url,
            allow_insecure_index=self.allow_insecure_index,
        )
        for index_url in self.extra_index_urls:
            _validate_index_url(
                index_url,
                allow_insecure_index=self.allow_insecure_index,
            )

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

    @property
    def has_url_credentials(self) -> bool:
        return any(_url_has_credentials(url) for url in (self.index_url, *self.extra_index_urls))

    def pip_arguments(self) -> list[str]:
        arguments = ["--index-url", _without_url_credentials(self.index_url)]
        for index_url in self.extra_index_urls:
            arguments.extend(["--extra-index-url", _without_url_credentials(index_url)])
        arguments.extend(["--keyring-provider", self.keyring_provider])
        return arguments

    @contextmanager
    def pip_subprocess(
        self,
        *,
        env: Mapping[str, str] | None = None,
    ) -> Iterator[tuple[list[str], dict[str, str] | None]]:
        if not self.has_url_credentials:
            yield self.pip_arguments(), dict(env) if env is not None else None
            return

        directory = tempfile.TemporaryDirectory(prefix="trustcheck-pip-config-")
        config_path = Path(directory.name) / ("pip.ini" if os.name == "nt" else "pip.conf")
        try:
            _write_private_text(config_path, self._pip_config_text())
            prepared_env = dict(env) if env is not None else dict(os.environ)
            prepared_env["PIP_CONFIG_FILE"] = str(config_path)
            yield [], prepared_env
        finally:
            _secure_delete(config_path)
            directory.cleanup()

    def _pip_config_text(self) -> str:
        parser = configparser.RawConfigParser()
        parser["global"] = {
            "index-url": self.index_url,
            "keyring-provider": self.keyring_provider,
        }
        if self.extra_index_urls:
            parser["global"]["extra-index-url"] = "\n" + "\n".join(
                self.extra_index_urls
            )
        stream = io.StringIO()
        parser.write(stream, space_around_delimiters=True)
        return stream.getvalue()

    def redacted(self) -> dict[str, object]:
        return {
            "index_url": redact_url_credentials(self.index_url),
            "extra_index_urls": [
                redact_url_credentials(url) for url in self.extra_index_urls
            ],
            "keyring_provider": self.keyring_provider,
            "allow_insecure_index": self.allow_insecure_index,
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
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class SimpleRepositoryClient:
    timeout: float = 15.0
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    keyring_provider: str = "auto"
    opener: UrlOpener | None = None
    runner: CommandRunner = subprocess.run
    python_executable: str = sys.executable
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    url_policy: IndexURLPolicy = field(default_factory=IndexURLPolicy)
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
                kind="index",
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
                    url_policy=self.url_policy,
                )
            else:
                result = parse_simple_html(
                    payload,
                    project=project,
                    index_url=normalized_index,
                    response_url=final_url,
                    url_policy=self.url_policy,
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
            matched_projects = []
            for index_url in indexes:
                index_project = self.get_project(index_url, project)
                if index_project is not None:
                    matched_projects.append((index_url, index_project))
            matches = [
                redact_url_credentials(
                    getattr(index_project, "index_url", index_url)
                )
                for index_url, index_project in matched_projects
            ]
            if len(matches) > 1:
                index_projects = tuple(
                    index_project
                    for _, index_project in matched_projects
                    if isinstance(index_project, IndexProject)
                )
                findings.append(
                    DependencyConfusionFinding(
                        project=project,
                        indexes=tuple(matches),
                        evidence=dependency_confusion_evidence(index_projects),
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
        kind: str = "artifact",
    ) -> tuple[bytes, str, str]:
        self._validate_request_url(url, kind=kind)
        if index_url is not None:
            self._validate_request_url(index_url, kind="index")
        request_url, headers = self._authenticated_request(url, index_url=index_url)
        if accept:
            headers["Accept"] = accept
        req = request.Request(request_url, headers=headers)
        opener = self.opener
        if opener is None:
            response_context = _safe_urlopen(
                req,
                timeout=self.timeout,
                policy=self.url_policy,
            )
        else:
            response_context = opener(req, timeout=self.timeout)
        with response_context as response:
            payload = _read_bounded_response(
                response,
                limit=self.max_response_bytes,
                url=redact_url_credentials(url),
            )
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
            self._validate_final_url(request_url, final_url, kind=kind)
            return payload, str(content_type), final_url

    def _validate_request_url(self, url: str, *, kind: str) -> None:
        try:
            if kind == "index":
                self.url_policy.validate_index_url(url)
            else:
                self.url_policy.validate_remote_artifact_url(url)
        except ValueError as exc:
            raise IndexError(str(exc)) from exc

    def _validate_final_url(self, request_url: str, final_url: str, *, kind: str) -> None:
        try:
            context = "index response URL" if kind == "index" else "artifact response URL"
            self.url_policy.validate_final_url(
                request_url,
                final_url,
                context=context,
            )
        except ValueError as exc:
            raise IndexError(str(exc)) from exc

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
                keyring = cast(
                    _KeyringModule,
                    importlib.import_module("keyring"),
                )
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
                [
                    self.python_executable,
                    "-m",
                    "keyring",
                    "get",
                    service,
                    username,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                shell=False,
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
    url_policy: IndexURLPolicy | None = None,
) -> IndexProject:
    policy = url_policy or IndexURLPolicy()
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
        policy.validate_remote_artifact_url(file_url)
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
                    redact_url_credentials(_metadata_url(file_url))
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
    def __init__(self, response_url: str, url_policy: IndexURLPolicy) -> None:
        super().__init__(convert_charrefs=True)
        self.response_url = response_url
        self.url_policy = url_policy
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
        self.url_policy.validate_remote_artifact_url(file_url)
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
                    redact_url_credentials(_metadata_url(clean_url))
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
    url_policy: IndexURLPolicy | None = None,
) -> IndexProject:
    parser = _SimpleHTMLParser(response_url, url_policy or IndexURLPolicy())
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
    try:
        parsed = parse.urlsplit(url)
    except ValueError:
        return url
    if parsed.username is None:
        return url
    return parse.urlunsplit(
        (
            parsed.scheme,
            f"<redacted>@{_parsed_host_port(parsed)}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
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


def dependency_confusion_evidence(
    projects: Sequence[IndexProject],
) -> tuple[str, ...]:
    evidence: list[str] = [
        "resolver_strategy=version-priority",
        "index_trust_order=not-enforced-by-pip",
        "mirror_relationship=not-declared",
    ]
    for project in projects:
        index_url = redact_url_credentials(project.index_url)
        evidence.append(
            f"available_versions[{index_url}]="
            f"{_format_available_versions(_project_versions(project))}"
        )
    evidence.extend(_filename_hash_mismatch_evidence(projects))
    evidence.extend(_version_metadata_mismatch_evidence(projects))
    return tuple(dict.fromkeys(evidence))


def _without_url_credentials(url: str) -> str:
    try:
        parsed = parse.urlsplit(url)
    except ValueError:
        return url
    if parsed.username is None:
        return url
    return parse.urlunsplit(
        (parsed.scheme, _parsed_host_port(parsed), parsed.path, parsed.query, parsed.fragment)
    )


def _project_versions(project: IndexProject) -> tuple[str, ...]:
    versions = {
        version
        for item in project.files
        if (version := _file_version(item.filename)) is not None
    }
    return tuple(sorted(versions, key=_version_sort_key))


def _file_version(filename: str) -> str | None:
    try:
        if filename.endswith(".whl"):
            _, parsed_version, _, _ = parse_wheel_filename(filename)
        else:
            _, parsed_version = parse_sdist_filename(filename)
    except (InvalidWheelFilename, InvalidSdistFilename):
        return None
    return str(parsed_version)


def _version_sort_key(version: str) -> tuple[int, object]:
    try:
        from packaging.version import Version

        return (0, Version(version))
    except Exception:
        return (1, version)


def _format_available_versions(versions: Sequence[str]) -> str:
    if not versions:
        return "unknown"
    if len(versions) <= 8:
        return ",".join(versions)
    return ",".join((*versions[:7], f"+{len(versions) - 7} more"))


def _filename_hash_mismatch_evidence(
    projects: Sequence[IndexProject],
) -> tuple[str, ...]:
    by_filename: dict[str, list[tuple[str, IndexFile]]] = {}
    for project in projects:
        index_url = redact_url_credentials(project.index_url)
        for item in project.files:
            by_filename.setdefault(item.filename, []).append((index_url, item))

    evidence: list[str] = []
    for filename, entries in sorted(by_filename.items()):
        if len(entries) < 2:
            continue
        hash_summaries = {_hash_summary(item.hashes) for _, item in entries}
        if len(hash_summaries) < 2:
            continue
        evidence.append(
            "filename_hash_mismatch:"
            f"{filename}="
            + ";".join(
                f"{index_url}:{_hash_summary(item.hashes)}"
                for index_url, item in entries
            )
        )
    return tuple(evidence[:8])


def _version_metadata_mismatch_evidence(
    projects: Sequence[IndexProject],
) -> tuple[str, ...]:
    by_version: dict[str, list[tuple[str, tuple[IndexFile, ...]]]] = {}
    for project in projects:
        index_url = redact_url_credentials(project.index_url)
        for version in _project_versions(project):
            by_version.setdefault(version, []).append(
                (index_url, files_for_version(project, version))
            )

    evidence: list[str] = []
    for version, entries in sorted(by_version.items(), key=lambda item: _version_sort_key(item[0])):
        if len(entries) < 2:
            continue
        signatures = {
            _metadata_signature(files)
            for _, files in entries
        }
        if len(signatures) < 2:
            continue
        evidence.append(
            f"version_metadata_mismatch:{version}="
            + ";".join(
                f"{index_url}:{_metadata_signature_label(files)}"
                for index_url, files in entries
            )
        )
    return tuple(evidence[:8])


def _metadata_signature(files: Sequence[IndexFile]) -> tuple[object, ...]:
    return (
        tuple(sorted({item.requires_python or "" for item in files})),
        tuple(sorted({str(item.yanked) for item in files})),
        tuple(sorted({_hash_summary(item.metadata_hashes) for item in files})),
        tuple(sorted({str(item.size) for item in files if item.size is not None})),
        tuple(sorted({item.upload_time or "" for item in files})),
    )


def _metadata_signature_label(files: Sequence[IndexFile]) -> str:
    requires_python, yanked, metadata_hashes, sizes, upload_times = _metadata_signature(files)
    parts = [
        f"requires_python={_join_compact(requires_python)}",
        f"yanked={_join_compact(yanked)}",
        f"metadata_hashes={_join_compact(metadata_hashes)}",
    ]
    if sizes:
        parts.append(f"sizes={_join_compact(sizes)}")
    if upload_times:
        parts.append(f"upload_times={_join_compact(upload_times)}")
    return ",".join(parts)


def _hash_summary(hashes: Sequence[tuple[str, str]]) -> str:
    if not hashes:
        return "missing"
    return "|".join(
        f"{algorithm.lower()}={digest.lower()}"
        for algorithm, digest in hashes
    )


def _join_compact(values: object) -> str:
    if not isinstance(values, tuple):
        return str(values)
    filtered = [str(value) for value in values if str(value)]
    if not filtered:
        return "unknown"
    if len(filtered) <= 3:
        return "/".join(filtered)
    return "/".join((*filtered[:2], f"+{len(filtered) - 2} more"))


def _parsed_host_port(parsed: parse.SplitResult) -> str:
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        hostname = f"{hostname}:{port}"
    return hostname


def _same_origin(
    first: parse.SplitResult,
    second: parse.SplitResult,
) -> bool:
    default_ports = {"http": 80, "https": 443}
    first_scheme = first.scheme.lower()
    second_scheme = second.scheme.lower()
    try:
        first_port = first.port
        second_port = second.port
    except ValueError:
        return False
    return (
        first_scheme == second_scheme
        and first.hostname == second.hostname
        and (first_port or default_ports.get(first_scheme))
        == (second_port or default_ports.get(second_scheme))
    )


def _validate_index_url(
    url: str,
    *,
    allow_insecure_index: bool = False,
) -> None:
    IndexURLPolicy(allow_insecure_index=allow_insecure_index).validate_index_url(url)


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
    if isinstance(value, dict):
        return _hash_mapping(value)
    if not isinstance(value, str) or "=" not in value:
        return ()
    algorithm, digest = value.split("=", 1)
    return _hash_mapping({algorithm: digest})


def _metadata_url(file_url: str) -> str:
    parsed = parse.urlsplit(file_url)
    return parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"{parsed.path}.metadata", parsed.query, "")
    )


def _split_url(url: str, *, context: str) -> parse.SplitResult:
    try:
        parsed = parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError(
            f"{context} has a malformed host or port: {redact_url_credentials(url)!r}"
        ) from exc
    if not parsed.scheme or not hostname:
        raise ValueError(
            f"{context} must include a scheme and host: {redact_url_credentials(url)!r}"
        )
    return parsed


def _url_has_credentials(url: str) -> bool:
    try:
        return parse.urlsplit(url).username is not None
    except ValueError:
        return False


def _remove_request_headers(req: request.Request, names: set[str]) -> None:
    for mapping in (req.headers, req.unredirected_hdrs):
        for key in list(mapping):
            if key.lower() in names:
                del mapping[key]


def _write_private_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            fd = -1
            stream.write(text)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if fd >= 0:
            os.close(fd)


def _secure_delete(path: Path) -> None:
    try:
        size = path.stat().st_size
        with path.open("r+b") as stream:
            if size:
                stream.write(b"\0" * size)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: object) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _yanked_value(value: object) -> bool | str:
    if value is True:
        return True
    if isinstance(value, str):
        return value
    return False
