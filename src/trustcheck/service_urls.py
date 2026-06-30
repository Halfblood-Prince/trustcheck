from __future__ import annotations

import re
from urllib.parse import urlparse

GITHUB_RESERVED_SEGMENTS = {
    "about",
    "account",
    "apps",
    "blog",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "gist",
    "git-guides",
    "github",
    "images",
    "issues",
    "join",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "organizations",
    "pricing",
    "pulls",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "team",
    "teams",
    "topics",
    "trending",
    "users",
}
GITHUB_REPO_SUBPATHS = {
    "actions",
    "blob",
    "commit",
    "commits",
    "compare",
    "discussions",
    "issues",
    "packages",
    "projects",
    "pull",
    "pulls",
    "releases",
    "security",
    "tags",
    "tree",
    "wiki",
}

def _normalize_repo_url(url: str | None) -> str:
    if not url:
        return ""

    ssh_match = re.fullmatch(r"git@(?P<host>github\.com|gitlab\.com):(?P<path>.+)", url.strip())
    if ssh_match:
        host = ssh_match.group("host")
        path = ssh_match.group("path")
        return _normalize_supported_forge_url(host, path)

    parsed = urlparse(url.strip())
    if not parsed.scheme and not parsed.netloc:
        if url.count("/") == 1:
            return _normalize_supported_forge_url("github.com", url)
        return ""

    host = parsed.hostname.lower() if parsed.hostname else ""
    path = parsed.path or ""

    if parsed.scheme.lower() == "ssh" and parsed.username == "git" and host:
        return _normalize_supported_forge_url(host, path)

    if parsed.scheme.lower().startswith("git+"):
        nested = urlparse(url[len("git+"):])
        host = nested.hostname.lower() if nested.hostname else ""
        path = nested.path or ""

    return _normalize_supported_forge_url(host, path)


def _publisher_repository_url(kind: str, repository: str | None) -> str | None:
    if not repository:
        return repository
    if repository.startswith(("http://", "https://")):
        return _normalize_repo_url(repository) or repository
    kind_normalized = kind.lower()
    if "github" in kind_normalized:
        return _normalize_repo_url(f"https://github.com/{repository}") or repository
    if "gitlab" in kind_normalized:
        return _normalize_repo_url(f"https://gitlab.com/{repository}") or repository
    return repository


def _is_explicit_repository_label(label: str) -> bool:
    label_norm = label.strip().lower()
    explicit_labels = {
        "source",
        "source code",
        "repository",
        "repo",
        "code",
        "source repository",
    }
    return label_norm in explicit_labels


def _normalize_supported_forge_url(host: str, path: str) -> str:
    host_normalized = host.lower().removesuffix(":")
    cleaned_path = path.strip().lstrip("/").rstrip("/")
    cleaned_path = cleaned_path.removesuffix(".git")

    if host_normalized == "github.com":
        segments = [segment for segment in cleaned_path.split("/") if segment]
        if len(segments) < 2:
            return ""
        if segments[0].lower() in GITHUB_RESERVED_SEGMENTS:
            return ""
        if len(segments) > 2 and segments[2].lower() not in GITHUB_REPO_SUBPATHS:
            return ""
        owner, repo = segments[0].lower(), segments[1].lower()
        return f"https://github.com/{owner}/{repo}"

    if host_normalized == "gitlab.com":
        had_gitlab_subpath = "/-/" in cleaned_path
        if had_gitlab_subpath:
            cleaned_path = cleaned_path.split("/-/", maxsplit=1)[0]
        segments = [segment for segment in cleaned_path.split("/") if segment]
        if len(segments) < 2:
            return ""
        if not had_gitlab_subpath and len(segments) > 3:
            return ""
        namespace = "/".join(segment.lower() for segment in segments)
        return f"https://gitlab.com/{namespace}"

    return ""

