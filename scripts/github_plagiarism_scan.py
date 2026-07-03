from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import error, parse, request

DEFAULT_SOURCE = "src/trustcheck"
DEFAULT_OUTPUT = "reports/github-code-copy-findings.md"
GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"
MIN_QUERY_CHARS = 32


@dataclass(frozen=True, slots=True)
class CodeFingerprint:
    path: str
    line: int
    query: str
    context: str
    sha256: str


@dataclass(frozen=True, slots=True)
class CodeMatch:
    repository: str
    path: str
    html_url: str
    fingerprint: CodeFingerprint


def collect_fingerprints(
    root: Path,
    *,
    source: str,
    max_fingerprints: int,
    min_query_chars: int = MIN_QUERY_CHARS,
) -> list[CodeFingerprint]:
    source_root = root / source
    candidates: list[tuple[int, str, int, str, str]] = []
    for file_path in sorted(source_root.rglob("*.py")):
        if any(part == "__pycache__" for part in file_path.parts):
            continue
        try:
            raw_lines = file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        code_lines = [
            (index, line.strip())
            for index, line in enumerate(raw_lines, 1)
            if _is_searchable_code_line(line.strip(), min_query_chars)
        ]
        for offset, (line_number, line) in enumerate(code_lines):
            query = _query_fragment(line)
            if len(query) < min_query_chars:
                continue
            context = "\n".join(
                value for _, value in code_lines[offset : offset + 4]
            )
            relative = file_path.relative_to(root).as_posix()
            score = len(query) + len(set(query))
            candidates.append((score, relative, line_number, query, context))

    selected: list[CodeFingerprint] = []
    seen_queries: set[str] = set()
    for _, relative, line_number, query, context in sorted(
        candidates,
        key=lambda item: (-item[0], item[1], item[2], item[3]),
    ):
        if query in seen_queries:
            continue
        seen_queries.add(query)
        selected.append(
            CodeFingerprint(
                path=relative,
                line=line_number,
                query=query,
                context=context,
                sha256=hashlib.sha256(context.encode("utf-8")).hexdigest(),
            )
        )
        if len(selected) >= max_fingerprints:
            break
    return selected


def search_github_code(
    fingerprints: Iterable[CodeFingerprint],
    *,
    token: str | None,
    repository: str,
    api_url: str = GITHUB_CODE_SEARCH_URL,
    per_page: int = 10,
    opener: Callable[[request.Request], Any] = request.urlopen,
) -> tuple[list[CodeMatch], list[str]]:
    if not token:
        return [], ["GITHUB_TOKEN was not set; GitHub code search was skipped."]

    matches: list[CodeMatch] = []
    warnings: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    excluded_repository = repository.casefold()
    for fingerprint in fingerprints:
        query = f'"{fingerprint.query}" in:file -repo:{repository}'
        url = f"{api_url}?{parse.urlencode({'q': query, 'per_page': str(per_page)})}"
        github_request = request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "trustcheck-plagiarism-scan",
            },
        )
        try:
            with opener(github_request) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            warnings.append(
                f"GitHub search failed for {fingerprint.path}:{fingerprint.line} "
                f"with HTTP {exc.code}."
            )
            continue
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(
                f"GitHub search failed for {fingerprint.path}:{fingerprint.line}: {exc}."
            )
            continue

        for item in payload.get("items", []):
            if not isinstance(item, dict):
                continue
            repo_payload = item.get("repository")
            if not isinstance(repo_payload, dict):
                continue
            full_name = str(repo_payload.get("full_name") or "")
            if not full_name or full_name.casefold() == excluded_repository:
                continue
            path = str(item.get("path") or "")
            html_url = str(item.get("html_url") or "")
            key = (full_name.casefold(), path, fingerprint.sha256)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                CodeMatch(
                    repository=full_name,
                    path=path,
                    html_url=html_url,
                    fingerprint=fingerprint,
                )
            )
    matches.sort(key=lambda item: (item.repository.casefold(), item.path, item.fingerprint.path))
    return matches, warnings


def render_report(
    *,
    repository: str,
    fingerprints: list[CodeFingerprint],
    matches: list[CodeMatch],
    warnings: list[str],
) -> str:
    lines = [
        "# GitHub Code Copy Scan Findings",
        "",
        "This report is generated by `.github/workflows/plagiarism-scan.yml`.",
        "Matches are review leads from exact public GitHub code search, not proof of plagiarism.",
        "",
        f"Source repository: `{repository or 'unknown'}`",
        f"Fingerprints searched: {len(fingerprints)}",
        f"External matches: {len(matches)}",
    ]
    if warnings:
        lines.append(f"Warnings: {len(warnings)}")
    lines.extend(["", "## Findings", ""])
    if not matches:
        lines.append("No external matches were found.")
    else:
        by_repository: dict[str, list[CodeMatch]] = {}
        for match in matches:
            by_repository.setdefault(match.repository, []).append(match)
        for repo_name, repo_matches in by_repository.items():
            lines.extend([f"### {repo_name}", ""])
            for match in repo_matches:
                source = f"{match.fingerprint.path}:{match.fingerprint.line}"
                lines.append(
                    f"- `{match.path}` matches `{source}` "
                    f"(fingerprint `{match.fingerprint.sha256[:12]}`)"
                )
                if match.html_url:
                    lines.append(f"  - GitHub: {match.html_url}")
                lines.append(f"  - Query fragment: `{match.fingerprint.query}`")
            lines.append("")
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines).rstrip() + "\n"


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search GitHub code for exact fragments from this repository."
    )
    parser.add_argument("--root", default=".", help="Repository root to scan.")
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="Source tree to fingerprint.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Markdown report path.")
    parser.add_argument("--max-fingerprints", type=int, default=40)
    parser.add_argument("--per-page", type=int, default=10)
    parser.add_argument("--api-url", default=GITHUB_CODE_SEARCH_URL)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    fingerprints = collect_fingerprints(
        root,
        source=args.source,
        max_fingerprints=max(1, args.max_fingerprints),
    )
    matches, warnings = search_github_code(
        fingerprints,
        token=os.environ.get("GITHUB_TOKEN"),
        repository=repository,
        api_url=args.api_url,
        per_page=max(1, args.per_page),
    )
    report = render_report(
        repository=repository,
        fingerprints=fingerprints,
        matches=matches,
        warnings=warnings,
    )
    write_report(root / args.output, report)
    return 0


def _is_searchable_code_line(line: str, min_query_chars: int) -> bool:
    if len(line) < min_query_chars:
        return False
    if line.startswith(("#", "import ", "from ", "def ", "class ", "@")):
        return False
    if line in {"return None", "return True", "return False"}:
        return False
    return any(character.isalpha() for character in line)


def _query_fragment(line: str, *, max_chars: int = 120) -> str:
    fragment = " ".join(line.replace('"', "").split())
    if len(fragment) <= max_chars:
        return fragment
    trimmed = fragment[:max_chars].rsplit(" ", 1)[0]
    return trimmed or fragment[:max_chars]


if __name__ == "__main__":
    raise SystemExit(main())
