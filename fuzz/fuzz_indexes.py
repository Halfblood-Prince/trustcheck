from __future__ import annotations

import hashlib
import sys

import atheris

with atheris.instrument_imports():
    from trustcheck.indexes import (
        IndexProject,
        SimpleRepositoryClient,
        normalize_index_url,
        redact_url_credentials,
    )


def test_one_input(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    parts = [part.strip() for part in text.splitlines() if part.strip()]
    if not parts:
        return
    projects = parts[:8]
    raw_indexes = parts[8:16] or ["https://pypi.org/simple", "https://private.test/simple"]
    indexes: list[str] = []
    for raw in raw_indexes:
        candidate = raw if "://" in raw else f"https://{raw}/simple"
        try:
            normalized = normalize_index_url(candidate)
        except ValueError:
            continue
        indexes.append(redact_url_credentials(normalized))
    indexes = list(dict.fromkeys(indexes))
    if len(indexes) < 2:
        return

    class Repository(SimpleRepositoryClient):
        def get_project(self, index_url: str, project: str) -> IndexProject | None:
            digest = hashlib.sha256(f"{index_url}\0{project}".encode()).digest()
            if digest[0] % 2:
                return None
            return IndexProject(name=project, index_url=index_url)

    Repository().find_dependency_confusion(projects, indexes)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
