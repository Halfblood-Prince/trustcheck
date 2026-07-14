from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class LockfileParser(Protocol):
    @property
    def name(self) -> str: ...

    def supports(self, path: Path) -> bool: ...

    def load(
        self,
        path: Path,
        *,
        extras: Sequence[str],
        groups: Sequence[str],
        environment: Mapping[str, str] | None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class FunctionLockfileParser:
    name: str
    supports_name: Callable[[str], bool]
    loader: Callable[
        [Path, Sequence[str], Sequence[str], Mapping[str, str] | None],
        object,
    ]

    def supports(self, path: Path) -> bool:
        return self.supports_name(path.name.lower())

    def load(
        self,
        path: Path,
        *,
        extras: Sequence[str],
        groups: Sequence[str],
        environment: Mapping[str, str] | None,
    ) -> object:
        return self.loader(path, extras, groups, environment)


def select_lockfile_parser(
    path: Path,
    parsers: Sequence[LockfileParser],
) -> LockfileParser | None:
    for parser in parsers:
        if parser.supports(path):
            return parser
    return None
