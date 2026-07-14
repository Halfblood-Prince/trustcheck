from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Sequence


def mutation_targets(config_path: Path, group_id: str) -> tuple[str, ...]:
    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    groups = payload.get("groups")
    if not isinstance(groups, list):
        raise ValueError("mutation group config must contain a groups array")
    for group in groups:
        if not isinstance(group, dict) or group.get("id") != group_id:
            continue
        targets = group.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"mutation group {group_id!r} has no targets")
        if not all(isinstance(target, str) and target for target in targets):
            raise ValueError(f"mutation group {group_id!r} contains an invalid target")
        return tuple(targets)
    raise ValueError(f"unknown mutation group: {group_id}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print mutmut targets for a group.")
    parser.add_argument("config", type=Path)
    parser.add_argument("group")
    args = parser.parse_args(argv)
    print("\n".join(mutation_targets(args.config, args.group)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
