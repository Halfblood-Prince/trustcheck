from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def check_score(path: Path, *, minimum: float) -> float:
    payload = json.loads(path.read_text(encoding="utf-8"))
    killed = int(payload.get("killed", 0))
    survived = int(payload.get("survived", 0))
    suspicious = int(payload.get("suspicious", 0))
    timeout = int(payload.get("timeout", 0))
    no_tests = int(payload.get("no_tests", 0))
    segfault = int(payload.get("segfault", 0))
    interrupted = int(payload.get("check_was_interrupted_by_user", 0))
    evaluated = killed + survived + suspicious + timeout + no_tests + segfault
    if evaluated == 0:
        raise ValueError("mutation run did not evaluate any mutants")
    if interrupted:
        raise ValueError("mutation run was interrupted")
    score = killed * 100.0 / evaluated
    if score < minimum:
        raise ValueError(f"mutation score {score:.2f}% is below {minimum:.2f}%")
    return score


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enforce a minimum mutmut score.")
    parser.add_argument("stats", type=Path)
    parser.add_argument("--minimum", type=float, default=80.0)
    args = parser.parse_args(argv)
    score = check_score(args.stats, minimum=args.minimum)
    print(f"Mutation score: {score:.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
