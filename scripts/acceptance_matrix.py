from __future__ import annotations

import argparse
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path

FORMAT_EXTENSIONS = {
    "json": ".json",
    "cyclonedx-1.7-json": ".cdx17.json",
    "spdx-3-json": ".spdx3.json",
}


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    case_id: str
    description: str
    args: tuple[str, ...]
    output_format: str
    expected_exit_codes: tuple[int, ...] = (0,)


ACCEPTANCE_CASES = {
    case.case_id: case
    for case in (
        AcceptanceCase(
            case_id="pip-tools",
            description="Hash-pinned pip-tools requirements export",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/requirements-hashed.txt",
                "--no-deps",
                "--with-osv",
                "--format",
                "cyclonedx-1.7-json",
            ),
            output_format="cyclonedx-1.7-json",
        ),
        AcceptanceCase(
            case_id="uv-lock",
            description="uv lockfile export",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/uv.lock",
                "--no-deps",
                "--with-osv",
                "--format",
                "spdx-3-json",
            ),
            output_format="spdx-3-json",
        ),
        AcceptanceCase(
            case_id="poetry-lock",
            description="Poetry lockfile export",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/poetry.lock",
                "--no-deps",
                "--with-osv",
                "--format",
                "cyclonedx-1.7-json",
            ),
            output_format="cyclonedx-1.7-json",
        ),
        AcceptanceCase(
            case_id="pdm-lock",
            description="PDM lockfile export",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/pdm.lock",
                "--no-deps",
                "--with-osv",
                "--format",
                "spdx-3-json",
            ),
            output_format="spdx-3-json",
        ),
        AcceptanceCase(
            case_id="pep751-pylock",
            description="PEP 751 pylock.toml export",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/pylock.toml",
                "--no-deps",
                "--with-osv",
                "--format",
                "cyclonedx-1.7-json",
            ),
            output_format="cyclonedx-1.7-json",
        ),
        AcceptanceCase(
            case_id="extras-markers",
            description="PEP 508 extras and environment markers",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/requirements-markers-extras.txt",
                "--no-deps",
                "--with-osv",
                "--format",
                "json",
            ),
            output_format="json",
        ),
        AcceptanceCase(
            case_id="private-index-fixture",
            description="Private-index directive fixture with public fallback package",
            args=(
                "scan",
                "-f",
                "benchmarks/corpus/requirements-private-index.txt",
                "--no-deps",
                "--with-osv",
                "--format",
                "json",
            ),
            output_format="json",
            expected_exit_codes=(0, 1),
        ),
        AcceptanceCase(
            case_id="native-wheel",
            description="Native wheel artifact inspection",
            args=(
                "scan",
                "psutil",
                "--version",
                "7.2.2",
                "--full",
                "--artifact-scope",
                "target",
                "--with-osv",
                "--format",
                "cyclonedx-1.7-json",
            ),
            output_format="cyclonedx-1.7-json",
        ),
        AcceptanceCase(
            case_id="sdist",
            description="Source distribution artifact scan",
            args=(
                "scan",
                "sampleproject",
                "--version",
                "4.0.0",
                "--standard",
                "--artifact-scope",
                "sdist",
                "--with-osv",
                "--format",
                "spdx-3-json",
            ),
            output_format="spdx-3-json",
        ),
    )
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one real-world trustcheck acceptance matrix case.",
    )
    parser.add_argument("--case", choices=sorted(ACCEPTANCE_CASES), required=True)
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("acceptance-reports"),
        help="Directory for rendered trustcheck reports.",
    )
    args = parser.parse_args(argv)

    case = ACCEPTANCE_CASES[args.case]
    report_dir = args.report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    output_file = report_dir / (
        case.case_id + FORMAT_EXTENSIONS.get(case.output_format, ".txt")
    )
    command = [
        sys.executable,
        "-m",
        "trustcheck",
        *case.args,
        "--output-file",
        str(output_file),
    ]
    print(f"Running acceptance case {case.case_id}: {case.description}")
    print("Command: " + " ".join(command))
    result = subprocess.run(command, check=False)  # nosec B603
    if result.returncode not in case.expected_exit_codes:
        print(
            (
                f"Unexpected exit code {result.returncode}; expected one of "
                f"{case.expected_exit_codes}"
            ),
            file=sys.stderr,
        )
        return result.returncode or 1
    if not output_file.is_file():
        print(f"Acceptance case did not create report: {output_file}", file=sys.stderr)
        return 1
    print(f"Wrote acceptance report: {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
