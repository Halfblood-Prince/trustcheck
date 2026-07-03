from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from urllib import request

CHANNELS = ("pypi", "github", "snap", "docker", "homebrew", "winget")
Status = Literal["pass", "fail"]


@dataclass(frozen=True, slots=True)
class ChannelResult:
    channel: str
    status: Status
    message: str
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReleaseParityResult:
    status: Status
    results: tuple[ChannelResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "results": [asdict(result) for result in self.results],
        }


def verify_release_channels(
    observations: Mapping[str, object],
    *,
    expected_version: str,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_checksums: Mapping[str, str] | None = None,
    expected_architectures: Sequence[str] = (),
    release_notes_fragments: Sequence[str] = (),
    required_channels: Sequence[str] = CHANNELS,
) -> ReleaseParityResult:
    results = tuple(
        _verify_channel(
            channel,
            observations.get(channel),
            expected_version=expected_version,
            expected_tag=expected_tag or f"v{expected_version}",
            expected_commit=expected_commit,
            expected_checksums=expected_checksums or {},
            expected_architectures=tuple(expected_architectures),
            release_notes_fragments=tuple(release_notes_fragments),
        )
        for channel in required_channels
    )
    return ReleaseParityResult(
        status="fail" if any(result.status == "fail" for result in results) else "pass",
        results=results,
    )


def render_text(result: ReleaseParityResult) -> str:
    lines = [f"release channel parity: {result.status}", ""]
    for item in result.results:
        lines.append(f"- [{item.status}] {item.channel}: {item.message}")
        for key, value in item.evidence.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def load_observations(path_or_url: str) -> dict[str, object]:
    if path_or_url.startswith(("https://", "http://")):
        with request.urlopen(path_or_url, timeout=30) as response:  # nosec B310
            payload = response.read()
    else:
        payload = Path(path_or_url).read_bytes()
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("observed channel metadata must be a JSON object")
    if "channels" in decoded:
        channels = decoded["channels"]
        if not isinstance(channels, dict):
            raise ValueError("observed channel metadata field 'channels' must be an object")
        return dict(channels)
    return decoded


def load_checksums(path: str | None) -> dict[str, str]:
    if path is None:
        return {}
    checksums: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        digest, _, filename = stripped.partition(" ")
        filename = filename.strip().lstrip("*")
        if len(digest) != 64 or not filename:
            raise ValueError(f"invalid SHA256SUMS entry: {line!r}")
        checksums[filename] = digest.lower()
    return checksums


def _verify_channel(
    channel: str,
    payload: object,
    *,
    expected_version: str,
    expected_tag: str,
    expected_commit: str | None,
    expected_checksums: Mapping[str, str],
    expected_architectures: Sequence[str],
    release_notes_fragments: Sequence[str],
) -> ChannelResult:
    if not isinstance(payload, Mapping):
        return ChannelResult(channel, "fail", "channel metadata is missing")
    observed_version = _optional_text(payload.get("version"))
    observed_tag = _optional_text(payload.get("tag"))
    if observed_version != expected_version and observed_tag != expected_tag:
        return ChannelResult(
            channel,
            "fail",
            "version does not match the intended release",
            {
                "expected_version": expected_version,
                "expected_tag": expected_tag,
                "observed_version": observed_version,
                "observed_tag": observed_tag,
            },
        )
    observed_commit = _optional_text(payload.get("commit"))
    if expected_commit and observed_commit and observed_commit != expected_commit:
        return ChannelResult(
            channel,
            "fail",
            "commit does not match the intended release",
            {"expected": expected_commit, "observed": observed_commit},
        )
    checksum_result = _check_checksums(channel, payload, expected_checksums)
    if checksum_result is not None:
        return ChannelResult(channel, "fail", checksum_result[0], checksum_result[1])
    architecture_result = _check_architectures(
        channel,
        payload,
        expected_architectures,
    )
    if architecture_result is not None:
        return ChannelResult(
            channel,
            "fail",
            architecture_result[0],
            architecture_result[1],
        )
    notes_result = _check_release_notes(payload, release_notes_fragments)
    if notes_result is not None:
        return ChannelResult(channel, "fail", notes_result[0], notes_result[1])
    return ChannelResult(
        channel,
        "pass",
        "channel exposes the intended release metadata",
        {
            "version": observed_version or observed_tag,
            "commit": observed_commit,
        },
    )


def _check_checksums(
    channel: str,
    payload: Mapping[str, object],
    expected_checksums: Mapping[str, str],
) -> tuple[str, dict[str, object]] | None:
    raw = payload.get("checksums")
    if not isinstance(raw, Mapping):
        return "checksums are missing", {}
    observed = {str(name): str(digest).lower() for name, digest in raw.items()}
    if not observed:
        return "checksums are missing", {}
    scoped_prefix = f"{channel}:"
    scoped_expected = {
        filename.removeprefix(scoped_prefix): digest
        for filename, digest in expected_checksums.items()
        if filename.startswith(scoped_prefix)
    }
    exact_expected = (
        scoped_expected
        if scoped_expected
        else {
            filename: digest
            for filename, digest in expected_checksums.items()
            if _is_python_distribution(filename)
        }
        if channel == "pypi"
        else expected_checksums
        if channel == "github"
        else {}
    )
    if not exact_expected:
        return None
    mismatched = {
        filename: {
            "expected": digest,
            "observed": observed.get(filename),
        }
        for filename, digest in exact_expected.items()
        if observed.get(filename) != digest
    }
    if mismatched:
        return "checksum parity failed", {"mismatched": mismatched}
    return None


def _check_architectures(
    channel: str,
    payload: Mapping[str, object],
    expected_architectures: Sequence[str],
) -> tuple[str, dict[str, object]] | None:
    scoped = [
        item.split("=", 1)[1]
        for item in expected_architectures
        if "=" in item and item.split("=", 1)[0] == channel
    ]
    global_architectures = [item for item in expected_architectures if "=" not in item]
    expected = scoped or global_architectures
    if not expected:
        return None
    raw = payload.get("architectures")
    if not isinstance(raw, list):
        return (
            "architecture metadata is missing",
            {"expected": list(expected)},
        )
    observed = {str(item) for item in raw}
    missing = sorted(set(expected).difference(observed))
    if missing:
        return (
            "architecture parity failed",
            {"missing": missing, "observed": sorted(observed)},
        )
    return None


def _check_release_notes(
    payload: Mapping[str, object],
    fragments: Sequence[str],
) -> tuple[str, dict[str, object]] | None:
    if not fragments:
        return None
    notes = _optional_text(payload.get("release_notes")) or ""
    missing = [fragment for fragment in fragments if fragment not in notes]
    if missing:
        return "release notes parity failed", {"missing_fragments": missing}
    return None


def _is_python_distribution(filename: str) -> bool:
    return filename.endswith((".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"))


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify post-release channel parity across PyPI, GitHub Release "
            "assets, Snap, Docker, Homebrew, and winget."
        )
    )
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--expected-checksums")
    parser.add_argument(
        "--expected-architecture",
        action="append",
        default=[],
        metavar="ARCH",
    )
    parser.add_argument(
        "--release-notes-fragment",
        action="append",
        default=[],
        metavar="TEXT",
    )
    parser.add_argument(
        "--required-channel",
        action="append",
        choices=CHANNELS,
        default=[],
        metavar="CHANNEL",
    )
    parser.add_argument(
        "--observed-json",
        required=True,
        help="Path or URL containing normalized release channel observations.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        result = verify_release_channels(
            load_observations(args.observed_json),
            expected_version=args.expected_version,
            expected_tag=args.tag,
            expected_commit=args.commit,
            expected_checksums=load_checksums(args.expected_checksums),
            expected_architectures=args.expected_architecture,
            release_notes_fragments=args.release_notes_fragment,
            required_channels=args.required_channel or CHANNELS,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(render_text(result))
    return 0 if result.status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
