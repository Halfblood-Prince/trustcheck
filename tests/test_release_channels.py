from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_release_channels import (
    load_checksums,
    verify_release_channels,
)


class ReleaseChannelParityTests(unittest.TestCase):
    def test_verifies_required_release_channels(self) -> None:
        observations = {
            channel: {
                "version": "2.1.1",
                "checksums": {
                    "trustcheck-2.1.1.tar.gz": "a" * 64,
                    "trustcheck-2.1.1-py3-none-any.whl": "b" * 64,
                },
                "release_notes": "Published from immutable commit abc123",
                "architectures": (
                    ["linux/amd64", "linux/arm64"]
                    if channel == "docker"
                    else ["amd64"]
                    if channel == "snap"
                    else []
                ),
            }
            for channel in ("pypi", "github", "snap", "docker", "homebrew", "winget")
        }
        observations["github"]["tag"] = "v2.1.1"
        observations["github"]["commit"] = "abc123"

        result = verify_release_channels(
            observations,
            expected_version="2.1.1",
            expected_tag="v2.1.1",
            expected_commit="abc123",
            expected_checksums={
                "trustcheck-2.1.1.tar.gz": "a" * 64,
                "trustcheck-2.1.1-py3-none-any.whl": "b" * 64,
            },
            expected_architectures=("docker=linux/amd64", "snap=amd64"),
            release_notes_fragments=("Published from immutable commit",),
        )

        self.assertEqual(result.status, "pass")
        self.assertTrue(all(item.status == "pass" for item in result.results))

    def test_reports_channel_mismatches(self) -> None:
        result = verify_release_channels(
            {
                "pypi": {
                    "version": "2.1.0",
                    "checksums": {},
                    "release_notes": "",
                }
            },
            expected_version="2.1.1",
            expected_checksums={"trustcheck-2.1.1.tar.gz": "a" * 64},
            required_channels=("pypi", "github"),
        )

        self.assertEqual(result.status, "fail")
        messages = {item.channel: item.message for item in result.results}
        self.assertEqual(
            messages["pypi"],
            "version does not match the intended release",
        )
        self.assertEqual(messages["github"], "channel metadata is missing")

    def test_loads_sha256sum_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SHA256SUMS.txt"
            path.write_text(
                f"{'a' * 64}  trustcheck-2.1.1.tar.gz\n",
                encoding="utf-8",
            )

            self.assertEqual(
                load_checksums(str(path)),
                {"trustcheck-2.1.1.tar.gz": "a" * 64},
            )


if __name__ == "__main__":
    unittest.main()
