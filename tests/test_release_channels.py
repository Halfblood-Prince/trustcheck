from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_release_channels import (
    load_checksums,
    load_observations,
    verify_release_channels,
)


class FakeHttpResponse:
    status = 200
    reason = "OK"
    data = b'{"channels": {"pypi": {"version": "2.1.1", "checksums": {}}}}'


class FakePoolManager:
    instances: list["FakePoolManager"] = []

    def __init__(self) -> None:
        self.method: str | None = None
        self.url: str | None = None
        self.headers: dict[str, str] = {}
        self.timeout: object | None = None
        FakePoolManager.instances.append(self)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        timeout: object,
    ) -> FakeHttpResponse:
        self.method = method
        self.url = url
        self.headers = headers
        self.timeout = timeout
        return FakeHttpResponse()


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

    def test_loads_observations_from_local_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observations.json"
            path.write_text(
                '{"channels": {"pypi": {"version": "2.1.1"}}}',
                encoding="utf-8",
            )

            self.assertEqual(
                load_observations(str(path)),
                {"pypi": {"version": "2.1.1"}},
            )

    def test_loads_observations_from_https_json(self) -> None:
        FakePoolManager.instances.clear()
        with patch(
            "scripts.verify_release_channels.urllib3.PoolManager",
            FakePoolManager,
        ):
            observations = load_observations(
                "https://release.example/observations.json?tag=v2.1.1"
            )

        self.assertEqual(observations["pypi"]["version"], "2.1.1")
        self.assertEqual(len(FakePoolManager.instances), 1)
        pool = FakePoolManager.instances[0]
        self.assertEqual(pool.method, "GET")
        self.assertEqual(
            pool.url,
            "https://release.example/observations.json?tag=v2.1.1",
        )
        self.assertEqual(pool.headers["Accept"], "application/json")
        self.assertIsNotNone(pool.timeout)

    def test_rejects_observation_file_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "must use https"):
            load_observations("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
