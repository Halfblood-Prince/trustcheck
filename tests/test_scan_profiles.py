from __future__ import annotations

import hashlib
import io
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import urllib3
from test_artifacts import build_wheel

from trustcheck.cli import (
    ScanTarget,
    _build_scan_state,
    _clone_pypi_client,
    build_parser,
    main,
)
from trustcheck.indexes import DEFAULT_INDEX_URL
from trustcheck.models import TrustReport
from trustcheck.plugins import PluginManager
from trustcheck.policy import PolicySettings
from trustcheck.pypi import JSON_ACCEPT, PypiClient
from trustcheck.resolver import TargetEnvironment
from trustcheck.service import ArtifactDigestCache, inspect_package


class ProfileClient:
    timeout = 1.0
    max_retries = 0
    backoff_factor = 0.0
    offline = False
    cache_dir = None

    def __init__(self, artifacts: list[tuple[str, bytes, bool]]) -> None:
        self.request_hook = None
        self.downloads: list[str] = []
        self.provenance_calls: list[str] = []
        self.history_calls = 0
        self._payloads = {
            f"https://files.example/{filename}": payload
            for filename, payload, _ in artifacts
        }
        self.release = {
            "info": {
                "name": "demo",
                "version": "1.0.0",
                "summary": "demo",
                "requires_dist": [],
                "project_urls": {},
            },
            "urls": [
                {
                    "filename": filename,
                    "url": f"https://files.example/{filename}",
                    "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                    "yanked": yanked,
                    "digests": {"sha256": hashlib.sha256(payload).hexdigest()},
                }
                for filename, payload, yanked in artifacts
            ],
            "releases": {"1.0.0": []},
            "vulnerabilities": [],
        }

    def get_release(self, project: str, version: str) -> dict[str, Any]:
        assert project == "demo"
        assert version == "1.0.0"
        return self.release

    def get_project(self, project: str) -> dict[str, Any]:
        assert project == "demo"
        self.history_calls += 1
        return self.release

    def get_provenance(
        self,
        project: str,
        version: str,
        filename: str,
    ) -> dict[str, Any]:
        assert project == "demo"
        assert version == "1.0.0"
        self.provenance_calls.append(filename)
        return {"version": 1, "attestation_bundles": []}

    def download_distribution(self, url: str) -> bytes:
        self.downloads.append(url)
        return self._payloads[url]

    def package_url(self, project: str, version: str) -> str:
        return f"https://pypi.org/project/{project}/{version}/"


class ScanProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wheel = build_wheel(project="demo", version="1.0.0")
        self.sdist = b"not-a-valid-sdist"

    def test_cli_profiles_are_exclusive_and_fast_is_default(self) -> None:
        parser = build_parser()

        self.assertEqual(parser.parse_args(["scan", "demo"]).scan_profile, "fast")
        self.assertEqual(
            parser.parse_args(["scan", "demo", "--standard"]).scan_profile,
            "standard",
        )
        self.assertEqual(
            parser.parse_args(["scan", "demo", "--full"]).scan_profile,
            "full",
        )
        self.assertEqual(parser.parse_args(["scan", "demo"]).artifact_scope, "target")
        self.assertEqual(
            parser.parse_args(
                ["scan", "demo", "--full", "--artifact-scope", "all"]
            ).artifact_scope,
            "all",
        )
        with self.assertRaises(SystemExit):
            parser.parse_args(["scan", "demo", "--fast", "--full"])

    def test_fast_profile_only_collects_metadata_and_advisories(self) -> None:
        client = ProfileClient([("demo-1.0.0.whl", self.wheel, False)])

        report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="fast",
            include_vulnerabilities=True,
        )

        self.assertEqual(report.files, [])
        self.assertEqual(client.provenance_calls, [])
        self.assertEqual(client.downloads, [])
        self.assertEqual(client.history_calls, 0)

    def test_standard_profile_checks_one_preferred_artifact(self) -> None:
        client = ProfileClient(
            [
                ("demo-1.0.0.tar.gz", self.sdist, False),
                ("demo-1.0.0-py3-none-any.whl", self.wheel, False),
                ("demo-1.0.0-py2-none-any.whl", self.wheel, True),
            ]
        )

        with ThreadPoolExecutor(max_workers=1) as executor:
            report = inspect_package(
                "demo",
                version="1.0.0",
                client=client,  # type: ignore[arg-type]
                scan_profile="standard",
                max_workers=3,
                artifact_executor=executor,
            )

        self.assertEqual(
            [item.filename for item in report.files],
            ["demo-1.0.0-py3-none-any.whl"],
        )
        self.assertEqual(
            client.provenance_calls,
            ["demo-1.0.0-py3-none-any.whl"],
        )
        self.assertEqual(client.downloads, [])
        self.assertEqual(client.history_calls, 0)
        self.assertFalse(report.files[0].artifact.inspected)
        self.assertFalse(report.malicious_package.artifact_analysis)

    def test_full_profile_inspects_all_artifacts_and_reuses_digest(self) -> None:
        client = ProfileClient(
            [
                ("demo-1.0.0.whl", self.wheel, False),
                ("demo-1.0.0-copy.whl", self.wheel, False),
            ]
        )

        report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="full",
            artifact_scope="all",
            max_workers=2,
        )

        self.assertEqual(len(report.files), 2)
        self.assertTrue(all(item.artifact.inspected for item in report.files))
        self.assertEqual(len(client.downloads), 1)
        self.assertEqual(client.history_calls, 1)
        self.assertTrue(report.malicious_package.artifact_analysis)

    def test_full_profile_bounds_artifact_work_and_preserves_order(self) -> None:
        artifacts = [
            (
                f"demo-1.0.0-{index}.whl",
                build_wheel(
                    project="demo",
                    version="1.0.0",
                    extra_files={f"demo/{index}.txt": str(index).encode()},
                ),
                False,
            )
            for index in range(4)
        ]
        client = ProfileClient(artifacts)
        active = 0
        maximum = 0
        lock = threading.Lock()
        original_download = client.download_distribution

        def download(url: str) -> bytes:
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(0.02)
                return original_download(url)
            finally:
                with lock:
                    active -= 1

        client.download_distribution = download  # type: ignore[method-assign]
        report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="full",
            artifact_scope="all",
            max_workers=2,
        )

        self.assertEqual(maximum, 2)
        self.assertEqual(
            [item.filename for item in report.files],
            [filename for filename, _, _ in artifacts],
        )

    def test_profile_and_digest_cache_validate_inputs_and_failures(self) -> None:
        with self.assertRaisesRegex(ValueError, "scan_profile"):
            inspect_package("demo", scan_profile="turbo")
        with self.assertRaisesRegex(ValueError, "max_workers"):
            inspect_package("demo", max_workers=0)
        with self.assertRaisesRegex(ValueError, "artifact_scope"):
            inspect_package("demo", scan_profile="full", artifact_scope="wheels")

        cache = ArtifactDigestCache()

        def fail(url: str) -> bytes:
            raise RuntimeError(url)

        with self.assertRaisesRegex(RuntimeError, "artifact"):
            cache.fetch("artifact", None, fail)

    def test_digest_cache_coalesces_waiters_and_serves_cached_payload(self) -> None:
        cache = ArtifactDigestCache()
        payload = b"shared-artifact"
        digest = hashlib.sha256(payload).hexdigest()
        started = threading.Event()
        release = threading.Event()
        calls = 0

        def load(url: str) -> bytes:
            nonlocal calls
            del url
            calls += 1
            started.set()
            release.wait(timeout=1)
            return payload

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(cache.fetch, "one", digest, load)
            started.wait(timeout=1)
            second = executor.submit(cache.fetch, "two", digest, load)
            release.set()
            self.assertEqual(first.result(), payload)
            self.assertEqual(second.result(), payload)

        self.assertEqual(cache.fetch("three", digest, load), payload)
        self.assertEqual(calls, 1)

    def test_artifact_scopes_filter_for_cross_target_and_sdist_review(self) -> None:
        client = ProfileClient(
            [
                ("demo-1.0.0-cp312-cp312-manylinux_2_28_x86_64.whl", self.wheel, False),
                ("demo-1.0.0-cp311-cp311-manylinux_2_28_x86_64.whl", self.wheel, False),
                ("demo-1.0.0.tar.gz", self.sdist, False),
            ]
        )
        target = TargetEnvironment(
            python_version="3.12",
            platforms=("manylinux_2_28_x86_64",),
            implementation="cp",
            abis=("cp312",),
        )

        target_report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="standard",
            artifact_scope="target",
            target_environment=target,
        )
        sdist_report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="standard",
            artifact_scope="sdist",
            target_environment=target,
        )
        all_report = inspect_package(
            "demo",
            version="1.0.0",
            client=client,  # type: ignore[arg-type]
            scan_profile="standard",
            artifact_scope="all",
            target_environment=target,
        )

        self.assertEqual(
            [item.filename for item in target_report.files],
            ["demo-1.0.0-cp312-cp312-manylinux_2_28_x86_64.whl"],
        )
        self.assertEqual(
            [item.filename for item in sdist_report.files],
            ["demo-1.0.0.tar.gz"],
        )
        self.assertEqual(len(all_report.files), 3)

    def test_standard_and_full_package_cli_render_complete_reports(self) -> None:
        report = TrustReport(
            project="demo",
            version="1.0.0",
            summary="demo",
            package_url="https://pypi.org/project/demo/1.0.0/",
        )
        with patch(
            "trustcheck.cli._scan_project_vulnerabilities",
            return_value=report,
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                json_exit = main(["scan", "demo", "--standard", "--format", "json"])
            self.assertIn('"project": "demo"', stdout.getvalue())

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                text_exit = main(["scan", "demo", "--full"])
            self.assertIn("demo 1.0.0", stdout.getvalue())

        self.assertEqual((json_exit, text_exit), (0, 0))

    def test_resume_fingerprint_changes_with_scan_profile(self) -> None:
        target = ScanTarget(requirement="demo==1", project="demo", version="1")
        args = SimpleNamespace(
            resume_state="",
            scan_profile="fast",
            index_url=DEFAULT_INDEX_URL,
            extra_index_url=[],
            keyring_provider="auto",
        )
        with TemporaryDirectory() as directory:
            args.resume_state = str(Path(directory) / "scan.json")
            fast = _build_scan_state(
                "requirements.txt",
                [target],
                keys=["demo"],
                args=args,
                policy=PolicySettings(),
                plugin_manager=PluginManager(),
            )
            args.scan_profile = "full"
            full = _build_scan_state(
                "requirements.txt",
                [target],
                keys=["demo"],
                args=args,
                policy=PolicySettings(),
                plugin_manager=PluginManager(),
            )

        assert fast is not None and full is not None
        self.assertNotEqual(fast.fingerprint, full.fingerprint)


class PoolReuseTests(unittest.TestCase):
    class Response:
        status = 200

        def __init__(self, data: bytes) -> None:
            self.data = data
            self.released = False

        def release_conn(self) -> None:
            self.released = True

    class Pool:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []
            self.responses: list[PoolReuseTests.Response] = []

        def request(self, method: str, url: str, **kwargs: Any) -> PoolReuseTests.Response:
            del kwargs
            self.calls.append((method, url))
            response = PoolReuseTests.Response(b'{"info":{"version":"1.0.0"}}')
            self.responses.append(response)
            return response

    def test_pypi_pool_is_reused_by_requests_and_cloned_workers(self) -> None:
        pool = self.Pool()
        client = PypiClient(
            enable_cache=False,
            max_retries=0,
            http_pool=pool,  # type: ignore[arg-type]
        )

        client.get_project("demo")
        client.get_project("demo")
        clone = _clone_pypi_client(client)

        self.assertEqual(len(pool.calls), 2)
        self.assertTrue(all(response.released for response in pool.responses))
        self.assertIs(clone.http_pool, pool)
        self.assertEqual(pool.calls[0][1], "https://pypi.org/pypi/demo/json")
        self.assertEqual(JSON_ACCEPT, "application/json")

        without_pool = PypiClient(http_pool=None)
        with self.assertRaisesRegex(RuntimeError, "not configured"):
            without_pool._request_from_pool("https://example", {})

    def test_pool_http_and_transport_errors_keep_retry_semantics(self) -> None:
        client = PypiClient(max_retries=0)
        timeout = client._pool_error(
            urllib3.exceptions.ReadTimeoutError(None, "https://example", "timed out"),
            "https://example",
        )
        tls = client._pool_error(
            urllib3.exceptions.SSLError("bad certificate"),
            "https://example",
        )
        transient = client._pool_error(
            urllib3.exceptions.ProtocolError("reset"),
            "https://example",
        )
        self.assertTrue(timeout.transient)
        self.assertEqual(tls.subcode, "network_tls")
        self.assertTrue(transient.transient)

        class StatusPool(self.Pool):
            def __init__(self, statuses: list[int]) -> None:
                super().__init__()
                self.statuses = statuses

            def request(self, method: str, url: str, **kwargs: Any) -> PoolReuseTests.Response:
                response = super().request(method, url, **kwargs)
                response.status = self.statuses.pop(0)
                return response

        retry_pool = StatusPool([503, 200])
        retrying = PypiClient(
            max_retries=1,
            sleep=lambda delay: None,
            http_pool=retry_pool,  # type: ignore[arg-type]
        )
        self.assertEqual(retrying.get_project("demo")["info"]["version"], "1.0.0")

        missing = PypiClient(
            max_retries=0,
            http_pool=StatusPool([404]),  # type: ignore[arg-type]
        )
        with self.assertRaises(RuntimeError) as caught:
            missing.get_project("demo")
        self.assertEqual(getattr(caught.exception, "subcode", None), "http_not_found")

        class FailingPool(self.Pool):
            def request(self, method: str, url: str, **kwargs: Any) -> PoolReuseTests.Response:
                del method, url, kwargs
                raise urllib3.exceptions.ProtocolError("connection reset")

        failed = PypiClient(
            max_retries=0,
            http_pool=FailingPool(),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(RuntimeError, "connection reset"):
            failed.get_project("demo")


if __name__ == "__main__":
    unittest.main()
