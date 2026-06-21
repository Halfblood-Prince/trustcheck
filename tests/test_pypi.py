from __future__ import annotations

import json
import socket
import ssl
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib import error

import trustcheck
from trustcheck import pypi as pypi_module
from trustcheck.resolver import ArtifactReference


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        content_length: int | None = None,
    ) -> None:
        self._io = BytesIO(payload)
        self.status = status
        self.headers = (
            {"Content-Length": str(content_length)}
            if content_length is not None
            else {}
        )

    def read(self, size: int = -1) -> bytes:
        return self._io.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class PypiClientTests(unittest.TestCase):
    def test_user_agent_is_versioned(self) -> None:
        client = pypi_module.PypiClient()
        self.assertEqual(client.user_agent, pypi_module.DEFAULT_USER_AGENT)
        self.assertEqual(client.user_agent, f"trustcheck/{trustcheck.__version__}")

    def test_retries_transient_http_errors_before_succeeding(self) -> None:
        attempts: list[int] = []
        sleeps: list[float] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            if len(attempts) < 3:
                raise error.HTTPError(
                    "https://pypi.org/pypi/gridoptim/json",
                    503,
                    "service unavailable",
                    hdrs=None,
                    fp=None,
                )
            return FakeResponse(json.dumps({"info": {"version": "1.0.0"}}).encode())

        client = pypi_module.PypiClient(max_retries=2, backoff_factor=0.1, sleep=sleeps.append)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            payload = client.get_project("gridoptim")

        self.assertEqual(payload["info"]["version"], "1.0.0")
        self.assertEqual(len(attempts), 3)
        self.assertEqual(sleeps, [0.1, 0.2])

    def test_does_not_retry_permanent_404(self) -> None:
        attempts: list[int] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            raise error.HTTPError(
                "https://pypi.org/pypi/gridoptim/json",
                404,
                "not found",
                hdrs=None,
                fp=None,
            )

        client = pypi_module.PypiClient(max_retries=3, sleep=lambda delay: None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(pypi_module.PypiClientError) as ctx:
                client.get_project("gridoptim")

        self.assertEqual(ctx.exception.subcode, "http_not_found")
        self.assertEqual(len(attempts), 1)

    def test_url_errors_report_retry_hint(self) -> None:
        client = pypi_module.PypiClient(max_retries=0, sleep=lambda delay: None)

        with patch(
            "urllib.request.urlopen",
            side_effect=error.URLError("temporary failure in name resolution"),
        ):
            with self.assertRaisesRegex(pypi_module.PypiClientError, "retrying may help"):
                client.get_project("gridoptim")

    def test_direct_socket_timeout_is_treated_as_transient(self) -> None:
        attempts: list[int] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            raise socket.timeout("timed out")

        client = pypi_module.PypiClient(max_retries=1, sleep=lambda delay: None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(pypi_module.PypiClientError, "retrying may help"):
                client.get_project("gridoptim")

        self.assertEqual(len(attempts), 2)

    def test_permanent_url_error_string_is_not_retried(self) -> None:
        attempts: list[int] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            raise error.URLError("connection refused")

        client = pypi_module.PypiClient(max_retries=3, sleep=lambda delay: None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(
                pypi_module.PypiClientError, "retrying is unlikely to help"
            ):
                client.get_project("gridoptim")

        self.assertEqual(len(attempts), 1)

    def test_tls_errors_are_classified_as_permanent(self) -> None:
        client = pypi_module.PypiClient(max_retries=2, sleep=lambda delay: None)

        with patch(
            "urllib.request.urlopen",
            side_effect=error.URLError(ssl.SSLError("certificate verify failed")),
        ):
            with self.assertRaises(pypi_module.PypiClientError) as ctx:
                client.get_project("gridoptim")

        self.assertEqual(ctx.exception.subcode, "network_tls")

    def test_temporary_dns_error_is_retried(self) -> None:
        attempts: list[int] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            raise error.URLError(socket.gaierror(socket.EAI_AGAIN, "temporary failure"))

        client = pypi_module.PypiClient(max_retries=1, sleep=lambda delay: None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(pypi_module.PypiClientError, "retrying may help"):
                client.get_project("gridoptim")

        self.assertEqual(len(attempts), 2)

    def test_non_temporary_dns_error_is_not_retried(self) -> None:
        attempts: list[int] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            raise error.URLError(socket.gaierror(socket.EAI_NONAME, "name or service not known"))

        client = pypi_module.PypiClient(max_retries=2, sleep=lambda delay: None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(
                pypi_module.PypiClientError, "retrying is unlikely to help"
            ):
                client.get_project("gridoptim")

        self.assertEqual(len(attempts), 1)

    def test_malformed_json_is_permanent(self) -> None:
        client = pypi_module.PypiClient(max_retries=2, sleep=lambda delay: None)

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(b"{not-json"),
        ):
            with self.assertRaises(pypi_module.PypiClientError) as ctx:
                client.get_project("gridoptim")

        self.assertEqual(ctx.exception.subcode, "json_malformed")

    def test_non_http_request_url_is_rejected(self) -> None:
        client = pypi_module.PypiClient(max_retries=0)

        with self.assertRaises(pypi_module.PypiClientError) as ctx:
            client.download_distribution("file:///tmp/package.whl")

        self.assertEqual(ctx.exception.subcode, "url_scheme_invalid")

    def test_list_project_urls_is_normalized_to_empty_mapping(self) -> None:
        client = pypi_module.PypiClient(max_retries=0, sleep=lambda delay: None)

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(json.dumps({"info": {"project_urls": []}}).encode()),
        ):
            payload = client.get_project("gridoptim")

        self.assertEqual(payload["info"]["project_urls"], {})

    def test_unexpected_provenance_shape_is_handled_gracefully(self) -> None:
        client = pypi_module.PypiClient(max_retries=0, sleep=lambda delay: None)

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(json.dumps({"attestation_bundles": {}}).encode()),
        ):
            with self.assertRaisesRegex(
                pypi_module.PypiClientError, "unexpected provenance response shape"
            ):
                client.get_provenance("gridoptim", "2.2.0", "gridoptim.whl")

    def test_json_requests_are_cached(self) -> None:
        calls: list[str] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            calls.append("hit")
            return FakeResponse(json.dumps({"info": {"version": "1.0.0"}}).encode())

        client = pypi_module.PypiClient()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            first = client.get_project("gridoptim")
            second = client.get_project("gridoptim")

        self.assertEqual(first, second)
        self.assertEqual(calls, ["hit"])

    def test_download_requests_are_cached(self) -> None:
        calls: list[str] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            calls.append("hit")
            return FakeResponse(b"wheel-bytes")

        client = pypi_module.PypiClient()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            first = client.download_distribution(
                "https://files.pythonhosted.org/packages/gridoptim.whl"
            )
            second = client.download_distribution(
                "https://files.pythonhosted.org/packages/gridoptim.whl"
            )

        self.assertEqual(first, b"wheel-bytes")
        self.assertEqual(second, b"wheel-bytes")
        self.assertEqual(calls, ["hit"])

    def test_download_rejects_streams_and_declared_lengths_over_cap(self) -> None:
        url = "https://files.pythonhosted.org/packages/large.whl"
        for response in (
            FakeResponse(b"12345"),
            FakeResponse(b"", content_length=5),
        ):
            client = pypi_module.PypiClient(
                max_download_bytes=4,
                max_retries=0,
                enable_cache=False,
            )
            with self.subTest(response=response), patch(
                "urllib.request.urlopen",
                return_value=response,
            ):
                with self.assertRaises(pypi_module.PypiClientError) as ctx:
                    client.download_distribution(url)
            self.assertEqual(ctx.exception.subcode, "response_too_large")

        malformed_length = FakeResponse(b"ok")
        malformed_length.headers["Content-Length"] = "unknown"
        with patch("urllib.request.urlopen", return_value=malformed_length):
            self.assertEqual(
                pypi_module.PypiClient(enable_cache=False).download_distribution(url),
                b"ok",
            )

        class UnboundedResponse(FakeResponse):
            def read(self, size: int = -1) -> bytes:
                if size != -1:
                    raise TypeError("size unsupported")
                return super().read()

        with patch("urllib.request.urlopen", return_value=UnboundedResponse(b"ok")):
            self.assertEqual(
                pypi_module.PypiClient(enable_cache=False).download_distribution(url),
                b"ok",
            )

    def test_request_hook_receives_retry_events(self) -> None:
        events: list[tuple[str, dict[str, object]]] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            raise error.URLError("timed out")

        client = pypi_module.PypiClient(
            max_retries=1,
            backoff_factor=0.1,
            sleep=lambda delay: None,
            request_hook=lambda event, payload: events.append((event, payload)),
        )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(pypi_module.PypiClientError):
                client.get_project("gridoptim")

        event_names = [event for event, _ in events]
        self.assertIn("request", event_names)
        self.assertIn("failure", event_names)
        self.assertIn("retry", event_names)

    def test_disk_cache_supports_offline_mode(self) -> None:
        cache_store: dict[tuple[str, str | None], bytes] = {}

        def read_cache(
            self: pypi_module.PypiClient, url: str, *, accept: str | None
        ) -> bytes | None:
            return cache_store.get((url, accept))

        def write_cache(
            self: pypi_module.PypiClient,
            url: str,
            payload: bytes,
            *,
            accept: str | None,
        ) -> None:
            cache_store[(url, accept)] = payload

        with patch.object(pypi_module.PypiClient, "_read_disk_cache", read_cache), patch.object(
            pypi_module.PypiClient,
            "_write_disk_cache",
            write_cache,
        ):
            client = pypi_module.PypiClient(cache_dir=".cache/test-cache")
            with patch(
                "urllib.request.urlopen",
                return_value=FakeResponse(json.dumps({"info": {"version": "1.0.0"}}).encode()),
            ):
                payload = client.get_project("gridoptim")

            self.assertEqual(payload["info"]["version"], "1.0.0")
            self.assertTrue(cache_store)

            offline_client = pypi_module.PypiClient(cache_dir=".cache/test-cache", offline=True)
            offline_payload = offline_client.get_project("gridoptim")
            self.assertEqual(offline_payload["info"]["version"], "1.0.0")

    def test_offline_mode_reports_cache_miss_subcode(self) -> None:
        with patch.object(pypi_module.PypiClient, "_read_disk_cache", return_value=None):
            client = pypi_module.PypiClient(cache_dir=".cache/test-cache", offline=True)

            with self.assertRaises(pypi_module.PypiClientError) as ctx:
                client.get_project("gridoptim")

        self.assertEqual(ctx.exception.subcode, "offline_cache_miss")

    def test_cache_disabled_does_not_retain_json_or_distribution_payloads(self) -> None:
        responses = [
            FakeResponse(json.dumps({"info": {"version": "1.0.0"}}).encode()),
            FakeResponse(json.dumps({"info": {"version": "1.0.0"}}).encode()),
            FakeResponse(b"first-wheel"),
            FakeResponse(b"second-wheel"),
        ]
        client = pypi_module.PypiClient(enable_cache=False)

        with patch("urllib.request.urlopen", side_effect=responses) as urlopen:
            client.get_project("demo")
            client.get_project("demo")
            first = client.download_distribution("https://example.com/demo.whl")
            second = client.download_distribution("https://example.com/demo.whl")

        self.assertIsNone(client._json_cache)
        self.assertIsNone(client._bytes_cache)
        self.assertEqual(first, b"first-wheel")
        self.assertEqual(second, b"second-wheel")
        self.assertEqual(urlopen.call_count, 4)

    def test_release_and_provenance_paths_quote_user_input(self) -> None:
        client = pypi_module.PypiClient()
        project_payload = {"info": {"version": "1+local"}}
        provenance_payload = {"version": 1, "attestation_bundles": []}

        with patch.object(
            pypi_module.PypiClient,
            "_get_json",
            autospec=True,
            side_effect=[project_payload, provenance_payload],
        ) as get_json:
            release = client.get_release("demo package", "1+local")
            provenance = client.get_provenance(
                "demo package",
                "1+local",
                "demo package.whl",
            )

        self.assertEqual(release["info"]["version"], "1+local")
        self.assertEqual(provenance["version"], 1)
        self.assertEqual(
            get_json.call_args_list[0].args[1],
            "/pypi/demo%20package/1%2Blocal/json",
        )
        self.assertEqual(
            get_json.call_args_list[1].args[1],
            "/integrity/demo%20package/1%2Blocal/demo%20package.whl/provenance",
        )

    def test_offline_download_returns_disk_cached_bytes(self) -> None:
        client = pypi_module.PypiClient(offline=True)
        with patch.object(
            pypi_module.PypiClient,
            "_read_disk_cache",
            return_value=b"cached-wheel",
        ):
            payload = client.download_distribution("https://example.com/demo.whl")

        self.assertEqual(payload, b"cached-wheel")

        bounded = pypi_module.PypiClient(offline=True, max_download_bytes=1)
        with patch.object(
            pypi_module.PypiClient,
            "_read_disk_cache",
            return_value=b"cached-wheel",
        ), self.assertRaisesRegex(pypi_module.PypiClientError, "download limit"):
            bounded.download_distribution("https://example.com/demo.whl")

    def test_disk_cached_json_populates_memory_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            client = pypi_module.PypiClient(cache_dir=tmpdir)
            url = "https://pypi.org/pypi/demo/json"
            cache_path = client._cache_path(url, accept=pypi_module.JSON_ACCEPT)
            assert cache_path is not None
            Path(cache_path).write_bytes(b'{"info":{"version":"1.0.0"}}')

            first = client.get_project("demo")
            Path(cache_path).unlink()
            second = client.get_project("demo")

        self.assertEqual(first, second)
        self.assertEqual(second["info"]["version"], "1.0.0")

    def test_nested_url_error_reasons_and_network_helpers(self) -> None:
        class ReasonWrapper:
            def __init__(self, reason: object) -> None:
                self.reason = reason

        class EmptyReason:
            def __str__(self) -> str:
                return ""

        client = pypi_module.PypiClient()
        nested = ReasonWrapper(ReasonWrapper(None))

        self.assertIsInstance(client._unwrap_url_error_reason(nested), ReasonWrapper)
        self.assertTrue(client._is_transient_network_reason(TimeoutError("timed out")))
        self.assertTrue(
            client._is_transient_network_reason(
                OSError(socket.EAI_AGAIN, "temporary failure")
            )
        )
        self.assertTrue(client._is_transient_network_reason(OSError("timed out")))
        self.assertFalse(client._is_transient_network_reason("connection refused"))
        self.assertFalse(client._is_transient_network_reason(object()))
        self.assertEqual(client._format_network_reason(EmptyReason()), "EmptyReason")
        self.assertEqual(
            client._network_subcode(OSError("temporary failure"), True),
            "network_transient",
        )
        self.assertEqual(
            client._network_subcode(OSError("permanent failure"), False),
            "network_error",
        )

    def test_invalid_project_shape_has_stable_subcode(self) -> None:
        client = pypi_module.PypiClient()
        with self.assertRaises(pypi_module.PypiClientError) as ctx:
            client._validate_project_payload(
                {"urls": [{"url": "https://example.com/demo.whl"}]},
                "/pypi/demo/json",
            )

        self.assertEqual(ctx.exception.subcode, "project_shape_invalid")

    def test_index_backed_client_builds_release_from_locked_artifacts(self) -> None:
        artifact = ArtifactReference(
            filename="demo-1.0-py3-none-any.whl",
            url="https://private.example/files/demo.whl",
            hashes=(("sha256", "a" * 64),),
        )
        repository = SimpleNamespace(download=lambda url, index_url=None: b"wheel")
        client = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(),
            project="demo",
            version="1.0",
            index_url="https://user:secret@private.example/simple",
            artifacts=(artifact,),
            requires_dist=("dep>=1",),
            repository_client=repository,
        )

        release = client.get_release("Demo", "1.0")
        project = client.get_project("demo")

        self.assertEqual(release["info"]["requires_dist"], ["dep>=1"])
        self.assertEqual(release["urls"][0]["digests"]["sha256"], "a" * 64)
        self.assertIn("1.0", project["releases"])
        self.assertEqual(
            client.download_distribution(artifact.url or ""),
            b"wheel",
        )
        self.assertNotIn("secret", client.package_url("demo", "1.0"))
        self.assertEqual(
            client.get_provenance("demo", "1.0", "demo.whl"),
            {"version": 1, "attestation_bundles": []},
        )

    def test_index_backed_client_discovers_hash_locked_artifacts(self) -> None:
        from trustcheck.indexes import IndexFile, IndexProject

        digest = "a" * 64
        repository = SimpleNamespace(
            get_project=lambda index, project: IndexProject(
                name=project,
                index_url=index,
                files=(
                    IndexFile(
                        filename="demo-1.0-py3-none-any.whl",
                        url="https://private.example/files/demo.whl",
                        hashes=(("sha256", digest),),
                    ),
                    IndexFile(
                        filename="demo-2.0-py3-none-any.whl",
                        url="https://private.example/files/demo2.whl",
                        hashes=(("sha256", "b" * 64),),
                    ),
                ),
            )
        )
        client = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(),
            project="demo",
            version="1.0",
            index_url="https://private.example/simple",
            artifacts=(
                ArtifactReference(hashes=(("sha256", digest),)),
            ),
            repository_client=repository,
        )

        release = client.get_release("demo", "1.0")

        self.assertEqual(len(release["urls"]), 1)
        self.assertEqual(
            release["urls"][0]["filename"],
            "demo-1.0-py3-none-any.whl",
        )

    def test_index_backed_client_reads_local_artifacts_and_validates_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_path = Path(tmpdir) / "demo.whl"
            artifact_path.write_bytes(b"local")
            client = pypi_module.IndexBackedPackageClient(
                base_client=pypi_module.PypiClient(),
                project="demo",
                version="1.0",
                index_url="https://private.example/simple",
                artifacts=(
                    ArtifactReference(
                        filename="demo.whl",
                        url=artifact_path.as_uri(),
                    ),
                ),
                repository_client=SimpleNamespace(),
            )
            self.assertEqual(
                client.download_distribution(artifact_path.as_uri()),
                b"local",
            )
            client.base_client.max_download_bytes = 1
            with self.assertRaisesRegex(pypi_module.PypiClientError, "download limit"):
                client.download_distribution(artifact_path.as_uri())

        with self.assertRaisesRegex(pypi_module.PypiClientError, "scoped"):
            client.get_project("other")
        with self.assertRaisesRegex(pypi_module.PypiClientError, "locked version"):
            client.get_release("demo", "2.0")
        with self.assertRaisesRegex(pypi_module.PypiClientError, "locked version"):
            client.get_provenance("demo", "2.0", "demo.whl")

    def test_index_backed_client_reports_missing_and_failed_artifacts(self) -> None:
        repository = SimpleNamespace(
            get_project=lambda index, project: None,
            download=lambda url, index_url=None: (_ for _ in ()).throw(
                RuntimeError("denied")
            ),
        )
        client = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(),
            project="demo",
            version="1.0",
            index_url="https://private.example/simple",
            artifacts=(ArtifactReference(hashes=(("sha256", "a" * 64),)),),
            repository_client=repository,
        )
        with self.assertRaisesRegex(pypi_module.PypiClientError, "not found"):
            client.get_release("demo", "1.0")
        with self.assertRaisesRegex(pypi_module.PypiClientError, "denied"):
            client.download_distribution("https://private.example/demo.whl")

    def test_index_backed_client_default_repository_and_local_read_failure(self) -> None:
        client = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(timeout=3.0),
            project="demo",
            version="1.0",
            index_url="https://private.example/simple",
        )
        self.assertEqual(client.timeout, 3.0)
        self.assertIsNotNone(client.repository_client)
        with self.assertRaisesRegex(pypi_module.PypiClientError, "unable to read"):
            client.download_distribution("file:///definitely/missing/demo.whl")

    def test_index_backed_client_rejects_nonmatching_index_artifacts(self) -> None:
        from trustcheck.indexes import IndexFile, IndexProject

        repository = SimpleNamespace(
            get_project=lambda index, project: IndexProject(
                name=project,
                index_url=index,
                files=(
                    IndexFile(
                        filename="demo-1.0-py3-none-any.whl",
                        url="https://private.example/files/demo.whl",
                        hashes=(("sha256", "b" * 64),),
                    ),
                ),
            )
        )
        client = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(),
            project="demo",
            version="1.0",
            index_url="https://private.example/simple",
            artifacts=(
                ArtifactReference(hashes=(("sha256", "a" * 64),)),
            ),
            repository_client=repository,
        )
        with self.assertRaisesRegex(pypi_module.PypiClientError, "no locked artifacts"):
            client.get_release("demo", "1.0")

        release = pypi_module.IndexBackedPackageClient(
            base_client=pypi_module.PypiClient(),
            project="demo",
            version="1.0",
            index_url="https://private.example/simple",
            artifacts=(
                ArtifactReference(url="https://private.example/files/demo.whl"),
            ),
            repository_client=repository,
        ).get_release("demo", "1.0")
        self.assertEqual(release["urls"][0]["filename"], "demo.whl")
