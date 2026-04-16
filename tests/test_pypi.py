from __future__ import annotations

import json
import socket
import ssl
import unittest
from io import BytesIO
from unittest.mock import patch
from urllib import error

import trustcheck
from trustcheck import pypi as pypi_module


class FakeResponse:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self._io = BytesIO(payload)
        self.status = status

    def read(self) -> bytes:
        return self._io.read()

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
