from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib import error, parse, request

from tests.security_http_fixture import security_http_server
from trustcheck.indexes import (
    IndexConfiguration,
    IndexError,
    IndexFile,
    IndexProject,
    IndexURLPolicy,
    SimpleRepositoryClient,
    _hash_fragment,
    _hash_mapping,
    _metadata_hashes,
    _optional_int,
    _optional_string,
    _PolicyRedirectHandler,
    _same_origin,
    _without_url_credentials,
    _yanked_value,
    files_for_version,
    normalize_index_url,
    parse_simple_html,
    parse_simple_json,
    redact_url_credentials,
)


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        content_type: str = "application/vnd.pypi.simple.v1+json",
        url: str = "https://index.example/simple/demo/",
    ) -> None:
        self.payload = BytesIO(payload)
        self.headers = {"Content-Type": content_type}
        self.url = url

    def read(self) -> bytes:
        return self.payload.read()

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class RedirectLoopHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", self.path)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def simple_payload() -> bytes:
    return json.dumps(
        {
            "meta": {"api-version": "1.4"},
            "name": "demo",
            "files": [
                {
                    "filename": "demo-1.0-py3-none-any.whl",
                    "url": "../../files/demo-1.0-py3-none-any.whl",
                    "hashes": {"sha256": "a" * 64},
                    "requires-python": ">=3.11",
                    "yanked": "broken",
                    "size": 12,
                    "upload-time": "2026-01-01T00:00:00Z",
                    "core-metadata": f"sha256={'b' * 64}",
                },
                {"filename": 3, "url": None},
            ],
        }
    ).encode()


class IndexTests(unittest.TestCase):
    def test_index_configuration_normalizes_and_redacts(self) -> None:
        configuration = IndexConfiguration(
            index_url="https://user:secret@index.example/simple",
            extra_index_urls=(
                "https://pypi.org/simple/",
                "https://pypi.org/simple",
            ),
            keyring_provider="subprocess",
        )

        self.assertEqual(len(configuration.all_urls), 2)
        self.assertTrue(configuration.has_multiple_indexes)
        self.assertEqual(
            configuration.pip_arguments(),
            [
                "--index-url",
                "https://index.example/simple",
                "--extra-index-url",
                "https://pypi.org/simple/",
                "--extra-index-url",
                "https://pypi.org/simple",
                "--keyring-provider",
                "subprocess",
            ],
        )
        self.assertTrue(configuration.has_url_credentials)
        with configuration.pip_subprocess() as (arguments, environment):
            self.assertEqual(arguments, [])
            assert environment is not None
            config_path = Path(environment["PIP_CONFIG_FILE"])
            config_text = config_path.read_text(encoding="utf-8")
            self.assertIn(
                "index-url = https://user:secret@index.example/simple",
                config_text,
            )
            self.assertIn("keyring-provider = subprocess", config_text)
        self.assertFalse(config_path.exists())
        self.assertEqual(
            configuration.redacted()["index_url"],
            "https://<redacted>@index.example/simple",
        )
        self.assertEqual(
            normalize_index_url("https://index.example/simple"),
            "https://index.example/simple/",
        )
        self.assertEqual(
            redact_url_credentials(
                "failure for https://user:secret@index.example/simple/demo/"
            ),
            "failure for https://<redacted>@index.example/simple/demo/",
        )

    def test_index_configuration_rejects_invalid_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "keyring provider"):
            IndexConfiguration(keyring_provider="bad")
        with self.assertRaisesRegex(ValueError, "scheme and host|HTTPS"):
            IndexConfiguration(index_url="file:///tmp/simple")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            IndexConfiguration(index_url="http://index.example/simple")
        self.assertEqual(
            IndexConfiguration(
                index_url="http://index.example/simple",
                allow_insecure_index=True,
            ).all_urls,
            ("http://index.example/simple/",),
        )
        with self.assertRaisesRegex(ValueError, "empty"):
            normalize_index_url("  ")

    def test_url_policy_handles_hosts_ports_and_insecure_opt_in(self) -> None:
        policy = IndexURLPolicy(allow_insecure_index=True)
        for url in (
            "http://127.0.0.1:8080/simple",
            "http://[::1]:8080/simple",
            "http://localhost/simple",
            "https://index.example/simple",
        ):
            with self.subTest(url=url):
                policy.validate_index_url(url)

        for url in (
            "https://index.example:bad/simple",
            "https://[::1/simple",
            "https:///simple",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                ValueError,
                "malformed|scheme and host",
            ):
                policy.validate_index_url(url)

    def test_redirect_policy_allows_same_origin_and_strips_cross_origin_auth(self) -> None:
        handler = _PolicyRedirectHandler(IndexURLPolicy())
        token = "Basic dXNlcjpzZWNyZXQ="
        source = request.Request(
            "https://index.example/simple/demo/",
            headers={"Authorization": token},
        )

        same_origin = handler.redirect_request(
            source,
            None,
            302,
            "Found",
            {},
            "https://index.example/simple/other/",
        )
        assert same_origin is not None
        self.assertEqual(same_origin.get_header("Authorization"), token)

        cross_origin = handler.redirect_request(
            source,
            None,
            302,
            "Found",
            {},
            "https://files.example/demo.whl",
        )
        assert cross_origin is not None
        self.assertIsNone(cross_origin.get_header("Authorization"))

        long_redirect = handler.redirect_request(
            source,
            None,
            302,
            "Found",
            {},
            "https://index.example/simple/" + ("a" * 8192),
        )
        assert long_redirect is not None
        self.assertTrue(long_redirect.full_url.endswith("a" * 8192))

        with self.assertRaises(error.URLError):
            handler.redirect_request(
                source,
                None,
                302,
                "Found",
                {},
                "http://index.example/simple/demo/",
            )

    def test_redirect_loop_honors_policy_limit(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectLoopHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = SimpleRepositoryClient(
                timeout=1.0,
                url_policy=IndexURLPolicy(
                    allow_insecure_index=True,
                    max_redirects=2,
                ),
            )
            with self.assertRaisesRegex(IndexError, "redirect|HTTP 302"):
                client.get_project(
                    f"http://127.0.0.1:{server.server_port}/simple",
                    "demo",
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_parse_pep691_json_preserves_file_metadata(self) -> None:
        project = parse_simple_json(
            simple_payload(),
            project="Demo",
            index_url="https://index.example/simple/",
            response_url="https://index.example/simple/demo/",
        )

        self.assertEqual(project.api_version, "1.4")
        self.assertEqual(len(project.files), 1)
        artifact = project.files[0]
        self.assertEqual(artifact.filename, "demo-1.0-py3-none-any.whl")
        self.assertEqual(
            artifact.url,
            "https://index.example/files/demo-1.0-py3-none-any.whl",
        )
        self.assertEqual(artifact.hashes, (("sha256", "a" * 64),))
        self.assertEqual(artifact.metadata_hashes, (("sha256", "b" * 64),))
        self.assertEqual(
            artifact.metadata_url,
            "https://index.example/files/demo-1.0-py3-none-any.whl.metadata",
        )
        self.assertEqual(artifact.requires_python, ">=3.11")
        self.assertEqual(artifact.yanked, "broken")
        self.assertEqual(artifact.size, 12)

    def test_parse_pep691_json_core_metadata_dict_and_query_sidecar_url(self) -> None:
        payload = json.dumps(
            {
                "meta": {"api-version": "1.4"},
                "files": [
                    {
                        "filename": "demo-1.0-py3-none-any.whl",
                        "url": "demo-1.0-py3-none-any.whl?token=abc",
                        "core-metadata": {"sha256": "b" * 64},
                    },
                ],
            }
        ).encode()

        project = parse_simple_json(
            payload,
            project="demo",
            index_url="https://index.example/simple/",
            response_url="https://index.example/simple/demo/",
        )

        artifact = project.files[0]
        self.assertEqual(artifact.metadata_hashes, (("sha256", "b" * 64),))
        self.assertEqual(
            artifact.metadata_url,
            "https://index.example/simple/demo/"
            "demo-1.0-py3-none-any.whl.metadata?token=abc",
        )

    def test_parse_pep691_json_fuzz_regressions(self) -> None:
        payload = (
            b'{"meta":{"api-version":"1.4"},"files":false,'
            b'"files":[{"filename":"demo-1.0-py3-none-any.whl",'
            b'"url":"https://User%40example:Secret@index.example/demo.whl",'
            b'"hashes":{"SHA256":"' + (b"A" * 64) + b'"},'
            b'"core-metadata":true,'
            b'"size":true,'
            b'"upload-time":false}]}'
        )

        project = parse_simple_json(
            payload,
            project="demo",
            index_url="https://index.example/simple/",
            response_url="https://index.example/simple/demo/",
        )

        artifact = project.files[0]
        self.assertEqual(
            artifact.url,
            "https://<redacted>@index.example/demo.whl",
        )
        self.assertEqual(artifact.hashes, (("sha256", "a" * 64),))
        self.assertEqual(
            artifact.metadata_url,
            "https://<redacted>@index.example/demo.whl.metadata",
        )
        self.assertEqual(artifact.metadata_hashes, ())
        self.assertIsNone(artifact.size)
        self.assertIsNone(artifact.upload_time)

    def test_parse_pep691_rejects_unsupported_or_invalid_payloads(self) -> None:
        cases = [
            (b"[]", "object"),
            (b'{"meta":{"api-version":"2.0"},"files":[]}', "unsupported"),
            (b'{"meta":{"api-version":"1.0"}}', "files array"),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    parse_simple_json(
                        payload,
                        project="demo",
                        index_url="https://index.example/simple/",
                        response_url="https://index.example/simple/demo/",
                    )

    def test_parse_remote_index_rejects_unsafe_artifact_schemes(self) -> None:
        for scheme_url in (
            "file:///tmp/demo.whl",
            "ftp://index.example/demo.whl",
            "data:text/plain,demo",
            "plugin+demo://artifact",
        ):
            payload = json.dumps(
                {
                    "meta": {"api-version": "1.4"},
                    "files": [
                        {
                            "filename": "demo-1.0-py3-none-any.whl",
                            "url": scheme_url,
                        },
                    ],
                }
            ).encode()
            with self.subTest(url=scheme_url), self.assertRaisesRegex(
                ValueError,
                "HTTPS|scheme and host",
            ):
                parse_simple_json(
                    payload,
                    project="demo",
                    index_url="https://index.example/simple/",
                    response_url="https://index.example/simple/demo/",
                )

    def test_parse_pep503_html_and_versions(self) -> None:
        html = f"""
        <html><head>
          <meta name="pypi:repository-version" content="1.4">
          <meta name="api-version" content="1.4">
        </head><body>
          <a href="/">root</a>
          <a href="../../files/demo-1.0.tar.gz#sha256={'c' * 64}"
             data-requires-python="&gt;=3.11"
             data-yanked
             data-dist-info-metadata="sha256={'d' * 64}">demo</a>
          <a href="https://exämple.test/files/demo-1.1.tar.gz#SHA256={'e' * 64}"
             data-core-metadata="true">unicode-host</a>
          <a>missing</a>
        </body></html>
        """.encode()
        project = parse_simple_html(
            html,
            project="demo",
            index_url="https://index.example/simple/",
            response_url="https://index.example/simple/demo/",
        )

        self.assertEqual(len(project.files), 2)
        artifact = project.files[0]
        self.assertEqual(artifact.hashes, (("sha256", "c" * 64),))
        self.assertEqual(artifact.requires_python, ">=3.11")
        self.assertEqual(artifact.metadata_hashes, (("sha256", "d" * 64),))
        self.assertEqual(
            [item.filename for item in files_for_version(project, "1.0")],
            ["demo-1.0.tar.gz"],
        )
        self.assertEqual(
            artifact.metadata_url,
            "https://index.example/files/demo-1.0.tar.gz.metadata",
        )
        unicode_artifact = project.files[1]
        self.assertEqual(unicode_artifact.hashes, (("sha256", "e" * 64),))
        self.assertEqual(
            unicode_artifact.metadata_url,
            "https://exämple.test/files/demo-1.1.tar.gz.metadata",
        )
        self.assertEqual(files_for_version(project, "2.0"), ())

    def test_simple_client_queries_caches_and_locates_artifacts(self) -> None:
        calls: list[request.Request] = []

        def opener(req: request.Request, timeout: float) -> FakeResponse:
            self.assertEqual(timeout, 4.0)
            calls.append(req)
            return FakeResponse(simple_payload())

        client = SimpleRepositoryClient(timeout=4.0, opener=opener)
        first = client.get_project("https://index.example/simple", "Demo")
        second = client.get_project("https://index.example/simple/", "demo")

        self.assertIs(first, second)
        self.assertEqual(len(calls), 1)
        assert first is not None
        self.assertEqual(
            client.locate_artifact_index(
                "demo",
                first.files[0].url,
                ("https://index.example/simple", "https://other.example/simple"),
            ),
            "https://index.example/simple",
        )
        self.assertEqual(
            client.locate_artifact_index(
                "demo",
                None,
                ("https://index.example/simple",),
            ),
            "https://index.example/simple",
        )

    def test_simple_client_supports_html_download_404_and_failures(self) -> None:
        html = b'<a href="demo-1.0.tar.gz#sha256=aa">demo</a>'
        responses: list[object] = [
            FakeResponse(html, content_type="text/html"),
            FakeResponse(b"artifact", content_type="application/octet-stream"),
        ]

        def opener(req: request.Request, timeout: float) -> FakeResponse:
            del req, timeout
            response = responses.pop(0)
            assert isinstance(response, FakeResponse)
            return response

        client = SimpleRepositoryClient(opener=opener)
        project = client.get_project("https://index.example/simple", "demo")
        assert project is not None
        self.assertEqual(project.files[0].hashes, (("sha256", "aa"),))
        self.assertEqual(
            client.download(
                "https://index.example/files/demo.tar.gz",
                index_url="https://index.example/simple",
            ),
            b"artifact",
        )

        not_found = error.HTTPError("url", 404, "missing", None, None)
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: (_ for _ in ()).throw(not_found)
        )
        self.assertIsNone(
            client.get_project("https://index.example/simple", "missing")
        )

        server_error = error.HTTPError("url", 500, "bad", None, None)
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: (_ for _ in ()).throw(server_error)
        )
        with self.assertRaisesRegex(IndexError, "HTTP 500"):
            client.get_project("https://index.example/simple", "demo")
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: (_ for _ in ()).throw(
                error.URLError("offline")
            )
        )
        with self.assertRaisesRegex(IndexError, "unable to query"):
            client.get_project("https://index.example/simple", "demo")
        with self.assertRaisesRegex(IndexError, "unable to download"):
            client.download("https://index.example/demo.whl")

    def test_simple_client_validates_final_response_url(self) -> None:
        downgraded = FakeResponse(
            simple_payload(),
            url="http://index.example/simple/demo/",
        )
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: downgraded,
        )

        with self.assertRaisesRegex(IndexError, "HTTPS-to-HTTP"):
            client.get_project("https://index.example/simple", "demo")

    def test_simple_client_streaming_cap_handles_headers_and_observed_size(self) -> None:
        declared = FakeResponse(b"", content_type="application/octet-stream")
        declared.headers["Content-Length"] = "5"
        observed = FakeResponse(b"12345", content_type="application/octet-stream")
        for response in (declared, observed):
            client = SimpleRepositoryClient(
                opener=lambda *args, response=response, **kwargs: response,
                max_response_bytes=4,
            )
            with self.subTest(response=response), self.assertRaisesRegex(
                IndexError, "exceeds"
            ):
                client.download("https://index.example/demo.whl")

        malformed = FakeResponse(b"ok")
        malformed.headers["Content-Length"] = "unknown"
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: malformed,
            max_response_bytes=4,
        )
        self.assertEqual(client.download("https://index.example/demo.whl"), b"ok")

    def test_security_http_fixture_exercises_sensitive_index_boundaries(self) -> None:
        with security_http_server() as base_url:
            client = SimpleRepositoryClient(
                max_response_bytes=1024,
                url_policy=IndexURLPolicy(allow_insecure_index=True),
            )
            authenticated_url = base_url.replace("http://", "http://user:pass@")

            self.assertEqual(
                client.download(f"{authenticated_url}/auth"),
                b'{"meta":{"api-version":"1.0"},"files":[]}',
            )
            self.assertEqual(client.download(f"{base_url}/chunked"), b"chunk-body")
            self.assertEqual(
                client.download(f"{base_url}/demo.whl.metadata"),
                b"Metadata-Version: 2.3\nName: demo\n",
            )
            self.assertEqual(
                client.download(f"{base_url}/demo.whl.provenance"),
                b'{"provenance":[]}',
            )
            self.assertEqual(
                client.download(f"{base_url}/incorrect-length"),
                b"s",
            )
            self.assertEqual(
                client.download(f"{base_url}/slow"),
                b'{"meta":{"api-version":"1.0"},"files":[]}',
            )
            with self.assertRaisesRegex(IndexError, "Redirection|scheme and host|HTTPS"):
                client.download(f"{base_url}/redirect")
            with self.assertRaisesRegex(IndexError, "exceeds"):
                client.download(f"{base_url}/oversized")
            with self.assertRaisesRegex(IndexError, "invalid Simple"):
                client.get_project(base_url, "malformed-json")
            self.assertEqual(
                client.get_project(base_url, "malformed-html").files,
                (),
            )

    def test_simple_client_rejects_malformed_responses(self) -> None:
        client = SimpleRepositoryClient(
            opener=lambda *args, **kwargs: FakeResponse(b"{bad")
        )
        with self.assertRaisesRegex(IndexError, "invalid Simple"):
            client.get_project("https://index.example/simple", "demo")

    def test_basic_netrc_import_and_subprocess_keyring_authentication(self) -> None:
        captured: list[str | None] = []

        def opener(req: request.Request, timeout: float) -> FakeResponse:
            del timeout
            captured.append(req.get_header("Authorization"))
            return FakeResponse(simple_payload())

        client = SimpleRepositoryClient(opener=opener)
        client.get_project(
            "https://user:secret@index.example/simple",
            "demo",
        )
        expected = base64.b64encode(b"user:secret").decode()
        self.assertEqual(captured.pop(), f"Basic {expected}")
        client.download(
            "https://files.example/demo.whl",
            index_url="https://user:secret@index.example/simple",
        )
        self.assertIsNone(captured.pop())

        fake_netrc = SimpleNamespace(
            authenticators=lambda host: ("netrc-user", None, "netrc-pass")
        )
        with patch("trustcheck.indexes.netrc.netrc", return_value=fake_netrc):
            client = SimpleRepositoryClient(opener=opener)
            client.get_project("https://netrc.example/simple", "demo")
        expected = base64.b64encode(b"netrc-user:netrc-pass").decode()
        self.assertEqual(captured.pop(), f"Basic {expected}")

        fake_keyring = SimpleNamespace(
            get_password=lambda service, username: (
                "import-pass"
                if (service, username) == ("index.example", "user")
                else None
            )
        )
        with patch.dict(sys.modules, {"keyring": fake_keyring}):
            client = SimpleRepositoryClient(
                opener=opener,
                keyring_provider="import",
            )
            client.get_project("https://user@index.example/simple", "demo")
        expected = base64.b64encode(b"user:import-pass").decode()
        self.assertEqual(captured.pop(), f"Basic {expected}")
        with patch.dict(sys.modules, {"keyring": fake_keyring}):
            client = SimpleRepositoryClient(
                opener=opener,
                keyring_provider="auto",
            )
            client.get_project("https://user@index.example/simple", "demo")
        self.assertEqual(captured.pop(), f"Basic {expected}")

        def runner(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="subprocess-pass\n",
                stderr="",
            )
        client = SimpleRepositoryClient(
            opener=opener,
            keyring_provider="subprocess",
            runner=runner,
        )
        client.get_project("https://user@index.example/simple", "demo")
        expected = base64.b64encode(b"user:subprocess-pass").decode()
        self.assertEqual(captured.pop(), f"Basic {expected}")

    def test_keyring_failures_are_reported(self) -> None:
        with patch.dict(sys.modules, {"keyring": None}):
            client = SimpleRepositoryClient(keyring_provider="import")
            with self.assertRaisesRegex(IndexError, "not installed"):
                client._keyring_password("index.example", "user")

        fake_keyring = SimpleNamespace(
            get_password=lambda service, username: (_ for _ in ()).throw(
                RuntimeError("locked")
            )
        )
        with patch.dict(sys.modules, {"keyring": fake_keyring}):
            client = SimpleRepositoryClient(keyring_provider="import")
            with self.assertRaisesRegex(IndexError, "lookup failed"):
                client._keyring_password("index.example", "user")
            self.assertIsNone(
                SimpleRepositoryClient(
                    keyring_provider="auto"
                )._keyring_password("index.example", "user")
            )

        def os_error(command, **kwargs):
            del command, kwargs
            raise OSError("missing")

        client = SimpleRepositoryClient(
            keyring_provider="subprocess",
            runner=os_error,
        )
        with self.assertRaisesRegex(IndexError, "unavailable"):
            client._keyring_password("index.example", "user")

        client = SimpleRepositoryClient(
            keyring_provider="subprocess",
            runner=lambda command, **kwargs: subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="denied",
            ),
        )
        with self.assertRaisesRegex(IndexError, "denied"):
            client._keyring_password("index.example", "user")
        self.assertIsNone(
            SimpleRepositoryClient(
                keyring_provider="disabled"
            )._keyring_password("index.example", "user")
        )
        with patch.dict(sys.modules, {"keyring": None}):
            self.assertIsNone(
                SimpleRepositoryClient(
                    keyring_provider="auto",
                    runner=os_error,
                )._keyring_password("index.example", "user")
            )
            self.assertIsNone(
                SimpleRepositoryClient(
                    keyring_provider="auto",
                    runner=lambda command, **kwargs: subprocess.CompletedProcess(
                        command,
                        1,
                        stdout="",
                        stderr="denied",
                    ),
                )._keyring_password("index.example", "user")
            )

    def test_dependency_confusion_detection(self) -> None:
        projects = {
            (
                "https://private.example/simple/",
                "private-only",
            ): IndexProject(
                name="private-only",
                index_url="https://private.example/simple",
            ),
            (
                "https://private.example/simple/",
                "collision",
            ): IndexProject(
                name="collision",
                index_url="https://private.example/simple",
                files=(
                    IndexFile(
                        filename="collision-1.0-py3-none-any.whl",
                        url="https://private.example/files/collision-1.0.whl",
                        hashes=(("sha256", "a" * 64),),
                        requires_python=">=3.11",
                        metadata_hashes=(("sha256", "b" * 64),),
                        size=12,
                        upload_time="2026-01-01T00:00:00Z",
                    ),
                    IndexFile(
                        filename="collision-2.0-py3-none-any.whl",
                        url="https://private.example/files/collision-2.0.whl",
                        hashes=(("sha256", "c" * 64),),
                    ),
                ),
            ),
            (
                "https://pypi.org/simple/",
                "collision",
            ): IndexProject(
                name="collision",
                index_url="https://pypi.org/simple",
                files=(
                    IndexFile(
                        filename="collision-1.0-py3-none-any.whl",
                        url="https://files.pythonhosted.org/collision-1.0.whl",
                        hashes=(("sha256", "d" * 64),),
                        requires_python=">=3.10",
                        metadata_hashes=(("sha256", "e" * 64),),
                        size=14,
                        upload_time="2026-01-02T00:00:00Z",
                    ),
                ),
            ),
        }

        class FakeClient(SimpleRepositoryClient):
            def get_project(self, index_url: str, project: str):
                return projects.get((normalize_index_url(index_url), project))

        client = FakeClient()
        findings = client.find_dependency_confusion(
            ["private-only", "collision", "collision"],
            ["https://private.example/simple", "https://pypi.org/simple"],
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.project, "collision")
        self.assertEqual(
            finding.indexes,
            (
                "https://private.example/simple",
                "https://pypi.org/simple",
            ),
        )
        self.assertIn("resolver_strategy=version-priority", finding.evidence)
        self.assertIn("index_trust_order=not-enforced-by-pip", finding.evidence)
        self.assertIn(
            "available_versions[https://private.example/simple]=1.0,2.0",
            finding.evidence,
        )
        self.assertIn(
            "available_versions[https://pypi.org/simple]=1.0",
            finding.evidence,
        )
        self.assertTrue(
            any(
                item.startswith(
                    "filename_hash_mismatch:collision-1.0-py3-none-any.whl="
                )
                for item in finding.evidence
            )
        )
        self.assertTrue(
            any(
                item.startswith("version_metadata_mismatch:1.0=")
                for item in finding.evidence
            )
        )
        self.assertEqual(
            client.find_dependency_confusion(
                ["collision"],
                ["https://private.example/simple"],
            ),
            (),
        )

    def test_index_location_and_parser_fallback_branches(self) -> None:
        class FakeClient(SimpleRepositoryClient):
            def get_project(self, index_url: str, project: str):
                del project
                if "missing" in index_url:
                    return None
                return IndexProject(
                    name="demo",
                    index_url=index_url,
                    files=(
                        IndexFile(
                            filename="demo.whl",
                            url="https://files.example/demo.whl",
                        ),
                    ),
                )

        client = FakeClient()
        self.assertIsNone(
            client.locate_artifact_index(
                "demo",
                None,
                ("https://one/simple", "https://two/simple"),
            )
        )
        self.assertEqual(
            client.locate_artifact_index(
                "demo",
                "https://files.example/demo.whl",
                ("https://missing/simple", "https://found/simple"),
            ),
            "https://found/simple",
        )
        self.assertIsNone(
            client.locate_artifact_index(
                "demo",
                "https://files.example/other.whl",
                ("https://missing/simple", "https://found/simple"),
            )
        )

        payload = json.dumps(
            {
                "meta": {},
                "files": [
                    "bad",
                    {"filename": "demo.whl", "url": 3},
                    {
                        "filename": "demo.whl",
                        "url": "demo.whl",
                        "dist-info-metadata": True,
                        "hashes": {"sha256": 3, 4: "aa", "sha512": "GG"},
                        "size": -1,
                        "upload-time": 3,
                        "yanked": True,
                    },
                ],
            }
        ).encode()
        project = parse_simple_json(
            payload,
            project="demo",
            index_url="https://index.example/simple/",
            response_url="https://index.example/simple/demo/",
        )
        self.assertIsNone(project.api_version)
        self.assertEqual(project.files[0].hashes, (("4", "aa"),))
        self.assertTrue(project.files[0].yanked)
        self.assertIsNone(project.files[0].size)
        self.assertIsNone(project.files[0].upload_time)

    def test_index_helper_edge_cases(self) -> None:
        self.assertEqual(redact_url_credentials("https://example.com/simple"), "https://example.com/simple")
        self.assertEqual(
            redact_url_credentials("https://user:pass@example.com:8443/simple"),
            "https://<redacted>@example.com:8443/simple",
        )
        self.assertEqual(
            _without_url_credentials("https://user:pass@example.com:8443/simple"),
            "https://example.com:8443/simple",
        )
        self.assertEqual(_without_url_credentials("https://example.com/simple"), "https://example.com/simple")
        self.assertTrue(
            _same_origin(
                parse.urlsplit("https://example.com/simple"),
                parse.urlsplit("https://example.com:443/files/demo.whl"),
            )
        )
        self.assertFalse(
            _same_origin(
                parse.urlsplit("https://example.com/simple"),
                parse.urlsplit("http://example.com/files/demo.whl"),
            )
        )
        self.assertEqual(_hash_mapping(None), ())
        self.assertEqual(_hash_mapping({3: "aa", "sha256": 3}), ())
        self.assertEqual(_hash_fragment(""), ())
        self.assertEqual(_hash_fragment("sha256"), ())
        self.assertEqual(_metadata_hashes(True), ())
        self.assertEqual(_metadata_hashes("true"), ())
        self.assertEqual(
            _metadata_hashes({"sha256": "a" * 64}),
            (("sha256", "a" * 64),),
        )
        self.assertEqual(_optional_string(3), None)
        self.assertEqual(_optional_int(-1), None)
        self.assertEqual(_optional_int(True), None)
        self.assertEqual(_yanked_value(True), True)
        self.assertEqual(_yanked_value(None), False)

        project = IndexProject(
            name="demo",
            index_url="https://index.example/simple",
            files=(IndexFile(filename="not-a-distribution.txt", url="https://x"),),
        )
        self.assertEqual(files_for_version(project, "1.0"), ())

    def test_netrc_and_empty_keyring_credentials(self) -> None:
        with patch(
            "trustcheck.indexes.netrc.netrc",
            side_effect=FileNotFoundError(),
        ):
            self.assertEqual(
                SimpleRepositoryClient()._netrc_credentials("example.com"),
                (None, None),
            )
        fake_netrc = SimpleNamespace(authenticators=lambda host: None)
        with patch("trustcheck.indexes.netrc.netrc", return_value=fake_netrc):
            self.assertEqual(
                SimpleRepositoryClient()._netrc_credentials("example.com"),
                (None, None),
            )
        client = SimpleRepositoryClient(
            keyring_provider="subprocess",
            runner=lambda command, **kwargs: subprocess.CompletedProcess(
                command,
                0,
                stdout="\n",
                stderr="",
            ),
        )
        self.assertIsNone(client._keyring_password("example.com", "user"))


if __name__ == "__main__":
    unittest.main()
