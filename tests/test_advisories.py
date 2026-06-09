from __future__ import annotations

import json
import socket
import unittest
from io import BytesIO
from unittest.mock import patch
from urllib import error

from trustcheck.advisories import (
    OsvClient,
    _extract_osv_fixed_versions,
    _extract_osv_link,
    _higher_severity,
    _matching_affected_items,
    _merge_sources,
    _severity_score,
    _string_list,
    merge_vulnerabilities,
    parse_osv_vulnerabilities,
)
from trustcheck.models import VulnerabilityRecord
from trustcheck.pypi import PypiClientError


class FakeResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self._io = BytesIO(
            payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        )
        self.status = status

    def read(self) -> bytes:
        return self._io.read()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class OsvClientTests(unittest.TestCase):
    def test_query_posts_exact_pypi_version_handles_pagination_and_caches(self) -> None:
        requests: list[dict[str, object]] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            request_payload = json.loads(getattr(req, "data"))
            requests.append(request_payload)
            if len(requests) == 1:
                return FakeResponse(
                    {
                        "vulns": [{"id": "GHSA-462w-v97r-4m45"}],
                        "next_page_token": "next-page",
                    }
                )
            return FakeResponse({"vulns": [{"id": "GHSA-second"}]})

        events: list[str] = []
        client = OsvClient(
            request_hook=lambda event, payload: events.append(event),
        )
        with patch("trustcheck.advisories.request.urlopen", side_effect=fake_urlopen):
            first = client.query("Jinja2", "2.10.0")
            second = client.query("jinja2", "2.10.0")

        self.assertEqual(
            [item["id"] for item in first],
            ["GHSA-462w-v97r-4m45", "GHSA-second"],
        )
        self.assertEqual(first, second)
        self.assertEqual(
            requests,
            [
                {
                    "package": {"name": "Jinja2", "ecosystem": "PyPI"},
                    "version": "2.10.0",
                },
                {
                    "package": {"name": "Jinja2", "ecosystem": "PyPI"},
                    "version": "2.10.0",
                    "page_token": "next-page",
                },
            ],
        )
        self.assertEqual(events.count("request"), 2)
        self.assertIn("cache_hit", events)

    def test_query_retries_transient_failures(self) -> None:
        attempts: list[int] = []
        sleeps: list[float] = []

        def fake_urlopen(req: object, timeout: float) -> FakeResponse:
            attempts.append(1)
            if len(attempts) == 1:
                raise error.HTTPError(
                    "https://api.osv.dev/v1/query",
                    503,
                    "service unavailable",
                    hdrs=None,
                    fp=None,
                )
            return FakeResponse({"vulns": []})

        client = OsvClient(max_retries=1, backoff_factor=0.2, sleep=sleeps.append)
        with patch("trustcheck.advisories.request.urlopen", side_effect=fake_urlopen):
            self.assertEqual(client.query("demo", "1.0.0"), [])

        self.assertEqual(len(attempts), 2)
        self.assertEqual(sleeps, [0.2])

    def test_query_reports_offline_and_response_errors(self) -> None:
        with self.assertRaisesRegex(PypiClientError, "offline mode"):
            OsvClient(offline=True).query("demo", "1.0.0")

        cases = [
            (FakeResponse(b"{bad-json"), "json_malformed"),
            (FakeResponse([]), "json_non_object"),
            (FakeResponse({"vulns": {}}), "response_shape_invalid"),
        ]
        for response, subcode in cases:
            with self.subTest(subcode=subcode):
                with patch(
                    "trustcheck.advisories.request.urlopen",
                    return_value=response,
                ):
                    with self.assertRaises(PypiClientError) as ctx:
                        OsvClient(max_retries=0).query("demo", "1.0.0")
                self.assertEqual(ctx.exception.subcode, subcode)

    def test_query_rejects_non_http_base_url(self) -> None:
        with self.assertRaises(PypiClientError) as ctx:
            OsvClient(base_url="file:///tmp/osv").query("demo", "1.0.0")
        self.assertEqual(ctx.exception.subcode, "url_scheme_invalid")

    def test_query_rejects_repeated_pagination_token(self) -> None:
        responses = [
            FakeResponse({"next_page_token": "repeat"}),
            FakeResponse({"next_page_token": "repeat"}),
        ]
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=responses,
        ):
            with self.assertRaises(PypiClientError) as ctx:
                OsvClient(max_retries=0).query("demo", "1.0.0")

        self.assertEqual(ctx.exception.subcode, "pagination_invalid")

    def test_query_classifies_permanent_and_network_errors(self) -> None:
        failures = [
            (
                error.HTTPError(
                    "https://api.osv.dev/v1/query",
                    400,
                    "bad request",
                    hdrs=None,
                    fp=None,
                ),
                "http_error",
            ),
            (error.URLError("temporary failure"), "network_error"),
            (socket.timeout("timed out"), "network_timeout"),
        ]
        for failure, subcode in failures:
            with self.subTest(subcode=subcode):
                with patch(
                    "trustcheck.advisories.request.urlopen",
                    side_effect=failure,
                ):
                    with self.assertRaises(PypiClientError) as ctx:
                        OsvClient(max_retries=0).query("demo", "1.0.0")
                self.assertEqual(ctx.exception.subcode, subcode)


class AdvisoryNormalizationTests(unittest.TestCase):
    def test_parse_osv_vulnerability_extracts_required_intelligence(self) -> None:
        records = parse_osv_vulnerabilities(
            [
                {
                    "id": "GHSA-462w-v97r-4m45",
                    "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
                    "summary": "Jinja2 sandbox escape via str.format_map",
                    "database_specific": {"severity": "high"},
                    "affected": [
                        {
                            "package": {"name": "Jinja2", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.10.1"},
                                    ],
                                },
                                {
                                    "type": "GIT",
                                    "events": [{"fixed": "deadbeef"}],
                                },
                            ],
                        },
                        {
                            "package": {"name": "other", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"fixed": "9.9.9"}],
                                }
                            ],
                        },
                    ],
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": "https://github.com/advisories/GHSA-462w-v97r-4m45",
                        }
                    ],
                }
            ],
            project="jinja2",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.id, "GHSA-462w-v97r-4m45")
        self.assertEqual(record.aliases, ["CVE-2019-10906", "PYSEC-2019-217"])
        self.assertEqual(record.source, "OSV")
        self.assertEqual(record.severity, "HIGH")
        self.assertEqual(record.fixed_in, ["2.10.1"])
        self.assertEqual(
            record.link,
            "https://github.com/advisories/GHSA-462w-v97r-4m45",
        )

    def test_parse_osv_vulnerability_uses_severity_and_link_fallbacks(self) -> None:
        records = parse_osv_vulnerabilities(
            [
                {
                    "id": "GHSA-ecosystem",
                    "affected": [
                        {
                            "package": {"name": "demo", "ecosystem": "PyPI"},
                            "ecosystem_specific": {"severity": "moderate"},
                        }
                    ],
                    "references": [{"type": "FIX", "url": "https://example.com/fix"}],
                },
                {
                    "id": "GHSA-cvss",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                },
                {"details": "Only detailed text", "aliases": "invalid"},
            ],
            project="demo",
        )

        self.assertEqual(records[0].severity, "MODERATE")
        self.assertEqual(
            records[0].link,
            "https://osv.dev/vulnerability/GHSA-ecosystem",
        )
        self.assertTrue(records[1].severity.startswith("CVSS_V3:"))
        self.assertEqual(records[2].id, "unknown")
        self.assertEqual(records[2].summary, "Only detailed text")
        self.assertEqual(records[2].aliases, [])

    def test_merge_vulnerabilities_deduplicates_aliases_and_combines_evidence(self) -> None:
        pypi = VulnerabilityRecord(
            id="PYSEC-2019-217",
            summary="No summary provided.",
            aliases=["CVE-2019-10906"],
            source="PyPI",
            severity="MEDIUM",
            fixed_in=["1.0.1"],
        )
        osv = VulnerabilityRecord(
            id="GHSA-462w-v97r-4m45",
            summary="Remote code execution",
            aliases=["CVE-2019-10906"],
            source="OSV",
            severity="CRITICAL",
            fixed_in=["1.0.2"],
            link="https://github.com/advisories/GHSA-462w-v97r-4m45",
        )

        merged = merge_vulnerabilities([pypi], [osv])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].id, "PYSEC-2019-217")
        self.assertEqual(
            merged[0].aliases,
            ["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
        )
        self.assertEqual(merged[0].summary, "Remote code execution")
        self.assertEqual(merged[0].source, "PyPI, OSV")
        self.assertEqual(merged[0].severity, "CRITICAL")
        self.assertEqual(merged[0].fixed_in, ["1.0.1", "1.0.2"])
        self.assertEqual(
            merged[0].link,
            "https://github.com/advisories/GHSA-462w-v97r-4m45",
        )

    def test_merge_vulnerabilities_keeps_distinct_records(self) -> None:
        records = merge_vulnerabilities(
            [VulnerabilityRecord(id="CVE-1", summary="first")],
            [VulnerabilityRecord(id="CVE-2", summary="second")],
        )
        self.assertEqual([record.id for record in records], ["CVE-1", "CVE-2"])

    def test_normalization_helpers_tolerate_sparse_and_unknown_values(self) -> None:
        self.assertIsNone(_merge_sources(None, ""))
        self.assertEqual(_merge_sources("PyPI, OSV", "OSV"), "PyPI, OSV")
        self.assertEqual(_higher_severity(None, "HIGH"), "HIGH")
        self.assertEqual(_higher_severity("HIGH", None), "HIGH")
        self.assertEqual(_higher_severity("CUSTOM", "CRITICAL"), "CUSTOM")
        self.assertEqual(_higher_severity("HIGH", "MEDIUM"), "HIGH")
        self.assertEqual(_severity_score(["skip", {"score": "7.1"}]), "7.1")
        self.assertIsNone(_severity_score({"score": "7.1"}))
        self.assertEqual(_string_list(["CVE-1", "", 3]), ["CVE-1"])

    def test_osv_helpers_skip_malformed_affected_ranges_and_references(self) -> None:
        item = {
            "affected": [
                "not-an-object",
                {},
                {"package": "not-an-object"},
                {"package": {"name": "demo", "ecosystem": "npm"}},
                {
                    "package": {"name": "Demo"},
                    "ranges": [
                        "not-an-object",
                        {"type": "GIT", "events": [{"fixed": "git-sha"}]},
                        {"type": "ECOSYSTEM", "events": "not-a-list"},
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                "not-an-object",
                                {"fixed": ""},
                                {"fixed": "2.0.0"},
                            ],
                        },
                    ],
                },
            ],
            "references": [
                "not-an-object",
                {"type": "FIX", "url": "https://example.com/fix"},
                {"type": "WEB", "url": "ftp://example.com/advisory"},
                {"type": "REPORT", "url": "https://example.com/report"},
            ],
        }

        matches = _matching_affected_items(item, project="demo")
        self.assertEqual(len(matches), 1)
        self.assertEqual(_extract_osv_fixed_versions(item, project="demo"), ["2.0.0"])
        self.assertEqual(
            _extract_osv_link(item, "GHSA-demo"),
            "https://example.com/report",
        )
