from __future__ import annotations

import json
import socket
import threading
import unittest
from io import BytesIO
from typing import Any
from unittest.mock import patch
from urllib import error

from trustcheck.advisories import (
    CisaKevClient,
    EpssClient,
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
    _cvss_candidates,
    _cvss_candidates_from_mapping,
    _cvss_metrics,
    _cvss_version,
    _extract_osv_cvss,
    _extract_osv_cwes,
    _extract_osv_fixed_versions,
    _extract_osv_link,
    _higher_severity,
    _latest_timestamp,
    _matching_affected_items,
    _merge_sources,
    _normalize_cvss_vector,
    _optional_float,
    _optional_string,
    _score_cvss_v2,
    _score_cvss_v3,
    _score_cvss_vector,
    _severity_score,
    _string_list,
    merge_vulnerabilities,
    normalize_severity,
    parse_osv_vulnerabilities,
    parse_pypi_vulnerabilities,
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

        self.assertEqual(records[0].severity, "MEDIUM")
        self.assertEqual(
            records[0].link,
            "https://osv.dev/vulnerability/GHSA-ecosystem",
        )
        self.assertEqual(records[1].severity, "CRITICAL")
        self.assertEqual(records[1].cvss_score, 9.8)
        self.assertEqual(records[1].cvss_version, "3.1")
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

    def test_merge_vulnerabilities_collapses_alias_bridge_records(self) -> None:
        records = merge_vulnerabilities(
            [VulnerabilityRecord(id="GHSA-one", summary="first")],
            [VulnerabilityRecord(id="CVE-2026-1", summary="second")],
            [
                VulnerabilityRecord(
                    id="PYSEC-2026-1",
                    aliases=["GHSA-one", "CVE-2026-1"],
                    summary="bridge",
                )
            ],
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0].aliases,
            ["CVE-2026-1", "PYSEC-2026-1"],
        )

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
        self.assertEqual(normalize_severity("important"), "HIGH")
        self.assertEqual(normalize_severity(None, score=3.9), "LOW")

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

    def test_cvss_cwe_and_withdrawal_normalization(self) -> None:
        item = {
            "id": "GHSA-demo",
            "withdrawn": "2026-06-01T00:00:00Z",
            "database_specific": {
                "cwe_ids": ["CWE-79", "CWE-89"],
            },
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"
                        "C:H/I:H/A:H"
                    ),
                }
            ],
            "affected": [
                {
                    "package": {"name": "demo", "ecosystem": "PyPI"},
                    "database_specific": {"cwe": "CWE-22"},
                }
            ],
        }

        score, vector, version = _extract_osv_cvss(item, project="demo")
        records = parse_osv_vulnerabilities([item], project="demo")

        self.assertEqual((score, version), (9.8, "3.1"))
        self.assertTrue((vector or "").startswith("CVSS:3.1/"))
        self.assertEqual(
            _extract_osv_cwes(item, project="demo"),
            ["CWE-22", "CWE-79", "CWE-89"],
        )
        self.assertTrue(records[0].withdrawn)
        self.assertEqual(records[0].withdrawn_at, "2026-06-01T00:00:00Z")

    def test_parse_pypi_vulnerabilities_normalizes_rich_and_sparse_rows(self) -> None:
        records = parse_pypi_vulnerabilities(
            [
                {
                    "id": "CVE-2026-2000",
                    "summary": "PyPI advisory",
                    "aliases": ["GHSA-demo"],
                    "source": "PyPI Advisory DB",
                    "severity": "important",
                    "cvss_score": "8.1",
                    "cvss_vector": (
                        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    ),
                    "cwes": {"primary": "CWE-79", "other": "CWE-89"},
                    "fixed_in": ["2.0"],
                    "link": "https://example.com/CVE-2026-2000",
                    "withdrawn": True,
                    "withdrawn_at": "2026-06-01T00:00:00Z",
                },
                {"details": "Sparse advisory", "cvss_score": True},
            ]
        )

        self.assertEqual(records[0].severity, "HIGH")
        self.assertEqual(records[0].cvss_score, 8.1)
        self.assertEqual(records[0].cvss_version, "3.0")
        self.assertEqual(records[0].cwes, ["CWE-79", "CWE-89"])
        self.assertTrue(records[0].withdrawn)
        self.assertEqual(records[1].id, "unknown")
        self.assertEqual(records[1].summary, "Sparse advisory")
        self.assertIsNone(records[1].cvss_score)

    def test_merge_preserves_strongest_normalized_enrichment(self) -> None:
        existing = VulnerabilityRecord(
            id="GHSA-demo",
            summary="No summary provided.",
            aliases=["CVE-2026-2000"],
            source="OSV",
            severity="MEDIUM",
            cvss_score=5.0,
            cwes=["CWE-79"],
            withdrawn=True,
            withdrawn_at="2026-05-01T00:00:00Z",
            epss_score=0.2,
        )
        incoming = VulnerabilityRecord(
            id="CVE-2026-2000",
            summary="Detailed advisory",
            source="Ecosyste.ms",
            severity="HIGH",
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/vector",
            cvss_version="3.1",
            cwes=["CWE-89"],
            withdrawn=True,
            withdrawn_at="2026-06-01T00:00:00Z",
            kev=True,
            kev_date_added="2026-05-01",
            kev_due_date="2026-05-22",
            kev_required_action="Upgrade.",
            kev_known_ransomware_campaign_use="Known",
            epss_score=0.8,
            epss_percentile=0.99,
            epss_date="2026-06-13",
        )

        record = merge_vulnerabilities([existing], [incoming])[0]

        self.assertEqual(record.summary, "Detailed advisory")
        self.assertEqual(record.cvss_score, 8.8)
        self.assertEqual(record.cvss_vector, "CVSS:3.1/vector")
        self.assertEqual(record.cwes, ["CWE-79", "CWE-89"])
        self.assertTrue(record.withdrawn)
        self.assertEqual(record.withdrawn_at, "2026-06-01T00:00:00Z")
        self.assertTrue(record.kev)
        self.assertEqual(record.kev_required_action, "Upgrade.")
        self.assertEqual(record.epss_score, 0.8)

        active = merge_vulnerabilities(
            [record],
            [
                VulnerabilityRecord(
                    id="CVE-2026-2000",
                    summary="Active duplicate",
                    cvss_vector="CVSS:4.0/vector",
                )
            ],
        )[0]
        self.assertFalse(active.withdrawn)
        self.assertIsNone(active.withdrawn_at)
        self.assertEqual(active.cvss_vector, "CVSS:3.1/vector")

        vector_only = merge_vulnerabilities(
            [VulnerabilityRecord(id="CVE-1", summary="first")],
            [
                VulnerabilityRecord(
                    id="CVE-1",
                    summary="second",
                    cvss_vector="CVSS:4.0/vector",
                    cvss_version="4.0",
                )
            ],
        )[0]
        self.assertEqual(vector_only.cvss_version, "4.0")

    def test_cvss_helpers_cover_versions_boundaries_and_malformed_values(self) -> None:
        v3_changed = (
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N"
        )
        v3_zero = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        v2 = "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"
        v2_zero = "CVSS:2.0/AV:L/AC:H/Au:M/C:N/I:N/A:N"

        self.assertEqual(_score_cvss_v3(v3_changed), 7.6)
        self.assertEqual(_score_cvss_v3(v3_zero), 0.0)
        self.assertIsNone(_score_cvss_v3("CVSS:3.1/AV:N"))
        self.assertEqual(_score_cvss_v2(v2), 7.5)
        self.assertEqual(_score_cvss_v2(v2_zero), 0.0)
        self.assertIsNone(_score_cvss_v2("CVSS:2.0/AV:N"))
        self.assertEqual(_score_cvss_vector(v2), 7.5)
        self.assertIsNone(_score_cvss_vector("CVSS:4.0/vector"))
        self.assertIsNone(_cvss_version(None))
        self.assertIsNone(_cvss_version("not-a-vector"))

        self.assertEqual(
            _normalize_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS_V2"),
            v2,
        )
        self.assertEqual(
            _normalize_cvss_vector(
                "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS_V3",
            ),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.assertEqual(
            _normalize_cvss_vector("AV:N/AT:N", "CVSS_V4"),
            "CVSS:4.0/AV:N/AT:N",
        )
        self.assertEqual(_normalize_cvss_vector("opaque", None), "opaque")
        self.assertEqual(_normalize_cvss_vector(v3_changed, None), v3_changed)
        self.assertEqual(_cvss_metrics("CVSS:3.1/AV:N/bad/S:U"), {"AV": "N", "S": "U"})

        self.assertEqual(_cvss_candidates("invalid"), [])
        self.assertEqual(
            _cvss_candidates(
                [
                    "skip",
                    {"type": "CVSS_V3", "score": "7.2"},
                    {"type": "CUSTOM", "score": "not-a-number"},
                ]
            ),
            [(7.2, None, "CVSS_V3")],
        )
        mapping = _cvss_candidates_from_mapping(
            {
                "cvss": v3_zero,
                "cvss_vector": 12,
                "cvss_score": "4.2",
                "score": "bad",
            }
        )
        self.assertEqual(mapping[0], (0.0, v3_zero, "3.1"))
        self.assertEqual(mapping[1], (4.2, None, None))

        self.assertEqual(_severity_score([{"score": "4.0"}]), "4.0")
        self.assertIsNone(_severity_score([{"score": ""}]))
        for score, expected in (
            (9.0, "CRITICAL"),
            (7.0, "HIGH"),
            (4.0, "MEDIUM"),
            (0.0, "NONE"),
        ):
            with self.subTest(score=score):
                self.assertEqual(normalize_severity("custom", score=score), expected)
        self.assertIsNone(normalize_severity("custom"))
        self.assertIsNone(_optional_float(True))
        self.assertEqual(_optional_float(2), 2.0)
        self.assertIsNone(_optional_float("bad"))
        self.assertIsNone(_optional_float(object()))
        self.assertEqual(_optional_string("value"), "value")
        self.assertIsNone(_optional_string(""))
        self.assertEqual(_latest_timestamp(None, "2026-01-01"), "2026-01-01")
        self.assertIsNone(_latest_timestamp(None, None))


class VulnerabilityIntelligenceTests(unittest.TestCase):
    def test_queries_osv_compatible_providers_concurrently_and_merges(self) -> None:
        barrier = threading.Barrier(2)

        class Provider:
            def __init__(self, item: dict[str, Any]) -> None:
                self.item = item
                self.request_hook = None

            def query(self, project: str, version: str) -> list[dict[str, Any]]:
                barrier.wait(timeout=2)
                return [self.item]

        client = VulnerabilityIntelligenceClient(
            providers=(
                OsvProvider(
                    "OSV",
                    Provider({
                        "id": "GHSA-demo",
                        "aliases": ["CVE-2026-1000"],
                        "summary": "OSV summary",
                    }),
                ),
                OsvProvider(
                    "Ecosyste.ms",
                    Provider({
                        "id": "CVE-2026-1000",
                        "aliases": ["GHSA-demo"],
                        "summary": "Ecosyste.ms summary",
                        "database_specific": {"severity": "critical"},
                    }),
                ),
            )
        )

        records = client.query("demo", "1.0")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source, "OSV, Ecosyste.ms")
        self.assertEqual(records[0].severity, "CRITICAL")
        self.assertIn("CVE-2026-1000", records[0].aliases)

    def test_cisa_kev_and_epss_clients_parse_and_cache(self) -> None:
        responses = [
            FakeResponse({
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-1000",
                        "dateAdded": "2026-05-01",
                        "dueDate": "2026-05-22",
                        "requiredAction": "Apply updates.",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            }),
            FakeResponse({
                "data": [
                    {
                        "cve": "CVE-2026-1000",
                        "epss": "0.8123",
                        "percentile": "0.991",
                        "date": "2026-06-13",
                    }
                ]
            }),
        ]
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=responses,
        ) as urlopen:
            kev = CisaKevClient(max_retries=0)
            epss = EpssClient(max_retries=0)
            self.assertIn("CVE-2026-1000", kev.query(["cve-2026-1000"]))
            self.assertEqual(
                epss.query(["CVE-2026-1000"])["CVE-2026-1000"]["epss"],
                0.8123,
            )
            kev.query(["CVE-2026-1000"])
            epss.query(["CVE-2026-1000"])

        self.assertEqual(urlopen.call_count, 2)

    def test_enrichment_is_applied_to_merged_aliases(self) -> None:
        class Kev:
            request_hook = None

            def query(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
                return {
                    "CVE-2026-1000": {
                        "dateAdded": "2026-05-01",
                        "dueDate": "2026-05-22",
                        "requiredAction": "Apply updates.",
                        "knownRansomwareCampaignUse": "Known",
                    }
                }

        class Epss:
            request_hook = None

            def query(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
                return {
                    "CVE-2026-1000": {
                        "epss": 0.75,
                        "percentile": 0.98,
                        "date": "2026-06-13",
                    }
                }

        client = VulnerabilityIntelligenceClient(
            kev_client=Kev(),  # type: ignore[arg-type]
            epss_client=Epss(),  # type: ignore[arg-type]
        )
        records = client.query(
            "demo",
            "1.0",
            [
                VulnerabilityRecord(
                    id="GHSA-demo",
                    aliases=["CVE-2026-1000"],
                    summary="Known issue",
                )
            ],
        )

        self.assertTrue(records[0].kev)
        self.assertEqual(records[0].kev_due_date, "2026-05-22")
        self.assertEqual(records[0].epss_score, 0.75)
        self.assertEqual(records[0].epss_percentile, 0.98)

    def test_enrichment_clients_fail_closed_on_invalid_feeds_and_offline_cache_miss(
        self,
    ) -> None:
        self.assertEqual(CisaKevClient().query(["not-a-cve"]), {})
        self.assertEqual(EpssClient().query(["GHSA-demo"]), {})

        with self.assertRaises(PypiClientError) as kev_offline:
            CisaKevClient(offline=True).query(["CVE-2026-1000"])
        self.assertEqual(kev_offline.exception.subcode, "offline_unavailable")
        with self.assertRaises(PypiClientError) as epss_offline:
            EpssClient(offline=True).query(["CVE-2026-1000"])
        self.assertEqual(epss_offline.exception.subcode, "offline_unavailable")

        cases = [
            (CisaKevClient(max_retries=0), {"vulnerabilities": {}}, "CVE-2026-1000"),
            (EpssClient(max_retries=0), {"data": {}}, "CVE-2026-1000"),
        ]
        for client, payload, identifier in cases:
            with self.subTest(client=type(client).__name__):
                with patch(
                    "trustcheck.advisories.request.urlopen",
                    return_value=FakeResponse(payload),
                ):
                    with self.assertRaises(PypiClientError) as ctx:
                        client.query([identifier])
                self.assertEqual(ctx.exception.subcode, "response_shape_invalid")

        with self.assertRaises(PypiClientError) as invalid_url:
            CisaKevClient(url="file:///kev.json").query(["CVE-2026-1000"])
        self.assertEqual(invalid_url.exception.subcode, "url_scheme_invalid")

    def test_enrichment_get_retries_and_classifies_transport_and_json_errors(
        self,
    ) -> None:
        sleeps: list[float] = []
        events: list[str] = []
        responses: list[object] = [
            error.HTTPError("https://kev", 503, "busy", None, None),
            FakeResponse({"vulnerabilities": []}),
        ]
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=responses,
        ):
            result = CisaKevClient(
                max_retries=1,
                backoff_factor=0.3,
                sleep=sleeps.append,
                request_hook=lambda event, payload: events.append(event),
            ).query(["CVE-2026-1000"])
        self.assertEqual(result, {})
        self.assertEqual(sleeps, [0.3])
        self.assertIn("retry", events)

        failures = [
            (
                error.HTTPError("https://kev", 404, "missing", None, None),
                "http_error",
            ),
            (error.URLError("network down"), "network_error"),
            (socket.timeout("timed out"), "network_timeout"),
        ]
        for failure, subcode in failures:
            with self.subTest(subcode=subcode):
                with patch(
                    "trustcheck.advisories.request.urlopen",
                    side_effect=failure,
                ):
                    with self.assertRaises(PypiClientError) as ctx:
                        CisaKevClient(max_retries=0).query(["CVE-2026-1000"])
                self.assertEqual(ctx.exception.subcode, subcode)

        for response, subcode in (
            (FakeResponse(b"{bad"), "json_malformed"),
            (FakeResponse([]), "json_non_object"),
        ):
            with self.subTest(subcode=subcode):
                with patch(
                    "trustcheck.advisories.request.urlopen",
                    return_value=response,
                ):
                    with self.assertRaises(PypiClientError) as ctx:
                        EpssClient(max_retries=0).query(["CVE-2026-1000"])
                self.assertEqual(ctx.exception.subcode, subcode)

    def test_clients_skip_bad_rows_and_cache_negative_epss_results(self) -> None:
        responses = [
            FakeResponse(
                {
                    "vulnerabilities": [
                        "skip",
                        {"cveID": 123},
                        {"cveID": "not-a-cve"},
                        {"cveID": "CVE-2026-1000", "dateAdded": "2026-01-01"},
                    ]
                }
            ),
            FakeResponse(
                {
                    "data": [
                        "skip",
                        {"cve": 123},
                        {"cve": "CVE-2026-9999", "epss": "0.9"},
                        {
                            "cve": "CVE-2026-1000",
                            "epss": "bad",
                            "percentile": True,
                            "date": 123,
                        },
                    ]
                }
            ),
        ]
        events: list[str] = []
        with patch(
            "trustcheck.advisories.request.urlopen",
            side_effect=responses,
        ) as urlopen:
            kev = CisaKevClient(
                max_retries=0,
                request_hook=lambda event, payload: events.append(event),
            )
            epss = EpssClient(
                max_retries=0,
                request_hook=lambda event, payload: events.append(event),
            )
            self.assertEqual(
                list(kev.query(["CVE-2026-1000"])),
                ["CVE-2026-1000"],
            )
            self.assertEqual(
                epss.query(["CVE-2026-1000", "CVE-2026-2000"]),
                {
                    "CVE-2026-1000": {
                        "cve": "CVE-2026-1000",
                        "epss": None,
                        "percentile": None,
                        "date": None,
                    }
                },
            )
            self.assertEqual(epss.query(["CVE-2026-2000"]), {})
            kev.query(["CVE-2026-1000"])

        self.assertEqual(urlopen.call_count, 2)
        self.assertIn("cache_hit", events)

    def test_coordinator_handles_no_cves_single_enrichers_and_hook_chaining(
        self,
    ) -> None:
        calls: list[tuple[str, tuple[str, ...]]] = []
        hook_events: list[str] = []
        prior_events: list[str] = []

        class Enricher:
            def __init__(self, name: str) -> None:
                self.name = name
                self.request_hook = (
                    lambda event, payload: prior_events.append(event)
                )

            def query(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
                calls.append((self.name, tuple(cve_ids)))
                if self.request_hook is not None:
                    self.request_hook("fake", {})
                if self.name == "kev":
                    return {"CVE-2026-1000": {"dateAdded": "2026-01-01"}}
                return {"CVE-2026-1000": {"epss": 0.6}}

        base = [VulnerabilityRecord(id="GHSA-demo", summary="No CVE")]
        no_enrichment = VulnerabilityIntelligenceClient().query("demo", "1", base)
        self.assertEqual(no_enrichment, base)

        client = VulnerabilityIntelligenceClient(
            kev_client=Enricher("kev"),  # type: ignore[arg-type]
            request_hook=lambda event, payload: hook_events.append(event),
        )
        self.assertEqual(client.query("demo", "1", base), base)
        self.assertEqual(calls, [])

        record = VulnerabilityRecord(
            id="CVE-2026-1000",
            summary="CVE",
        )
        self.assertTrue(client.query("demo", "1", [record])[0].kev)
        self.assertEqual(calls, [("kev", ("CVE-2026-1000",))])
        self.assertEqual(hook_events, ["fake"])
        self.assertEqual(prior_events, ["fake"])

        epss_client = VulnerabilityIntelligenceClient(
            epss_client=Enricher("epss"),  # type: ignore[arg-type]
        )
        enriched = epss_client.query("demo", "1", [record])
        self.assertEqual(enriched[0].epss_score, 0.6)

    def test_enrichment_selects_earliest_kev_and_highest_epss_alias(self) -> None:
        record = VulnerabilityRecord(
            id="GHSA-demo",
            aliases=["CVE-2026-1000", "CVE-2026-2000"],
            summary="Multiple aliases",
        )

        class Kev:
            request_hook = None

            def query(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
                return {
                    "CVE-2026-1000": {"dateAdded": "2026-05-02"},
                    "CVE-2026-2000": {"dateAdded": "2026-05-01"},
                }

        class Epss:
            request_hook = None

            def query(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
                return {
                    "CVE-2026-1000": {"epss": "bad"},
                    "CVE-2026-2000": {"epss": 0.9, "percentile": 0.99},
                }

        result = VulnerabilityIntelligenceClient(
            kev_client=Kev(),  # type: ignore[arg-type]
            epss_client=Epss(),  # type: ignore[arg-type]
        ).query("demo", "1", [record])[0]

        self.assertEqual(result.kev_date_added, "2026-05-01")
        self.assertEqual(result.epss_score, 0.9)
