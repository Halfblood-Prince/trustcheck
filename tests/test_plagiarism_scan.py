from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib import error

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "github_plagiarism_scan.py"
SPEC = importlib.util.spec_from_file_location("github_plagiarism_scan", SCRIPT)
assert SPEC is not None
github_plagiarism_scan = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = github_plagiarism_scan
SPEC.loader.exec_module(github_plagiarism_scan)


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class GithubPlagiarismScanTests(unittest.TestCase):
    def test_collect_fingerprints_prefers_distinctive_source_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            package = root / "src" / "trustcheck"
            package.mkdir(parents=True)
            (package / "demo.py").write_text(
                "from __future__ import annotations\n"
                "# comments are not useful fingerprints\n"
                "def helper():\n"
                "    return 'short'\n"
                "    rendered = json.dumps(payload, indent=2, sort_keys=True)\n"
                "    stable = rendered.replace('secret-token', '<redacted>')\n",
                encoding="utf-8",
            )

            fingerprints = github_plagiarism_scan.collect_fingerprints(
                root,
                source="src/trustcheck",
                max_fingerprints=2,
            )

        self.assertEqual(len(fingerprints), 2)
        self.assertTrue(all(item.path == "src/trustcheck/demo.py" for item in fingerprints))
        self.assertTrue(all(item.sha256 for item in fingerprints))
        self.assertFalse(any(item.query.startswith("from ") for item in fingerprints))
        self.assertTrue(all('"' not in item.query for item in fingerprints))
        self.assertTrue(all(":" not in item.query for item in fingerprints))

    def test_search_filters_own_repository_and_report_is_stable(self) -> None:
        fingerprint = github_plagiarism_scan.CodeFingerprint(
            path="src/trustcheck/demo.py",
            line=5,
            query="rendered = json.dumps(payload, indent=2, sort_keys=True)",
            context="rendered = json.dumps(payload, indent=2, sort_keys=True)",
            sha256="a" * 64,
        )
        requested_urls: list[str] = []

        def opener(github_request):
            requested_urls.append(github_request.full_url)
            return FakeResponse(
                {
                    "items": [
                        {
                            "path": "src/trustcheck/demo.py",
                            "html_url": "https://github.com/example/trustcheck/blob/main/src/trustcheck/demo.py",
                            "repository": {"full_name": "owner/repo"},
                        },
                        {
                            "path": "copied/demo.py",
                            "html_url": "https://github.com/other/copy/blob/main/copied/demo.py",
                            "repository": {"full_name": "other/copy"},
                        },
                    ]
                }
            )

        matches, warnings = github_plagiarism_scan.search_github_code(
            [fingerprint],
            token="token",
            repository="owner/repo",
            opener=opener,
        )
        report = github_plagiarism_scan.render_report(
            repository="owner/repo",
            fingerprints=[fingerprint],
            matches=matches,
            warnings=warnings,
        )

        self.assertEqual(warnings, [])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].repository, "other/copy")
        self.assertIn("-repo%3Aowner%2Frepo", requested_urls[0])
        self.assertIn("External matches: 1", report)
        self.assertIn("other/copy", report)
        self.assertIn("fingerprint `aaaaaaaaaaaa`", report)
        self.assertNotIn("Generated", report)

    def test_missing_token_writes_warning_report(self) -> None:
        matches, warnings = github_plagiarism_scan.search_github_code(
            [],
            token=None,
            repository="owner/repo",
        )
        report = github_plagiarism_scan.render_report(
            repository="owner/repo",
            fingerprints=[],
            matches=matches,
            warnings=warnings,
        )

        self.assertEqual(matches, [])
        self.assertIn("GITHUB_TOKEN was not set", warnings[0])
        self.assertIn("Warnings: 1", report)
        self.assertIn("No external matches were found.", report)

    def test_forbidden_search_stops_after_one_actionable_warning(self) -> None:
        fingerprints = [
            github_plagiarism_scan.CodeFingerprint(
                path=f"src/trustcheck/demo_{index}.py",
                line=index,
                query=f"rendered = json.dumps(payload_{index}, sort_keys=True)",
                context=f"rendered = json.dumps(payload_{index}, sort_keys=True)",
                sha256=str(index) * 64,
            )
            for index in (1, 2)
        ]
        calls = 0

        def opener(github_request):
            nonlocal calls
            calls += 1
            raise error.HTTPError(
                github_request.full_url,
                403,
                "Forbidden",
                {"retry-after": "60"},
                io.BytesIO(
                    json.dumps(
                        {"message": "Resource not accessible by integration"}
                    ).encode("utf-8")
                ),
            )

        matches, warnings = github_plagiarism_scan.search_github_code(
            fingerprints,
            token="token",
            repository="owner/repo",
            opener=opener,
        )

        self.assertEqual(matches, [])
        self.assertEqual(calls, 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("HTTP 403", warnings[0])
        self.assertIn("Resource not accessible by integration", warnings[0])
        self.assertIn("Retry after 60 seconds", warnings[0])
        self.assertIn("TRUSTCHECK_GITHUB_SEARCH_TOKEN", warnings[0])

    def test_query_fragments_are_github_search_syntax_safe(self) -> None:
        fragment = github_plagiarism_scan._query_fragment(
            'nested = urlparse(url[len("git+"):])'
        )

        self.assertEqual(fragment, "nested urlparse url len git")
        self.assertNotIn(":", fragment)
        self.assertNotIn('"', fragment)
        self.assertNotIn("[", fragment)

    def test_parse_error_is_skipped_before_rate_limit_stops_scan(self) -> None:
        fingerprints = [
            github_plagiarism_scan.CodeFingerprint(
                path="src/trustcheck/service_urls.py",
                line=66,
                query="nested urlparse url len git",
                context="nested = urlparse(url[len('git+'):])",
                sha256="a" * 64,
            ),
            github_plagiarism_scan.CodeFingerprint(
                path="src/trustcheck/impact.py",
                line=491,
                query="return first value isinstance first value str",
                context="return first.value if isinstance(first.value, str) else None",
                sha256="b" * 64,
            ),
            github_plagiarism_scan.CodeFingerprint(
                path="src/trustcheck/other.py",
                line=1,
                query="should not be searched after rate limit",
                context="should not be searched after rate limit",
                sha256="c" * 64,
            ),
        ]
        calls = 0

        def opener(github_request):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise error.HTTPError(
                    github_request.full_url,
                    422,
                    "Unprocessable Entity",
                    {},
                    io.BytesIO(
                        json.dumps(
                            {"message": "ERROR_TYPE_QUERY_PARSING_FATAL"}
                        ).encode("utf-8")
                    ),
                )
            raise error.HTTPError(
                github_request.full_url,
                403,
                "Forbidden",
                {},
                io.BytesIO(
                    json.dumps(
                        {"message": "API rate limit exceeded for installation"}
                    ).encode("utf-8")
                ),
            )

        matches, warnings = github_plagiarism_scan.search_github_code(
            fingerprints,
            token="token",
            repository="owner/repo",
            opener=opener,
        )

        self.assertEqual(matches, [])
        self.assertEqual(calls, 2)
        self.assertEqual(len(warnings), 2)
        self.assertIn("HTTP 422", warnings[0])
        self.assertIn("ERROR_TYPE_QUERY_PARSING_FATAL", warnings[0])
        self.assertIn("HTTP 403", warnings[1])
        self.assertIn("API rate limit exceeded", warnings[1])


if __name__ == "__main__":
    unittest.main()
