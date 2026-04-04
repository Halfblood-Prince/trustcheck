from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from trustcheck.cli import EXIT_DATA_ERROR, EXIT_UPSTREAM_FAILURE, main
from trustcheck.pypi import PypiClientError


class CliFailureHandlingTests(unittest.TestCase):
    def test_network_outage_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError("unable to reach PyPI: timed out"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unable to inspect package from PyPI", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_missing_package_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=PypiClientError(
                "resource not found: https://pypi.org/pypi/demo/json"
            ),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo", "--version", "9.9.9"])

        self.assertEqual(exit_code, EXIT_UPSTREAM_FAILURE)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("resource not found", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_server_response_returns_clean_nonzero_exit_code(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch(
            "trustcheck.cli.inspect_package",
            side_effect=ValueError("missing required provenance fields"),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["inspect", "demo"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("received an invalid response", stderr.getvalue())
        self.assertIn("missing required provenance fields", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_debug_mode_prints_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("trustcheck.cli.inspect_package", side_effect=ValueError("broken payload")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--debug", "inspect", "demo"])

        self.assertEqual(exit_code, EXIT_DATA_ERROR)
        self.assertIn("Traceback", stderr.getvalue())
