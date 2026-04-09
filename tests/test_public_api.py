from __future__ import annotations

import unittest

import trustcheck
from trustcheck.contract import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION
from trustcheck.models import TrustReport


class PublicApiTests(unittest.TestCase):
    def test_supported_public_api_is_explicit(self) -> None:
        self.assertEqual(
            trustcheck.__all__,
            [
                "JSON_SCHEMA_ID",
                "JSON_SCHEMA_VERSION",
                "TrustReport",
                "__version__",
                "get_json_schema",
                "inspect_package",
            ],
        )
        self.assertIs(trustcheck.TrustReport, TrustReport)
        self.assertEqual(trustcheck.JSON_SCHEMA_VERSION, JSON_SCHEMA_VERSION)
        self.assertEqual(trustcheck.JSON_SCHEMA_ID, JSON_SCHEMA_ID)
        self.assertTrue(callable(trustcheck.inspect_package))
        self.assertTrue(callable(trustcheck.get_json_schema))
