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
                "INDUSTRY_OUTPUT_FORMATS",
                "OUTPUT_FORMATS",
                "ArtifactReference",
                "CisaKevClient",
                "DependencyConfusionFinding",
                "EpssClient",
                "ExportPackage",
                "IndexConfiguration",
                "IndexFile",
                "IndexProject",
                "LockfileResolution",
                "OsvClient",
                "OsvProvider",
                "LockedPackage",
                "PipResolver",
                "Resolution",
                "ResolutionError",
                "ResolvedDistribution",
                "SourceLocation",
                "TargetEnvironment",
                "TrustReport",
                "VulnerabilityIntelligenceClient",
                "VulnerabilitySuppression",
                "SimpleRepositoryClient",
                "__version__",
                "discover_installed_distributions",
                "get_json_schema",
                "inspect_package",
                "load_lockfile",
                "package_purl",
                "render_export",
            ],
        )
        self.assertIs(trustcheck.TrustReport, TrustReport)
        self.assertEqual(trustcheck.JSON_SCHEMA_VERSION, JSON_SCHEMA_VERSION)
        self.assertEqual(trustcheck.JSON_SCHEMA_ID, JSON_SCHEMA_ID)
        self.assertTrue(callable(trustcheck.inspect_package))
        self.assertTrue(callable(trustcheck.get_json_schema))
