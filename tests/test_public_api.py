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
                "REMEDIATION_SCHEMA_ID",
                "REMEDIATION_SCHEMA_VERSION",
                "INDUSTRY_OUTPUT_FORMATS",
                "OUTPUT_FORMATS",
                "ArtifactReference",
                "BlockedFix",
                "CisaKevClient",
                "DEFAULT_TRUSTED_PROJECTS",
                "DependencyConfusionFinding",
                "EpssClient",
                "ExportPackage",
                "FilePatch",
                "IndexConfiguration",
                "IndexFile",
                "IndexProject",
                "HeuristicFinding",
                "LockfileResolution",
                "MaliciousPackageAssessment",
                "OsvClient",
                "OsvProvider",
                "NativeBinaryInspection",
                "LockedPackage",
                "PipResolver",
                "PullRequestResult",
                "RemediationError",
                "RemediationPlan",
                "RemediationSummary",
                "RemediationUpgrade",
                "RemediationValidation",
                "Resolution",
                "ResolutionError",
                "ResolvedDistribution",
                "SourceLocation",
                "SemanticEdit",
                "TargetEnvironment",
                "TrustReport",
                "VulnerabilityIntelligenceClient",
                "VulnerabilitySuppression",
                "SimpleRepositoryClient",
                "__version__",
                "analyze_python_source",
                "apply_prepared_remediation",
                "create_pull_request",
                "discover_installed_distributions",
                "get_json_schema",
                "heuristic_score",
                "inspect_package",
                "inspect_native_binary",
                "load_lockfile",
                "package_purl",
                "plan_remediation",
                "prepare_remediation",
                "render_export",
            ],
        )
        self.assertIs(trustcheck.TrustReport, TrustReport)
        self.assertEqual(trustcheck.JSON_SCHEMA_VERSION, JSON_SCHEMA_VERSION)
        self.assertEqual(trustcheck.JSON_SCHEMA_ID, JSON_SCHEMA_ID)
        self.assertTrue(callable(trustcheck.inspect_package))
        self.assertTrue(callable(trustcheck.get_json_schema))
