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
                "ADVISORY_SNAPSHOT_SCHEMA",
                "PLUGIN_API_VERSION",
                "PLUGIN_GROUPS",
                "REMEDIATION_SCHEMA_ID",
                "REMEDIATION_SCHEMA_VERSION",
                "TRUST_MANIFEST_SCHEMA",
                "INDUSTRY_OUTPUT_FORMATS",
                "OUTPUT_FORMATS",
                "ArtifactReference",
                "ArtifactAnalyzerPlugin",
                "AdvisorySnapshotError",
                "AdvisorySnapshotStore",
                "AdvisorySourcePlugin",
                "BlockedFix",
                "CisaKevClient",
                "CacheIntegrityError",
                "ContentAddressedCache",
                "DEFAULT_TRUSTED_PROJECTS",
                "DEFAULT_TRUST_MANIFEST_PATH",
                "DependencyConfusionFinding",
                "DoctorCheck",
                "DoctorReport",
                "DynamicAnalysisEvidence",
                "DynamicAnalysisPhase",
                "DynamicAnalysisResult",
                "EpssClient",
                "ExportPackage",
                "FilePatch",
                "IndexConfiguration",
                "IndexPlugin",
                "IndexFile",
                "IndexProject",
                "HeuristicFinding",
                "HeuristicRuleMetadata",
                "LockfileResolution",
                "MaliciousPackageAssessment",
                "ManifestIssue",
                "ManifestVerificationResult",
                "OsvClient",
                "OsvProvider",
                "NativeBinaryInspection",
                "LockedPackage",
                "PipResolver",
                "PluginDescriptor",
                "PluginError",
                "PluginManager",
                "PolicyRulePlugin",
                "ProvenanceIssue",
                "ProvenanceMaterial",
                "PullRequestResult",
                "RemediationError",
                "RemediationPlan",
                "RemediationSummary",
                "RemediationUpgrade",
                "RemediationValidation",
                "RULE_METADATA",
                "Resolution",
                "ResolutionError",
                "RendererPlugin",
                "ResolvedDistribution",
                "SourceLocation",
                "SemanticEdit",
                "TargetEnvironment",
                "TrustReport",
                "VulnerabilityIntelligenceClient",
                "VulnerabilitySuppression",
                "SimpleRepositoryClient",
                "SLSA_PROVENANCE_V1",
                "SlsaProvenance",
                "SlsaValidationError",
                "__version__",
                "analyze_python_source",
                "analyze_slsa_provenance",
                "apply_prepared_remediation",
                "build_manifest",
                "collect_doctor_report",
                "create_pull_request",
                "discover_installed_distributions",
                "evaluate_source_release_provenance",
                "get_json_schema",
                "heuristic_score",
                "inspect_package",
                "inspect_native_binary",
                "load_lockfile",
                "load_manifest",
                "normalize_rule_thresholds",
                "normalize_score_thresholds",
                "package_purl",
                "plan_remediation",
                "prepare_remediation",
                "publisher_matches_organization_allowlist",
                "render_export",
                "render_doctor_json",
                "render_doctor_text",
                "render_manifest_verification_text",
                "validate_publisher_organization_allowlist",
                "verify_manifest",
                "write_manifest",
            ],
        )
        self.assertIs(trustcheck.TrustReport, TrustReport)
        self.assertEqual(trustcheck.JSON_SCHEMA_VERSION, JSON_SCHEMA_VERSION)
        self.assertEqual(trustcheck.JSON_SCHEMA_ID, JSON_SCHEMA_ID)
        self.assertTrue(callable(trustcheck.inspect_package))
        self.assertTrue(callable(trustcheck.get_json_schema))

    def test_lazy_public_api_helpers_cover_missing_and_dir(self) -> None:
        self.assertEqual(trustcheck.__getattr__("__version__"), trustcheck.__version__)
        self.assertIn("TrustReport", trustcheck.__dir__())
        with self.assertRaisesRegex(AttributeError, "definitely_missing"):
            trustcheck.__getattr__("definitely_missing")
