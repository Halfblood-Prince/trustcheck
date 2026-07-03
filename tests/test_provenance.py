from __future__ import annotations

import copy
import unittest

from trustcheck.models import (
    CoverageSummary,
    FileProvenance,
    PublisherIdentity,
    SlsaProvenance,
    TrustReport,
)
from trustcheck.provenance import (
    GITHUB_WORKFLOW_BUILD_TYPE_V1,
    SlsaValidationError,
    analyze_slsa_provenance,
    evaluate_source_release_provenance,
    is_immutable_reference,
    normalize_publisher_repository,
    normalize_repository_uri,
    publisher_matches_organization_allowlist,
    validate_publisher_organization_allowlist,
)

COMMIT = "c27d339ee6075c1f744c5d4b200f7901aad2c369"


def slsa_predicate() -> dict[str, object]:
    return {
        "buildDefinition": {
            "buildType": GITHUB_WORKFLOW_BUILD_TYPE_V1,
            "externalParameters": {
                "workflow": {
                    "ref": "refs/heads/main",
                    "repository": "https://github.com/example/demo",
                    "path": ".github/workflows/release.yml",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": (
                        "git+https://github.com/example/demo@refs/heads/main"
                    ),
                    "digest": {"gitCommit": COMMIT},
                },
                {
                    "uri": (
                        "https://github.com/actions/runner-images/"
                        "releases/tag/ubuntu24/20260601.1"
                    )
                },
            ],
        },
        "runDetails": {
            "builder": {
                "id": (
                    "https://github.com/example/builders/"
                    ".github/workflows/build.yml@refs/tags/v1"
                )
            },
            "metadata": {
                "invocationId": (
                    "https://github.com/example/demo/actions/runs/123/attempts/1"
                )
            },
        },
    }


def analyze(predicate: object | None = None):
    return analyze_slsa_provenance(
        slsa_predicate() if predicate is None else predicate,
        publisher_kind="GitHub",
        publisher_repository="example/demo",
        publisher_workflow=".github/workflows/release.yml",
    )


class SlsaProvenanceTests(unittest.TestCase):
    def test_interprets_canonical_github_workflow_provenance(self) -> None:
        result = analyze()

        self.assertTrue(result.valid)
        self.assertEqual(result.source_repository, "https://github.com/example/demo")
        self.assertEqual(result.source_commit, COMMIT)
        self.assertEqual(result.build_type, GITHUB_WORKFLOW_BUILD_TYPE_V1)
        self.assertEqual(result.workflow_path, ".github/workflows/release.yml")
        self.assertEqual(result.invocation_id.split("/")[-1], "1")
        self.assertTrue(result.materials[0].source)
        self.assertFalse(result.materials[1].source)
        self.assertEqual(
            {issue.code for issue in result.issues},
            {"mutable_workflow_reference", "weak_material_digest"},
        )

    def test_accepts_immutable_workflow_commit_and_action_pins(self) -> None:
        predicate = slsa_predicate()
        external = predicate["buildDefinition"]["externalParameters"]  # type: ignore[index]
        external["workflow"]["ref"] = COMMIT  # type: ignore[index]
        external["actionReferences"] = [  # type: ignore[index]
            f"actions/checkout@{COMMIT}",
            "pypa/gh-action-pypi-publish@release/v1",
            123,
        ]

        result = analyze(predicate)

        self.assertTrue(result.workflow_ref_immutable)
        self.assertEqual(
            result.action_references,
            [
                f"actions/checkout@{COMMIT}",
                "pypa/gh-action-pypi-publish@release/v1",
            ],
        )
        self.assertEqual(
            result.unpinned_actions,
            ["pypa/gh-action-pypi-publish@release/v1"],
        )
        self.assertIn(
            "unpinned_build_actions",
            {issue.code for issue in result.issues},
        )

    def test_generic_non_workflow_builder_does_not_require_workflow_ref(
        self,
    ) -> None:
        predicate = slsa_predicate()
        predicate["buildDefinition"]["buildType"] = (  # type: ignore[index]
            "https://build.example.com/types/package/v1"
        )
        predicate["buildDefinition"]["externalParameters"] = {}  # type: ignore[index]
        predicate["runDetails"]["builder"]["id"] = (  # type: ignore[index]
            "https://build.example.com/builders/hosted"
        )

        result = analyze_slsa_provenance(
            predicate,
            publisher_kind="Google",
            publisher_repository=None,
            publisher_workflow=None,
        )

        self.assertNotIn(
            "missing_workflow_reference",
            {issue.code for issue in result.issues},
        )

    def test_rejects_inconsistent_source_workflow_and_builder(self) -> None:
        cases: list[tuple[str, callable]] = [
            (
                "source repository",
                lambda value: value["buildDefinition"]["resolvedDependencies"][0].update(  # type: ignore[index]
                    {"uri": "git+https://github.com/other/demo@refs/heads/main"}
                ),
            ),
            (
                "workflow path",
                lambda value: value["buildDefinition"]["externalParameters"][  # type: ignore[index]
                    "workflow"
                ].update({"path": ".github/workflows/other.yml"}),
            ),
            (
                "non-GitHub builder",
                lambda value: value["runDetails"]["builder"].update(  # type: ignore[index]
                    {"id": "https://build.example.com/runner"}
                ),
            ),
            (
                "workflow commit",
                lambda value: value["buildDefinition"]["externalParameters"][  # type: ignore[index]
                    "workflow"
                ].update({"ref": "a" * 40}),
            ),
        ]
        for message, mutate in cases:
            with self.subTest(message=message):
                predicate = slsa_predicate()
                mutate(predicate)
                with self.assertRaisesRegex(SlsaValidationError, message):
                    analyze(predicate)

        predicate = slsa_predicate()
        with self.assertRaisesRegex(SlsaValidationError, "publisher kind"):
            analyze_slsa_provenance(
                predicate,
                publisher_kind="GitLab",
                publisher_repository="example/demo",
                publisher_workflow=".github/workflows/release.yml",
            )

        predicate = slsa_predicate()
        predicate["buildDefinition"]["externalParameters"]["workflow"][  # type: ignore[index]
            "repository"
        ] = "https://github.com/other/demo"
        with self.assertRaisesRegex(
            SlsaValidationError,
            "workflow repository",
        ):
            analyze(predicate)

    def test_rejects_structurally_invalid_provenance(self) -> None:
        cases: list[tuple[object, str]] = [
            ([], "predicate must be an object"),
            ({}, "buildDefinition must be an object"),
            (
                {"buildDefinition": {}, "runDetails": {}},
                "runDetails.builder must be an object",
            ),
        ]
        for predicate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SlsaValidationError, message):
                    analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"] = []  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "contain materials"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"] = [1]  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "must be an object"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][0]["digest"] = "bad"  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "digest must be an object"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["buildType"] = None  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "buildType is required"):
            analyze(predicate)

    def test_rejects_missing_source_digest_and_conflicting_materials(self) -> None:
        missing_digest = slsa_predicate()
        source = missing_digest["buildDefinition"]["resolvedDependencies"][0]  # type: ignore[index]
        source.pop("digest")  # type: ignore[union-attr]
        with self.assertRaisesRegex(SlsaValidationError, "full git commit"):
            analyze(missing_digest)

        conflicting = slsa_predicate()
        materials = conflicting["buildDefinition"]["resolvedDependencies"]  # type: ignore[index]
        duplicate = copy.deepcopy(materials[0])  # type: ignore[index]
        duplicate["digest"] = {"gitCommit": "a" * 40}
        materials.append(duplicate)  # type: ignore[union-attr]
        with self.assertRaisesRegex(SlsaValidationError, "conflicting digests"):
            analyze(conflicting)

        no_source = slsa_predicate()
        no_source["buildDefinition"]["resolvedDependencies"] = [  # type: ignore[index]
            {
                "uri": "pkg:pypi/demo@1.0",
                "digest": {"sha256": "a" * 64},
            }
        ]
        with self.assertRaisesRegex(SlsaValidationError, "no source repository"):
            analyze(no_source)

        commit_in_uri = slsa_predicate()
        source = commit_in_uri["buildDefinition"]["resolvedDependencies"][0]  # type: ignore[index]
        source["uri"] = f"git+https://github.com/example/demo@{COMMIT}"  # type: ignore[index]
        source["digest"] = {"custom": "opaque"}  # type: ignore[index]
        result = analyze(commit_in_uri)
        self.assertEqual(result.source_commit, COMMIT)

    def test_rejects_invalid_resource_and_identity_uris(self) -> None:
        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] = "demo"  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "absolute URI"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["runDetails"]["builder"]["id"] = "github-actions"  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "absolute URI"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][1]["digest"] = {  # type: ignore[index]
            "sha256": "not-a-digest"
        }
        with self.assertRaisesRegex(SlsaValidationError, "digest.sha256"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] = (  # type: ignore[index]
            "https:///missing-host"
        )
        with self.assertRaisesRegex(SlsaValidationError, "absolute URI"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] = "urn:"  # type: ignore[index]
        with self.assertRaisesRegex(SlsaValidationError, "absolute URI"):
            analyze(predicate)

        predicate = slsa_predicate()
        predicate["buildDefinition"]["resolvedDependencies"][1]["digest"] = {  # type: ignore[index]
            "custom": "opaque"
        }
        result = analyze(predicate)
        self.assertIn(
            "weak_material_digest",
            {issue.code for issue in result.issues},
        )

    def test_reports_missing_workflow_reference(self) -> None:
        predicate = slsa_predicate()
        workflow = predicate["buildDefinition"]["externalParameters"]["workflow"]  # type: ignore[index]
        workflow.pop("ref")  # type: ignore[union-attr]

        result = analyze(predicate)

        self.assertIsNone(result.workflow_ref_immutable)
        self.assertIn(
            "missing_workflow_reference",
            {issue.code for issue in result.issues},
        )

    def test_normalizes_repository_uris_and_immutable_references(self) -> None:
        self.assertEqual(
            normalize_repository_uri(
                "git+https://github.com/Example/Demo.git@refs/heads/main"
            ),
            "https://github.com/example/demo",
        )
        self.assertEqual(
            normalize_repository_uri("git@gitlab.com:Group/Subgroup/Demo.git"),
            "https://gitlab.com/group/subgroup/demo",
        )
        self.assertEqual(
            normalize_publisher_repository("GitHub", "Example/Demo"),
            "https://github.com/example/demo",
        )
        self.assertEqual(
            normalize_publisher_repository(
                "GitLab",
                "Example/Platform/Demo",
            ),
            "https://gitlab.com/example/platform/demo",
        )
        self.assertIsNone(normalize_publisher_repository("Google", "demo"))
        self.assertIsNone(normalize_publisher_repository("GitHub", None))
        self.assertIsNone(normalize_repository_uri("git@github.com"))
        self.assertIsNone(normalize_repository_uri("https://github.com/example"))
        self.assertIsNone(normalize_repository_uri("https://example.com/demo"))
        self.assertTrue(is_immutable_reference(f"sha256:{'a' * 64}"))
        self.assertFalse(is_immutable_reference("refs/tags/v1"))


class PublisherOrganizationAllowlistTests(unittest.TestCase):
    def test_validates_and_deduplicates_entries(self) -> None:
        self.assertEqual(
            validate_publisher_organization_allowlist(
                [" Example ", "github:example", "example"]
            ),
            ("example", "github:example"),
        )
        self.assertEqual(
            validate_publisher_organization_allowlist(["", "  "]),
            (),
        )
        with self.assertRaisesRegex(ValueError, "organization"):
            validate_publisher_organization_allowlist(["https://github.com/example"])
        with self.assertRaisesRegex(ValueError, "must be a list"):
            validate_publisher_organization_allowlist("github:example")

    def test_matches_provider_and_nested_organizations(self) -> None:
        github = PublisherIdentity(
            kind="GitHub",
            repository="https://github.com/example/demo",
            workflow="release.yml",
            environment=None,
        )
        gitlab = PublisherIdentity(
            kind="GitLab",
            repository="https://gitlab.com/example/platform/demo",
            workflow=".gitlab-ci.yml",
            environment=None,
        )

        self.assertTrue(
            publisher_matches_organization_allowlist(github, ["example"])
        )
        self.assertTrue(
            publisher_matches_organization_allowlist(
                github,
                ["github:example"],
            )
        )
        self.assertTrue(
            publisher_matches_organization_allowlist(
                gitlab,
                ["gitlab:example/platform"],
            )
        )
        self.assertFalse(
            publisher_matches_organization_allowlist(
                github,
                ["gitlab:example"],
            )
        )
        unsupported = PublisherIdentity(
            kind="Google",
            repository="projects/example",
            workflow=None,
            environment=None,
        )
        self.assertFalse(
            publisher_matches_organization_allowlist(
                unsupported,
                ["example"],
            )
        )


class SourceReleaseProvenanceTests(unittest.TestCase):
    def test_accepts_matching_declared_repository_tag_and_commit(self) -> None:
        report = TrustReport(
            project="demo",
            version="1.2.3",
            summary=None,
            package_url="https://pypi.org/project/demo/1.2.3/",
            declared_repository_urls=["https://github.com/example/demo"],
            repository_urls=["https://github.com/example/demo"],
            files=[
                FileProvenance(
                    filename="demo-1.2.3.tar.gz",
                    url="https://files.pythonhosted.org/packages/demo.tar.gz",
                    sha256="a" * 64,
                    has_provenance=True,
                    verified=True,
                    slsa_provenance=[
                        SlsaProvenance(
                            valid=True,
                            source_repository="https://github.com/example/demo",
                            source_commit=COMMIT,
                            workflow_ref="refs/tags/v1.2.3",
                        )
                    ],
                )
            ],
            coverage=CoverageSummary(
                total_files=1,
                files_with_provenance=1,
                verified_files=1,
                status="all-verified",
            ),
        )

        self.assertEqual(evaluate_source_release_provenance(report), [])
        self.assertEqual(report.risk_flags, [])

    def test_flags_repository_commit_tag_and_artifact_mismatch(self) -> None:
        report = TrustReport(
            project="demo",
            version="1.2.3",
            summary=None,
            package_url="https://pypi.org/project/demo/1.2.3/",
            declared_repository_urls=["https://github.com/example/demo"],
            files=[
                FileProvenance(
                    filename="demo-1.2.3.tar.gz",
                    url=(
                        "https://github.com/example/demo/releases/download/"
                        "v1.2.2/demo-1.2.3.tar.gz"
                    ),
                    sha256="a" * 64,
                    has_provenance=True,
                    verified=False,
                    slsa_provenance=[
                        SlsaProvenance(
                            valid=True,
                            source_repository="https://github.com/other/demo",
                            source_commit=COMMIT,
                            workflow_ref="refs/tags/v1.2.2",
                        ),
                        SlsaProvenance(
                            valid=True,
                            source_repository="https://github.com/other/demo",
                            source_commit="b" * 40,
                            workflow_ref="refs/tags/v1.2.2",
                        ),
                    ],
                )
            ],
            coverage=CoverageSummary(total_files=1),
        )

        flags = evaluate_source_release_provenance(report)

        self.assertEqual(
            {flag.code for flag in flags},
            {
                "source_release_repository_mismatch",
                "source_release_commit_mismatch",
                "source_release_tag_mismatch",
                "source_release_artifact_unverified",
                "source_release_github_asset_mismatch",
            },
        )
