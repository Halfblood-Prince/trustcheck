from __future__ import annotations

import base64
import json
import unittest
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.x509 import Certificate
from sigstore.errors import TUFError
from sigstore.errors import VerificationError as SigstoreVerificationError
from sigstore.models import Bundle

from trustcheck.attestations import (
    PYPI_PUBLISH_V1,
    Attestation,
    ConversionError,
    Distribution,
    Provenance,
    Publisher,
    VerificationError,
    _claim,
    _decode_der_utf8_string,
    _has_windows_symlink_error,
    _optional_claims,
    _production_verifier,
)


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def statement(
    *,
    filename: str = "sampleproject-4.0.0-py3-none-any.whl",
    digest: str = "abc123",
    predicate_type: str = PYPI_PUBLISH_V1,
    subjects: list[dict[str, object]] | None = None,
) -> bytes:
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects
        if subjects is not None
        else [{"name": filename, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": {"repository": "pypa/sampleproject"},
    }
    return json.dumps(payload).encode()


def make_attestation(payload: bytes | None = None) -> Attestation:
    return Attestation.model_validate(
        {
            "version": 1,
            "verification_material": {
                "certificate": encode(b"certificate"),
                "transparency_entries": [{"logIndex": "1"}],
            },
            "envelope": {
                "statement": encode(payload or statement()),
                "signature": encode(b"signature"),
            },
        }
    )


class DistributionTests(unittest.TestCase):
    def test_accepts_supported_distribution_filenames(self) -> None:
        wheel = Distribution(
            name="sampleproject-4.0.0-py3-none-any.whl",
            digest="abc123",
        )
        sdist = Distribution(name="sampleproject-4.0.0.tar.gz", digest="abc123")

        self.assertEqual(wheel.digest, "abc123")
        self.assertEqual(sdist.name, "sampleproject-4.0.0.tar.gz")

    def test_rejects_unknown_distribution_format(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown distribution format"):
            Distribution(name="sampleproject-4.0.0.exe", digest="abc123")


class PublisherTests(unittest.TestCase):
    def test_builds_supported_publisher_policies(self) -> None:
        publishers = [
            Publisher(kind="GitHub", repository="pypa/sampleproject", workflow="release.yml"),
            Publisher(
                kind="GitLab",
                repository="pypa/sampleproject",
                workflow_filepath=".gitlab-ci.yml",
            ),
            Publisher(kind="Google", email="publisher@example.com"),
            Publisher(
                kind="CircleCI",
                project_id="project-id",
                pipeline_definition_id="pipeline-id",
                vcs_origin="github.com/pypa/sampleproject",
                vcs_ref="refs/heads/main",
            ),
        ]

        self.assertEqual(
            [type(item.as_policy()).__name__ for item in publishers],
            [
                "_GitHubPublisherPolicy",
                "_GitLabPublisherPolicy",
                "Identity",
                "_CircleCIPublisherPolicy",
            ],
        )

    def test_rejects_missing_required_publisher_field(self) -> None:
        with self.assertRaisesRegex(VerificationError, "missing required field workflow"):
            Publisher(kind="GitHub", repository="pypa/sampleproject").as_policy()

    def test_rejects_unknown_publisher_kind(self) -> None:
        with self.assertRaisesRegex(VerificationError, "unsupported Trusted Publisher"):
            Publisher(kind="Unknown").as_policy()

    def test_preserves_open_ended_publisher_fields(self) -> None:
        publisher = Publisher.model_validate(
            {
                "kind": "GitHub",
                "repository": "pypa/sampleproject",
                "workflow": "release.yml",
                "claims": {"sub": "example"},
            }
        )

        self.assertEqual(publisher.model_dump()["claims"], {"sub": "example"})


class BundleTests(unittest.TestCase):
    def test_constructs_sigstore_bundle_json(self) -> None:
        attestation = make_attestation()
        expected = cast(Bundle, object())

        with patch("trustcheck.attestations.Bundle.from_json", return_value=expected) as loader:
            actual = attestation.to_bundle()

        self.assertIs(actual, expected)
        payload = json.loads(loader.call_args.args[0])
        self.assertEqual(
            payload["mediaType"],
            "application/vnd.dev.sigstore.bundle.v0.3+json",
        )
        self.assertEqual(
            payload["dsseEnvelope"]["payloadType"],
            "application/vnd.in-toto+json",
        )
        self.assertEqual(
            payload["verificationMaterial"]["certificate"]["rawBytes"],
            encode(b"certificate"),
        )
        self.assertEqual(
            payload["verificationMaterial"]["tlogEntries"],
            [{"logIndex": "1"}],
        )

    def test_wraps_invalid_sigstore_bundle(self) -> None:
        with patch(
            "trustcheck.attestations.Bundle.from_json",
            side_effect=ValueError("bad bundle"),
        ):
            with self.assertRaisesRegex(ConversionError, "invalid Sigstore bundle"):
                make_attestation().to_bundle()


class VerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = Publisher(
            kind="GitHub",
            repository="pypa/sampleproject",
            workflow="release.yml",
        )
        self.distribution = Distribution(
            name="sampleproject-4.0.0-py3-none-any.whl",
            digest="abc123",
        )

    def verify_payload(
        self,
        payload: bytes,
        *,
        payload_type: str = "application/vnd.in-toto+json",
    ) -> tuple[str, dict[str, Any] | None]:
        verifier = Mock()
        verifier.verify_dsse.return_value = (payload_type, payload)
        with (
            patch.object(
                Attestation,
                "to_bundle",
                return_value=cast(Bundle, object()),
            ),
            patch(
                "trustcheck.attestations.Verifier.production",
                return_value=verifier,
            ) as production,
        ):
            result = make_attestation(payload).verify(
                self.publisher,
                self.distribution,
                offline=True,
            )

        production.assert_called_once_with(offline=True)
        return result

    def test_verifies_matching_statement(self) -> None:
        predicate_type, predicate = self.verify_payload(statement())

        self.assertEqual(predicate_type, PYPI_PUBLISH_V1)
        self.assertEqual(predicate, {"repository": "pypa/sampleproject"})

    def test_wraps_sigstore_verification_failure(self) -> None:
        verifier = Mock()
        verifier.verify_dsse.side_effect = SigstoreVerificationError("bad signature")
        with (
            patch.object(
                Attestation,
                "to_bundle",
                return_value=cast(Bundle, object()),
            ),
            patch(
                "trustcheck.attestations.Verifier.production",
                return_value=verifier,
            ),
        ):
            with self.assertRaisesRegex(VerificationError, "bad signature"):
                make_attestation().verify(self.publisher, self.distribution)

    def test_rejects_wrong_dsse_payload_type(self) -> None:
        with self.assertRaisesRegex(VerificationError, "expected JSON envelope"):
            self.verify_payload(statement(), payload_type="text/plain")

    def test_rejects_malformed_statement(self) -> None:
        with self.assertRaisesRegex(VerificationError, "invalid statement"):
            self.verify_payload(b"not-json")

    def test_rejects_multiple_subjects(self) -> None:
        subjects = [
            {
                "name": "sampleproject-4.0.0-py3-none-any.whl",
                "digest": {"sha256": "abc123"},
            },
            {
                "name": "sampleproject-4.0.0.tar.gz",
                "digest": {"sha256": "abc123"},
            },
        ]
        with self.assertRaisesRegex(VerificationError, "too many subjects"):
            self.verify_payload(statement(subjects=subjects))

    def test_rejects_missing_subject_name(self) -> None:
        subjects = [{"name": None, "digest": {"sha256": "abc123"}}]
        with self.assertRaisesRegex(VerificationError, "missing name"):
            self.verify_payload(statement(subjects=subjects))

    def test_rejects_invalid_subject_filename(self) -> None:
        with self.assertRaisesRegex(VerificationError, "invalid subject"):
            self.verify_payload(statement(filename="sampleproject.exe"))

    def test_rejects_mismatched_distribution_name(self) -> None:
        with self.assertRaisesRegex(VerificationError, "does not match distribution name"):
            self.verify_payload(statement(filename="other-4.0.0-py3-none-any.whl"))

    def test_accepts_equivalent_normalized_distribution_name(self) -> None:
        self.distribution = Distribution(
            name="sampleproject-4.0.0-py3.py2-none-any.whl",
            digest=self.distribution.digest,
        )

        predicate_type, _ = self.verify_payload(
            statement(filename="sampleproject-4.0.0-py2.py3-none-any.whl")
        )

        self.assertEqual(predicate_type, PYPI_PUBLISH_V1)

    def test_rejects_mismatched_digest(self) -> None:
        with self.assertRaisesRegex(VerificationError, "does not match distribution digest"):
            self.verify_payload(statement(digest="different"))

    def test_rejects_unknown_attestation_type(self) -> None:
        with self.assertRaisesRegex(VerificationError, "unknown attestation type"):
            self.verify_payload(statement(predicate_type="https://example.com/unknown"))


class PublisherPolicyTests(unittest.TestCase):
    def test_github_policy_requires_repository_ref_or_digest(self) -> None:
        publisher_policy = Publisher(
            kind="GitHub",
            repository="pypa/sampleproject",
            workflow="release.yml",
        ).as_policy()
        cert = cast(Certificate, object())

        with (
            patch.object(publisher_policy._base_policy, "verify"),  # type: ignore[attr-defined]
            patch("trustcheck.attestations._optional_claims", return_value=[]),
        ):
            with self.assertRaisesRegex(
                SigstoreVerificationError,
                "Source Repository Digest",
            ):
                publisher_policy.verify(cert)

    def test_github_policy_checks_build_config_for_available_claims(self) -> None:
        publisher_policy = Publisher(
            kind="GitHub",
            repository="pypa/sampleproject",
            workflow="release.yml",
        ).as_policy()
        any_of = Mock()

        with (
            patch.object(publisher_policy._base_policy, "verify"),  # type: ignore[attr-defined]
            patch(
                "trustcheck.attestations._optional_claims",
                return_value=["refs/heads/main"],
            ),
            patch("trustcheck.attestations.policy.AnyOf", return_value=any_of),
        ):
            publisher_policy.verify(cast(Certificate, object()))

        any_of.verify.assert_called_once()

    def test_gitlab_policy_checks_digest_and_ref_build_configs(self) -> None:
        publisher_policy = Publisher(
            kind="GitLab",
            repository="pypa/sampleproject",
            workflow_filepath=".gitlab-ci.yml",
        ).as_policy()
        any_of = Mock()

        with (
            patch.object(publisher_policy._base_policy, "verify"),  # type: ignore[attr-defined]
            patch(
                "trustcheck.attestations._claim",
                side_effect=["digest", "refs/heads/main"],
            ),
            patch("trustcheck.attestations.policy.AnyOf", return_value=any_of),
        ):
            publisher_policy.verify(cast(Certificate, object()))

        any_of.verify.assert_called_once()

    def test_circleci_policy_delegates_to_combined_policy(self) -> None:
        publisher_policy = Publisher(
            kind="CircleCI",
            project_id="project-id",
            pipeline_definition_id="pipeline-id",
        ).as_policy()

        with patch.object(publisher_policy._policy, "verify") as verify:  # type: ignore[attr-defined]
            publisher_policy.verify(cast(Certificate, object()))

        verify.assert_called_once()


class DerClaimTests(unittest.TestCase):
    def test_reads_certificate_claim_and_skips_missing_optional_claims(self) -> None:
        first_oid = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12")
        second_oid = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.13")
        extension = Mock()
        extension.public_bytes.return_value = b"\x0c\x04test"
        cert = Mock()
        cert.extensions.get_extension_for_oid.return_value = SimpleNamespace(
            value=extension
        )

        self.assertEqual(_claim(cast(Certificate, cert), second_oid), "test")
        with patch(
            "trustcheck.attestations._claim",
            side_effect=[
                x509.ExtensionNotFound("missing claim", first_oid),
                "available",
            ],
        ):
            self.assertEqual(
                _optional_claims(
                    cast(Certificate, cert),
                    first_oid,
                    second_oid,
                ),
                ["available"],
            )

    def test_decodes_short_and_long_der_lengths(self) -> None:
        self.assertEqual(_decode_der_utf8_string(b"\x0c\x04test"), "test")
        value = b"a" * 128
        self.assertEqual(
            _decode_der_utf8_string(b"\x0c\x81\x80" + value),
            "a" * 128,
        )

    def test_rejects_invalid_der_claims(self) -> None:
        invalid = [
            b"",
            b"\x16\x04test",
            b"\x0c\x82\x01",
            b"\x0c\x05test",
            b"\x0c\x02\xff\xff",
        ]

        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(SigstoreVerificationError):
                    _decode_der_utf8_string(value)


class VerifierFactoryTests(unittest.TestCase):
    def test_retries_with_embedded_root_for_windows_symlink_failure(self) -> None:
        os_error = OSError("symbolic link privilege required")
        os_error.winerror = 1314  # type: ignore[attr-defined]
        tuf_error = TUFError("Failed to refresh TUF metadata")
        tuf_error.__cause__ = os_error
        fallback = Mock(spec=Bundle)

        with (
            patch("trustcheck.attestations.sys.platform", "win32"),
            patch(
                "trustcheck.attestations.Verifier.production",
                side_effect=[tuf_error, fallback],
            ) as production,
        ):
            verifier = _production_verifier(offline=False)

        self.assertIs(verifier, fallback)
        self.assertEqual(
            production.call_args_list,
            [unittest.mock.call(offline=False), unittest.mock.call(offline=True)],
        )

    def test_does_not_hide_other_tuf_failures(self) -> None:
        tuf_error = TUFError("network failure")

        with patch(
            "trustcheck.attestations.Verifier.production",
            side_effect=tuf_error,
        ):
            with self.assertRaises(TUFError):
                _production_verifier(offline=False)

    def test_detects_nested_windows_symlink_error(self) -> None:
        os_error = OSError("symbolic link privilege required")
        os_error.winerror = 1314  # type: ignore[attr-defined]
        wrapper = RuntimeError("wrapper")
        wrapper.__context__ = os_error

        self.assertTrue(_has_windows_symlink_error(wrapper))
        self.assertFalse(_has_windows_symlink_error(RuntimeError("different")))


class ProvenanceTests(unittest.TestCase):
    def test_parses_known_publisher_and_attestation(self) -> None:
        payload = {
            "version": 1,
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "GitHub",
                        "repository": "pypa/sampleproject",
                        "workflow": "release.yml",
                    },
                    "attestations": [make_attestation().model_dump(mode="json")],
                }
            ],
        }

        provenance = Provenance.model_validate(payload)

        self.assertEqual(
            provenance.attestation_bundles[0].publisher.repository,
            "pypa/sampleproject",
        )


if __name__ == "__main__":
    unittest.main()
