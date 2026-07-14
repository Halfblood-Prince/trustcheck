from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.check_mutation_score import check_score
from scripts.mutation_targets import mutation_targets


class MutationScoreTests(unittest.TestCase):
    def test_accepts_score_at_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stats.json"
            path.write_text(
                json.dumps({"killed": 8, "survived": 2}),
                encoding="utf-8",
            )
            score = check_score(path, minimum=80.0)

        self.assertEqual(score, 80.0)

    def test_rejects_empty_or_low_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stats.json"
            path.write_text(json.dumps({"killed": 0}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "did not evaluate"):
                check_score(path, minimum=80.0)

            path.write_text(
                json.dumps({"killed": 7, "survived": 3}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "below 80.00%"):
                check_score(path, minimum=80.0)

    def test_no_test_and_segfault_mutants_count_against_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stats.json"
            path.write_text(
                json.dumps({"killed": 8, "no_tests": 1, "segfault": 1}),
                encoding="utf-8",
            )

            self.assertEqual(check_score(path, minimum=80.0), 80.0)

    def test_mutation_group_manifest_covers_security_rotation(self) -> None:
        config = Path(".github/mutation-groups.toml")
        payload = tomllib.loads(config.read_text(encoding="utf-8"))
        groups = payload["groups"]
        group_ids = {group["id"] for group in groups}

        self.assertEqual(
            group_ids,
            {
                "policy-thresholds",
                "plugin-ipc-validation",
                "plugin-trust-binding",
                "resolver-guard-decisions",
                "provenance-identity-matching",
                "archive-record-limits",
                "remediation-candidates",
                "dependency-confusion",
                "advisory-merge-schema",
            },
        )
        for group in groups:
            with self.subTest(group=group["id"]):
                targets = mutation_targets(config, group["id"])
                self.assertGreaterEqual(len(targets), 3)
                self.assertTrue(all(target.startswith("trustcheck.") for target in targets))

        workflow = Path(".github/workflows/mutation.yml").read_text(encoding="utf-8")
        for group_id in group_ids:
            self.assertIn(f"- {group_id}", workflow)


if __name__ == "__main__":
    unittest.main()
