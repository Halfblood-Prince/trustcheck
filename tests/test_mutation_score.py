from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_mutation_score import check_score


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


if __name__ == "__main__":
    unittest.main()
