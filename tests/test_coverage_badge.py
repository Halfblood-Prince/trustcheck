from __future__ import annotations

import unittest

from scripts.update_coverage_badge import _coverage_percent


class CoverageBadgeTests(unittest.TestCase):
    def test_decimal_coverage_display_is_rounded_to_badge_percent(self) -> None:
        payload = {
            "totals": {
                "percent_covered": 98.014,
                "percent_covered_display": "98.01",
            }
        }

        self.assertEqual(_coverage_percent(payload), 98)


if __name__ == "__main__":
    unittest.main()
