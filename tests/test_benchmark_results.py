from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path


class PublishedBenchmarkTests(unittest.TestCase):
    def test_committed_result_is_signed_and_complete(self) -> None:
        root = Path(__file__).resolve().parents[1]
        namespace = runpy.run_path(str(root / "scripts" / "benchmark_signature.py"))
        result = root / "benchmarks" / "results" / "latest.json"
        namespace["verify"](
            result,
            root / "benchmarks" / "results" / "benchmark-public-key.pem",
            root / "benchmarks" / "results" / "latest.json.sig",
        )
        payload = json.loads(result.read_text(encoding="utf-8"))
        self.assertIn("Windows", payload["environment"]["platform"])
        self.assertIn("pip-audit", payload["environment"]["pip_audit"])
        self.assertGreater(payload["performance"]["trustcheck"]["peak_memory_bytes"], 0)
        self.assertGreater(payload["performance"]["pip_audit"]["peak_memory_bytes"], 0)
        self.assertIn("trustcheck_only", payload["correctness"])
        self.assertIn("pip_audit_only", payload["correctness"])
