from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path

from trustcheck.cli import build_parser


class PublishedBenchmarkTests(unittest.TestCase):
    def test_committed_result_is_signed_and_complete(self) -> None:
        root = Path(__file__).resolve().parents[1]
        attributes = (root / ".gitattributes").read_text(encoding="utf-8")
        lines = attributes.splitlines()
        for path in ("benchmarks/corpus/truth.json", "benchmarks/results/latest.json"):
            self.assertIn(f"{path} -text diff whitespace=cr-at-eol", lines)
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

    def test_committed_trustcheck_benchmark_commands_parse(self) -> None:
        root = Path(__file__).resolve().parents[1]
        payload = json.loads(
            (root / "benchmarks" / "results" / "latest.json").read_text(
                encoding="utf-8"
            )
        )
        parser = build_parser()
        commands = list(_trustcheck_commands(payload.get("commands")))

        self.assertGreater(len(commands), 0)
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(command[:3], ["python", "-m", "trustcheck"])
                self.assertNotIn("--max-workers", command)
                parser.parse_args(command[3:])


def _trustcheck_commands(value: object) -> list[list[str]]:
    if (
        isinstance(value, list)
        and len(value) >= 4
        and all(isinstance(item, str) for item in value)
        and value[:3] == ["python", "-m", "trustcheck"]
    ):
        return [value]
    if isinstance(value, dict):
        commands: list[list[str]] = []
        for item in value.values():
            commands.extend(_trustcheck_commands(item))
        return commands
    if isinstance(value, list):
        commands = []
        for item in value:
            commands.extend(_trustcheck_commands(item))
        return commands
    return []
