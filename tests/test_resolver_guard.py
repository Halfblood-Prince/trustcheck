from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustcheck import _resolver_guard


class StrictResolverGuardTests(unittest.TestCase):
    def test_install_guard_registers_child_process_audit_guard(self) -> None:
        hooks: list[object] = []
        with patch.object(
            _resolver_guard.sys,
            "addaudithook",
            side_effect=hooks.append,
        ):
            _resolver_guard.install_guard()
        self.assertEqual(len(hooks), 1)
        hook = hooks[0]
        self.assertTrue(callable(hook))
        for event in _resolver_guard.BLOCKED_PROCESS_EVENTS:
            with self.subTest(event=event), self.assertRaisesRegex(
                _resolver_guard.StrictResolverViolation,
                "strict resolver blocked",
            ):
                hook(event, ())

    def test_audit_guard_ignores_non_process_events(self) -> None:
        self.assertIsNone(_resolver_guard._deny_child_process("open", ()))

    def test_sitecustomize_source_is_standalone_and_blocks_process_events(self) -> None:
        source = _resolver_guard.sitecustomize_source()
        self.assertNotIn("pip._internal", source)
        self.assertNotIn("trustcheck", source)
        namespace: dict[str, object] = {}
        with patch.object(
            _resolver_guard.sys,
            "addaudithook",
            side_effect=lambda hook: namespace.update({"hook": hook}),
        ):
            exec(compile(source, "sitecustomize.py", "exec"), namespace)
        hook = namespace["hook"]
        self.assertTrue(callable(hook))
        with self.assertRaisesRegex(RuntimeError, "strict resolver blocked"):
            hook("subprocess.Popen", ())

    def test_write_sitecustomize_writes_startup_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _resolver_guard.write_sitecustomize(Path(tmpdir))
            self.assertEqual(path.name, "sitecustomize.py")
            self.assertIn("sys.addaudithook", path.read_text(encoding="utf-8"))

    def test_module_main_installs_guard_without_invoking_pip(self) -> None:
        hooks: list[object] = []
        with patch.object(
            _resolver_guard.sys,
            "addaudithook",
            side_effect=hooks.append,
        ):
            self.assertEqual(_resolver_guard.main(), 0)
        self.assertEqual(len(hooks), 1)

    def test_resolver_sources_do_not_import_private_pip_modules(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "trustcheck"
        offenders = [
            path
            for path in root.rglob("*.py")
            if "pip._internal" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [])
