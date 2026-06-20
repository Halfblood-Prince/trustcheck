from __future__ import annotations

import unittest
from unittest.mock import patch

from trustcheck import _resolver_guard


class StrictResolverGuardTests(unittest.TestCase):
    def test_main_registers_child_process_audit_guard(self) -> None:
        hooks: list[object] = []
        with patch.object(
            _resolver_guard.sys,
            "addaudithook",
            side_effect=hooks.append,
        ), patch.object(
            _resolver_guard,
            "pip_main",
            return_value=7,
        ) as pip:
            self.assertEqual(_resolver_guard.main(["install", "demo"]), 7)
        pip.assert_called_once_with(["install", "demo"])
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

    def test_main_uses_process_arguments_by_default(self) -> None:
        with patch.object(_resolver_guard.sys, "argv", ["guard", "--version"]), patch.object(
            _resolver_guard,
            "pip_main",
            return_value=0,
        ) as pip:
            self.assertEqual(_resolver_guard.main(), 0)
        pip.assert_called_once_with(["--version"])
