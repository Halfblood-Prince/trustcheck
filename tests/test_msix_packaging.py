from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from PIL import Image

from scripts.build_msix_layout import build_layout


class MsixPackagingTests(unittest.TestCase):
    def test_layout_contains_store_identity_and_execution_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "input.exe"
            logo = root / "logo.png"
            executable.write_bytes(b"exe")
            Image.new("RGB", (300, 200), "navy").save(logo)

            manifest = build_layout(
                executable=executable,
                logo=logo,
                layout=root / "layout",
                version="2.1.0",
                identity_name="Trustcheck.Test",
                publisher="CN=Trustcheck Test",
            )
            document = ElementTree.parse(manifest)
            text = manifest.read_text(encoding="utf-8")

            self.assertEqual(document.getroot().tag.rsplit("}", 1)[-1], "Package")
            self.assertIn('Name="Trustcheck.Test"', text)
            self.assertIn('Publisher="CN=Trustcheck Test"', text)
            self.assertIn('Version="2.1.0.0"', text)
            self.assertIn('Category="windows.appExecutionAlias"', text)
            self.assertIn('Alias="trustcheck.exe"', text)
            self.assertTrue((root / "layout" / "trustcheck.exe").is_file())
            with Image.open(root / "layout" / "Assets" / "Square44x44Logo.png") as icon:
                self.assertEqual(icon.size, (44, 44))
            with Image.open(root / "layout" / "Assets" / "Square150x150Logo.png") as icon:
                self.assertEqual(icon.size, (150, 150))

    def test_layout_rejects_prerelease_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "input.exe"
            logo = root / "logo.png"
            executable.write_bytes(b"exe")
            Image.new("RGB", (200, 200), "navy").save(logo)

            with self.assertRaisesRegex(ValueError, "stable package version"):
                build_layout(
                    executable=executable,
                    logo=logo,
                    layout=root / "layout",
                    version="2.1.0rc1",
                    identity_name="Trustcheck.Test",
                    publisher="CN=Trustcheck Test",
                )


if __name__ == "__main__":
    unittest.main()
