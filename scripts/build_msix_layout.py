from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Sequence

from packaging.version import Version
from PIL import Image


def build_layout(
    *,
    executable: Path,
    logo: Path,
    layout: Path,
    version: str,
    identity_name: str,
    publisher: str,
) -> Path:
    normalized = Version(version)
    release = (*normalized.release, 0, 0, 0, 0)[:4]
    msix_version = ".".join(str(component) for component in release)
    if normalized.is_prerelease or normalized.is_devrelease or normalized.is_postrelease:
        raise ValueError("MSIX releases require a stable package version")
    if any(component > 65535 for component in release):
        raise ValueError("MSIX version components must not exceed 65535")
    if not identity_name.strip() or not publisher.strip():
        raise ValueError("MSIX identity name and publisher are required")
    if not executable.is_file() or not logo.is_file():
        raise ValueError("MSIX executable and logo inputs must exist")

    assets = layout / "Assets"
    assets.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, layout / "trustcheck.exe")
    with Image.open(logo) as source_image:
        square_image = _center_crop(source_image.convert("RGBA"))
        square_image.resize((44, 44), Image.Resampling.LANCZOS).save(
            assets / "Square44x44Logo.png"
        )
        square_image.resize((150, 150), Image.Resampling.LANCZOS).save(
            assets / "Square150x150Logo.png"
        )

    manifest = layout / "AppxManifest.xml"
    manifest.write_text(
        f"""<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap5="http://schemas.microsoft.com/appx/manifest/uap/windows10/5"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap uap5 rescap">
  <Identity Name="{_xml(identity_name)}" Publisher="{_xml(publisher)}"
    Version="{msix_version}" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Trustcheck</DisplayName>
    <PublisherDisplayName>Trustcheck</PublisherDisplayName>
    <Logo>Assets\\Square44x44Logo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0"
      MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Applications>
    <Application Id="Trustcheck" Executable="trustcheck.exe"
      EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Trustcheck" Description="Package trust scanner"
        BackgroundColor="transparent" Square44x44Logo="Assets\\Square44x44Logo.png"
        Square150x150Logo="Assets\\Square150x150Logo.png" />
      <Extensions>
        <uap5:Extension Category="windows.appExecutionAlias" Executable="trustcheck.exe"
          EntryPoint="Windows.FullTrustApplication">
          <uap5:AppExecutionAlias>
            <uap5:ExecutionAlias Alias="trustcheck.exe" />
          </uap5:AppExecutionAlias>
        </uap5:Extension>
      </Extensions>
    </Application>
  </Applications>
  <Capabilities>
    <Capability Name="internetClient" />
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
""",
        encoding="utf-8",
    )
    return manifest


def _center_crop(image: Image.Image) -> Image.Image:
    edge = min(image.size)
    left = (image.width - edge) // 2
    top = (image.height - edge) // 2
    return image.crop((left, top, left + edge, top + edge))


def _xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Microsoft Store MSIX layout.")
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--logo", required=True, type=Path)
    parser.add_argument("--layout", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--identity-name", required=True)
    parser.add_argument("--publisher", required=True)
    args = parser.parse_args(argv)
    build_layout(
        executable=args.executable,
        logo=args.logo,
        layout=args.layout,
        version=args.version,
        identity_name=args.identity_name,
        publisher=args.publisher,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
