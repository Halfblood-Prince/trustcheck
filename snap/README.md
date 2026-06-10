# Snap package

The root `snap/snapcraft.yaml` builds the `trustcheck` CLI as a strict,
`core24` snap. The package uses the `network`, `home`, and `removable-media`
interfaces so it can query package registries and scan dependency files
without classic confinement.

Sigstore stores TUF trust metadata through the XDG data and cache paths. The
snap redirects those paths into `$SNAP_USER_COMMON` so provenance verification
can update trust material under strict confinement and retain it across snap
revisions.

Supported Snap platforms are:

- `amd64` for 64-bit x86
- `arm64` for 64-bit Arm
- `armhf` for 32-bit Arm

`i386` is not declared because the `core24` base does not support that build
architecture.

The same manifest supplies the Snap Store title, summary, Markdown product
description, project links, and `snap/gui/icon.png` storefront icon. Keep
those fields user-facing and update them whenever the supported scan surface
changes. After publishing the verified snap, the release workflow runs
`snapcraft upload-metadata --force` so the Store profile receives the new
summary, description, and icon.

Build and test locally on a supported Ubuntu host:

```bash
sudo snap install snapcraft --classic
snapcraft
snapcraft lint ./trustcheck_*.snap
sudo snap install --dangerous ./trustcheck_*.snap
snap run trustcheck --version
export PATH="/snap/bin:$PATH"
trustcheck --version
```

If `snap run trustcheck` works but `trustcheck` does not, the snap is healthy
and `/snap/bin` is missing from the current shell's `PATH`. Start a new login
session or add that directory as shown above.

By default, Snapcraft selects the platform matching the build host. On a
compatible builder, select a declared target explicitly with
`snapcraft --platform=<platform>`, for example
`snapcraft --platform=arm64`.

The committed development version is `0+git`. The release workflow replaces
it with the annotated release tag before building. The same value is passed
to `setuptools-scm`, so the Snap metadata and `trustcheck --version` agree.
