# Snap package

The root `snap/snapcraft.yaml` builds the `trustcheck` CLI as a strict,
`core24` snap. The package uses the `network`, `home`, and `removable-media`
interfaces so it can query package registries and scan dependency files
without classic confinement.

Build and test locally on a supported Ubuntu host:

```bash
sudo snap install snapcraft --classic
snapcraft
snapcraft lint ./trustcheck_*.snap
sudo snap install --dangerous ./trustcheck_*.snap
/snap/bin/trustcheck --version
```

The committed development version is `0+git`. The release workflow replaces
it with the annotated release tag before building. The same value is passed
to `setuptools-scm`, so the Snap metadata and `trustcheck --version` agree.

Store registration, scoped credentials, and release behavior are documented
in [the release publishing guide](../docs/guides/release-publishing.md).
