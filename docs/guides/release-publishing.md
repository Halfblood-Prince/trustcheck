# Release publishing

An annotated `vMAJOR.MINOR.PATCH` tag starts `.github/workflows/publish.yml`.
The workflow verifies the tag, runs the package test matrix, builds the Python
distribution, and builds, lints, installs, and smoke-tests the snap. Only
after those checks pass do three independent publication jobs start in
parallel:

- PyPI Trusted Publishing
- GitHub Release and GitHub Action version tags
- Snap Store publication to `stable`

## PyPI setup

Configure a PyPI Trusted Publisher for:

- repository: `Halfblood-Prince/trustcheck`
- workflow: `publish.yml`
- environment: leave empty unless the workflow is changed to use one

The workflow uses `pypa/gh-action-pypi-publish` with GitHub OIDC and publishes
only the wheel and sdist produced by the verified build job.

## GitHub Action and Marketplace setup

The workflow creates the immutable release tag, updates the compatible major
tag such as `v1`, and creates a GitHub Release containing the Python
distributions, SBOM, checksums, and snap.

GitHub does not expose Marketplace publication as a workflow or Releases API
field. For the first Marketplace publication, and for any release GitHub
requires to be explicitly associated with the listing:

1. Open the generated GitHub Release and choose **Edit**.
2. Select **Publish this Action to the GitHub Marketplace**.
3. Accept the Marketplace Developer Agreement if prompted.
4. Choose the security category, confirm the release tag, and save.

Two-factor authentication is required by GitHub for this operation. The
release workflow writes the release edit URL to its job summary.

The older Marketplace listing named `TrustCheck Python Package Scanner`
belongs to the separate `Halfblood-Prince/trustcheck-action` repository. It
does not receive releases from this repository. The root action now uses the
distinct Marketplace display name `TrustCheck Dependency Security Gate` so
this repository can be listed independently. Retire the old listing after
the new one is active if only one public listing should remain.

## Snap Store setup

Snap Store name ownership and credentials are account-level state and must be
configured once before the release workflow can publish.

Log in and register the package name:

```bash
snapcraft login
snapcraft register trustcheck
```

Create credentials restricted to this snap and the stable channel:

```bash
snapcraft export-login \
  --snaps=trustcheck \
  --channels=stable \
  --acls=package_access,package_push,package_update,package_release \
  snapcraft-login.txt
```

Add the complete file contents as the repository secret
`SNAPCRAFT_STORE_CREDENTIALS`. Set an expiration with `--expires` and rotate
the secret before it expires.

Release QA validates the credential with `snapcraft whoami` and confirms
access to the registered `trustcheck` name before any publisher starts. The
Snap Store publisher then downloads the exact snap that passed QA and
publishes it with `snapcore/action-publish` to `stable`; it never rebuilds
during publication.

## Creating a release

Update the changelog and commit all release changes, then create and push an
annotated tag:

```bash
git tag -a v1.10.0 -m "Release v1.10.0"
git push origin v1.10.0
```

Lightweight tags and prerelease-shaped tags are rejected. If any QA job
fails, none of the three publication jobs starts.
