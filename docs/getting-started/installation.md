# Installation

## Requirements

- Python `>=3.11`
- Network access to PyPI for live inspection

## Install from PyPI

```bash
pip install trustcheck
```

## Verify the CLI is available

```bash
trustcheck --help
```

Show the installed package version and report schema version:

```bash
trustcheck --version
```

## Upgrade

```bash
pip install --upgrade trustcheck
```

## Install from the Snap Store

```bash
sudo snap install trustcheck
trustcheck --version
```

Do not include punctuation after the package name in the install command.

### Snap command not found

Snap exposes the application as `/snap/bin/trustcheck`. Some distributions or
shell sessions do not add `/snap/bin` to `PATH` until the user logs out and
back in.

Confirm the installed application works independently of `PATH`:

```bash
snap run trustcheck --version
snap run trustcheck inspect requests
```

If those commands work, start a new login session or update the current one:

```bash
export PATH="/snap/bin:$PATH"
trustcheck --version
```

If `snap run trustcheck --version` fails too, inspect the installed revision:

```bash
snap info trustcheck
snap connections trustcheck
```

### Snap provenance verification reports permission denied

Versions before the XDG confinement fix could let Sigstore resolve its TUF
trust metadata to hidden directories in the real home directory. The Snap
`home` interface does not grant general access to hidden home paths, so
verification could report `[unexpected_verification_error] [Errno 13]
Permission denied`.

Refresh to the latest stable revision:

```bash
sudo snap refresh trustcheck
trustcheck inspect sampleproject --version 4.0.0
```

Current revisions keep Sigstore data, cache, and configuration under the
snap-owned `$SNAP_USER_COMMON` directory.

## Notes

CI runs should stay aligned with the package's advertised Python support. When you need fully reproducible automation, pin both the Python version and the `trustcheck` version.
