# Installation

## Requirements

- Python `>=3.10`
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

## Snap Store status

The repository includes a strict `core24` Snap package and release QA. Snap
installation will be documented here after the `trustcheck` store name is
registered and the first stable revision is published. Until then, PyPI is
the supported public installation channel.

## Notes

CI runs should stay aligned with the package's advertised Python support. When you need fully reproducible automation, pin both the Python version and the `trustcheck` version.
