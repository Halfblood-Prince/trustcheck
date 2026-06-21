# Fuzzing

The Atheris harnesses cover requirements, all supported lockfile parser
families, provenance envelopes and SLSA predicates, wheel/sdist metadata and
ZIP/TAR headers (including wheel `RECORD`), and SARIF/SPDX/CycloneDX exports.

Atheris is supported on Linux. Run one target from an installed checkout:

```bash
python -m pip install . atheris==3.0.0
python fuzz/fuzz_artifacts.py -runs=10000 -max_len=65536 -timeout=10
```

`.github/workflows/fuzz.yml` runs bounded smoke campaigns for every target on
pull requests, pushes to `main`, and a weekly schedule. A crash or timeout
fails its matrix job and libFuzzer prints the reproducing input.
