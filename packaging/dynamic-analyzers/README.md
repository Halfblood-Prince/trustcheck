# Trustcheck Bounded Install Analyzer Images

These image definitions build the offline backend images used by bounded install
analysis. Build one image for each supported Python version:

```bash
docker build \
  --build-arg PYTHON_VERSION=3.12 \
  -t ghcr.io/halfblood-prince/trustcheck-bounded-install-analyzer:python-3.12 \
  packaging/dynamic-analyzers
```

Publish images by immutable digest and configure runtime defaults in
`trustcheck.dynamic.DYNAMIC_ANALYZER_IMAGES`, for example:

```text
ghcr.io/halfblood-prince/trustcheck-bounded-install-analyzer:python-3.12@sha256:<digest>
```

Do not configure a default to a generic base image. If no published
Trustcheck analyzer digest is recorded for a Python profile, bounded install
analysis must fail as unsupported unless the caller supplies
`--dynamic-image IMAGE@sha256:DIGEST`.

The `.github/workflows/dynamic-analyzers.yml` workflow builds Python
3.11-3.14 analyzer images, tests the offline backend wheelhouse, runs benign
and malicious dynamic-analysis fixtures, scans the Python packages installed in
the image, publishes to GHCR with BuildKit SBOM and provenance attestations, and
uploads the immutable digest records that should be copied into
`DYNAMIC_ANALYZER_IMAGES`.

The analyzer runner uses `--no-index` during analysis and only reads backend
wheels from `/opt/trustcheck/wheelhouse`. Do not add network fetches to runtime
analysis phases.
