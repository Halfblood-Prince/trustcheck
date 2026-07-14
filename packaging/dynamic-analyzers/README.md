# Trustcheck Bounded Install Analyzer Images

These image definitions build the offline backend images used by bounded install
analysis. Build one image for each supported Python version:

```bash
docker build \
  --build-arg PYTHON_VERSION=3.12 \
  -t ghcr.io/trustcheck/bounded-install-analyzer:python-3.12 \
  packaging/dynamic-analyzers
```

Publish images by immutable digest and configure runtime defaults in
`trustcheck.dynamic.DYNAMIC_ANALYZER_IMAGES`, for example:

```text
ghcr.io/trustcheck/bounded-install-analyzer:python-3.12@sha256:<digest>
```

Do not configure a default to a generic base image. If no published
Trustcheck analyzer digest is recorded for a Python profile, bounded install
analysis must fail as unsupported unless the caller supplies
`--dynamic-image IMAGE@sha256:DIGEST`.

Publication automation must pin each Python base image by digest, build and
test the dedicated analyzer for every supported Python profile, scan the
image, generate an SBOM and provenance attestation, publish to GHCR, and record
the resulting immutable digest in `DYNAMIC_ANALYZER_IMAGES`.

The analyzer runner uses `--no-index` during analysis and only reads backend
wheels from `/opt/trustcheck/wheelhouse`. Do not add network fetches to runtime
analysis phases.
