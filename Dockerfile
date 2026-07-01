# syntax=docker/dockerfile:1.7

FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1 AS build

ARG TRUSTCHECK_VERSION=0.0.0+docker

ENV PIP_NO_CACHE_DIR=1 \
    SETUPTOOLS_SCM_PRETEND_VERSION=${TRUSTCHECK_VERSION} \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK=${TRUSTCHECK_VERSION}

WORKDIR /src

COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY requirements/runtime.lock requirements/runtime.lock
COPY src/ src/

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        build-essential \
        cargo \
        libffi-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip wheel \
        --disable-pip-version-check \
        --require-hashes \
        --wheel-dir /wheels \
        --requirement requirements/runtime.lock \
    && python -m pip wheel \
        --disable-pip-version-check \
        --no-deps \
        --wheel-dir /wheels \
        .

FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1 AS runtime

LABEL org.opencontainers.image.title="Trustcheck" \
      org.opencontainers.image.description="Package trust and provenance verification for PyPI consumers." \
      org.opencontainers.image.source="https://github.com/Halfblood-Prince/trustcheck" \
      org.opencontainers.image.licenses="LicenseRef-Trustcheck-Personal-Use"

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" --home /home/trustcheck trustcheck

COPY --from=build /wheels /tmp/trustcheck/

RUN python -m pip install \
        --disable-pip-version-check \
        --no-index \
        /tmp/trustcheck/*.whl \
    && python -m pip check \
    && rm -rf /tmp/trustcheck /root/.cache/pip

USER trustcheck
WORKDIR /workspace

ENTRYPOINT ["trustcheck"]
CMD ["--help"]
