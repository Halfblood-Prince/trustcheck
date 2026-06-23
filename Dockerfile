# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim AS build

ARG TRUSTCHECK_VERSION=0.0.0+docker

ENV PIP_NO_CACHE_DIR=1 \
    SETUPTOOLS_SCM_PRETEND_VERSION=${TRUSTCHECK_VERSION} \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK=${TRUSTCHECK_VERSION}

WORKDIR /src

COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src/ src/

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        build-essential \
        cargo \
        libffi-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip \
    && python -m pip wheel --wheel-dir /wheels .

FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="Trustcheck" \
      org.opencontainers.image.description="Package trust and provenance verification for PyPI consumers." \
      org.opencontainers.image.source="https://github.com/Halfblood-Prince/trustcheck" \
      org.opencontainers.image.licenses="LicenseRef-Trustcheck-Personal-Use"

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" --home /home/trustcheck trustcheck

COPY --from=build /wheels /tmp/trustcheck/

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-index --find-links=/tmp/trustcheck trustcheck \
    && python -m pip check \
    && rm -rf /tmp/trustcheck /root/.cache/pip

USER trustcheck
WORKDIR /workspace

ENTRYPOINT ["trustcheck"]
CMD ["--help"]
