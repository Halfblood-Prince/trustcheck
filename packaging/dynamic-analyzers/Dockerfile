ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.title="Trustcheck bounded install analyzer"
LABEL org.opencontainers.image.description="Offline backend image for Trustcheck bounded install analysis"
LABEL org.opencontainers.image.source="https://github.com/HalCh1/trustcheck"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_NO_CACHE_DIR=1

COPY requirements-build-backends.txt /opt/trustcheck/requirements-build-backends.txt

RUN python -m pip install --upgrade --no-cache-dir pip==25.2 \
    && python -m pip wheel \
        --wheel-dir /opt/trustcheck/wheelhouse \
        --requirement /opt/trustcheck/requirements-build-backends.txt \
    && python -m pip install \
        --no-index \
        --find-links /opt/trustcheck/wheelhouse \
        --requirement /opt/trustcheck/requirements-build-backends.txt \
    && python -m pip check \
    && chmod -R a+rX /opt/trustcheck

WORKDIR /work
USER 65534:65534
