from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


def _job_block(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job {job_name!r} was not found")
    return match.group(1)


class DockerWorkflowTests(unittest.TestCase):
    def test_dockerfile_packages_cli_into_non_root_runtime_image(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

        self.assertIn(
            "FROM python:3.14-slim@sha256:"
            "b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1 "
            "AS build",
            dockerfile,
        )
        self.assertIn(
            "FROM python:3.14-slim@sha256:"
            "b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1 "
            "AS runtime",
            dockerfile,
        )
        self.assertNotIn("python:${PYTHON_VERSION}-slim", dockerfile)
        self.assertIn("ARG TRUSTCHECK_VERSION=0.0.0+docker", dockerfile)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION=${TRUSTCHECK_VERSION}", dockerfile)
        self.assertIn("build-essential", dockerfile)
        self.assertIn("cargo", dockerfile)
        self.assertIn("COPY requirements/runtime.lock requirements/runtime.lock", dockerfile)
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("--requirement requirements/runtime.lock", dockerfile)
        self.assertIn("--no-deps", dockerfile)
        self.assertIn("--wheel-dir /wheels", dockerfile)
        self.assertNotIn("python -m pip install --upgrade pip", dockerfile)
        self.assertIn(
            "python -m pip install",
            dockerfile,
        )
        self.assertIn("--no-index", dockerfile)
        self.assertIn("/tmp/trustcheck/*.whl", dockerfile)
        self.assertIn("python -m pip check", dockerfile)
        self.assertIn("USER trustcheck", dockerfile)
        self.assertIn('ENTRYPOINT ["trustcheck"]', dockerfile)

        for ignored in (".git", "dist", "build", "tests/_tmp", "**/__pycache__"):
            with self.subTest(ignored=ignored):
                self.assertIn(ignored, dockerignore)

    def test_ci_builds_and_smoke_tests_docker_image(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        docker = _job_block(workflow, "docker-build-smoke-test")

        self.assertIn("needs: qa", docker)
        self.assertIn("packages: write", docker)
        self.assertIn("uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", docker)
        self.assertIn(
            "docker build --build-arg TRUSTCHECK_VERSION=0.0.0+docker -t trustcheck:ci .",
            docker,
        )
        self.assertIn("docker run --rm trustcheck:ci --version", docker)
        self.assertIn("docker run --rm trustcheck:ci --help", docker)
        self.assertIn(
            "github.event_name == 'push' && github.ref == 'refs/heads/main'",
            docker,
        )
        self.assertIn(
            "uses: docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
            docker,
        )
        self.assertIn(
            "uses: docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee",
            docker,
        )
        self.assertIn(
            "uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
            docker,
        )
        self.assertIn("registry: ghcr.io", docker)
        self.assertIn('image="ghcr.io/${GITHUB_REPOSITORY,,}"', docker)
        self.assertIn('echo "${image}:main"', docker)
        self.assertIn('echo "${image}:sha-${GITHUB_SHA}"', docker)
        self.assertIn("push: true", docker)
        self.assertIn("TRUSTCHECK_VERSION=0.0.0+docker", docker)
        self.assertIn("provenance: mode=max", docker)
        self.assertIn("sbom: true", docker)

    def test_release_publishes_multi_platform_docker_images(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        docker = _job_block(workflow, "publish-docker")

        self.assertIn("packages: write", workflow)
        self.assertIn("- coverage-build", docker)
        self.assertIn("- verify-tag", docker)
        self.assertIn(
            "uses: docker/setup-qemu-action@06116385d9baf250c9f4dcb4858b16962ea869c3",
            docker,
        )
        self.assertIn(
            "uses: docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
            docker,
        )
        self.assertIn(
            "uses: docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee",
            docker,
        )
        self.assertIn(
            "uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
            docker,
        )
        self.assertIn("registry: ghcr.io", docker)
        self.assertIn("push: true", docker)
        self.assertIn("platforms: linux/amd64,linux/arm64,linux/arm/v7", docker)
        self.assertIn("TRUSTCHECK_VERSION=${{ github.ref_name }}", docker)
        self.assertIn("provenance: mode=max", docker)
        self.assertIn("sbom: true", docker)
        self.assertIn('echo "${image}:latest"', docker)
        self.assertIn(
            "- GHCR Docker images for `linux/amd64`, `linux/arm64`, and `linux/arm/v7`",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
