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

        self.assertIn("FROM python:${PYTHON_VERSION}-slim AS build", dockerfile)
        self.assertIn("ARG TRUSTCHECK_VERSION=0.0.0+docker", dockerfile)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION=${TRUSTCHECK_VERSION}", dockerfile)
        self.assertIn("build-essential", dockerfile)
        self.assertIn("cargo", dockerfile)
        self.assertIn("python -m pip wheel --wheel-dir /wheels .", dockerfile)
        self.assertIn(
            "python -m pip install --no-index --find-links=/tmp/trustcheck trustcheck",
            dockerfile,
        )
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
        self.assertIn("uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10", docker)
        self.assertIn(
            "docker build --build-arg TRUSTCHECK_VERSION=0.0.0+docker -t trustcheck:ci .",
            docker,
        )
        self.assertIn("docker run --rm trustcheck:ci --version", docker)
        self.assertIn("docker run --rm trustcheck:ci --help", docker)

    def test_release_publishes_multi_platform_docker_images(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        docker = _job_block(workflow, "publish-docker")

        self.assertIn("packages: write", workflow)
        self.assertIn("- coverage-build", docker)
        self.assertIn("- verify-tag", docker)
        self.assertIn(
            "uses: docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
            docker,
        )
        self.assertIn(
            "uses: docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            docker,
        )
        self.assertIn(
            "uses: docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
            docker,
        )
        self.assertIn(
            "uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
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
