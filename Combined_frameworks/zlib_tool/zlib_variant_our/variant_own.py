import os
import subprocess
import sys
from pathlib import Path

IMAGE_NAME = "zlib-variant-tool:latest"
DOCKERFILE = "docker/dockerfile.zlib-variant"


def docker_image_exists(image_name):
    result = subprocess.run(
        ["docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def run_docker():
    project_root = Path(__file__).resolve().parents[2]

    if not docker_image_exists(IMAGE_NAME):
        print(f"Docker image {IMAGE_NAME} not found. Building it now...")
        subprocess.run(
            [
                "docker",
                "build",
                "-f",
                str(project_root / DOCKERFILE),
                "-t",
                IMAGE_NAME,
                str(project_root),
            ],
            check=True,
        )

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-e",
            "IN_DOCKER=1",
            "-e",
            "OLLAMA_URL=http://localhost:12543/api/generate",
            "-v",
            f"{project_root}:/app/Combined_frameworks",
            IMAGE_NAME,
            "--variant",
            "zlib_variant",
        ],
        check=True,
    )


def run_inside_docker():
    project_root = Path(__file__).resolve().parents[2]
    variant_dir = project_root / "zlib" / "zlib_variant_our"
    runner = variant_dir / "variant_zlib.py"

    env = os.environ.copy()
    env["PYTHONPATH"] = (
        f"{variant_dir}:"
        f"{project_root}:"
        f"/app:"
        f"/app/Combined_frameworks:"
        f"{env.get('PYTHONPATH', '')}"
    )

    subprocess.run(
        [sys.executable, str(runner)],
        cwd=str(variant_dir),
        env=env,
        check=True,
    )


if __name__ == "__main__":
    if os.getenv("IN_DOCKER") == "1":
        run_inside_docker()
    else:
        run_docker()
