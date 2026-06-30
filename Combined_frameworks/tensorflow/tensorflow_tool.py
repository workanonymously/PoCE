import os
import subprocess
import sys
from pathlib import Path


IMAGE_NAME = "tensorflow-tool:2.17.0"
DOCKERFILE = "docker/dockerfile.tensorflow-2.17.0"


def docker_image_exists(image_name):
    result = subprocess.run(
        ["docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def run_docker():
    project_root = Path(__file__).resolve().parents[1]
    tensorflow_dir = project_root / "tensorflow"
    dockerfile_path = project_root / DOCKERFILE

    if not docker_image_exists(IMAGE_NAME):
        print(f"Docker image {IMAGE_NAME} not found. Building it now...")
        subprocess.run(
            [
                "docker",
                "build",
                "-f",
                str(dockerfile_path),
                "-t",
                IMAGE_NAME,
                str(project_root),
            ],
            check=True,
        )

    command = [
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
        f"{tensorflow_dir}:/app/Combined_frameworks/tensorflow",
        IMAGE_NAME,
        "--framework",
        "tensorflow",
    ]

    subprocess.run(command, check=True)


def run_inside_docker():
    # tensorflow_runner.py is in the same folder as this launcher.
    from tensorflow_runner import main
    main()


if __name__ == "__main__":
    if os.getenv("IN_DOCKER") == "1":
        run_inside_docker()
    else:
        run_docker()
