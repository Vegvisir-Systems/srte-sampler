#!/usr/bin/env python3

import shutil
import subprocess
import sys
from pathlib import Path

# =========================
# Configuration
# =========================

# Sampler
STAGING_DIR = Path("/home/dima/staging/sampler_staging")
CERTS_DIR = Path("/home/dima/staging/sampler_staging/certs")
TECH_SUPPORT_DIR = Path("/home/dima/staging/sampler_staging/tech-support")
SAMPLER_CORE_ROOT = Path("/home/dima/srte-bw-sampler").resolve()
# Docker
DOCKER_BUILD_ROOT = Path("/home/dima/staging").resolve()
DOCKER_IMAGE_NAME = "srte-sampler"
DOCKER_IMAGE_VERSION = "0.1"


COPY_TARGETS = [
    "bgp",
    "config_manager",
    "http_api",
    "sampler",
    "historic_show_tech.py",
    "cli.py",
    "srte-bw-sampler.py"
]


# =========================
# Helpers
# =========================

def log(message):
    print(f"[sampler_builder] {message}")

def run_command(command, cwd=None):
    log(f"Running: {' '.join(command)}")
    result = subprocess.run(
        command,
        cwd=cwd,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(command)}")

# =========================
# Pipeline steps
# =========================

def run_tests():
    """
    Placeholder for tests.
    Later you can add pytest, unit tests, etc.
    """
    log("Skipping tests (not implemented yet)")
    # Example for later:
    # run_command(["pytest", "tests"])


def prepare_sampler_staging():
    log(f"Preparing staging directory: {STAGING_DIR}")

    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)

    STAGING_DIR.mkdir()
    CERTS_DIR.mkdir()
    TECH_SUPPORT_DIR.mkdir()



    for target in COPY_TARGETS:
        src = SAMPLER_CORE_ROOT / target
        dest = STAGING_DIR / target

        if not src.exists():
            raise FileNotFoundError(f"Missing source: {src}")

        if src.is_dir():
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)

        log(f"Copied {src} → {dest}")



def build_docker_image():
    log("Building Docker image")

    if not DOCKER_BUILD_ROOT.exists():
        raise FileNotFoundError(
            f"Docker build root not found: {DOCKER_BUILD_ROOT}"
        )

    image_tag = f"{DOCKER_IMAGE_NAME}:{DOCKER_IMAGE_VERSION}"

    run_command(
        ["docker", "build", "-t", image_tag, "."],
        cwd=DOCKER_BUILD_ROOT
    )

    log(f"Docker image built successfully: {image_tag}")


def export_docker_image():
    log("Exporting Docker image")

    image_tag = f"{DOCKER_IMAGE_NAME}:{DOCKER_IMAGE_VERSION}"
    tar_path = DOCKER_BUILD_ROOT / f"{DOCKER_IMAGE_NAME}-{DOCKER_IMAGE_VERSION}.tar"

    run_command(
        ["docker", "save", "-o", str(tar_path), image_tag]
    )

    run_command(
        ["gzip", "-f", str(tar_path)]
    )

    log(f"Docker image exported: {tar_path}.gz")


def main():
    try:
        run_tests()
        prepare_sampler_staging()
        build_docker_image()
        export_docker_image()
        log("Pipeline completed successfully\n")
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
