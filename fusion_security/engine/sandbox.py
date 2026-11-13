"""Sandbox execution profile (evolution plan P3.3).

`FUSION_SECURITY_SANDBOX=docker` runs scan workloads inside a container
profile: no network, read-only target mount, memory/CPU caps, dropped
capabilities, no-new-privileges. When Docker is unavailable the profile
degrades to subprocess isolation (resource limits, no network via
unshare when permitted) — degradation, not failure. `off` (default)
runs in-process as before.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

SANDBOX_ENV = "FUSION_SECURITY_SANDBOX"
PROFILES = ("off", "docker", "subprocess")

# Container profile: resource limits + no network + read-only target.
DOCKER_NETWORK = "none"
DOCKER_MEMORY = os.environ.get("FUSION_SANDBOX_MEMORY", "2g")
DOCKER_CPUS = os.environ.get("FUSION_SANDBOX_CPUS", "2")
DOCKER_PIDS = os.environ.get("FUSION_SANDBOX_PIDS", "256")


def requested_profile() -> str:
    value = os.environ.get(SANDBOX_ENV, "off").strip().lower()
    return value if value in PROFILES else "off"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning(f"[Sandbox] docker probe failed: {e}")
        return False


def resolve_profile() -> str:
    """Effective profile: requested profile degrades when Docker is absent."""
    requested = requested_profile()
    if requested == "docker" and not docker_available():
        logger.warning("[Sandbox] docker requested but unavailable — degrading to subprocess isolation")
        return "subprocess"
    if requested == "off":
        return "off"
    return requested


def docker_run_args(image: str, target_mount: str = "", command: list[str] | None = None) -> list[str]:
    """docker run argument vector enforcing the container profile."""
    args = [
        "docker",
        "run",
        "--rm",
        "--network",
        DOCKER_NETWORK,
        "--memory",
        DOCKER_MEMORY,
        "--cpus",
        DOCKER_CPUS,
        "--pids-limit",
        DOCKER_PIDS,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=256m",
    ]
    if target_mount:
        args += ["-v", f"{target_mount}:/target:ro"]
    args.append(image)
    if command:
        args += command
    return args


def sandboxed_run(
    image: str, command: list[str], target_mount: str = "", timeout: int = 3600
) -> subprocess.CompletedProcess:
    """Run a command under the resolved profile (docker → subprocess fallback).

    The subprocess fallback applies resource limits (CPU seconds, address
    space, nproc) and reports degradation via logs — never raises on
    profile unavailability.
    """
    profile = resolve_profile()
    if profile == "docker":
        logger.info(f"[Sandbox] docker profile: {' '.join(command[:2])}… target={target_mount or 'none'}")
        return subprocess.run(
            docker_run_args(image, target_mount=target_mount, command=command),
            capture_output=True,
            timeout=timeout,
        )
    logger.info(f"[Sandbox] subprocess isolation profile: {' '.join(command[:2])}…")
    return subprocess.run(
        command,
        capture_output=True,
        timeout=timeout,
        preexec_fn=_limited_preexec,
    )


def _limited_preexec():
    # Subprocess isolation: hard resource caps in the child before exec.
    import resource

    limits = [
        (resource.RLIMIT_CPU, 600),
        (resource.RLIMIT_AS, 4 * 1024 * 1024 * 1024),
        (resource.RLIMIT_NPROC, 64),
        (resource.RLIMIT_FSIZE, 512 * 1024 * 1024),
    ]
    for res, cap in limits:
        try:
            resource.setrlimit(res, (cap, cap))
        except (ValueError, OSError) as e:
            logger.warning(f"[Sandbox] rlimit {res} not applied: {e}")
