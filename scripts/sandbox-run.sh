#!/usr/bin/env bash
# Sandbox launcher (evolution plan P3.3): runs the full scan pipeline inside
# the FUSION_SECURITY_SANDBOX=docker container profile (no network, read-only
# target mount, resource caps). Degrades to subprocess isolation with
# resource limits when Docker is unavailable — degradation, not failure.
#
# Usage: scripts/sandbox-run.sh <target-dir> [extra scan args...]
set -euo pipefail

TARGET_DIR="${1:?usage: sandbox-run.sh <target-dir> [extra scan args...]}"
shift
IMAGE="${FUSION_SANDBOX_IMAGE:-fusion-security:sandbox}"

if command -v docker >/dev/null 2>&1 && docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
    echo "[sandbox-run] profile=docker network=none target-mount=ro"
    exec docker run --rm \
        --network none \
        --memory "${FUSION_SANDBOX_MEMORY:-2g}" \
        --cpus "${FUSION_SANDBOX_CPUS:-2}" \
        --pids-limit "${FUSION_SANDBOX_PIDS:-256}" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --read-only \
        --tmpfs /tmp:rw,size=256m \
        -v "$(cd "$TARGET_DIR" && pwd):/target:ro" \
        "$IMAGE" \
        fusion-security scan /target --no-ai "$@"
else
    echo "[sandbox-run] docker unavailable — degrading to subprocess isolation" >&2
    export FUSION_SECURITY_SANDBOX=subprocess
    (
        ulimit -t 600 2>/dev/null || true
        ulimit -v 4194304 2>/dev/null || true
        exec fusion-security scan "$TARGET_DIR" --no-ai "$@"
    )
fi
