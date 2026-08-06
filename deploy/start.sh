#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
    echo "Usage: $0 {start|stop|status|logs}"
    exit 1
}

check_docker() {
    if ! command -v docker &>/dev/null; then
        echo "Error: docker not found"
        exit 1
    fi
    if ! docker info &>/dev/null; then
        echo "Error: docker daemon not running"
        exit 1
    fi
}

case "${1:-}" in
    start)
        check_docker
        echo "Starting Fusion-Security..."
        docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d --build
        echo "Waiting for services to be healthy..."
        sleep 5
        echo "Fusion-Security API: http://localhost:11454"
        echo "Fusion-MLX API: http://localhost:11432"
        ;;
    stop)
        check_docker
        echo "Stopping Fusion-Security..."
        docker compose -f "$PROJECT_DIR/docker-compose.yml" down
        echo "Stopped."
        ;;
    status)
        check_docker
        docker compose -f "$PROJECT_DIR/docker-compose.yml" ps
        ;;
    logs)
        check_docker
        docker compose -f "$PROJECT_DIR/docker-compose.yml" logs -f --tail=100
        ;;
    *)
        usage
        ;;
esac
