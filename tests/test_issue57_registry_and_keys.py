"""Issue #57 acceptance tests: start.sh port-registry self-check + legacy key-name cleanup."""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
START_SH = REPO_ROOT / "start.sh"

REGISTRY_TEMPLATE = """services:
  fusion-security:
    host: 127.0.0.1
    port: {security_port}
  fusion-mlx:
    host: 127.0.0.1
    port: {mlx_port}
"""

LEGACY_KEY_NAMES = ("FUSION_MLX_API_KEY", "FUSION_API_KEY", "MLX_API_KEY", "FUSION_GATEWAY_ADMIN_KEY")


def _run_check(registry: Path, port: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = {
        "FUSION_SECURITY_PORT": port,
        "FUSION_REGISTRY": str(registry),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(registry.parent),
    }
    if extra_env:
        env.update(extra_env)
    logger.debug(f"[test] run check_port_registry port={port} registry={registry} extra={extra_env}")
    return subprocess.run(
        ["bash", "-c", f"source '{START_SH}'; check_port_registry"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class TestPortRegistryCheck:
    def test_refuses_unregistered_port(self, tmp_path):
        registry = tmp_path / "port-registry.yaml"
        registry.write_text(REGISTRY_TEMPLATE.format(security_port=11454, mlx_port=11434))
        r = _run_check(registry, "19999")
        assert r.returncode == 1, f"expected refusal, got rc={r.returncode} stderr={r.stderr}"
        assert "refusing to start" in r.stderr

    def test_passes_registered_port(self, tmp_path):
        registry = tmp_path / "port-registry.yaml"
        registry.write_text(REGISTRY_TEMPLATE.format(security_port=11454, mlx_port=11434))
        r = _run_check(registry, "11454")
        assert r.returncode == 0, f"expected pass, got rc={r.returncode} stderr={r.stderr}"
        assert "refusing" not in r.stderr

    def test_skip_env_bypasses(self, tmp_path):
        registry = tmp_path / "port-registry.yaml"
        registry.write_text(REGISTRY_TEMPLATE.format(security_port=11454, mlx_port=11434))
        r = _run_check(registry, "19999", extra_env={"FUSION_SKIP_REGISTRY_CHECK": "1"})
        assert r.returncode == 0, f"expected bypass, got rc={r.returncode} stderr={r.stderr}"
        assert "bypassed" in r.stderr

    def test_missing_registry_file_warns_and_continues(self, tmp_path):
        registry = tmp_path / "nonexistent-registry.yaml"
        r = _run_check(registry, "11454")
        assert r.returncode == 0, f"expected warn+continue, got rc={r.returncode} stderr={r.stderr}"
        assert "self-check skipped" in r.stderr

    def test_other_service_same_port_still_refuses(self, tmp_path):
        # 端口被别的服务占用登记不能蒙混过关:grep -A3 限定在 fusion-security 块内。
        registry = tmp_path / "port-registry.yaml"
        registry.write_text(REGISTRY_TEMPLATE.format(security_port=11454, mlx_port=19999))
        r = _run_check(registry, "19999")
        assert r.returncode == 1, f"expected refusal (port owned by fusion-mlx), rc={r.returncode}"
        assert "refusing to start" in r.stderr


class TestLegacyKeyNames:
    def test_no_legacy_key_names_in_source(self):
        hits = []
        targets = list((REPO_ROOT / "fusion_security").rglob("*.py")) + [START_SH]
        for p in targets:
            text = p.read_text(encoding="utf-8")
            for name in LEGACY_KEY_NAMES:
                if name in text:
                    hits.append(f"{p.relative_to(REPO_ROOT)}: {name}")
        logger.debug(f"[test] legacy key-name scan hits: {hits}")
        assert not hits, f"legacy key names remain (scripts/check-env.py rule 2c): {hits}"

    def test_shell_registry_admin_key_env_is_canonical(self):
        from fusion_security import shell_registry

        assert shell_registry.ADMIN_KEY_ENV == "FUSION_ADMIN_KEY"
