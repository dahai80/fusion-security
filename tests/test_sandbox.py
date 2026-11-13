"""Tests for P3.3 sandbox execution profile (args, resolution, degradation)."""

from __future__ import annotations

from unittest.mock import patch

from fusion_security.engine.sandbox import (
    PROFILES,
    docker_available,
    docker_run_args,
    requested_profile,
    resolve_profile,
    sandboxed_run,
)


class TestProfileResolution:
    def test_default_off(self, monkeypatch):
        monkeypatch.delenv("FUSION_SECURITY_SANDBOX", raising=False)
        assert requested_profile() == "off"
        assert resolve_profile() == "off"

    def test_unknown_value_falls_to_off(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "nsjail")
        assert requested_profile() == "off"

    def test_subprocess_profile_respected(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "subprocess")
        assert resolve_profile() == "subprocess"

    def test_docker_degrades_when_unavailable(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "docker")
        with patch("fusion_security.engine.sandbox.docker_available", return_value=False):
            assert resolve_profile() == "subprocess"

    def test_docker_profile_when_available(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "docker")
        with patch("fusion_security.engine.sandbox.docker_available", return_value=True):
            assert resolve_profile() == "docker"

    def test_profiles_enum(self):
        assert PROFILES == ("off", "docker", "subprocess")


class TestDockerArgs:
    def test_args_enforce_profile(self):
        args = docker_run_args("img", "/data", ["scan", "/target"])
        joined = " ".join(args)
        assert "--network none" in joined
        assert "--memory" in joined
        assert "--cpus" in joined
        assert "--pids-limit" in joined
        assert "--cap-drop ALL" in joined
        assert "--security-opt no-new-privileges" in joined
        assert "--read-only" in joined
        assert "/data:/target:ro" in joined
        assert args[-2:] == ["scan", "/target"]

    def test_args_without_mount(self):
        args = docker_run_args("img")
        assert not any("/target:ro" in a for a in args)


class TestSandboxedRun:
    def test_subprocess_fallback_runs_command(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "subprocess")
        result = sandboxed_run("img", ["python3", "-c", "print('ok')"])
        assert result.returncode == 0
        assert "ok" in result.stdout.decode()

    def test_docker_mode_without_docker_degrades_not_raises(self, monkeypatch):
        monkeypatch.setenv("FUSION_SECURITY_SANDBOX", "docker")
        with patch("fusion_security.engine.sandbox.docker_available", return_value=False):
            result = sandboxed_run("img", ["python3", "-c", "print('fallback')"])
        assert result.returncode == 0
        assert "fallback" in result.stdout.decode()

    def test_docker_available_probe_handles_missing_binary(self, monkeypatch):
        monkeypatch.setenv("PATH", "")
        assert docker_available() is False
