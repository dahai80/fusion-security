import time

from fusion_security.engine.resume import (
    CheckpointManager,
    CircuitBreaker,
    CircuitState,
    RetryPolicy,
    StageCheckpoint,
)


class TestStageCheckpoint:
    def test_to_dict_roundtrip(self):
        cp = StageCheckpoint(scan_id="s1", project_path="/tmp", completed_stage="discover")
        d = cp.to_dict()
        assert d["scan_id"] == "s1"
        cp2 = StageCheckpoint.from_dict(d)
        assert cp2.scan_id == "s1"
        assert cp2.completed_stage == "discover"

    def test_from_dict_ignores_extra_keys(self):
        cp = StageCheckpoint.from_dict({"scan_id": "s2", "bogus": True})
        assert cp.scan_id == "s2"


class TestCheckpointManager:
    def test_save_and_load(self, tmp_path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "cp"))
        cp = StageCheckpoint(scan_id="ck1", project_path="/p", completed_stage="recon")
        mgr.save(cp)
        loaded = mgr.load("ck1")
        assert loaded is not None
        assert loaded.scan_id == "ck1"

    def test_load_nonexistent(self, tmp_path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "cp"))
        assert mgr.load("nope") is None

    def test_remove(self, tmp_path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "cp"))
        cp = StageCheckpoint(scan_id="ck2", completed_stage="discover")
        mgr.save(cp)
        assert mgr.remove("ck2") is True
        assert mgr.load("ck2") is None

    def test_list_checkpoints(self, tmp_path):
        mgr = CheckpointManager(checkpoint_dir=str(tmp_path / "cp"))
        mgr.save(StageCheckpoint(scan_id="a1", completed_stage="recon"))
        mgr.save(StageCheckpoint(scan_id="a2", completed_stage="verify"))
        cps = mgr.list_checkpoints()
        ids = {c.scan_id for c in cps}
        assert ids == {"a1", "a2"}


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_half_open_after_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_success_closes_from_half_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_failure_in_half_open_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED


class TestRetryPolicy:
    def test_delay_increases(self):
        rp = RetryPolicy(base_delay=1.0, exponential_base=2.0, max_delay=30.0)
        assert rp.get_delay(0) == 1.0
        assert rp.get_delay(1) == 2.0
        assert rp.get_delay(2) == 4.0

    def test_delay_capped(self):
        rp = RetryPolicy(base_delay=1.0, exponential_base=10.0, max_delay=30.0)
        assert rp.get_delay(5) == 30.0
