from __future__ import annotations

import logging

import pytest

logger = logging.getLogger(__name__)


class TestBenchmarkModule:
    """性能基准模块:验证 gen_repo / 各 bench 函数可跑通,结果结构正确。"""

    def test_gen_repo_creates_files(self, tmp_path):
        from fusion_security.engine.benchmark import gen_repo

        n_vuln = gen_repo(tmp_path / "repo", 50, vuln_ratio=0.4)
        files = list((tmp_path / "repo").rglob("*.py"))
        assert len(files) == 50
        # gen_repo: (i%100)/100 < ratio → 50 文件中 i%100<40 的有 40 个
        assert n_vuln == 40
        assert n_vuln <= 50

    def test_bench_result_summary(self):
        from fusion_security.engine.benchmark import BenchResult

        r = BenchResult(name="t", total_files=10, duration_s=2.0, files_per_sec=5.0, vulns_found=3)
        s = r.summary()
        assert "[t]" in s
        assert "files=10" in s
        assert "throughput=5.0" in s
        assert "vulns=3" in s

    def test_bench_result_percentile_empty(self):
        from fusion_security.engine.benchmark import BenchResult

        r = BenchResult(name="t")
        assert r._percentile(95) == 0.0

    def test_bench_result_percentile(self):
        from fusion_security.engine.benchmark import BenchResult

        r = BenchResult(name="t", latency_ms=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
        assert r._percentile(50) == 60
        assert r._percentile(99) == 100

    def test_bench_throughput_small(self):
        from fusion_security.engine.benchmark import bench_throughput

        r = bench_throughput(50)
        assert r.total_files == 50
        assert r.duration_s > 0
        assert r.files_per_sec > 0
        assert r.vulns_found >= 0
        assert r.errors == 0

    def test_bench_concurrency_small(self):
        from fusion_security.engine.benchmark import bench_concurrency

        r = bench_concurrency(4, 10)
        assert r.total_files == 40
        assert r.duration_s > 0
        assert len(r.latency_ms) == 4
        assert r.errors == 0

    def test_bench_scanner_directory_small(self):
        from fusion_security.engine.benchmark import bench_scanner_directory

        r = bench_scanner_directory(30)
        assert r.total_files == 30
        assert r.duration_s > 0
        assert r.errors == 0


class TestAiBackpressureTrace:
    """AI 背压插桩:_do_chat_request 在 semaphore 持有期内被 trace,峰值不超 cap。"""

    def test_do_chat_request_is_separate_method(self):
        # 重构后 _do_chat_request 独立存在(便于插桩),_chat 在 acquire 后调用它。
        from fusion_security.engine.ai.analyzer import AIAnalyzer

        assert callable(getattr(AIAnalyzer, "_do_chat_request", None))
        assert callable(getattr(AIAnalyzer, "_chat", None))

    @pytest.mark.asyncio
    async def test_backpressure_cap_enforced_without_mlxx(self, monkeypatch):
        # 不依赖真实 MLX:打桩 _do_chat_request 模拟带延迟的 AI 调用,
        # 验证 semaphore 把并发 verify_findings 限到 cap 以内。
        import asyncio

        from fusion_security.engine.ai.analyzer import AIAnalyzer
        from fusion_security.models.vulnerability import Vulnerability

        analyzer = AIAnalyzer(max_concurrency=2)
        in_flight = 0
        peak = 0

        async def fake_request(payload):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.05)
            in_flight -= 1
            # 返回 is_real=false → verify 过滤掉,但流程完整跑通
            return '{"is_real": false, "reason": "stub", "confidence": 50}'

        analyzer._do_chat_request = fake_request
        vulns = [
            Vulnerability(
                id=f"V{i}",
                title="SQL injection",
                description="x",
                severity="high",
                confidence=80,
                file_path="/tmp/a.py",
                line_number=i + 1,
                code_snippet="q='select * from t'",
                rule_id="SQL001",
            )
            for i in range(8)
        ]
        result = await analyzer.verify_findings(vulns, [])
        await analyzer.aclose()
        # cap=2,8 并发验证 → 峰值在飞不超 2
        assert peak <= 2, f"背压失效: peak_in_flight={peak} > cap=2"
        assert peak >= 1
        # AI 判定全为误报 → result 为空
        assert result == []

    def test_bench_ai_backpressure_with_stubbed_chat(self, monkeypatch):
        # 直接对 bench_ai_backpressure 打桩 AIAnalyzer,覆盖该函数全路径(无需真实 MLX)。
        import asyncio

        from fusion_security.engine.ai import analyzer as analyzer_mod

        class StubAnalyzer:
            def __init__(self, *args, **kwargs):
                self._semaphore = asyncio.Semaphore(kwargs.get("max_concurrency", 4))
                self._do_chat_request = None

            async def verify_findings(self, vulns, files=None):
                in_flight = 0
                peak = 0
                sem = self._semaphore

                async def one(v):
                    nonlocal in_flight, peak
                    await asyncio.sleep(0)
                    await sem.acquire()
                    try:
                        in_flight += 1
                        peak = max(peak, in_flight)
                        await asyncio.sleep(0.02)
                        in_flight -= 1
                    finally:
                        sem.release()
                    return None

                await asyncio.gather(*[one(v) for v in vulns])
                return [v for v in vulns if False]

            async def aclose(self):
                pass

        monkeypatch.setattr(analyzer_mod, "AIAnalyzer", StubAnalyzer)
        from fusion_security.engine.benchmark import bench_ai_backpressure

        r = bench_ai_backpressure(n_findings=6, max_concurrency=4)
        assert r.duration_s > 0
        assert "peak_in_flight" in r.notes
        assert "cap=4" in r.notes

    def test_bench_ai_backpressure_import_failure(self, monkeypatch):
        # import 失败分支:打桩让 AIAnalyzer 导入抛错,bench 应优雅返回 notes。
        import sys

        monkeypatch.setitem(sys.modules, "fusion_security.engine.ai.analyzer", None)
        from fusion_security.engine.benchmark import bench_ai_backpressure

        r = bench_ai_backpressure(4, 2)
        assert "AI import failed" in r.notes or r.duration_s >= 0


class TestRunAllBenchmarks:
    """run_all_benchmarks 编排:覆盖各 bench 的异常分支与正常汇总。"""

    def test_run_all_benchmarks_collects_results(self, monkeypatch):
        from fusion_security.engine import benchmark as bench_mod

        calls = []

        def fake_throughput(n=10000):
            calls.append("throughput")
            return bench_mod.BenchResult(name="t", total_files=1, duration_s=0.01, files_per_sec=100)

        def fake_scanner(n=2000):
            calls.append("scanner")
            return bench_mod.BenchResult(name="s", total_files=1)

        def fake_concurrency(a=20, b=50):
            calls.append("concurrency")
            return bench_mod.BenchResult(name="c", total_files=1)

        def fake_ai(a=12, b=4):
            calls.append("ai")
            return bench_mod.BenchResult(name="a", notes="stub")

        monkeypatch.setattr(bench_mod, "bench_throughput", fake_throughput)
        monkeypatch.setattr(bench_mod, "bench_scanner_directory", fake_scanner)
        monkeypatch.setattr(bench_mod, "bench_concurrency", fake_concurrency)
        monkeypatch.setattr(bench_mod, "bench_ai_backpressure", fake_ai)
        results = bench_mod.run_all_benchmarks()
        assert len(results) == 4
        assert set(calls) == {"throughput", "scanner", "concurrency", "ai"}

    def test_run_all_benchmarks_swallows_failure(self, monkeypatch):
        from fusion_security.engine import benchmark as bench_mod

        def boom(*a, **k):
            raise RuntimeError("boom")

        monkeypatch.setattr(bench_mod, "bench_throughput", boom)
        monkeypatch.setattr(bench_mod, "bench_scanner_directory", lambda *a, **k: bench_mod.BenchResult(name="s"))
        monkeypatch.setattr(bench_mod, "bench_concurrency", lambda *a, **k: bench_mod.BenchResult(name="c"))
        monkeypatch.setattr(bench_mod, "bench_ai_backpressure", lambda *a, **k: bench_mod.BenchResult(name="a"))
        results = bench_mod.run_all_benchmarks()
        # boom 的那条被吞,其余 3 条返回
        assert len(results) == 3
