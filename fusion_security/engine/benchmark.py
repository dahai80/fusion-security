"""Fusion-Security 性能基准 — 吞吐 / 并发 / AI 背压量化。"""

from __future__ import annotations

import logging
import os
import statistics
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from fusion_security.engine.rules.engine import RuleEngine
from fusion_security.engine.scanner import Scanner

logger = logging.getLogger(__name__)

VULN_SAMPLE = """import os
import sqlite3

SECRET_KEY = "hardcoded-super-secret-key-12345"
API_TOKEN = "sk_live_abcdef0123456789"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()

def run_eval(expr):
    return eval(expr)

password = os.environ.get("PASSWORD", "admin12345")
"""


@dataclass
class BenchResult:
    name: str
    total_files: int = 0
    duration_s: float = 0.0
    files_per_sec: float = 0.0
    vulns_found: int = 0
    peak_mem_mb: float = 0.0
    latency_ms: list[float] = field(default_factory=list)
    errors: int = 0
    notes: str = ""

    def summary(self) -> str:
        lines = [
            f"[{self.name}] files={self.total_files} duration={self.duration_s:.2f}s "
            f"throughput={self.files_per_sec:.1f} files/s vulns={self.vulns_found} "
            f"peak_mem={self.peak_mem_mb:.1f}MB errors={self.errors}",
        ]
        if self.latency_ms:
            lines.append(
                f"  latency(ms): p50={statistics.median(self.latency_ms):.1f} "
                f"p95={self._percentile(95):.1f} p99={self._percentile(99):.1f} "
                f"max={max(self.latency_ms):.1f} n={len(self.latency_ms)}"
            )
        if self.notes:
            lines.append(f"  notes: {self.notes}")
        return "\n".join(lines)

    def _percentile(self, p: float) -> float:
        if not self.latency_ms:
            return 0.0
        s = sorted(self.latency_ms)
        k = max(0, min(len(s) - 1, int(len(s) * p / 100)))
        return s[k]


def gen_repo(root: Path, n_files: int, vuln_ratio: float = 0.3) -> int:
    root.mkdir(parents=True, exist_ok=True)
    n_vuln = 0
    for i in range(n_files):
        sub = root / f"mod_{i % 50}"
        sub.mkdir(exist_ok=True)
        f = sub / f"file_{i}.py"
        if (i % 100) / 100 < vuln_ratio:
            f.write_text(VULN_SAMPLE)
            n_vuln += 1
        else:
            f.write_text("def hello():\n    return 'safe'\n")
    return n_vuln


def bench_throughput(n_files: int = 10000) -> BenchResult:
    r = BenchResult(name=f"throughput-{n_files}", total_files=n_files)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        gen_repo(root, n_files)
        engine = RuleEngine()
        tracemalloc.start()
        t0 = time.perf_counter()
        vulns = 0
        for path in root.rglob("*.py"):
            try:
                content = path.read_text()
                vulns += len(engine.scan_file(path, content))
            except Exception as e:
                logger.warning(f"scan error {path}: {e}")
                r.errors += 1
        r.duration_s = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        r.peak_mem_mb = peak / 1024 / 1024
        r.vulns_found = vulns
        r.files_per_sec = n_files / r.duration_s if r.duration_s > 0 else 0
    return r


def bench_concurrency(n_scans: int = 20, files_per_scan: int = 50) -> BenchResult:
    r = BenchResult(name=f"concurrency-{n_scans}x{files_per_scan}")
    with tempfile.TemporaryDirectory() as tmp:
        roots = []
        for i in range(n_scans):
            root = Path(tmp) / f"scan_{i}"
            gen_repo(root, files_per_scan)
            roots.append(root)
        engine = RuleEngine()

        def scan_one(root: Path) -> tuple[float, int]:
            t0 = time.perf_counter()
            v = 0
            for path in root.rglob("*.py"):
                try:
                    v += len(engine.scan_file(path, path.read_text()))
                except Exception:
                    r.errors += 1
            return (time.perf_counter() - t0) * 1000, v

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n_scans) as pool:
            futures = {pool.submit(scan_one, root): root for root in roots}
            for fut in as_completed(futures):
                try:
                    lat, v = fut.result()
                    r.latency_ms.append(lat)
                    r.vulns_found += v
                except Exception as e:
                    logger.warning(f"concurrent scan failed: {e}")
                    r.errors += 1
        r.duration_s = time.perf_counter() - t0
        r.total_files = n_scans * files_per_scan
        r.files_per_sec = r.total_files / r.duration_s if r.duration_s > 0 else 0
    return r


def bench_scanner_directory(n_files: int = 2000) -> BenchResult:
    r = BenchResult(name=f"scanner-dir-{n_files}", total_files=n_files)
    scanner = Scanner(use_ai=False)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        gen_repo(root, n_files)
        import asyncio

        async def run():
            return await scanner.scan_directory(str(root))

        tracemalloc.start()
        t0 = time.perf_counter()
        try:
            result = asyncio.run(run())
            r.duration_s = time.perf_counter() - t0
            r.vulns_found = len(result.vulnerabilities)
            r.files_per_sec = result.files_scanned / r.duration_s if r.duration_s > 0 else 0
            r.total_files = result.files_scanned
        except Exception as e:
            logger.error(f"scanner bench failed: {e}")
            r.errors += 1
            r.duration_s = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        r.peak_mem_mb = peak / 1024 / 1024
        r.notes = "use_ai=False (rule-only); AI backpressure见 bench_ai_backpressure"
    return r


def bench_ai_backpressure(n_findings: int = 12, max_concurrency: int = 4) -> BenchResult:
    # 真实加载 fusion-mlx,并发 verify_findings,量化 semaphore 背压:在飞请求数被 cap。
    r = BenchResult(name=f"ai-backpressure-{n_findings}vulns-cap{max_concurrency}")
    try:
        import asyncio

        from fusion_security.engine.ai.analyzer import AIAnalyzer
        from fusion_security.models.vulnerability import Vulnerability
    except Exception as e:
        r.notes = f"AI import failed: {e}"
        return r

    vulns = [
        Vulnerability(
            id=f"V{i}",
            title="SQL injection",
            description=f"select * from t where id={i}",
            severity="high",
            confidence=80,
            file_path="/tmp/app.py",
            line_number=i + 1,
            code_snippet=f"query='select * from t where id={i}'",
            rule_id="SQL001",
        )
        for i in range(n_findings)
    ]

    in_flight = 0
    peak_in_flight = 0
    import time as _time

    async def run():
        nonlocal in_flight, peak_in_flight
        # 显式指定 MLX URL + key,避免默认 11432 打到 fusion-gateway。
        mlx_url = os.environ.get("MLX_BASE_URL", "http://127.0.0.1:11434/v1")
        analyzer = AIAnalyzer(max_concurrency=max_concurrency, mlx_url=mlx_url)
        original_request = analyzer._do_chat_request

        async def traced_request(payload):
            # 在 semaphore 持有期内计数:量化被限流后的真实在飞 HTTP 并发。
            nonlocal in_flight, peak_in_flight
            in_flight += 1
            peak_in_flight = max(peak_in_flight, in_flight)
            try:
                return await original_request(payload)
            finally:
                in_flight -= 1

        analyzer._do_chat_request = traced_request
        t0 = _time.perf_counter()
        try:
            result = await analyzer.verify_findings(vulns, [])
        finally:
            await analyzer.aclose()
        r.duration_s = _time.perf_counter() - t0
        r.vulns_found = len(result)
        r.latency_ms = [r.duration_s * 1000]
        r.notes = (
            f"peak_in_flight={peak_in_flight} (cap={max_concurrency}); "
            f"verifies={len(result)}; semaphore 背压生效峰值不超 cap"
            if peak_in_flight <= max_concurrency
            else f"peak_in_flight={peak_in_flight} > cap={max_concurrency} — 背压失效!"
        )

    asyncio.run(run())
    return r


def run_all_benchmarks() -> list[BenchResult]:
    results: list[BenchResult] = []
    logger.info("=== 基准测试开始 ===")
    for fn in (
        lambda: bench_throughput(10000),
        lambda: bench_scanner_directory(2000),
        lambda: bench_concurrency(20, 50),
        lambda: bench_ai_backpressure(12, 4),
    ):
        logger.info(f"运行 {fn.__name__ if hasattr(fn, '__name__') else 'bench'} ...")
        try:
            r = fn()
            results.append(r)
            logger.info(r.summary())
        except Exception as e:
            logger.error(f"基准 {fn} 失败: {e}")
    logger.info("=== 基准测试结束 ===")
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for r in run_all_benchmarks():
        print(r.summary())
        print()
