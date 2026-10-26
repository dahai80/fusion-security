"""README 测试数漂移守卫(Issue #43)。

CI 步骤:收集真实用例数,与 README.md / README_CN.md 徽章里的数字比对,
漂移超过 10% 即失败 —— 防止文档再次虚报测试规模。

本地重生成真实计数:
    pytest --collect-only -q | tail -1
"""

import re
import subprocess
import sys
from pathlib import Path

# 允许漂移阈值(比例),新用例增长或删减在阈值内不阻塞 CI。
DRIFT_TOLERANCE = 0.10
REPO_ROOT = Path(__file__).resolve().parent.parent
BADGE_PATTERNS = {
    "README.md": r"tests-(\d+)%20passed",
    "README_CN.md": r"测试-(\d+)%20通过",
}


def collect_actual_count() -> int:
    result = subprocess.run(
        ["pytest", "--collect-only", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    output = result.stdout + result.stderr
    match = re.search(r"(\d+) tests? collected", output)
    if not match:
        print(f"[check-test-count] 无法从 pytest 输出解析用例数:\n{output[-500:]}", file=sys.stderr)
        return -1
    return int(match.group(1))


def read_badge_count(readme: str, pattern: str) -> int:
    path = REPO_ROOT / readme
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if not match:
        print(f"[check-test-count] {readme} 未找到测试数徽章(模式 {pattern})", file=sys.stderr)
        return -1
    return int(match.group(1))


def main() -> int:
    actual = collect_actual_count()
    if actual < 0:
        return 1
    failed = False
    for readme, pattern in BADGE_PATTERNS.items():
        claimed = read_badge_count(readme, pattern)
        if claimed < 0:
            failed = True
            continue
        drift = abs(claimed - actual) / actual
        status = "ok" if drift <= DRIFT_TOLERANCE else "DRIFT"
        print(f"[check-test-count] {readme}: badge={claimed} actual={actual} drift={drift:.1%} {status}")
        if drift > DRIFT_TOLERANCE:
            print(
                f"[check-test-count] {readme} 测试数漂移超 {DRIFT_TOLERANCE:.0%} —— "
                f"运行 `pytest --collect-only -q | tail -1` 后更新徽章数字",
                file=sys.stderr,
            )
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
