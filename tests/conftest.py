"""pytest 共享配置:测试环境关闭限流(单 IP 高频请求会触发 429)。"""

from __future__ import annotations

import os

os.environ.setdefault("FUSION_RATE_LIMIT", "0")
