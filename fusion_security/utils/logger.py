"""Fusion-Security 日志工具。"""

from __future__ import annotations

import logging
import re
import sys

logger = logging.getLogger(__name__)

# 密钥类键名常见写法：password / secret / token / api_key / authorization / credential / private_key 等。
_SECRET_KEY = (
    r"(?i)(password|passwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|refresh[_-]?token|auth[_-]?token|"
    r"authorization|credential|bearer)\s*[:=]\s*"
)
# 键值对：键后跟引号或裸值。命中后只保留键与分隔符，值替换为 [REDACTED]。
_KV_PATTERN = re.compile(_SECRET_KEY + r"[\"']?[A-Za-z0-9_\-\.:/+=~$&%#@!]+")
# Bearer 头：Authorization: Bearer xxx 或裸 Bearer xxx。
_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=:/+]+")
# 长十六进制/Base64 串（>=32 字符，常见 API token / JWT / sha256），仅在 secret 上下文附近才误伤小。
# 单独长串误伤概率高（文件哈希、commit sha），故不全局匹配，仅靠 KV/Bearer 模式覆盖。
_REDACTED = "[REDACTED]"


class SecretRedactingFilter(logging.Filter):
    """日志过滤器：脱敏密钥类键值对与 Bearer 令牌，防止凭证落盘到 stdout/日志文件。"""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception as e:
            logger.debug(f"日志脱敏取消息失败, 原样放行: {e}")
            return True
        # 先脱敏 Bearer 令牌（避免 KV 模式先吃掉 "Bearer" 单词导致令牌残留），再脱敏键值对。
        redacted = _BEARER_PATTERN.sub("Bearer " + _REDACTED, msg)
        redacted = _KV_PATTERN.sub(_REDACTED, redacted)
        if redacted != msg:
            # 已完成格式化，固定 msg 并清空 args，避免再次 % 插值报错。
            record.msg = redacted
            record.args = None
        return True


def setup_logger(name: str = "fusion_security", level: int = logging.INFO, verbose: bool = False):
    root_logger = logging.getLogger(name)
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    fmt = "[%(asctime)s] %(levelname)-8s %(message)s" if verbose else "%(levelname)-8s %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    handler.addFilter(SecretRedactingFilter())
    root_logger.addHandler(handler)
    return root_logger
