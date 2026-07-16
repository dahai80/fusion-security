"""Fusion-Security 日志工具。"""

import logging
import sys


def setup_logger(name: str = "fusion_security", level: int = logging.INFO, verbose: bool = False):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    fmt = "[%(asctime)s] %(levelname)-8s %(message)s" if verbose else "%(levelname)-8s %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger