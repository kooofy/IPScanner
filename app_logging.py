# -*- coding: utf-8 -*-
"""统一日志模块（P1-6）。

背景
----
项目此前**完全没有 logging**：113 处 `except Exception`、44 处静默 `pass`，
出问题时只能靠用户口述与零散的 `sys.stderr.write`，无法定位。

约定
----
- 日志文件写到 ``app_paths.data_dir()/ipscanner.log``（冻结态自动落到可写目录，
  不会因为装在 Program Files 而写失败）。
- 轮转：单文件 1 MB × 3 个备份，长期运行不会撑爆磁盘。
- 控制台输出仅在**开发态**或显式开启时启用，避免 GUI 版弹出黑框。
- 全项目统一用 ``get_logger(__name__)``；不要再新增 ``print`` /
  ``sys.stderr.write`` 来输出诊断信息。

用法
----
    from app_logging import get_logger
    log = get_logger(__name__)
    ...
    except Exception as e:
        log.debug("解析失败，已跳过: %s", e)      # 预期内的失败 → debug
        log.warning("写入配置失败: %s", e)        # 影响功能 → warning
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_LOGGER_NAME = "ipscanner"
_configured = False

LOG_FILENAME = "ipscanner.log"
_MAX_BYTES = 1024 * 1024        # 1 MB
_BACKUP_COUNT = 3
_FMT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"


def log_path() -> str:
    """当前日志文件路径（尽力而为，取不到数据目录时退回 CWD）。"""
    try:
        from app_paths import data_dir
        return os.path.join(data_dir(), LOG_FILENAME)
    except Exception:
        return os.path.join(os.getcwd(), LOG_FILENAME)


def _is_frozen() -> bool:
    try:
        from app_paths import is_frozen
        return is_frozen()
    except Exception:
        return bool(getattr(sys, "frozen", False))


def setup(level=None, console=None) -> logging.Logger:
    """初始化根 logger（幂等，重复调用直接返回）。"""
    global _configured
    root = logging.getLogger(_LOGGER_NAME)
    if _configured:
        return root

    root.setLevel(logging.INFO if level is None else level)
    # 不向 root logger 传播：否则第三方库/解释器可能重复输出或劫持
    root.propagate = False
    fmt = logging.Formatter(_FMT)

    try:
        fh = RotatingFileHandler(
            log_path(), maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT, encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except Exception:
        # 日志本身不能成为崩溃源：拿不到文件句柄（目录不可写 / 磁盘满）就只留控制台。
        # 此处刻意不记日志 —— 正在配置的就是日志系统本身。
        pass

    if console is None:
        console = not _is_frozen()     # 开发态才输出到 stderr
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    _configured = True
    return root


def get_logger(name: str = None) -> logging.Logger:
    """取子 logger。传 __name__ 即可，内部会缩短为最后一段模块名。"""
    if not _configured:
        setup()
    if not name:
        return logging.getLogger(_LOGGER_NAME)
    short = str(name).rsplit(".", 1)[-1]
    return logging.getLogger(f"{_LOGGER_NAME}.{short}")


def is_configured() -> bool:
    return _configured
