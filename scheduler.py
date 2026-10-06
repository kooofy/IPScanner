# -*- coding: utf-8 -*-
"""定时扫描的调度集成。

为什么是"系统计划任务"而不是"应用内定时器"
------------------------------------------
应用内定时器要求 GUI 一直开着 —— 对"无人值守的资产监控"这个目标来说是最脆弱的
方案：关掉窗口、注销、重启都会让监控静默中断，而且用户不会收到任何提示。
交给系统调度器则天然满足"机器开着就一定会跑"，也让扫描发生在独立进程里，
不会因为 GUI 卡顿而漂移。

因此本模块把调度委托给：
* Windows → ``schtasks``（任务计划程序）
* Linux / macOS → ``crontab``

命令构造全部是**纯函数**（``build_*``），只有 ``register`` / ``unregister``
才真正执行外部命令。这样调度的正确性可以在不碰系统调度器的前提下被单测覆盖 ——
直接改系统计划任务是很难在 CI 里验证、也很难回滚的操作。
"""
import os
import platform
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

from app_logging import get_logger
from i18n import tr

_log = get_logger(__name__)

DEFAULT_TASK_NAME = "IPScanner Scheduled Scan"

FREQ_MINUTE = "minute"
FREQ_HOURLY = "hourly"
FREQ_DAILY = "daily"

_SCHTASKS_FREQ = {
    FREQ_MINUTE: "MINUTE",
    FREQ_HOURLY: "HOURLY",
    FREQ_DAILY: "DAILY",
}

# schtasks 对 /MO 的取值范围有硬性限制（分钟 1~1439，小时 1~23）
_MO_LIMITS = {FREQ_MINUTE: (1, 1439), FREQ_HOURLY: (1, 23)}


class ScheduleError(ValueError):
    """调度参数非法。"""


def _clamp_interval(freq: str, interval: int) -> int:
    if freq == FREQ_DAILY:
        return 1
    lo, hi = _MO_LIMITS[freq]
    return max(lo, min(hi, int(interval)))


def _validate_time(at: str) -> str:
    """校验并规范化 ``HH:MM``。"""
    s = (at or "").strip()
    if not s:
        return "09:00"
    parts = s.split(":")
    if len(parts) != 2:
        raise ScheduleError(tr("时间格式必须是 HH:MM"))
    try:
        hh, mm = int(parts[0]), int(parts[1])
    except ValueError:
        raise ScheduleError(tr("时间格式必须是 HH:MM")) from None
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise ScheduleError(tr("时间格式必须是 HH:MM"))
    return f"{hh:02d}:{mm:02d}"


def validate_schedule(freq: str, interval: int = 1, at: str = "09:00") -> None:
    """校验一组调度参数，非法时抛 :class:`ScheduleError`。

    调用方（如 CLI 的 ``schedule`` 子命令）应在**触碰系统调度器之前**调用它：
    schtasks / crontab 对越界参数只会回一句含糊的"参数错误"，
    用户对不上是哪一项写错了。
    """
    if freq not in _SCHTASKS_FREQ:
        raise ScheduleError(f"不支持的调度频率: {freq}")
    if freq == FREQ_DAILY:
        _validate_time(at)
    else:
        _clamp_interval(freq, interval)


# ── Windows：schtasks ────────────────────────────────────────────────

def build_schtasks_create(name: str, command: str, freq: str,
                          interval: int = 1, at: str = "09:00",
                          run_highest: bool = False) -> List[str]:
    """构造 ``schtasks /Create`` 的 argv。

    ``command`` 是**完整的命令行字符串**（可执行文件 + 参数），会被塞进 ``/TR``。
    这里刻意返回 argv 列表而不是拼接好的字符串：调用方用 ``subprocess`` 列表形式
    执行时，Python 会负责内层引号的转义，避免手工拼 shell 字符串引入注入面。
    """
    if freq not in _SCHTASKS_FREQ:
        raise ScheduleError(f"不支持的调度频率: {freq}")
    if not name or not name.strip():
        raise ScheduleError(tr("任务名不能为空"))
    if not command or not command.strip():
        raise ScheduleError(tr("任务命令不能为空"))

    argv = ["schtasks", "/Create", "/TN", name.strip(), "/TR", command,
            "/SC", _SCHTASKS_FREQ[freq], "/F"]
    if freq == FREQ_DAILY:
        argv += ["/ST", _validate_time(at)]
    else:
        argv += ["/MO", str(_clamp_interval(freq, interval))]
    if run_highest:
        # SYN 半开扫描 / ARP 主动探测需要管理员权限；不加这个开关，
        # 计划任务会在普通权限下静默回退到 TCP 全连接
        argv += ["/RL", "HIGHEST"]
    return argv


def build_schtasks_delete(name: str) -> List[str]:
    return ["schtasks", "/Delete", "/TN", name, "/F"]


def build_schtasks_query(name: str) -> List[str]:
    return ["schtasks", "/Query", "/TN", name]


# ── POSIX：crontab ───────────────────────────────────────────────────

def build_cron_line(command: str, freq: str, interval: int = 1,
                    at: str = "09:00") -> str:
    """构造一行 crontab 条目（不含换行）。"""
    if freq not in _SCHTASKS_FREQ:
        raise ScheduleError(f"不支持的调度频率: {freq}")
    if not command or not command.strip():
        raise ScheduleError(tr("任务命令不能为空"))

    if freq == FREQ_MINUTE:
        step = _clamp_interval(freq, interval)
        return f"*/{step} * * * * {command}"
    if freq == FREQ_HOURLY:
        step = _clamp_interval(freq, interval)
        return f"0 */{step} * * * {command}"
    hh, mm = _validate_time(at).split(":")
    return f"{int(mm)} {int(hh)} * * * {command}"


def build_cron_block(command: str, freq: str, interval: int = 1,
                     at: str = "09:00", tag: str = "IPScanner") -> str:
    """带标记注释的 crontab 片段 —— 卸载时靠这行标记精确删除，不动用户其它条目。"""
    return (f"# >>> {tag} >>>\n"
            f"{build_cron_line(command, freq, interval, at)}\n"
            f"# <<< {tag} <<<\n")


# ── 命令组装 ─────────────────────────────────────────────────────────

def default_executable() -> Tuple[str, List[str]]:
    """返回 ``(可执行文件, 前置参数)``。

    * 源码运行 → ``(python, ["cli.py"])``
    * 打包运行 → 同目录下的 ``IPScanner_cli.exe``（无前置参数）

    打包态下不能用 ``sys.executable``：那是 GUI 版 exe，它会弹窗而不是走 CLI。
    """
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        cli_exe = os.path.join(exe_dir, "IPScanner_cli.exe")
        if os.path.exists(cli_exe):
            return cli_exe, []
        # CLI 版没跟着分发（或用户只拷了 GUI）→ 退回 GUI exe 并留痕，
        # 让用户知道计划任务实际会拉起一个带界面的进程
        _log.warning("未找到 IPScanner_cli.exe，计划任务将调用 GUI 版：%s", sys.argv[0])
        return os.path.abspath(sys.argv[0]), []
    cli_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
    return sys.executable, [cli_py]


def build_scan_argv(ranges: Sequence[str], level: str = "quick",
                    save_snapshot: bool = True, note: str = "",
                    notify: bool = True) -> List[str]:
    """构造一次"扫描 + 存快照 + 变更告警"的 CLI 参数（不含可执行文件）。"""
    argv = ["scan"]
    for r in ranges:
        if r and str(r).strip():
            argv += ["-r", str(r).strip()]
    argv += ["--level", level or "quick"]
    if save_snapshot:
        argv.append("--save-snapshot")
    if note:
        argv += ["--note", note]
    if notify:
        argv.append("--notify")
    return argv


def build_task_command(executable: str, prefix: Sequence[str],
                       cli_args: Sequence[str]) -> str:
    """把可执行文件与参数拼成一条命令行字符串（供 /TR 或 cron 使用）。"""
    parts = [f'"{executable}"'] if " " in executable else [executable]
    parts += list(prefix)
    parts += [a if " " not in str(a) else f'"{a}"' for a in cli_args]
    return " ".join(parts)


# ── 实际注册 / 卸载 ──────────────────────────────────────────────────

def _run(argv: Sequence[str], timeout: float = 20) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError:
        return False, tr("找不到系统调度命令")
    except subprocess.TimeoutExpired:
        return False, tr("系统调度命令超时")
    except OSError as e:
        # PermissionError（被安全策略/组策略拦截、普通用户无权注册系统任务）
        # 也是 OSError。**必须**接住：调用方（CLI/GUI）期望的是"返回 (False, 原因)"，
        # 而不是一个把整个命令打断的异常 —— 否则用户看到的是 traceback，
        # 而不是"权限不足，请用管理员身份运行"。
        return False, str(e)
    out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if proc.returncode == 0:
        return True, out
    return False, err or out or f"退出码 {proc.returncode}"


def is_supported() -> bool:
    """当前平台是否支持自动注册计划任务。"""
    if platform.system() == "Windows":
        return shutil.which("schtasks") is not None
    return shutil.which("crontab") is not None


def register(name: str, command: str, freq: str, interval: int = 1,
             at: str = "09:00", run_highest: bool = False) -> Tuple[bool, str]:
    """注册（或覆盖）计划任务。返回 ``(是否成功, 消息)``。"""
    if platform.system() == "Windows":
        argv = build_schtasks_create(name, command, freq, interval, at, run_highest)
        return _run(argv)

    # POSIX：先删掉同名旧条目再追加，保证幂等。
    # 用带标记注释的块（而不是裸 crontab 行）写入 —— 卸载时靠这组标记精确删除，
    # 不会误伤用户自己写的其它条目。
    ok, msg = unregister(name)
    if not ok and msg:
        _log.debug("卸载旧 cron 条目失败（首次注册时会走到这里）: %s", msg)
    existing = _read_crontab()
    if existing is None:
        return False, tr("读取 crontab 失败")
    block = build_cron_block(command, freq, interval, at, tag=name)
    new = existing + ("" if (not existing or existing.endswith("\n")) else "\n") + block
    return _write_crontab(new)


def unregister(name: str) -> Tuple[bool, str]:
    """删除计划任务。返回 ``(是否成功, 消息)``。"""
    if platform.system() == "Windows":
        return _run(build_schtasks_delete(name))

    existing = _read_crontab()
    if existing is None:
        return False, tr("读取 crontab 失败")
    tag = f"# >>> {name} >>>"
    end = f"# <<< {name} <<<"
    if tag not in existing:
        return True, tr("未找到已注册的计划任务")
    out, skip = [], False
    for line in existing.splitlines():
        if line.strip() == tag:
            skip = True
            continue
        if line.strip() == end:
            skip = False
            continue
        if not skip:
            out.append(line)
    return _write_crontab("\n".join(out) + ("\n" if out else ""))


def query(name: str) -> Tuple[bool, str]:
    """查询计划任务是否存在。"""
    if platform.system() == "Windows":
        return _run(build_schtasks_query(name))
    existing = _read_crontab()
    if existing is None:
        return False, tr("读取 crontab 失败")
    return (f"# >>> {name} >>>" in existing), ""


def _read_crontab() -> Optional[str]:
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        _log.warning("读取 crontab 失败: %s", e)
        return None
    if proc.returncode != 0:
        # "no crontab for <user>" 是全新用户的正常状态，不是错误
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        if "no crontab" in err.lower():
            return ""
        _log.warning("读取 crontab 失败: %s", err.strip())
        return ""
    return (proc.stdout or b"").decode("utf-8", errors="replace")


def _write_crontab(content: str) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(["crontab", "-"], input=content.encode("utf-8"),
                              capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode == 0:
        return True, ""
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    return False, err or f"退出码 {proc.returncode}"
