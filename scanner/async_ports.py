# -*- coding: utf-8 -*-
"""异步 connect 端口探测：`asyncio` + IOCP，无需任何驱动/依赖。

为什么要有这个模块
------------------
Windows 上 SYN 半开扫描依赖 Npcap，而 Npcap 免费授权**只有 5 次安装、明确禁止
再分发**，不能随包捆绑（见 `PRODUCT_ADVISORY.md` §9），于是绝大多数用户的 SYN
扫描永远退化成 connect。既然结果只能来自 connect，就该把 connect 做到最快 ——
而 connect 的瓶颈**不是 CPU 也不是带宽，是"同时在飞的 socket 数"**。

旧的 `ports.scan_ports()` 用线程池加并发：一个 OS 线程一个阻塞 `connect_ex`。
线程有真实成本（Windows 默认保留 1MB 栈、上下文切换、GIL 争用），并发沾到几千
就顶不动了。`asyncio` 的 ProactorEventLoop 在 Windows 上走 **IOCP**（内核级
重叠 I/O），**一个线程**就能挂起几千个 connect，把 connect 扫描的速度拉到接近
SYN 的水平 —— 且**不需要任何驱动、不需要管理员**。

与 `scanner/ports.py` 的关系
----------------------------
本模块**只管 connect 模式的并发探测**，不碰 SYN/UDP（那两个仍需原始套接字）。
`ports.scan_ports()` 默认走这里的异步实现；线程池路径作为**可切换的回退**保留
（见 `ports.py` 的开关），以便一旦异步路径在某个环境上出问题能立刻退回去。

诚实降级
--------
`ProactorEventLoop` 不可用（非 Windows、或将来 Python 改了默认）时，本模块
**显式报告不可用**（`requires_proactor()`），由调用方回退到线程池 —— 而不是
"假装能用然后悄悄变慢/出错"。

零依赖 / 零 PyQt
----------------
只用标准库（`asyncio` / `socket` / `time`）。与 `scanner/` 其余模块同口径。
"""
import asyncio
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from app_logging import get_logger

from . import throttle

_log = get_logger(__name__)

# 单次 asyncio 调度里同时在飞的 connect 上限。
#
# 线程池路径的硬上限是 384（见 ports.py 的说明）。异步路径没有"线程"这个成本，
# 理论上可以开到几千 —— 但**每台设备**都开几千并发会在"几十台设备并行富化"
# 时把本机端口耗尽（Windows 动态端口范围默认约 16384，还要留给其它程序）。
# 取 1024 是折中：单台远快于 384 的线程池（实测见测试），又不至于在 50 台并发
# 富化时把 ephemeral 端口打满（50 × 1024 = 51200 > 16384，但 asyncio 的
# Semaphore 是**每台各自**的，真实在飞数是各设备之和，由引擎的 max_threads 层
# 再兜一层；此值是单台的适度激进档）。
DEFAULT_CONCURRENCY = 1024

# 事件循环按需惰性创建并跨调用复用 —— 与 ports.py 的单例池同一动机：
# 一次创建、长期复用，避免每次 scan_ports() 都重建一个 loop/proactor。
_loop: Optional[asyncio.AbstractEventLoop] = None
_loop_lock = threading.Lock()

# 模块级能力缓存：ProactorEventLoop 是否可用（本进程内不变，缓存避免反复探测）。
_cap_cache: Optional[Tuple[bool, str]] = None


def requires_proactor() -> Tuple[bool, str]:
    """异步路径是否可用。返回 ``(可用, 不可用原因)``。

    Windows 上 ``ProactorEventLoop`` 是默认实现（走 IOCP）；非 Windows、
    或将来 Python 变了默认，则本模块退化为"不可用"，由 `ports.py` 回退线程池。
    """
    global _cap_cache
    if _cap_cache is not None:
        return _cap_cache
    if not hasattr(asyncio, "ProactorEventLoop"):
        _cap_cache = (False, "本 Python 无 ProactorEventLoop（非 Windows 或版本过旧）")
    else:
        _cap_cache = (True, "")
    return _cap_cache


def reset_capability_cache() -> None:
    """清空能力缓存（供测试隔离；正常流程不需要）。"""
    global _cap_cache
    _cap_cache = None


def _get_loop() -> asyncio.AbstractEventLoop:
    """返回进程内共享的事件循环（首次调用时惰性创建并设为 Proactor）。

    必须是 Proactor（IOCP）而非 Selector：Selector 在 Windows 上对 socket
    并发受 ``select()`` 的 FD_SETSIZE 限制（默认 512），根本开不了几千并发。
    """
    global _loop
    if _loop is None:
        with _loop_lock:
            if _loop is None:
                if hasattr(asyncio, "ProactorEventLoop"):
                    loop = asyncio.ProactorEventLoop()
                else:  # pragma: no cover - 非 Windows 的兜底分支
                    loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                _loop = loop
    return _loop


def shutdown_loop() -> None:
    """关闭并丢弃共享事件循环，下次调用会重新惰性创建。

    正常扫描流程**不需要**调用它（loop 设计成跨设备、跨扫描复用）。
    提供它只是为了测试隔离与进程收尾。
    """
    global _loop
    with _loop_lock:
        loop, _loop = _loop, None
    if loop is not None and not loop.is_closed():
        try:
            loop.close()
        except Exception as e:  # noqa: BLE001
            _log.debug("关闭异步探测事件循环失败：%s", e)


async def _probe_one(ip: str, port: int, timeout: float) -> Tuple[bool, float]:
    """异步探测单个 TCP 端口。返回 ``(是否开放, connect 耗时秒)``。

    用 ``open_connection`` 而非裸 socket：它把"socket 连接 + 等待"交给 IOCP，
    协程让出控制权期间**不占线程**。任何异常（拒绝/超时/网络不可达）一律
    视为"关闭" —— 这是端口扫描的常态，与同步 ``scan_port`` 的语义一致。
    """
    t0 = time.perf_counter()
    try:
        # wait_for 兜超时：该环境下的 ProactorEventLoop 不总是把 socket 超时
        # 转成 asyncio.TimeoutError，显式包一层最稳。
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception as e:  # noqa: BLE001
            # 连接已成功建立，关闭握手失败不影响"端口开放"的结论 ——
            # 只记 debug，不升级成异常。
            _log.debug("端口已连接但关闭握手失败（不影响开放结论）%s:%s: %s",
                       ip, port, e)
        return True, (time.perf_counter() - t0)
    except (asyncio.TimeoutError, socket.timeout):
        return False, 0.0
    except (ConnectionRefusedError, OSError):
        # 拒绝 / 不可达 / 复位 —— 都按"关闭"处理。
        return False, 0.0
    except Exception as e:  # noqa: BLE001
        _log.debug("异步端口探测异常，按关闭处理 %s:%s: %s", ip, port, e)
        return False, 0.0


async def _probe_all(ip: str, ports: List[int], concurrency: int,
                     timeout: float) -> Dict[int, Tuple[bool, float]]:
    """以 ``concurrency`` 为上限并发探测 ``ports``，返回 ``{port: (ok, 耗时)}``。

    用 Semaphore 限流：同时飞的 connect 不超过 ``concurrency``。结果收集顺序
    与 ports 无关（as_completed 语义），由调用方负责排序。
    """
    # 礼貌模式（v2.1 §2.4）：投递前按当前档打乱端口顺序，避免固定顺序
    # 每次扫都是同一串规律性的 SYN（那是 IDS 最喜欢的特征）。fast 档下
    # shuffle=False ⇒ 原样返回，行为与改造前逐字节一致。
    ports = throttle.shuffle_for(ports)
    sem = asyncio.Semaphore(concurrency)
    results: Dict[int, Tuple[bool, float]] = {}

    async def _guarded(p: int) -> None:
        # 令牌桶放行闸门在**进 Semaphore 之前**：等令牌的协程不该占着并发额度，
        # 否则 polite 档下排队时间会把实际并发顶到上限之外。
        throttle.throttle_gate()
        async with sem:
            results[p] = await _probe_one(ip, p, timeout)

    if not ports:
        return results
    await asyncio.gather(*(_guarded(p) for p in ports))
    return results


def probe_ports_async(ip: str, ports: List[int], *, concurrency: Optional[int] = None,
                      timeout: float = 0.5,
                      rtt_callback: Optional[Callable[[float], None]] = None) -> List[int]:
    """并发探测 ``ports``，返回**开放端口列表**（已排序），与 ``scan_ports`` 同契约。

    ``concurrency``：同时在飞的 connect 上限。**不给（``None``）时按当前礼貌档
    推导**（``throttle.concurrency_for(DEFAULT_CONCURRENCY)``）——
    ``fast`` 档不设限 ⇒ 与改造前逐字节等价；显式传值则完全听调用方的
    （调用方比本模块更清楚自己要多少）。

    ``rtt_callback``：仅在端口**开放**时回调其 connect 耗时（秒），与同步路径
    的语义完全一致 —— 供上层做 RTT 自适应超时。

    ⚠ 本函数**同步阻塞**直到全部探测完成（内部 ``run_until_complete``）。
    之所以不暴露成 ``async def``：调用方（``scanner/`` 与引擎）全是同步代码，
    且引擎自己已有线程层并发；把它做成协程需要把整条调用链改成 async，
    收益（省一层线程）不抵改动面（动了 GUI 线程、CLI、引擎）与风险。
    """
    ok, reason = requires_proactor()
    if not ok:
        raise RuntimeError(f"异步端口探测不可用：{reason}")
    if not ports:
        return []

    if concurrency is None:
        concurrency = throttle.concurrency_for(DEFAULT_CONCURRENCY)
    concurrency = max(1, concurrency)

    loop = _get_loop()
    raw = loop.run_until_complete(
        _probe_all(ip, ports, concurrency, timeout)
    )
    open_ports: List[int] = []
    for port, (is_open, elapsed) in raw.items():
        if is_open:
            open_ports.append(port)
            if rtt_callback is not None and elapsed > 0:
                rtt_callback(elapsed)
    return sorted(open_ports)
