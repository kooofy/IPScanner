# -*- coding: utf-8 -*-
"""有界并发执行工具：批量远程识别（WMI / NetBIOS）共用。

为什么需要
----------
``WmiThread`` / ``NetbiosThread`` 早期是纯串行 for 循环：

- WMI：每台一次 PowerShell ``Get-CimInstance``，单台超时 8s
- NetBIOS：每台一次 UDP/137 NBSTAT，单台超时 1.5s

N 台设备最坏耗时 = N × 单台超时。而在一批不可达 / 被防火墙拦截的主机上
「超时」是常态而非异常，于是 20 台 WMI 就要等约 160 秒，界面只剩一句
「WMI 识别进行中」，用户体感等同卡死。

本模块把「逐个跑」换成「有界并发跑」：总耗时降到约
``ceil(N / max_workers) × 单台超时``，同时保留三条原有语义：

1. **失败隔离** —— 单台抛异常不影响其余设备；
2. **逐台回传** —— 每完成一台立即回调，进度持续前进而非最后一次性刷新；
3. **不保序** —— 回调按完成顺序触发。调用方以 target 为键归位，
   现有 ``_on_wmi_result`` / ``_on_netbios_result`` 本就是按 IP 查行，天然兼容。

关键实现细节
------------
``on_result`` 在**调用 run_bounded 的那个线程**里被回调（``as_completed``
在主调线程迭代），而**不是**在线程池的工作线程里。因此 ``QThread.run()``
内 ``emit`` 信号的行为与改造前完全一致，不会引入跨线程信号投递的新问题。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_bounded(targets, worker, max_workers=4, on_result=None, cancel_event=None):
    """并发对每个 target 调用 ``worker(target)``。

    Args:
        targets: 可迭代的目标列表，元素原样传给 ``worker``。
        worker: 单元素处理函数，签名 ``worker(target) -> Any``。
        max_workers: 并发度，自动收敛到 ``[1, len(targets)]``。
        on_result: 回调 ``on_result(target, result, exc)``；
            ``exc`` 非 None 表示 ``worker`` 抛了异常（此时 ``result`` 为 None）。
        cancel_event: ``threading.Event``。被 set 后不再提交剩余任务；
            已在执行中的任务会自然跑完（不强行中断子进程）。

    Returns:
        ``(done, skipped)``：已执行数量、因取消而跳过的数量。
    """
    items = list(targets)
    if not items:
        return 0, 0

    workers = max(1, min(int(max_workers or 1), len(items)))
    done = 0
    skipped = 0

    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="identify") as pool:
        futures = {}
        for idx, item in enumerate(items):
            if cancel_event is not None and cancel_event.is_set():
                skipped = len(items) - idx
                break
            futures[pool.submit(worker, item)] = item

        for fut in as_completed(futures):
            item = futures[fut]
            try:
                result, exc = fut.result(), None
            except Exception as e:  # noqa: BLE001 - 单台失败要透传给调用方，不能中断整批
                result, exc = None, e
            done += 1
            if on_result is not None:
                on_result(item, result, exc)

    return done, skipped
