# -*- coding: utf-8 -*-
"""端口探测线程池收敛（P1-1）测试。

背景：旧实现**每次** ``scan_ports()`` 调用都新建一个线程池。端口扫描在整个
流水线里是按设备反复调用的，最坏组合（50 台 enrich 并发 × 每台 64 worker ×
协议端口再扫一次）≈ 数千个线程在创建/销毁中抖动。修复方案是收敛为
**进程内单例有界池**。

本测试锁死三条契约：
1. 池是**单例**（多次取用返回同一对象，不重复新建）；
2. 池是**有界**的（线程数有硬上限，不随设备/端口数放大）；
3. ``_scan_ports_syn`` / ``_scan_ports_udp`` 走这个共享池，不再各自内联
   ``ThreadPoolExecutor(...)``。

⚠ v2.1 §2.1 起，**connect 模式的默认引擎改成了 asyncio（IOCP）**，不再走这个
线程池（见 ``test_async_ports.py``）。线程池如今是 connect 的**回退路径**，
以及 SYN/UDP 的主路径。因此本文件对 connect 的断言改为：
- ``scan_ports`` 在**异步可用**时**不**使用线程池（新契约）；
- ``scan_ports`` 在**强制回退**（``IPSCANNER_TCP_ENGINE=threaded``）时**仍**使用
  共享池、且反复调用只建一次池（旧契约在回退路径下继续成立）。
"""
import concurrent.futures
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_WINDOWS = sys.platform == "win32"

from scanner import ports


class SingletonTest(unittest.TestCase):

    def setUp(self):
        ports.shutdown_port_pool()

    def tearDown(self):
        ports.shutdown_port_pool()

    def test_returns_same_object(self):
        """多次取用必须是同一个池 —— 这正是"收敛"的含义。"""
        a = ports._get_port_pool()
        b = ports._get_port_pool()
        self.assertIs(a, b)

    def test_bounded_workers(self):
        """线程数有硬上限：明显大于 enrich 并发(50)，又远小于旧实现的最坏值。"""
        w = ports.port_pool_workers()
        self.assertGreater(w, 50)
        self.assertLessEqual(w, 512)
        self.assertEqual(ports._get_port_pool()._max_workers, w)

    def test_shutdown_then_recreate(self):
        """关闭后再取用会惰性重建（且不是同一个对象）。"""
        first = ports._get_port_pool()
        ports.shutdown_port_pool()
        second = ports._get_port_pool()
        self.assertIsNot(first, second)

    def test_shutdown_is_idempotent(self):
        ports._get_port_pool()
        ports.shutdown_port_pool()
        ports.shutdown_port_pool()          # 再关一次不应抛异常
        self.assertIsNone(ports._port_pool)


class SharedPoolUsageTest(unittest.TestCase):
    """三种模式都必须复用共享池，而不是各自新建。"""

    def setUp(self):
        ports.shutdown_port_pool()
        # _syn_failed 是跨模块共享状态；若被其它测试置位，_scan_ports_udp
        # 会直接返回 [] 而不碰线程池，导致"是否复用共享池"的断言失真。
        ports._C._syn_failed.clear()
        # 🔴 异步引擎失败标记同样是跨模块共享状态。若被别的测试置位，
        # connect 会静默改走线程池路径 —— 于是
        # test_scan_ports_connect_bypasses_pool_when_async 拿到的池是 MagicMock，
        # 而 as_completed() 会永远等一个永不完事的 future（**真挂死**，
        # 不是失败）。v2.1 §2.1 在 macOS/Linux CI 上烧掉 6 小时就是这一条。
        ports.reset_async_engine_state()

    def tearDown(self):
        ports.shutdown_port_pool()
        ports._C._syn_failed.clear()
        ports.reset_async_engine_state()

    def test_scan_ports_connect_uses_shared_pool_when_threaded(self):
        """强制回退线程池时，connect 仍复用共享池（回退路径的旧契约）。"""
        real = ports._get_port_pool()
        with mock.patch.dict(os.environ, {ports._ENGINE_ENV: "threaded"}), \
             mock.patch.object(ports, "_get_port_pool",
                               return_value=real) as spy:
            ports.scan_ports("127.0.0.1", ports=[80, 81], timeout=0.1)
        spy.assert_called()

    @unittest.skipUnless(_WINDOWS, "异步默认引擎仅 Windows（ProactorEventLoop）")
    def test_scan_ports_connect_bypasses_pool_when_async(self):
        """默认（异步）引擎下，connect **不**走线程池（v2.1 §2.1 新契约）。

        🔴 本测试把 `_get_port_pool` 换成裸 MagicMock —— 那意味着**任何**
        走到线程池路径的情况都是致命的：`as_completed()` 会 `event.wait()`
        等一个永不完事的 future，**进程真挂死**（不是断言失败）。
        所以除了依赖 `skipUnless(_WINDOWS)`，还必须断言前置引擎确实是异步，
        且 mock 的池**绝不能**被调用（这两件事互为保险）。
        """
        engine = ports.tcp_engine()
        if engine != "async":
            self.skipTest(f"当前 connect 引擎为 {engine}，本测试只对异步引擎有意义")
        with mock.patch.object(ports, "_get_port_pool") as spy, \
             mock.patch("scanner.async_ports.probe_ports_async",
                        return_value=[80]) as aspy:
            got = ports.scan_ports("127.0.0.1", ports=[80, 81], timeout=0.1)
        aspy.assert_called_once()
        spy.assert_not_called()
        self.assertEqual(got, [80])

    def test_scan_ports_syn_uses_shared_pool(self):
        real = ports._get_port_pool()
        with mock.patch.object(ports, "syn_scan_port", return_value="closed"), \
             mock.patch.object(ports, "_get_port_pool",
                               return_value=real) as spy:
            ports._scan_ports_syn("127.0.0.1", [80, 81], 0.1)
        spy.assert_called()

    def test_scan_ports_udp_uses_shared_pool(self):
        real = ports._get_port_pool()
        with mock.patch.object(ports, "udp_scan_port", return_value="open"), \
             mock.patch.object(ports, "_get_port_pool",
                               return_value=real) as spy:
            ports._scan_ports_udp("127.0.0.1", [53, 123], 0.1)
        spy.assert_called()

    def test_no_inline_pool_creation_on_repeated_calls(self):
        """反复调用不得反复新建池：把构造器包成计数器，跑多轮后只应建一次。

        ``ports`` 内部用 ``concurrent.futures.ThreadPoolExecutor(...)`` 构造池，
        因此补丁打在 ``ports`` 模块引用的那个名字上即可（不污染全局 concurrent.futures）。

        ⚠ 必须强制 ``threaded`` 引擎：异步路径（v2.1 §2.1 起的默认）根本不碰池。
        """
        created = []
        real_cls = concurrent.futures.ThreadPoolExecutor

        def counting(*a, **kw):
            created.append(1)
            return real_cls(*a, **kw)

        with mock.patch.dict(os.environ, {ports._ENGINE_ENV: "threaded"}), \
             mock.patch.object(ports.concurrent.futures,
                               "ThreadPoolExecutor", counting):
            for _ in range(5):
                ports.scan_ports("127.0.0.1", ports=[80], timeout=0.05)

        self.assertEqual(len(created), 1,
                         "共享池应在首次调用时创建一次，之后复用")


class BehaviourUnchangedTest(unittest.TestCase):
    """收敛线程池不应改变扫描结果。"""

    def setUp(self):
        ports.shutdown_port_pool()

    def tearDown(self):
        ports.shutdown_port_pool()

    def test_detects_listening_port(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            open_ports = ports.scan_ports("127.0.0.1", ports=[port], timeout=0.5)
            self.assertEqual(open_ports, [port])
        finally:
            srv.close()

    def test_closed_port_not_reported(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()          # 关掉 → 该端口应探测为关闭
        self.assertEqual(
            ports.scan_ports("127.0.0.1", ports=[port], timeout=0.2), [])


class ProtoPortReuseTest(unittest.TestCase):
    """协议端口复用：完整端口扫描已覆盖协议端口时，不应再重复探测一遍。

    协议端口（80/443/21/3389）都在常用端口表里，所以"完整扫描 + 协议识别"
    同时开启时旧实现会把同一批端口扫两次。这条复用逻辑既省一次网络往返，
    也少一轮线程池排队。
    """

    def test_reuse_when_all_covered(self):
        from scanner.engine import _proto_ports_already_scanned
        self.assertTrue(_proto_ports_already_scanned(
            True, [21, 80, 443, 3389, 22], [21, 80, 443, 3389]))

    def test_reuse_uses_default_table_when_ports_none(self):
        from scanner.engine import _proto_ports_already_scanned
        # ports=None 表示用默认常用端口表，其中已包含 80/443/21/3389
        self.assertTrue(_proto_ports_already_scanned(
            True, None, [80, 443, 21, 3389]))

    def test_no_reuse_when_not_scanning_ports(self):
        from scanner.engine import _proto_ports_already_scanned
        self.assertFalse(_proto_ports_already_scanned(
            False, [21, 80, 443, 3389], [21, 80, 443, 3389]))

    def test_no_reuse_when_any_port_missing(self):
        from scanner.engine import _proto_ports_already_scanned
        # 自定义端口列表缺了 3389 → 必须补扫，不能复用
        self.assertFalse(_proto_ports_already_scanned(
            True, [21, 80, 443], [21, 80, 443, 3389]))

    def test_no_reuse_for_empty_proto_list(self):
        from scanner.engine import _proto_ports_already_scanned
        # 空列表在逻辑上"全部覆盖"为真，但调用方本就不会走到这里；
        # 明确锁定行为，避免将来误用。
        self.assertTrue(_proto_ports_already_scanned(True, [80], []))


if __name__ == "__main__":
    unittest.main()
