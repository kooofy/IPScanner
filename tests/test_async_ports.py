# -*- coding: utf-8 -*-
"""v2.1 §2.1：异步 connect 端口探测（asyncio + IOCP）测试。

背景：Windows 上 SYN 扫描依赖 Npcap，而它禁止再分发、不能捆绑，于是 connect
是绝大多数用户的唯一选择。旧 connect 用线程池加并发，线程成本限制了几千并发
的可能。新实现用 ``asyncio`` + ProactorEventLoop(IOCP) 在**一个线程**里挂起
上千个 connect，实测 2000 个关闭端口约 2× 提速。

本测试锁死：
1. **功能等价**：异步路径与线程池路径在"开放/关闭/混合"三种负载下结果**逐条一致**；
2. **并发上限**：Semaphore 生效，同时在飞的 connect 不超过 concurrency；
3. **RTT 契约**：``rtt_callback`` 仅在端口开放时回调，且耗时 > 0；
4. **诚实降级**：ProactorEventLoop 不可用时 ``requires_proactor`` 报不可用，
   ``ports.scan_ports`` 自动回退线程池；
5. **失败回退**：异步引擎在真实扫描中抛错 → warning + 回退线程池 + 置位进程标记；
6. **开关**：``IPSCANNER_TCP_ENGINE=threaded`` 强制走线程池。
"""
import os
import socket
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import async_ports
from scanner import ports


def _listen_socket():
    """起一个真实监听端口，返回 (socket, port)；调用方负责 close。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    return srv, srv.getsockname()[1]


def _closed_port():
    """取一个当前必定无人监听的端口。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    p = srv.getsockname()[1]
    srv.close()
    return p


class _EngineStateMixin(unittest.TestCase):
    """隔离引擎相关的进程级状态。"""

    def setUp(self):
        ports.reset_async_engine_state()
        async_ports.reset_capability_cache()
        os.environ.pop(ports._ENGINE_ENV, None)

    def tearDown(self):
        ports.reset_async_engine_state()
        async_ports.reset_capability_cache()
        os.environ.pop(ports._ENGINE_ENV, None)
        async_ports.shutdown_loop()
        ports.shutdown_port_pool()


class CapabilityTest(_EngineStateMixin):

    def test_proactor_available_on_this_env(self):
        ok, reason = async_ports.requires_proactor()
        # CI 是 Windows；能力探测应报可用且原因为空。
        self.assertTrue(ok, f"预期 Proactor 可用，实际原因：{reason}")
        self.assertEqual(reason, "")

    def test_capability_cached(self):
        first = async_ports.requires_proactor()
        second = async_ports.requires_proactor()
        self.assertIs(first, second)

    def test_reset_capability_cache_reprobes(self):
        async_ports.requires_proactor()
        self.assertIsNotNone(async_ports._cap_cache)
        async_ports.reset_capability_cache()
        # 重置后缓存清空，下次调用重新探测并填充
        self.assertIsNone(async_ports._cap_cache)
        async_ports.requires_proactor()
        self.assertIsNotNone(async_ports._cap_cache)

    def test_no_proactor_reports_unavailable(self):
        """模拟非 Windows：无 ProactorEventLoop → 报不可用并带原因。"""
        async_ports.reset_capability_cache()
        import builtins
        real_hasattr = builtins.hasattr

        def _fake_hasattr(obj, name):
            if obj is async_ports.asyncio and name == "ProactorEventLoop":
                return False
            return real_hasattr(obj, name)

        with mock.patch("builtins.hasattr", _fake_hasattr):
            ok, reason = async_ports.requires_proactor()
        self.assertFalse(ok)
        self.assertIn("ProactorEventLoop", reason)


class ParityTest(_EngineStateMixin):
    """异步路径与线程池路径结果必须逐条一致。"""

    def test_open_port_parity(self):
        srv, port = _listen_socket()
        try:
            a = async_ports.probe_ports_async("127.0.0.1", [port], timeout=0.5)
            b = ports._scan_ports_connect_threaded("127.0.0.1", [port], 0.5)
            self.assertEqual(a, b)
            self.assertEqual(a, [port])
        finally:
            srv.close()

    def test_closed_port_parity(self):
        p = _closed_port()
        a = async_ports.probe_ports_async("127.0.0.1", [p], timeout=0.2)
        b = ports._scan_ports_connect_threaded("127.0.0.1", [p], 0.2)
        self.assertEqual(a, b)
        self.assertEqual(a, [])

    def test_mixed_parity_and_sorted(self):
        srv, openp = _listen_socket()
        closed = [_closed_port() for _ in range(5)]
        # 故意打乱顺序：开放端口夹在关闭端口中间，且开放端口在关闭端口**之后**
        pset = closed[:2] + [openp] + closed[2:]
        try:
            a = async_ports.probe_ports_async("127.0.0.1", pset, timeout=0.3)
            b = ports._scan_ports_connect_threaded("127.0.0.1", pset, 0.3)
            self.assertEqual(a, b)
            self.assertEqual(a, [openp])
            self.assertEqual(a, sorted(a))
        finally:
            srv.close()

    def test_empty_ports_returns_empty(self):
        self.assertEqual(async_ports.probe_ports_async("127.0.0.1", []), [])

    def test_multiple_open_ports(self):
        s1, p1 = _listen_socket()
        s2, p2 = _listen_socket()
        try:
            got = async_ports.probe_ports_async("127.0.0.1", [p1, p2], timeout=0.5)
            self.assertEqual(got, sorted([p1, p2]))
        finally:
            s1.close()
            s2.close()


class RttCallbackTest(_EngineStateMixin):

    def test_rtt_only_for_open(self):
        srv, openp = _listen_socket()
        p_closed = _closed_port()
        rtts = []
        try:
            async_ports.probe_ports_async(
                "127.0.0.1", [openp, p_closed], timeout=0.3,
                rtt_callback=rtts.append,
            )
        finally:
            srv.close()
        # 只有一个开放端口 → 恰好一次回调，且耗时为正
        self.assertEqual(len(rtts), 1)
        self.assertGreater(rtts[0], 0.0)

    def test_no_callback_when_none(self):
        srv, openp = _listen_socket()
        try:
            # 不传回调不应抛
            got = async_ports.probe_ports_async("127.0.0.1", [openp], timeout=0.3)
            self.assertEqual(got, [openp])
        finally:
            srv.close()


class ConcurrencyCapTest(_EngineStateMixin):
    """Semaphore 必须限制同时在飞的 connect 数。"""

    def test_concurrency_cap_enforced(self):
        in_flight = {"now": 0, "peak": 0}

        async def _tracking(ip, port, timeout):
            in_flight["now"] += 1
            in_flight["peak"] = max(in_flight["peak"], in_flight["now"])
            try:
                # 让协程有机会让出，制造重叠窗口
                import asyncio
                await asyncio.sleep(0)
                return False, 0.0
            finally:
                in_flight["now"] -= 1

        with mock.patch.object(async_ports, "_probe_one", _tracking):
            async_ports.probe_ports_async(
                "127.0.0.1", list(range(1, 50)), concurrency=4, timeout=0.1,
            )
        self.assertLessEqual(in_flight["peak"], 4,
                             f"并发峰值 {in_flight['peak']} 超过上限 4")
        self.assertGreater(in_flight["peak"], 1, "并发上限过严，未产生重叠")

    def test_single_concurrency_serializes(self):
        in_flight = {"now": 0, "peak": 0}

        async def _tracking(ip, port, timeout):
            in_flight["now"] += 1
            in_flight["peak"] = max(in_flight["peak"], in_flight["now"])
            try:
                import asyncio
                await asyncio.sleep(0)
                return False, 0.0
            finally:
                in_flight["now"] -= 1

        with mock.patch.object(async_ports, "_probe_one", _tracking):
            async_ports.probe_ports_async(
                "127.0.0.1", list(range(1, 10)), concurrency=1, timeout=0.1,
            )
        self.assertEqual(in_flight["peak"], 1)


class EngineSelectionTest(_EngineStateMixin):
    """ports 层的引擎选择与回退。"""

    def test_default_is_async_on_windows(self):
        self.assertEqual(ports.tcp_engine(), "async")

    def test_env_threaded_forces_pool(self):
        os.environ[ports._ENGINE_ENV] = "threaded"
        self.assertEqual(ports.tcp_engine(), "threaded")
        # 强制线程池时 scan_ports 必须**不**调用异步实现
        srv, openp = _listen_socket()
        try:
            with mock.patch.object(async_ports, "probe_ports_async") as spy:
                got = ports.scan_ports("127.0.0.1", ports=[openp], timeout=0.3)
            spy.assert_not_called()
            self.assertEqual(got, [openp])
        finally:
            srv.close()

    def test_env_async_forces_async(self):
        os.environ[ports._ENGINE_ENV] = "async"
        self.assertEqual(ports.tcp_engine(), "async")

    def test_async_engine_failure_falls_back(self):
        """异步路径抛错 → 本次回退线程池并给出正确结果 + 置位回退标记。"""
        srv, openp = _listen_socket()
        try:
            with mock.patch.object(
                async_ports, "probe_ports_async",
                side_effect=RuntimeError("simulated"),
            ):
                got = ports.scan_ports("127.0.0.1", ports=[openp], timeout=0.3)
            self.assertEqual(got, [openp])
            # 失败后引擎永久回退
            self.assertEqual(ports.tcp_engine(), "threaded")
        finally:
            srv.close()

    def test_reset_restores_async(self):
        ports._async_engine_failed.set()
        self.assertEqual(ports.tcp_engine(), "threaded")
        ports.reset_async_engine_state()
        self.assertEqual(ports.tcp_engine(), "async")

    def test_proactor_unavailable_falls_back(self):
        """模拟非 Windows：Proactor 不可用 → 自动回退线程池。"""
        with mock.patch.object(
            async_ports, "requires_proactor", return_value=(False, "非 Windows"),
        ):
            self.assertEqual(ports.tcp_engine(), "threaded")
            srv, openp = _listen_socket()
            try:
                got = ports.scan_ports("127.0.0.1", ports=[openp], timeout=0.3)
                self.assertEqual(got, [openp])
            finally:
                srv.close()

    def test_probe_ports_async_raises_when_unavailable(self):
        with mock.patch.object(
            async_ports, "requires_proactor", return_value=(False, "非 Windows"),
        ):
            with self.assertRaises(RuntimeError):
                async_ports.probe_ports_async("127.0.0.1", [80])


class LoopLifecycleTest(_EngineStateMixin):

    def test_loop_reused_across_calls(self):
        loop1 = async_ports._get_loop()
        loop2 = async_ports._get_loop()
        self.assertIs(loop1, loop2)

    def test_shutdown_loop_recreates(self):
        first = async_ports._get_loop()
        async_ports.shutdown_loop()
        second = async_ports._get_loop()
        self.assertIsNot(first, second)

    def test_shutdown_twice_safe(self):
        async_ports._get_loop()
        async_ports.shutdown_loop()
        async_ports.shutdown_loop()  # 再关一次不应抛

    def test_shutdown_loop_swallows_close_error(self):
        """loop.close() 抛错也不应升级成异常（只记 debug）。"""
        async_ports._get_loop()
        with mock.patch.object(
            async_ports.asyncio.AbstractEventLoop, "close",
            side_effect=RuntimeError("close boom"),
        ):
            async_ports.shutdown_loop()  # 不应抛


class ProbeOneDegradationTest(_EngineStateMixin):
    """单端口探测的各种异常都按"关闭"处理，不升级成扫描失败。"""

    def test_connection_refused_is_closed(self):
        p = _closed_port()
        got = async_ports.probe_ports_async("127.0.0.1", [p], timeout=0.2)
        self.assertEqual(got, [])

    def test_timeout_exception_is_closed(self):
        """显式模拟 TimeoutError 分支。"""
        import asyncio
        loop = async_ports._get_loop()
        with mock.patch.object(
            asyncio, "open_connection",
            side_effect=asyncio.TimeoutError(),
        ):
            ok, elapsed = loop.run_until_complete(
                async_ports._probe_one("127.0.0.1", 80, 0.1)
            )
        self.assertFalse(ok)
        self.assertEqual(elapsed, 0.0)

    def test_socket_timeout_exception_is_closed(self):
        """socket.timeout 分支（部分平台把超时转成这个）。"""
        import asyncio
        loop = async_ports._get_loop()
        with mock.patch.object(
            asyncio, "open_connection",
            side_effect=socket.timeout(),
        ):
            ok, elapsed = loop.run_until_complete(
                async_ports._probe_one("127.0.0.1", 80, 0.1)
            )
        self.assertFalse(ok)
        self.assertEqual(elapsed, 0.0)

    def test_writer_close_error_still_open(self):
        """连接成功但关闭握手失败（wait_closed 抛错）：端口仍应判为开放。"""
        class _BadWriter:
            def close(self):
                pass  # close 本身成功

            async def wait_closed(self):
                raise RuntimeError("wait_closed boom")

        class _Reader:
            pass

        import asyncio
        loop = async_ports._get_loop()

        async def _open_coro():
            return _Reader(), _BadWriter()

        def _fake_open(ip, port):
            return _open_coro()

        with mock.patch.object(asyncio, "open_connection", _fake_open):
            ok, elapsed = loop.run_until_complete(
                async_ports._probe_one("127.0.0.1", 80, 0.5)
            )
        self.assertTrue(ok)

    def test_unexpected_exception_is_closed(self):
        import asyncio
        loop = async_ports._get_loop()
        with mock.patch.object(
            asyncio, "open_connection",
            side_effect=ValueError("boom"),
        ):
            ok, elapsed = loop.run_until_complete(
                async_ports._probe_one("127.0.0.1", 80, 0.1)
            )
        self.assertFalse(ok)
        self.assertEqual(elapsed, 0.0)

    def test_probe_all_empty_ports(self):
        """_probe_all 对空端口列表走早返回分支。"""
        loop = async_ports._get_loop()
        got = loop.run_until_complete(
            async_ports._probe_all("127.0.0.1", [], 8, 0.1)
        )
        self.assertEqual(got, {})


if __name__ == "__main__":
    unittest.main()
