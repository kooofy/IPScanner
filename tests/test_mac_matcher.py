# -*- coding: utf-8 -*-
"""MacMatcher 内存索引测试（P0-3）。

核心回归点：
1. 匹配语义必须与 MacLibrary.match 完全一致（IP 优先、其次 MAC），
   否则「移出主线程」会顺手改变业务结果。
2. 匹配过程不得再触碰 SQLite —— 大网段下每台设备一次字典查找。
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import db_util
from mac_library import MacLibrary, MacMatcher
from scanner.models import ScanResult


class MacMatcherTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "mac_library.db")
        self.lib = MacLibrary(self.db)
        self.lib.add(ip="192.168.1.10", mac="AA:BB:CC:00:00:01",
                     device_type="电脑", location="一楼机房", user="张三", remark="财务")
        self.lib.add(ip="192.168.1.11", mac="AA:BB:CC:00:00:02",
                     device_type="打印机", location="二楼", user="", remark="")
        self.lib.add(ip="", mac="AA:BB:CC:00:00:03",
                     device_type="交换机", location="弱电间", user="", remark="核心")

    def tearDown(self):
        db_util.close_connection(self.db)

    def _matcher(self):
        m = MacMatcher.from_library(self.lib)
        self.assertIsNotNone(m)
        return m

    # ---------- 语义一致性 ----------

    def test_parity_with_library_match(self):
        """MacMatcher 与 MacLibrary.match 对同一批查询必须返回同一行。"""
        m = self._matcher()
        cases = [
            ("192.168.1.10", "aa:bb:cc:00:00:01"),   # IP + MAC 都命中
            ("192.168.1.10", ""),                     # 仅 IP 命中
            ("192.168.1.11", "AA-BB-CC-00-00-02"),    # 仅 MAC 命中（连字符格式）
            ("10.0.0.1", "AA:BB:CC:00:00:03"),        # IP 未命中、MAC 命中
            ("10.0.0.1", "FF:FF:FF:FF:FF:FF"),        # 都不命中
            ("", "AA:BB:CC:00:00:03"),                # 空 IP，仅 MAC
            ("192.168.1.10", "FF:FF:FF:FF:FF:FF"),    # IP 优先于 MAC
        ]
        for ip, mac in cases:
            expected = self.lib.match(ip, mac)
            got = m.match(ip, mac)
            if expected is None:
                self.assertIsNone(got, msg=f"{(ip, mac)} 应未命中")
            else:
                self.assertIsNotNone(got, msg=f"{(ip, mac)} 应命中")
                self.assertEqual(expected["id"], got["id"], msg=f"{(ip, mac)} 命中了不同行")

    def test_ip_takes_priority_over_mac(self):
        """IP 与 MAC 分别命中不同行时，必须返回 IP 命中的那一行（与旧实现一致）。"""
        # 注意：MacLibrary.add 对非空 MAC 是 upsert，所以这里必须用**另一个 MAC**，
        # 否则第二条会覆盖第一条，构造不出"IP 与 MAC 指向不同行"的场景。
        self.lib.add(ip="192.168.1.99", mac="AA:BB:CC:00:00:09", device_type="另一台")
        m = self._matcher()

        # 192.168.1.10 → 第 1 行；AA:BB:CC:00:00:09 → 新插入的第 4 行
        row = m.match("192.168.1.10", "AA:BB:CC:00:00:09")
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "192.168.1.10")
        self.assertEqual(row["device_type"], "电脑")

        # 反过来：IP 不命中时，才回退到 MAC 匹配
        row_by_mac = m.match("10.0.0.1", "AA:BB:CC:00:00:09")
        self.assertIsNotNone(row_by_mac)
        self.assertEqual(row_by_mac["ip"], "192.168.1.99")
        self.assertEqual(row_by_mac["device_type"], "另一台")

        # 与旧实现逐条对齐，防止两条路径的优先级悄悄漂移
        for ip, mac in (("192.168.1.10", "AA:BB:CC:00:00:09"),
                        ("10.0.0.1", "AA:BB:CC:00:00:09")):
            expected = self.lib.match(ip, mac)
            self.assertEqual(expected["id"], m.match(ip, mac)["id"],
                             msg=f"{(ip, mac)} 与 MacLibrary.match 结果不一致")

    def test_mac_format_variants(self):
        """MAC 写法差异（大小写 / 连字符 / 无分隔）都能命中。"""
        m = self._matcher()
        for variant in ("AA:BB:CC:00:00:01", "aa:bb:cc:00:00:01",
                        "AA-BB-CC-00-00-01", "aabbcc000001"):
            self.assertIsNotNone(m.match("", variant), msg=variant)

    def test_empty_query_returns_none(self):
        m = self._matcher()
        self.assertIsNone(m.match("", ""))
        self.assertIsNone(m.match("   ", "  "))

    # ---------- apply_to ----------

    def test_apply_to_writes_fields(self):
        m = self._matcher()
        r = ScanResult(ip="192.168.1.10", mac="aa:bb:cc:00:00:01")
        self.assertTrue(m.apply_to(r))
        self.assertTrue(r.excel_matched)
        self.assertEqual(r.device_type, "电脑")
        self.assertEqual(r.location, "一楼机房")
        self.assertEqual(r.user, "张三")
        self.assertEqual(r.remark, "财务")

    def test_apply_to_returns_false_and_leaves_result_untouched(self):
        m = self._matcher()
        r = ScanResult(ip="10.9.9.9", mac="ff:ff:ff:ff:ff:ff")
        r.location = "原有值"
        self.assertFalse(m.apply_to(r))
        self.assertFalse(r.excel_matched)
        self.assertEqual(r.location, "原有值")

    def test_apply_to_by_mac_only(self):
        """无 IP、只有 MAC 的设备（地址库第 3 条）应能被扫到的 MAC 命中。"""
        m = self._matcher()
        r = ScanResult(ip="172.16.0.5", mac="AA:BB:CC:00:00:03")
        self.assertTrue(m.apply_to(r))
        self.assertEqual(r.device_type, "交换机")
        self.assertEqual(r.location, "弱电间")

    # ---------- 构造边界 ----------

    def test_from_library_none_or_empty(self):
        self.assertIsNone(MacMatcher.from_library(None))
        empty_db = os.path.join(self.tmp, "empty.db")
        empty = MacLibrary(empty_db)
        try:
            self.assertIsNone(MacMatcher.from_library(empty))
        finally:
            db_util.close_connection(empty_db)

    def test_size_reflects_loaded_rows(self):
        m = self._matcher()
        # 3 条记录，IP 索引 2 条（第 3 条无 IP），MAC 索引 3 条
        self.assertEqual(len(m._by_ip), 2)
        self.assertEqual(len(m._by_mac), 3)

    def test_matcher_is_pure_memory(self):
        """构建完成后关闭数据库连接，匹配仍应正常工作（证明不依赖 SQLite）。"""
        m = self._matcher()
        db_util.close_connection(self.db)
        self.assertTrue(m.apply_to(ScanResult(ip="192.168.1.11")))
        self.assertIsNotNone(m.match("", "AA:BB:CC:00:00:03"))

    # ---------- 性能特征 ----------

    def test_matching_is_fast(self):
        """65536 次匹配必须在数量级上快于「逐条 SQLite 查询」（后者需数十秒）。

        阈值刻意放宽到 5s：本测试要区分的是「内存索引」与「逐行查库」这两个
        **数量级**，不是给机器跑分。原先卡 1.0s，在负载高的 CI runner 上会抖动
        （实测同一份代码在机器繁忙时耗时 1.5s+），把正确实现误判成性能回归。
        """
        m = self._matcher()
        t0 = time.monotonic()
        for i in range(65536):
            m.match(f"192.168.1.{i % 256}", "aa:bb:cc:00:00:01")
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 5.0, msg=f"65536 次匹配耗时 {elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()
