# -*- coding: utf-8 -*-
"""三档扫描级别 + 端口 Top N 显示 单元测试（纯函数，无 PyQt 依赖）。"""
import unittest

from scanner import (
    get_ports_for_level, format_ports_display, COMMON_PORTS,
    PORT_DISPLAY_TOP_N,
)


class TestScanLevels(unittest.TestCase):
    def test_quick_is_common_ports(self):
        # quick 应保持历史默认行为（高频服务端口），向后兼容
        self.assertEqual(get_ports_for_level("quick"), COMMON_PORTS)
        self.assertEqual(len(get_ports_for_level("quick")), len(COMMON_PORTS))

    def test_standard_is_well_known_range(self):
        ports = get_ports_for_level("standard")
        self.assertEqual(ports, list(range(1, 1024)))
        self.assertEqual(len(ports), 1023)

    def test_all_is_full_range(self):
        ports = get_ports_for_level("all")
        self.assertEqual(ports, list(range(1, 65536)))
        self.assertEqual(len(ports), 65535)

    def test_unknown_level_falls_back_to_common(self):
        self.assertEqual(get_ports_for_level("bogus"), COMMON_PORTS)
        self.assertEqual(get_ports_for_level(""), COMMON_PORTS)
        self.assertEqual(get_ports_for_level(None), COMMON_PORTS)


class TestFormatPortsDisplay(unittest.TestCase):
    def test_empty(self):
        disp, full = format_ports_display([])
        self.assertEqual(disp, "—")
        self.assertEqual(full, "—")

    def test_empty_none(self):
        disp, full = format_ports_display(None)
        self.assertEqual(disp, "—")
        self.assertEqual(full, "—")

    def test_within_top_n_full_shown(self):
        ports = [80, 443, 22]
        disp, full = format_ports_display(ports)
        # 排序后完整显示，且 display == full
        self.assertEqual(disp, "22, 80, 443")
        self.assertEqual(full, "22, 80, 443")

    def test_exact_top_n_no_truncation(self):
        ports = list(range(1, PORT_DISPLAY_TOP_N + 1))
        disp, full = format_ports_display(ports)
        # 恰好等于 top_n 不应截断
        self.assertEqual(disp.count(",") + 1, PORT_DISPLAY_TOP_N)
        self.assertEqual(disp, full)

    def test_over_top_n_truncated_with_more(self):
        ports = list(range(1, 31))  # 30 个端口，top_n 默认 20
        disp, full = format_ports_display(ports)
        self.assertIn("+10 more", disp)
        # display 含前 20 + "+10 more"
        self.assertEqual(disp.count(",") + 1, PORT_DISPLAY_TOP_N + 1)  # 20 个 + 1 个 "+10 more"
        # full 仍是全部 30 个，且不含 "more"
        self.assertNotIn("more", full)
        self.assertEqual(full.count(",") + 1, 30)

    def test_custom_top_n(self):
        ports = list(range(1, 26))  # 25 个
        disp, full = format_ports_display(ports, top_n=5)
        self.assertIn("+20 more", disp)
        self.assertEqual(full.count(",") + 1, 25)

    def test_unsorted_input_is_sorted(self):
        ports = [443, 22, 80]
        disp, full = format_ports_display(ports)
        self.assertEqual(disp, "22, 80, 443")


if __name__ == "__main__":
    unittest.main(verbosity=2)
