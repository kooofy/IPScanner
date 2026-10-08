# -*- coding: utf-8 -*-
"""详情面板与空状态面板的行为契约（UI_REVIEW P0-1 / P0-2）。

用真实的 Qt widget（offscreen）验证渲染结果，而不是断言"函数被调用过" ——
这两块 UI 的价值全在"到底显示了什么"，只测调用链等于没测。

重点回归：
- **无 banner 的服务必须仍然显示**。详情面板早期实现把所有分区都按
  「标签/值」两栏渲染，值为空即整行跳过；而 SMB/RDP 这类服务经常没有
  banner，结果就是"用户最想看的那几行被悄悄吃掉"。
- 冲突设备的 IP 取法。`_apply_row_marks` 会把第 0 列文本改成 `"⚠ <ip>"`，
  任何"读第 0 列文本当 IP"的代码都会拿到脏字符串。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QTreeWidget

import i18n
from empty_state import EmptyStatePanel
from detail_panel import DeviceDetailPanel
from main_window_tree import ResultTreeItem, TreeMixin, _ROLE_DEV_IP
from scanner.models import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
    i18n.init("zh-CN")


class _TreeHarness(TreeMixin, QTreeWidget):
    """只依赖 _item_ip / _ROLE_DEV_IP 的最小宿主。"""

    def __init__(self):
        QTreeWidget.__init__(self)
        self.table = self
        self._ip_item_map = {}
        self._result_map = {}


class DetailPanelRenderTest(unittest.TestCase):

    def setUp(self):
        self.p = DeviceDetailPanel()

    def tearDown(self):
        self.p.deleteLater()

    def test_header_carries_ip_status_and_rtt(self):
        r = ScanResult(ip="10.0.0.5", status="online", response_time=12.34)
        self.p.set_device(r)
        text = self.p.title.text()
        self.assertIn("10.0.0.5", text)
        self.assertIn(tr_online(), text)
        self.assertIn("12.3", text)

    def test_service_without_banner_is_still_listed(self):
        """核心回归：无 banner 的服务不能被当成"空行"丢弃。"""
        r = ScanResult(ip="10.0.0.6", status="online", service_details=[
            {"proto": "SMB", "port": 445, "banner": ""},
            {"proto": "SSH", "port": 22, "banner": "OpenSSH_8.9p1"},
        ])
        self.p.set_device(r)
        plain = self.p._plain_text()
        self.assertIn("445", plain)
        self.assertIn("22", plain)
        self.assertIn("OpenSSH_8.9p1", plain)

    def test_services_fall_back_to_plain_list(self):
        """旧结果没有 service_details 时，退回 services 列表展示。"""
        r = ScanResult(ip="10.0.0.7", status="online", services=["HTTP", "RDP"])
        self.p.set_device(r)
        plain = self.p._plain_text()
        self.assertIn("HTTP", plain)
        self.assertIn("RDP", plain)

    def test_conflict_notes_appear_under_risk(self):
        r = ScanResult(ip="10.0.0.8", status="online")
        self.p.set_device(r, ["[高] IP 冲突：与 AA:BB 共用此地址"])
        plain = self.p._plain_text()
        self.assertIn(tr_risk(), plain)
        self.assertIn("AA:BB", plain)

    def test_no_conflict_means_no_risk_section(self):
        r = ScanResult(ip="10.0.0.9", status="online", hostname="PC-1")
        self.p.set_device(r, [])
        self.assertNotIn(tr_risk(), self.p._plain_text())

    def test_clear_restores_hint_and_drops_actions(self):
        r = ScanResult(ip="10.0.0.10", status="online", hostname="PC-2")
        self.p.set_device(r)
        self.assertTrue(self.p.hint.isHidden())
        self.assertFalse(self.p.btn_copy.isHidden())

        self.p.clear()
        self.assertFalse(self.p.hint.isHidden())
        self.assertTrue(self.p.btn_copy.isHidden())
        self.assertEqual(self.p._plain_text(), "")

    def test_device_with_only_ip_does_not_render_empty_panel(self):
        """极端输入：只有 IP、其余全空时也要给一句说明，不能是一块空白。"""
        self.p.set_device(ScanResult(ip="10.0.0.11", status="offline"))
        plain = self.p._plain_text()
        self.assertIn("10.0.0.11", plain)
        self.assertGreater(len(plain.strip().splitlines()), 1)

    def test_sections_whose_fields_are_all_empty_are_dropped(self):
        """核心回归：不能出现"只印一个分区标题、下面空无一行"的空壳分区。"""
        r = ScanResult(ip="10.0.0.20", status="offline")
        self.p.set_device(r)
        plain = self.p._plain_text()
        self.assertNotIn(f"[{i18n.tr('系统')}]", plain)
        self.assertNotIn(f"[{i18n.tr('服务')}]", plain)
        self.assertNotIn(f"[{i18n.tr('风险')}]", plain)

    def test_probe_method_hidden_when_no_ports(self):
        """离线主机没有开放端口时，不该显示"端口探测方式"。"""
        r = ScanResult(ip="10.0.0.21", status="offline")
        self.p.set_device(r)
        self.assertNotIn(i18n.tr("端口探测方式"), self.p._plain_text())

    def test_probe_method_shown_when_ports_exist(self):
        r = ScanResult(ip="10.0.0.22", status="online", open_ports=[22],
                       scan_method="syn")
        self.p.set_device(r)
        self.assertIn(i18n.tr("端口探测方式"), self.p._plain_text())

    def test_empty_pair_values_are_skipped(self):
        """两栏分区里，空值行应被跳过（避免一片空标签）。"""
        r = ScanResult(ip="10.0.0.12", status="online", hostname="PC-3")
        self.p.set_device(r)
        plain = self.p._plain_text()
        self.assertIn("PC-3", plain)
        # 未提供的字段（制造商/序列号…）不应出现标签
        self.assertNotIn(tr_serial() + ":", plain)


class DetailPanelSignalsTest(unittest.TestCase):

    def setUp(self):
        self.p = DeviceDetailPanel()

    def tearDown(self):
        self.p.deleteLater()

    def test_rescan_emits_current_ip(self):
        got = []
        self.p.rescan_requested.connect(got.append)
        self.p.set_device(ScanResult(ip="10.0.1.1", status="online"))
        self.p.btn_rescan.click()
        self.assertEqual(got, ["10.0.1.1"])

    def test_copy_emits_plain_text(self):
        got = []
        self.p.copy_requested.connect(got.append)
        self.p.set_device(ScanResult(ip="10.0.1.2", status="online", hostname="H1"))
        self.p.btn_copy.click()
        self.assertEqual(len(got), 1)
        self.assertIn("10.0.1.2", got[0])
        self.assertIn("H1", got[0])


class EmptyStatePanelTest(unittest.TestCase):

    def setUp(self):
        self.e = EmptyStatePanel()

    def tearDown(self):
        self.e.deleteLater()

    def test_scan_hint_updates_text(self):
        self.e.set_scan_hint("级别 快速 · 端口数 4")
        self.assertEqual(self.e.hint.text(), "级别 快速 · 端口数 4")

    def test_empty_hint_is_hidden_when_blank(self):
        self.e.set_scan_hint("")
        self.assertTrue(self.e.hint.isHidden())

    def test_buttons_emit_their_signals(self):
        local, scan = [], []
        self.e.scan_local_requested.connect(lambda: local.append(1))
        self.e.scan_requested.connect(lambda: scan.append(1))
        self.e.btn_local.click()
        self.e.btn_scan.click()
        self.assertEqual(local, [1])
        self.assertEqual(scan, [1])


class ItemIpRoleTest(unittest.TestCase):
    """`_item_ip` 必须返回规范 IP，不受冲突标记前缀污染。"""

    def setUp(self):
        self.h = _TreeHarness()
        self.item = ResultTreeItem()
        self.h.addTopLevelItem(self.item)

    def tearDown(self):
        self.h.clear()
        self.h.deleteLater()

    def test_returns_canonical_ip_after_conflict_mark(self):
        self.item.setData(0, _ROLE_DEV_IP, "192.168.1.42")
        # 模拟 _apply_row_marks 的行为：文本被加上警告前缀
        self.item.setText(0, "⚠ 192.168.1.42")
        self.assertEqual(self.h._item_ip(self.item), "192.168.1.42")

    def test_falls_back_to_text_when_role_missing(self):
        self.item.setText(0, "10.0.0.99")
        self.assertEqual(self.h._item_ip(self.item), "10.0.0.99")

    def test_service_child_resolves_to_parent_ip(self):
        self.item.setData(0, _ROLE_DEV_IP, "10.0.0.50")
        child = ResultTreeItem()
        self.item.addChild(child)
        self.assertEqual(self.h._item_ip(child), "10.0.0.50")

    def test_none_item_is_safe(self):
        self.assertIsNone(self.h._item_ip(None))


def tr_online() -> str:
    return i18n.tr("在线")


def tr_risk() -> str:
    return i18n.tr("风险")


def tr_serial() -> str:
    return i18n.tr("序列号")


if __name__ == "__main__":
    unittest.main()
