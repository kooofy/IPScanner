# -*- coding: utf-8 -*-
"""服务子项渲染契约（P2-8）。

`_add_service_children` 的子项内容完全由 result 的服务/WMI/NetBIOS 字段决定，
因此可以按内容签名判断"是否需要重建"。旧实现无条件 `takeChildren()` 全量重建，
带来两个用户可见的问题：

- 已展开的设备，其子项展开态/选中态在每次刷新时被清空；
- 扫描过程中每行都会被刷新一次，重建造成可感知的闪烁。

这里用真实的 QTreeWidget（offscreen）验证"内容没变就不重建、变了必须重建"。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QTreeWidget

import i18n
from main_window_tree import _ROLE_SVC_SIG, ResultTreeItem, TreeMixin
from scanner.constants import SVC_SMB
from scanner.models import ScanResult

_app = None


def setUpModule():
    # 统一走 ensure_qt_app()：它保证进程内那个唯一的 application 对象是
    # QApplication 而不是 QCoreApplication，否则建 widget 会让进程直接 abort。
    # 详见 tests/_qt_app.py。
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


class _Harness(TreeMixin, QTreeWidget):
    """最小宿主。

    `_add_service_children` 只依赖 self.table / self._service_icon /
    self._link_color / self.style()。其中 `_link_color` 实际定义在 MainWindow 上，
    这里给个桩即可 —— 没必要为了测一个渲染细节去构造整个 MainWindow。
    """

    def __init__(self):
        QTreeWidget.__init__(self)
        self.table = self

    def _service_icon(self, proto):
        return None

    def _link_color(self):
        return QColor("#2563EB")


class ServiceChildrenRebuildTest(unittest.TestCase):

    def setUp(self):
        self.h = _Harness()
        self.item = ResultTreeItem()
        self.h.addTopLevelItem(self.item)

    def tearDown(self):
        self.h.clear()
        self.h.deleteLater()

    def test_children_are_built(self):
        r = ScanResult(ip="10.0.0.1", services=["HTTP", "SSH"])
        self.h._add_service_children(self.item, r)
        self.assertEqual(self.item.childCount(), 2)

    def test_unchanged_content_reuses_existing_children(self):
        """核心回归：内容不变时必须复用原有子项对象。

        断言"是不是同一个对象"比断言调用次数更贴近用户可见行为 ——
        重建换来的新对象必然丢失展开态与选中态。
        """
        r = ScanResult(ip="10.0.0.1", services=["HTTP", "SSH"])
        self.h._add_service_children(self.item, r)
        first = self.item.child(0)

        self.h._add_service_children(self.item, r)

        self.assertIs(self.item.child(0), first,
                      "内容未变时子项被重建了（P2-8 回归）")

    def test_added_service_rebuilds_children(self):
        r = ScanResult(ip="10.0.0.1", services=["HTTP"])
        self.h._add_service_children(self.item, r)
        self.assertEqual(self.item.childCount(), 1)

        r.services.append("SSH")
        self.h._add_service_children(self.item, r)

        self.assertEqual(self.item.childCount(), 2, "服务增加后未重建子项")

    def test_banner_change_rebuilds_children(self):
        r = ScanResult(ip="10.0.0.1", services=["HTTP"])
        self.h._add_service_children(self.item, r)
        first = self.item.child(0)

        r.service_details = [{"proto": "HTTP", "port": 80, "banner": "nginx/1.22"}]
        self.h._add_service_children(self.item, r)

        self.assertIsNot(self.item.child(0), first)
        self.assertIn("nginx", self.item.child(0).text(0))

    def test_removed_services_clear_children_and_hide_indicator(self):
        r = ScanResult(ip="10.0.0.1", services=["HTTP"])
        self.h._add_service_children(self.item, r)
        self.assertEqual(self.item.childCount(), 1)

        r.services = []
        r.service_details = []
        self.h._add_service_children(self.item, r)

        self.assertEqual(self.item.childCount(), 0)
        self.assertEqual(self.item.childIndicatorPolicy(),
                         ResultTreeItem.DontShowIndicator)

    def test_wmi_and_netbios_children(self):
        r = ScanResult(ip="10.0.0.1",
                       wmi_identified=True,
                       wmi_manufacturer="Dell Inc.", wmi_model="OptiPlex 7080",
                       netbios_identified=True, netbios_name="PC-01")
        self.h._add_service_children(self.item, r)
        self.assertEqual(self.item.childCount(), 2)

    def test_wmi_field_change_rebuilds_children(self):
        """WMI 子项的文本由多个字段拼成，任一变化都必须触发重建。"""
        r = ScanResult(ip="10.0.0.1", wmi_identified=True, wmi_model="OptiPlex 7080")
        self.h._add_service_children(self.item, r)
        first = self.item.child(0)

        r.wmi_serial = "ABC123"
        self.h._add_service_children(self.item, r)

        self.assertIsNot(self.item.child(0), first)
        self.assertIn("ABC123", self.item.child(0).text(0))

    def test_children_follow_language_switch(self):
        """签名必须包含**翻译后**的协议名。

        否则切换界面语言后签名不变，子项会停留在旧语言 ——
        这是把惰性翻译引入渲染路径后最容易踩的坑。
        """
        r = ScanResult(ip="10.0.0.1", services=[SVC_SMB])

        i18n.init("zh-CN")
        try:
            self.h._add_service_children(self.item, r)
            zh = self.item.child(0).text(0)
            i18n.init("en-US")
            self.h._add_service_children(self.item, r)
            en = self.item.child(0).text(0)
        finally:
            i18n.init("zh-CN")

        self.assertNotEqual(zh, en, "切换语言后服务子项未跟随翻译")
        self.assertIn("SMB", zh)
        self.assertIn("SMB", en)

    def test_signature_slot_does_not_collide_with_sort_key(self):
        """签名槽位不能覆盖第 0 列的排序键（IP 数值排序依赖它）。

        `_set_item_data` 把 IP 数值排序键写在 (0, UserRole)，子项把
        proto/ip/banner 写在 (0, UserRole+1..+5) —— 签名必须避开这些槽位。
        """
        from ui_utils import _ip_to_int

        self.item.setData(0, Qt.UserRole, _ip_to_int("192.168.1.10"))
        r = ScanResult(ip="192.168.1.10", services=["HTTP"])
        self.h._add_service_children(self.item, r)

        self.assertEqual(self.item.data(0, Qt.UserRole), 0xC0A8010A,
                         "排序键被服务子项渲染覆盖了")
        self.assertIsNotNone(self.item.data(0, _ROLE_SVC_SIG),
                             "签名未写入预期槽位")


if __name__ == "__main__":
    unittest.main()
