# -*- coding: utf-8 -*-
"""「随机 MAC」判据与制造商列的显示契约。

背景：手机 / 笔记本开了「随机硬件地址」后，MAC 的 U/L 位（首字节 bit 1）= 1，
前缀不属于任何厂商，OUI 查询**必然**返回空串。若界面把它和"库里没收录的陌生
厂商"都显示成 `—`，用户就无法区分这两种情况 —— 前者不用管，后者要排查。

因此契约有两条，都在这里钉死：
1. `is_randomized_mac()` 只看 U/L 位，非法输入一律返回 False（宁可显示 `—`
   也不要谎报"随机"）；
2. 制造商列：**有厂商名时厂商优先**；没有厂商且是随机 MAC 时显示「随机 MAC」；
   其余情况仍是 `—`。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QTreeWidget

import i18n
from i18n import tr
from main_window_tree import ResultTreeItem, TreeMixin
from oui_database import is_randomized_mac
from scanner.models import ScanResult
from theme_tokens import token

_app = None
_orig_lang = None


def setUpModule():
    # 统一走 ensure_qt_app()：它保证进程内那个唯一的 application 对象是
    # QApplication 而不是 QCoreApplication，否则建 widget 会让进程直接 abort。
    global _app, _orig_lang
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
    _orig_lang = i18n.current_lang()
    i18n.init("zh-CN")


def tearDownModule():
    # 还原进程语言：不还原会污染字母序在后的测试模块（CI 的 locale 是 en-US，
    # 本机是 zh-CN，两边表现不同）。
    if _orig_lang:
        i18n.init(_orig_lang)


class IsRandomizedMacTest(unittest.TestCase):
    """U/L 位判据。第二十六进制位是 2/6/A/E 即为随机（本地管理）。"""

    def test_locally_administered_addresses(self):
        # 第 2 个十六进制位 ∈ {2, 6, A, E} ⇒ 本地管理位 = 1
        for mac in (
            "F2:67:D1:B2:C9:48", "66:F9:5B:19:6C:5E", "42:FA:C5:64:B8:6E",
            "82:53:E5:34:50:27", "5E:03:3A:7D:DB:CE", "9E:F5:32:FA:3D:42",
            "02:A3:CC:11:1C:B3", "A2:37:9B:CE:DE:15", "3E:0F:2B:9C:1A:D1",
            "CE:EC:58:F7:39:EF", "E6:56:23:5E:A3:0C", "D6:1F:30:5A:68:2C",
            "86:1E:CC:6D:49:5C", "6E:6B:1F:F5:EA:25", "BE:B3:78:1E:96:4F",
            "0E:FB:CE:67:5B:60", "FE:4D:95:E8:15:7C",
        ):
            self.assertTrue(is_randomized_mac(mac), mac)

    def test_globally_unique_addresses(self):
        # 第 2 个十六进制位 ∈ {0, 4, 8, C} ⇒ 厂商烧录的全局唯一地址
        for mac in (
            "C0:38:96:38:4D:F9", "00:F4:8D:F0:E2:1D", "04:79:75:20:00:9D",
            "88:B1:11:E6:59:6A", "50:2B:73:D9:01:E6", "A8:4A:28:63:1A:46",
            "64:C3:94:88:FB:C5", "18:47:3D:B3:32:3F", "3C:A6:F6:1F:7A:5D",
            "6C:1F:F7:E4:97:A4", "24:00:00:00:00:01", "AC:DE:48:00:11:22",
        ):
            self.assertFalse(is_randomized_mac(mac), mac)

    def test_accepts_dashes_and_case(self):
        self.assertTrue(is_randomized_mac("f2-67-d1-b2-c9-48"))
        self.assertTrue(is_randomized_mac("F2-67-D1-B2-C9-48"))
        self.assertFalse(is_randomized_mac("c0-38-96-38-4d-f9"))

    def test_empty_and_none_are_not_random(self):
        for v in ("", None):
            self.assertFalse(is_randomized_mac(v))

    def test_malformed_is_not_random(self):
        """无法解析的值**不能**被当成随机 MAC —— 否则会把陌生设备说成"隐私地址"。"""
        for v in ("zz:11:22:33:44:55", "G0:11:22:33:44:55", "1", ":", "0x02"):
            self.assertFalse(is_randomized_mac(v), v)


class _Harness(TreeMixin, QTreeWidget):
    """最小宿主：`_set_item_data` 只依赖 table / dark_mode / 两个颜色函数。"""

    def __init__(self):
        QTreeWidget.__init__(self)
        self.table = self
        self.dark_mode = False
        # `_set_item_data` 末尾会走 `_apply_row_marks` → `_apply_risk_mark`，
        # 那里读 `self._result_map`（唯一没有 getattr 兜底的属性）。
        # 空字典 ⇒ 取到 None ⇒ 风险列直接返回，不影响本测试关心的第 4 列。
        self._result_map = {}

    def _link_color(self):
        return QColor(token("accent", self.dark_mode))


class ManufacturerColumnTest(unittest.TestCase):
    """第 4 列（制造商）的显示优先级。"""

    def setUp(self):
        self.h = _Harness()

    def _col4(self, **kw):
        result = ScanResult(ip="10.0.0.1", status="online", **kw)
        item = ResultTreeItem()
        self.h._set_item_data(item, result)
        return item.text(4)

    def test_vendor_wins(self):
        self.assertEqual(self._col4(vendor="Apple"), "Apple")

    def test_vendor_wins_even_on_random_mac(self):
        """厂商名是权威信息，不能被"随机 MAC"覆盖（个别虚拟网卡两样都有）。"""
        self.assertEqual(
            self._col4(mac="F2:67:D1:B2:C9:48", vendor="VMware"), "VMware")

    def test_random_mac_without_vendor_is_labelled(self):
        self.assertEqual(
            self._col4(mac="F2:67:D1:B2:C9:48"), tr("随机 MAC"))

    def test_globally_unique_without_vendor_stays_dash(self):
        """真实 MAC 查不到厂商 = 库里没收录，仍然是 `—`（不谎报随机）。"""
        self.assertEqual(self._col4(mac="C0:38:96:38:4D:F9"), "—")

    def test_no_mac_stays_dash(self):
        self.assertEqual(self._col4(), "—")

    def test_device_type_still_appended(self):
        """随机 MAC + 地址库设备类型 ⇒ 两者都要保留，不能互相吞掉。"""
        self.assertEqual(
            self._col4(mac="F2:67:D1:B2:C9:48", device_type="手机"),
            tr("随机 MAC") + " · 手机")

    def test_device_type_alone_unchanged(self):
        self.assertEqual(self._col4(device_type="打印机"), "打印机")

    def test_label_is_translated(self):
        """标签必须走 tr()，且 en-US.json 里要有对应译文（否则英文界面会漏中文）。"""
        import io
        import json
        path = os.path.join(ROOT, "i18n", "en-US.json")
        with io.open(path, encoding="utf-8") as f:
            table = json.load(f)
        self.assertIn("随机 MAC", table)
        self.assertTrue(table["随机 MAC"])


if __name__ == "__main__":
    unittest.main()
