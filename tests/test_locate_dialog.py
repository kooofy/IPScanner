# -*- coding: utf-8 -*-
"""设备定位对话框（`ui_dialogs/locate.py`）测试。

本机 offscreen Qt **没有字体**，截图全白 —— 所以断言一律走控件文本与可见性，
不看图（项目铁律）。
"""
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests._qt_app import ensure_qt_app  # noqa: E402

ensure_qt_app()

import history_store  # noqa: E402
from ui_dialogs.locate import LocateDeviceDialog, classify_query  # noqa: E402


class ClassifyQueryTest(unittest.TestCase):
    """输入自动判别：三种写法互不重叠，不该让用户先选类型。"""

    def test_mac_with_colons(self):
        self.assertEqual(classify_query("AA:BB:CC:DD:EE:FF"),
                         ("mac", "AA:BB:CC:DD:EE:FF"))

    def test_mac_with_dashes_and_lowercase(self):
        self.assertEqual(classify_query("aa-bb-cc-dd-ee-ff"),
                         ("mac", "aa-bb-cc-dd-ee-ff"))

    def test_ipv4(self):
        self.assertEqual(classify_query("192.168.1.50"), ("ip", "192.168.1.50"))

    def test_hostname(self):
        self.assertEqual(classify_query("FIN-PC-01"), ("hostname", "FIN-PC-01"))

    def test_surrounding_space_ignored(self):
        self.assertEqual(classify_query("  10.0.0.1  "), ("ip", "10.0.0.1"))

    def test_partial_mac_falls_back_to_hostname(self):
        """写残的 MAC 当主机名处理，而不是报「格式错误」—— 库里可能真有这么个名字。"""
        self.assertEqual(classify_query("AA:BB:CC:DD:EE"), ("hostname", "AA:BB:CC:DD:EE"))

    def test_ipv4_boundaries(self):
        self.assertEqual(classify_query("0.0.0.0"), ("ip", "0.0.0.0"))
        self.assertEqual(classify_query("255.255.255.255"),
                         ("ip", "255.255.255.255"))

    def test_invalid_ipv4_falls_back_to_hostname(self):
        """越界/残缺的点分串不是 IP，也不该报错 —— 当主机名查即可。

        这里刻意用正则而非 `ipaddress` + try/except：后者会被
        `tests/test_logging_policy.py` 的棘轮判为新增静默吞异常。
        """
        for bad in ("999.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "192.168.1."):
            self.assertEqual(classify_query(bad), ("hostname", bad), bad)


class LocateDialogTest(unittest.TestCase):

    MAC = "AA:BB:CC:DD:EE:FF"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "locate.db")
        self.dlg = LocateDeviceDialog(db_path=self.db)

    def tearDown(self):
        self.dlg.close()
        self.dlg.deleteLater()
        import db_util
        db_util.close_connection(self.db)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, port="Gi0/24", real=True):
        sid = history_store.save_snapshot(
            [{"ip": "192.168.1.50", "status": "online", "mac": self.MAC,
              "hostname": "FIN-PC-01"}], db_path=self.db)
        history_store.save_port_map(sid, [{
            "switch_ip": "10.0.0.2", "switch_name": "access-sw-1", "error": "",
            "mappings": [{"mac": self.MAC, "port_name": port,
                          "port_is_real": real}],
        }], db_path=self.db)

    def _hint_shown(self) -> bool:
        """提示行是否被显式显示。

        用 `isHidden()` 而不是 `isVisible()`：对话框没 `show()` 时，子控件的
        `isVisible()` 恒为 False（父不可见 → 子不可见），断言会永远失败。
        `isHidden()` 反映的是"有没有被 setVisible(False) 藏起来"，才是这里要测的。
        """
        return not self.dlg.hint_label.isHidden()

    def test_found_shows_switch_and_port(self):
        self._seed()
        r = self.dlg.locate(self.MAC)
        self.assertTrue(r["found"])
        text = self.dlg.result_label.text()
        self.assertIn("access-sw-1", text)
        self.assertIn("Gi0/24", text)
        self.assertIn("FIN-PC-01", text)
        self.assertFalse(self._hint_shown())

    def test_found_by_hostname(self):
        self._seed()
        r = self.dlg.locate("FIN-PC-01")
        self.assertTrue(r["found"])
        self.assertIn("Gi0/24", self.dlg.result_label.text())

    def test_bridge_port_only_is_flagged_in_ui(self):
        """只有桥接端口号时必须标出来 —— 不能当端口名糊弄过去（诚实降级）。"""
        self._seed(port="Port 5", real=False)
        self.dlg.locate(self.MAC)
        self.assertIn("仅桥接端口号", self.dlg.result_label.text())

    def test_not_found_shows_reason_and_actionable_hint(self):
        """没采集过转发表 → 说明原因，并告诉用户怎么开启。"""
        history_store.save_snapshot(
            [{"ip": "192.168.1.50", "status": "online", "mac": self.MAC,
              "hostname": "FIN-PC-01"}], db_path=self.db)
        r = self.dlg.locate(self.MAC)
        self.assertFalse(r["found"])
        self.assertIn("从未采集过交换机转发表", self.dlg.result_label.text())
        self.assertTrue(self._hint_shown())
        self.assertIn("读取交换机转发表", self.dlg.hint_label.text())

    def test_unknown_device_hint_points_at_scanning(self):
        self.dlg.locate("FF:FF:FF:FF:FF:FF")
        self.assertIn("没有这台设备的记录", self.dlg.result_label.text())
        self.assertTrue(self._hint_shown())

    def test_empty_input_shows_prompt_and_hides_hint(self):
        self.assertIsNone(self.dlg._do_locate())
        self.assertIn("请输入", self.dlg.result_label.text())
        self.assertFalse(self._hint_shown())

    def test_second_query_clears_previous_hint(self):
        """先查失败（有提示），再查成功 —— 提示必须消失，不能留上一次的。"""
        self.dlg.locate("FF:FF:FF:FF:FF:FF")
        self.assertTrue(self._hint_shown())
        self._seed()
        self.dlg.locate(self.MAC)
        self.assertFalse(self._hint_shown())

    def test_enter_key_triggers_query(self):
        """回车即查询（输入框 returnPressed 已接线）。"""
        self._seed()
        self.dlg.query_input.setText(self.MAC)
        self.dlg.query_input.returnPressed.emit()
        self.assertIn("Gi0/24", self.dlg.result_label.text())


if __name__ == "__main__":
    unittest.main()
