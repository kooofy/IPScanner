# -*- coding: utf-8 -*-
"""资产台账编辑对话框与详情面板「资产信息」分区（v2.3 §3.4）。

本机 offscreen Qt **没有字体**，截图全白 —— 所以断言一律走控件文本与可见性，
不看图（项目铁律）。

⚠ **界面文案断言必须跟着当前语言走**：所有文案都经 `tr()` 渲染，
写死中文在英文 runner（CI）上必挂（2026-10-15 §3.3 踩过：`cli.main()` 会把
整个进程语言切成 en-US）。本文件的期望串一律用 `tr()` 推导，或断言
**语言无关的规范值**（`asset_lifecycle.WARRANTY_*` / 日期字面量）。

重点回归：
- **未填保修日期绝不显示「已过期」**（§3.4 验收 4）—— 这是"没填"与"过期"
  的语义区分，搞混了会让用户以为设备真的过期了。
- **非法输入不静默存空**：`values()` 抛 `ValueError`，对话框不 accept。
- **自定义字段键名原样**（§3.4 验收 2）：`{"机架": "A3"}` 存取不被翻译。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import datetime  # noqa: E402

from tests._qt_app import ensure_qt_app  # noqa: E402

ensure_qt_app()

import asset_lifecycle  # noqa: E402
import i18n  # noqa: E402
from detail_panel import DeviceDetailPanel  # noqa: E402
from scanner.models import ScanResult  # noqa: E402
from ui_dialogs.asset_edit import AssetEditDialog  # noqa: E402
from ui_utils import (  # noqa: E402
    format_custom_fields, format_warranty, warranty_status_text,
)


def _days_from_now(days):
    """本地时区的 N 天后日期（测试与 `warranty_state` 同时区推导）。"""
    return (datetime.date.today() + datetime.timedelta(days=days)).isoformat()


def _panel_text(panel) -> str:
    return panel._plain_text()


class AssetEditDialogTest(unittest.TestCase):

    def setUp(self):
        i18n.init("zh-CN")
        self.dlg = AssetEditDialog("aa:bb:cc:dd:ee:01")

    def tearDown(self):
        self.dlg.deleteLater()

    # ── 校验 ──────────────────────────────────────────

    def test_valid_values_pass_through(self):
        self.dlg.purchase_edit.setText("2024-03-15")
        self.dlg.warranty_edit.setText("2027-03-15")
        self.dlg.owner_edit.setText("张三")
        self.dlg.serial_edit.setText("SN-001")
        self.dlg.location_edit.setText("3F/A区")
        self.dlg.custom_edit.setPlainText('{"机架": "A3"}')
        out = self.dlg.values()
        self.assertEqual(out["purchase_date"], "2024-03-15")
        self.assertEqual(out["warranty_end"], "2027-03-15")
        self.assertEqual(out["owner"], "张三")
        self.assertEqual(out["serial"], "SN-001")
        self.assertEqual(out["location_tree"], "3F/A区")
        # 键名**原样**：不被翻译、不被规范化大小写（§3.4 验收 2）
        self.assertEqual(out["custom_json"], '{"机架": "A3"}')

    def test_bad_purchase_date_raises(self):
        """真正无法解析的输入才报错（斜杠 `2024/03/15` 是**合法**格式，
        写入时归一成 `2024-03-15`，见 `update_asset_lifecycle`）。"""
        self.dlg.purchase_edit.setText("not-a-date")
        with self.assertRaises(ValueError):
            self.dlg.values()

    def test_bad_warranty_date_raises(self):
        self.dlg.warranty_edit.setText("not-a-date")
        with self.assertRaises(ValueError):
            self.dlg.values()

    def test_bad_custom_json_raises(self):
        self.dlg.custom_edit.setPlainText("{机架: A3}")
        with self.assertRaises(ValueError):
            self.dlg.values()

    def test_empty_fields_are_allowed(self):
        """留空 = 清空该字段，不是错误 —— 否则用户没法删除填错的日期。"""
        out = self.dlg.values()
        self.assertEqual(out["purchase_date"], "")
        self.assertEqual(out["warranty_end"], "")
        self.assertEqual(out["custom_json"], "")

    def test_error_message_mentions_the_offending_field(self):
        """报错要说清是哪个字段、填了什么 —— 只说「格式错误」用户不知道改哪。"""
        self.dlg.warranty_edit.setText("2027-13-99")
        with self.assertRaises(ValueError) as ctx:
            self.dlg.values()
        self.assertIn("2027-13-99", str(ctx.exception))

    def test_error_message_goes_through_tr(self):
        """文案必须经 `tr()`：否则英文界面上会混出中文（CI locale 是 en-US）。"""
        self.dlg.purchase_edit.setText("bad")
        with self.assertRaises(ValueError):
            self.dlg.values()
        # 中文断言走 tr() 推导：换语言时期望串跟着换，不会挂
        expected = i18n.tr("{field}格式无效：{value}（应为 YYYY-MM-DD）").format(
            field=i18n.tr("采购日期"), value="bad")
        try:
            self.dlg.values()
        except ValueError as exc:
            self.assertEqual(str(exc), expected)

    # ── 载入 / 取值 ────────────────────────────────────

    def test_existing_values_are_loaded(self):
        dlg = AssetEditDialog("aa:bb:cc:dd:ee:01", {
            "purchase_date": "2023-01-01",
            "warranty_end": "2026-01-01",
            "owner": "李四",
            "serial": "SN-9",
            "location_tree": "机房B",
            "custom_json": '{"机架": "B1"}',
        })
        try:
            self.assertEqual(dlg.owner_edit.text(), "李四")
            self.assertEqual(dlg.warranty_edit.text(), "2026-01-01")
            self.assertEqual(dlg.custom_edit.toPlainText(), '{"机架": "B1"}')
        finally:
            dlg.deleteLater()

    def test_empty_asset_loads_blank(self):
        self.assertEqual(self.dlg.owner_edit.text(), "")
        self.assertEqual(self.dlg.custom_edit.toPlainText(), "")

    def test_custom_json_is_not_reformatted_on_load(self):
        """载入时原样回填 —— 用户存的紧凑 JSON 不该被改写成带缩进的多行。"""
        dlg = AssetEditDialog("aa:bb:cc:dd:ee:01",
                              {"custom_json": '{"a":1,"b":2}'})
        try:
            self.assertEqual(dlg.custom_edit.toPlainText(), '{"a":1,"b":2}')
        finally:
            dlg.deleteLater()

    def test_accept_is_blocked_on_invalid_input(self):
        """非法输入点击 OK → 留在对话框（不 accept），用户改完再存。

        🔴 `msg_warn` 是模态框：offscreen 下会挂死进程 —— 必须 mock 掉
        （`ui_dialogs.asset_edit.msg_warn`），否则整份测试文件在 CI 上 abort。
        """
        from unittest import mock
        with mock.patch("ui_dialogs.asset_edit.msg_warn") as warn:
            self.dlg.warranty_edit.setText("2027-02-30")
            self.dlg._on_accept()
            self.assertFalse(self.dlg.result())
            self.assertTrue(warn.called)


class DetailPanelAssetSectionTest(unittest.TestCase):
    """详情面板「资产信息」分区的渲染契约。"""

    def setUp(self):
        i18n.init("zh-CN")
        self.p = DeviceDetailPanel()
        self.result = ScanResult(ip="10.0.0.9", status="online",
                                 mac="aa:bb:cc:dd:ee:01")

    def tearDown(self):
        self.p.deleteLater()

    def test_no_asset_hides_the_section(self):
        self.p.set_device(self.result)
        text = _panel_text(self.p)
        self.assertNotIn(i18n.tr("资产信息"), text)

    def test_empty_asset_hides_the_section_and_edit_button(self):
        self.p.set_device(self.result, asset={})
        text = _panel_text(self.p)
        self.assertNotIn(i18n.tr("资产信息"), text)
        # `isVisibleTo` 而非 `isVisible`：测试里面板没 show()，后者恒 False
        self.assertFalse(self.p.btn_asset_edit.isVisibleTo(self.p))

    def test_asset_shows_owner_and_dates(self):
        self.p.set_device(self.result, asset={
            "identity_key": "aa:bb:cc:dd:ee:01",
            "purchase_date": "2024-03-15",
            "warranty_end": "2030-03-15",
            "owner": "张三",
            "location_tree": "3F/A区",
        })
        text = _panel_text(self.p)
        self.assertIn("张三", text)
        self.assertIn("2024-03-15", text)
        self.assertIn("2030-03-15", text)
        self.assertIn("3F/A区", text)
        self.assertTrue(self.p.btn_asset_edit.isVisibleTo(self.p))

    def test_unset_warranty_never_shows_expired(self):
        """🔴 §3.4 验收 4：没填保修日期 = 「未填」，**绝不**报「已过期」。"""
        self.p.set_device(self.result, asset={"owner": "张三"})
        text = _panel_text(self.p)
        self.assertIn(i18n.tr("未填"), text)
        self.assertNotIn(i18n.tr("已过期"), text)

    def test_expired_warranty_shows_expired(self):
        self.p.set_device(self.result, asset={
            "warranty_end": "2020-01-01", "owner": "张三"})
        text = _panel_text(self.p)
        self.assertIn(i18n.tr("已过期"), text)
        self.assertIn("2020-01-01", text)

    def test_expiring_warranty_is_flagged(self):
        """即将到期必须有状态行（正常保修反而不印 —— 那是默认预期）。"""
        state = asset_lifecycle.warranty_state(_days_from_now(20))
        self.assertEqual(state["status"], asset_lifecycle.WARRANTY_EXPIRING)
        self.p.set_device(self.result, asset={
            "warranty_end": state["end"], "owner": "张三"})
        text = _panel_text(self.p)
        self.assertIn(i18n.tr("即将到期"), text)

    def test_ok_warranty_has_no_status_row(self):
        state = asset_lifecycle.warranty_state(_days_from_now(300))
        self.assertEqual(state["status"], asset_lifecycle.WARRANTY_OK)
        self.p.set_device(self.result, asset={
            "warranty_end": state["end"], "owner": "张三"})
        text = _panel_text(self.p)
        self.assertNotIn(i18n.tr("保修状态"), text)

    def test_custom_fields_show_verbatim_keys(self):
        """自定义字段的键名原样显示、不被翻译（§3.4 验收 2）。"""
        self.p.set_device(self.result, asset={
            "custom_json": '{"机架": "A3", "rack": 3}'})
        text = _panel_text(self.p)
        self.assertIn("机架", text)
        self.assertIn("A3", text)
        self.assertIn("rack", text)

    def test_edit_button_emits_identity_key(self):
        received = []
        self.p.asset_edit_requested.connect(received.append)
        self.p.set_device(self.result, asset={
            "identity_key": "aa:bb:cc:dd:ee:01", "owner": "张三"})
        self.assertTrue(self.p.btn_asset_edit.isVisibleTo(self.p))
        self.p.btn_asset_edit.click()
        self.assertEqual(received, ["aa:bb:cc:dd:ee:01"])


class WarrantyDisplayTest(unittest.TestCase):
    """`ui_utils` 显示层与领域层的接线（语言无关的量也要断言）。"""

    def setUp(self):
        i18n.init("zh-CN")

    def test_unset_line_is_the_unset_word(self):
        self.assertEqual(format_warranty("", None, asset_lifecycle.WARRANTY_UNSET),
                         i18n.tr("未填"))

    def test_expired_line_counts_days(self):
        state = asset_lifecycle.warranty_state("2020-01-01")
        line = format_warranty(state["end"], state["days_left"], state["status"])
        self.assertIn("2020-01-01", line)
        self.assertIn(i18n.tr("已过期"), line)

    def test_expiring_line_shows_days_left(self):
        end = _days_from_now(10)
        state = asset_lifecycle.warranty_state(end)
        self.assertEqual(state["status"], asset_lifecycle.WARRANTY_EXPIRING)
        line = format_warranty(state["end"], state["days_left"], state["status"])
        self.assertIn(end, line)
        self.assertIn("10", line)

    def test_custom_fields_empty_is_empty(self):
        self.assertEqual(format_custom_fields(""), "")
        self.assertEqual(format_custom_fields("{}"), "")

    def test_custom_fields_lists_every_key(self):
        out = format_custom_fields('{"机架": "A3", "rack": 3}')
        self.assertIn("机架", out)
        self.assertIn("rack", out)

    def test_status_text_covers_all_states(self):
        for status in asset_lifecycle.WARRANTY_STATUSES:
            self.assertTrue(warranty_status_text(status))


class BilingualGuardTest(unittest.TestCase):
    """本机 zh-CN 过、CI en-US 也能过 —— 期望串跟着语言走。

    复现手法：import **之前**把 `locale.getdefaultlocale` 改成 en-US。
    `cli.main()` 内部会 `i18n.init(None)` 触发同款切换。
    """

    def test_key_wording_holds_in_both_languages(self):
        for lang in ("zh-CN", "en-US"):
            i18n.init(lang)
            line = format_warranty("2020-01-01", -100,
                                   asset_lifecycle.WARRANTY_EXPIRED)
            self.assertIn("2020-01-01", line, f"[{lang}] 日期丢了")
            self.assertTrue(line, f"[{lang}] 空行")
            unset = format_warranty("", None, asset_lifecycle.WARRANTY_UNSET)
            self.assertTrue(unset, f"[{lang}] 未填行是空的")
        i18n.init("zh-CN")


if __name__ == "__main__":
    unittest.main()
