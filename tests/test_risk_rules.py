# -*- coding: utf-8 -*-
"""风险评分与风险列（UI_REVIEW.md P3-4）。

守四件事：

1. **算法**（`risk_rules.score_risk`）—— 纯函数，逐条规则 + 标定用例；
2. **刻度与阈值** —— 等级边界、封顶、理由带分值、垃圾输入不炸；
3. **文案** —— 每个等级 / 理由代码都有显示名，且随语言切换；
4. **接线** —— 列索引与 `COLUMN_LABELS` 一致、「安全」预设含风险列、真
   `MainWindow` 的单元格文本 / 颜色 / 切主题跟随。

标定用例是这份文件里最要紧的部分：风险列的价值**不在于"能报"，而在于
"不什么都报"**。一台普通 Windows 主机（135/139/445/3389）必须得 0 分，
否则这一列对局域网资产盘点毫无用处。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication

import i18n
import main_window
import risk_rules
from scanner import ScanResult

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


def _result(ports=(), status="online"):
    return ScanResult(ip="10.0.0.1", status=status, open_ports=list(ports))


class _FakeConflict:
    """最小冲突替身：`score_risk` 只读 `.severity` 与 `.conflict_type`。"""

    def __init__(self, conflict_type, severity):
        self.conflict_type = conflict_type
        self.severity = severity


class ScoringTest(unittest.TestCase):

    def test_clean_host_scores_zero(self):
        """🔴 标定基线：普通 Windows 主机必须 0 分。"""
        risk = risk_rules.score_risk(_result([135, 139, 445, 3389]))
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_NONE)
        self.assertEqual(risk["reasons"], [])

    def test_telnet_is_the_heaviest_single_port(self):
        risk = risk_rules.score_risk(_result([23]))
        self.assertEqual(risk["score"], 30)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_MEDIUM)

    def test_http_only_counts_when_https_is_absent(self):
        plain = risk_rules.score_risk(_result([80]))
        secure = risk_rules.score_risk(_result([80, 443]))
        self.assertEqual(plain["score"], 10)
        self.assertEqual(secure["score"], 0,
                         "同机开了 HTTPS 还报「HTTP 明文」就是噪声")

    def test_scores_add_up_and_are_capped(self):
        risk = risk_rules.score_risk(_result([21, 23, 69, 161, 5900, 80]))
        self.assertEqual(risk["score"], risk_rules.RISK_MAX,
                         "多项叠加必须封顶到 RISK_MAX")

    def test_reasons_carry_points_and_sum_to_the_score(self):
        risk = risk_rules.score_risk(_result([23, 21]))
        self.assertEqual(sum(p for _, p in risk["reasons"]), risk["score"])
        self.assertEqual([code for code, _ in risk["reasons"]],
                         ["cleartext_telnet", "cleartext_ftp"],
                         "理由必须保序，tooltip 才好读")

    def test_conflict_points_follow_the_detector_severity(self):
        """冲突分值直接取严重级别 —— 不另立一套判断，避免两处漂移。"""
        high = risk_rules.score_risk(
            _result(), [_FakeConflict("duplicate_mac", "high")])
        warn = risk_rules.score_risk(
            _result(), [_FakeConflict("unknown_device", "warning")])
        self.assertEqual(high["score"], 40)
        self.assertEqual(warn["score"], 20)
        self.assertEqual(high["reasons"][0][0], "duplicate_mac")

    def test_conflict_and_ports_combine(self):
        risk = risk_rules.score_risk(
            _result([23]), [_FakeConflict("duplicate_mac", "high")])
        self.assertEqual(risk["score"], 70)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_HIGH)

    def test_none_result_scores_zero(self):
        risk = risk_rules.score_risk(None)
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], risk_rules.RISK_LEVEL_NONE)

    def test_calibration_examples(self):
        """真实端口组合的等级必须符合直觉（否则这一列会变成噪声）。"""
        cases = [
            ("普通 Windows 主机", [135, 139, 445, 3389],
             risk_rules.RISK_LEVEL_NONE),
            ("打印机", [80, 161, 9100], risk_rules.RISK_LEVEL_LOW),
            ("群晖 NAS", [80, 445, 5000], risk_rules.RISK_LEVEL_LOW),
            ("路由器", [23, 80, 161], risk_rules.RISK_LEVEL_MEDIUM),
            ("网络摄像头", [23, 80, 554], risk_rules.RISK_LEVEL_MEDIUM),
        ]
        for name, ports, want in cases:
            with self.subTest(case=name):
                got = risk_rules.score_risk(_result(ports))["level"]
                self.assertEqual(got, want, "%s 的等级判错了" % name)


class LevelThresholdTest(unittest.TestCase):

    def test_boundaries(self):
        cases = [(0, "none"), (1, "low"), (29, "low"), (30, "medium"),
                 (59, "medium"), (60, "high"), (100, "high")]
        for score, want in cases:
            with self.subTest(score=score):
                self.assertEqual(risk_rules.risk_level(score), want)

    def test_thresholds_are_descending(self):
        """`risk_level()` 顺序命中即返回，阈值不降序会命中错的一档。"""
        scores = [t for t, _ in risk_rules.RISK_THRESHOLDS]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_garbage_scores_zero(self):
        for value in (None, "", "abc", -5):
            with self.subTest(value=value):
                self.assertEqual(risk_rules.risk_level(value),
                                 risk_rules.RISK_LEVEL_NONE)


class LabelTest(unittest.TestCase):

    def tearDown(self):
        i18n.init("zh-CN")

    def test_level_labels_follow_language(self):
        i18n.init("zh-CN")
        zh = risk_rules.risk_level_label(risk_rules.RISK_LEVEL_HIGH)
        i18n.init("en-US")
        en = risk_rules.risk_level_label(risk_rules.RISK_LEVEL_HIGH)
        i18n.init("zh-CN")
        self.assertEqual(zh, "高")
        self.assertEqual(en, "High")

    def test_every_level_has_a_token_and_a_label(self):
        for level in (risk_rules.RISK_LEVEL_NONE, risk_rules.RISK_LEVEL_LOW,
                      risk_rules.RISK_LEVEL_MEDIUM, risk_rules.RISK_LEVEL_HIGH):
            with self.subTest(level=level):
                self.assertIn(level, risk_rules.RISK_LEVEL_TOKEN)
                self.assertTrue(risk_rules._RISK_LEVEL_TEXT.get(level),
                                "%s 没有显示名" % level)

    def test_every_reason_code_has_a_label(self):
        codes = {code for code, _, _ in risk_rules._PORT_RULES}
        codes.add(risk_rules._REASON_CLEARTEXT_HTTP)
        codes.update({"duplicate_mac", "duplicate_hostname", "unknown_device"})
        for code in codes:
            with self.subTest(code=code):
                self.assertTrue(
                    risk_rules._REASON_TEXT.get(code),
                    "%s 没有显示名 —— tooltip 会把裸代码露给用户" % code)

    def test_unknown_codes_pass_through(self):
        self.assertEqual(risk_rules.reason_label("nope"), "nope")
        self.assertEqual(risk_rules.risk_level_label("nope"), "nope")


class FormatTest(unittest.TestCase):

    def tearDown(self):
        i18n.init("zh-CN")

    def test_none_level_renders_a_dash(self):
        i18n.init("zh-CN")
        self.assertEqual(
            risk_rules.format_risk(
                {"score": 0, "level": risk_rules.RISK_LEVEL_NONE, "reasons": []}),
            "—")

    def test_medium_level_renders_label_and_score(self):
        i18n.init("zh-CN")
        self.assertEqual(
            risk_rules.format_risk(
                {"score": 55, "level": risk_rules.RISK_LEVEL_MEDIUM,
                 "reasons": []}),
            "中 55")

    def test_tooltip_splits_the_score(self):
        i18n.init("zh-CN")
        tip = risk_rules.format_risk_tooltip(risk_rules.score_risk(_result([23, 21])))
        self.assertIn("50", tip)
        self.assertIn("Telnet", tip)
        self.assertIn("FTP", tip)

    def test_tooltip_for_a_clean_host(self):
        i18n.init("zh-CN")
        tip = risk_rules.format_risk_tooltip(risk_rules.score_risk(_result([])))
        self.assertTrue(tip.strip(), "零分也要给一句解释，不能是空 tooltip")


class ColumnWiringTest(unittest.TestCase):
    """列索引 / 预设的接线（漂移了这列就会错位到别的列上）。"""

    def test_column_index_matches_the_label_table(self):
        self.assertEqual(main_window.COLUMN_LABELS[risk_rules.RISK_COLUMN],
                         "风险",
                         "RISK_COLUMN 与 COLUMN_LABELS 不同步了")

    def test_security_preset_includes_the_risk_column(self):
        presets = {key: cols for key, _, cols in main_window.COLUMN_PRESETS}
        self.assertIn(risk_rules.RISK_COLUMN, presets["security"],
                      "「安全」预设缺了风险列 —— 恰恰缺了那句结论")

    def test_every_preset_index_is_a_real_column(self):
        for key, _, cols in main_window.COLUMN_PRESETS:
            for col in cols:
                self.assertTrue(0 <= col < len(main_window.COLUMN_LABELS),
                                "%s 预设含不存在的列 %d" % (key, col))

    def test_all_preset_covers_every_column(self):
        all_cols = {key: cols for key, _, cols in main_window.COLUMN_PRESETS}["all"]
        self.assertEqual(sorted(all_cols),
                         list(range(len(main_window.COLUMN_LABELS))))

    def test_every_column_has_a_default_width(self):
        for col in range(len(main_window.COLUMN_LABELS)):
            with self.subTest(col=col):
                self.assertIn(col, main_window._BASE_COLUMN_WIDTHS,
                              "第 %d 列没有默认宽度" % col)


class RiskCellTest(unittest.TestCase):
    """真 `MainWindow`：单元格文本、颜色、切主题跟随。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_risk_")
        self._orig = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        i18n.init("zh-CN")
        self.mw = main_window.MainWindow()
        self.mw.show()
        QApplication.processEvents()

    def tearDown(self):
        self.mw.close()
        main_window.data_dir = self._orig
        i18n.init("zh-CN")

    def _add(self, ip, ports):
        self.mw._upsert_table_row(
            ScanResult(ip=ip, status="online", open_ports=list(ports)))
        return self.mw._ip_item_map[ip]

    def test_clean_host_shows_a_dash(self):
        item = self._add("10.0.0.1", [445])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "—")

    def test_risky_host_shows_level_and_score(self):
        item = self._add("10.0.0.2", [23, 21])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "中 50")

    def test_cell_is_coloured_by_level(self):
        clean = self._add("10.0.0.3", [445])
        risky = self._add("10.0.0.4", [23, 21, 5900])
        self.assertNotEqual(
            clean.foreground(risk_rules.RISK_COLUMN).color().name(),
            risky.foreground(risk_rules.RISK_COLUMN).color().name(),
            "风险等级不同却同色")

    def test_tooltip_explains_the_score(self):
        item = self._add("10.0.0.7", [23])
        self.assertIn("Telnet", item.toolTip(risk_rules.RISK_COLUMN))

    def test_conflict_raises_the_score(self):
        """冲突一变，风险列必须跟着变 —— 两处不同源就会出现自相矛盾的行。"""
        from conflict_detector import SEVERITY_HIGH, Conflict
        item = self._add("10.0.0.5", [])
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "—")
        self.mw._conflicts = [
            Conflict("duplicate_mac", SEVERITY_HIGH, "x", ips=["10.0.0.5"])]
        self.mw._conflict_ips = {"10.0.0.5": ["duplicate_mac"]}
        self.mw._apply_row_marks(item, "10.0.0.5")
        self.assertEqual(item.text(risk_rules.RISK_COLUMN), "中 40")

    def test_cell_colour_follows_the_theme(self):
        item = self._add("10.0.0.6", [23, 21])
        self.mw.dark_mode = False
        self.mw._refresh_theme_marks()
        light = item.foreground(risk_rules.RISK_COLUMN).color().name()
        self.mw.dark_mode = True
        self.mw._refresh_theme_marks()
        dark = item.foreground(risk_rules.RISK_COLUMN).color().name()
        self.assertNotEqual(light, dark, "风险列的颜色没有跟随主题")

    def test_cell_is_centred_like_the_other_short_columns(self):
        """短内容列（状态 / 响应时间 / 风险）一律居中 —— 与左对齐的长文本列区分开。"""
        item = self._add("10.0.0.8", [23])
        align = int(item.textAlignment(risk_rules.RISK_COLUMN))
        self.assertTrue(align & int(Qt.AlignHCenter),
                        "风险列没有水平居中（与状态、响应时间列不一致）")
        self.assertTrue(align & int(Qt.AlignVCenter),
                        "风险列没有垂直居中")


if __name__ == "__main__":
    unittest.main()
