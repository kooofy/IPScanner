# -*- coding: utf-8 -*-
"""概览仪表盘测试（UI_REVIEW P3-2）。

分三层：
1. `ui_logic.build_overview` —— 纯统计，脱离 Qt 也能跑；
2. `ui_logic.build_subnet_stats` —— 从 `SubnetUtilizationDialog._analyze`
   提取后的**行为等价**回归（对话框与概览共用同一份数据）；
3. `OverviewPanel` —— 渲染层，重点是"规范值必须惰性翻译"和"重填不泄漏控件"。

最后一类是 QSS 覆盖守卫：概览用的 objectName 必须在浅色/深色两套样式里都存在，
否则深色主题下会出现"漏白"（与 UI_REVIEW P2-2 同类问题）。
"""
import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication, QLabel, QProgressBar

import i18n
import ui_logic
from scanner.models import ScanResult
from change_detector import (
    CHANGE_NEW_DEVICE, CHANGE_IP_CHANGED, CHANGE_MAC_CHANGED,
    CHANGE_DEVICE_GONE,
)

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()
    i18n.init("zh-CN")


def _qss(name: str) -> str:
    with io.open(os.path.join(ROOT, "assets", "styles", name),
                 encoding="utf-8") as fh:
        return fh.read()


def _dev(ip, status="online", vendor="", dclass="", ports=None):
    r = ScanResult(ip=ip)
    r.status = status
    r.vendor = vendor
    r.device_class = dclass
    r.open_ports = list(ports or [])
    return r


class _Change:
    """最小可用的变更替身：`build_overview` 只读 `change_type`。"""

    def __init__(self, ctype, ip="1.1.1.1"):
        self.change_type = ctype
        self.ip = ip


class BuildOverviewTest(unittest.TestCase):
    """纯统计：不看文案，只看数字与结构。"""

    def setUp(self):
        self.results = [
            _dev("10.0.0.1", "online", vendor="Dell", dclass="电脑", ports=[80, 443]),
            _dev("10.0.0.2", "online", vendor="Dell", dclass="电脑", ports=[445]),
            _dev("10.0.0.3", "online", vendor="HP", dclass="打印机"),
            _dev("10.0.0.4", "offline", vendor="Dell", dclass="电脑"),
            _dev("10.0.1.5", "scanning"),  # 未完成 -> unknown
        ]

    def test_status_counts_and_ratio(self):
        d = ui_logic.build_overview(self.results)
        self.assertEqual(d["total"], 5)
        self.assertEqual(d["online"], 3)
        self.assertEqual(d["offline"], 1)
        self.assertEqual(d["unknown"], 1)
        self.assertAlmostEqual(d["online_ratio"], 60.0)

    def test_services_and_ports_count_online_only(self):
        """离线设备不该被算进"有开放端口" —— 它根本没探。"""
        d = ui_logic.build_overview(self.results)
        self.assertEqual(d["services"], 2)   # 只有前两台有端口
        self.assertEqual(d["ports"], 3)      # 80,443 + 445

    def test_offline_device_ports_are_ignored(self):
        results = [_dev("1.1.1.1", "offline", ports=[22, 23, 24])]
        d = ui_logic.build_overview(results)
        self.assertEqual(d["services"], 0)
        self.assertEqual(d["ports"], 0)

    def test_vendors_sorted_desc_and_offline_excluded(self):
        d = ui_logic.build_overview(self.results)
        self.assertEqual(d["vendors"][0], ("Dell", 2))  # 离线那台不计
        self.assertEqual(dict(d["vendors"])["HP"], 1)
        self.assertEqual(d["vendor_kinds"], 2)

    def test_device_classes_keep_canonical_values(self):
        """**核心约束**：这里必须返回规范值，不能提前翻译。

        否则英文界面会拿到中文串，且 `build_overview` 的结果会随界面语言漂移，
        纯函数测试也就没法写了。
        """
        d = ui_logic.build_overview(self.results)
        classes = dict(d["device_classes"])
        self.assertEqual(classes["电脑"], 2)
        self.assertEqual(classes["打印机"], 1)
        # 离线那台电脑不算
        self.assertEqual(sum(classes.values()), 3)

    def test_device_classes_do_not_depend_on_active_language(self):
        d_zh = ui_logic.build_overview(self.results)
        i18n.init("en-US")
        try:
            d_en = ui_logic.build_overview(self.results)
        finally:
            i18n.init("zh-CN")
        self.assertEqual(d_zh["device_classes"], d_en["device_classes"],
                         "统计结果不该随界面语言变化")

    def test_top_n_limits_lists_but_kinds_count_all(self):
        results = [_dev(f"10.0.0.{i}", vendor=f"V{i}", dclass=f"C{i}")
                   for i in range(1, 9)]
        d = ui_logic.build_overview(results, top_n=3)
        self.assertEqual(len(d["vendors"]), 3)
        self.assertEqual(len(d["device_classes"]), 3)
        self.assertEqual(d["vendor_kinds"], 8)
        self.assertEqual(d["class_kinds"], 8)

    def test_tie_break_is_stable_by_name(self):
        """同台数时按名称排序，保证每次渲染顺序一致（不会"跳来跳去"）。"""
        results = [_dev("10.0.0.1", vendor="B"), _dev("10.0.0.2", vendor="A")]
        d = ui_logic.build_overview(results)
        self.assertEqual([v for v, _n in d["vendors"]], ["A", "B"])

    def test_change_counts(self):
        changes = [_Change(CHANGE_NEW_DEVICE), _Change(CHANGE_NEW_DEVICE),
                   _Change(CHANGE_IP_CHANGED)]
        d = ui_logic.build_overview(self.results, changes=changes)
        self.assertEqual(d["changes"][CHANGE_NEW_DEVICE], 2)
        self.assertEqual(d["changes"][CHANGE_IP_CHANGED], 1)
        self.assertNotIn(CHANGE_DEVICE_GONE, d["changes"])  # 没出现就不该有键

    def test_conflicts_are_counted(self):
        from conflict_detector import Conflict, SEVERITY_HIGH, SEVERITY_WARNING
        conflicts = [Conflict(conflict_type="t", severity=SEVERITY_HIGH, description="d"),
                     Conflict(conflict_type="t", severity=SEVERITY_WARNING, description="d")]
        d = ui_logic.build_overview(self.results, conflicts=conflicts)
        self.assertEqual(d["conflicts"]["high"], 1)
        self.assertEqual(d["conflicts"]["warning"], 1)

    def test_empty_input_is_safe(self):
        d = ui_logic.build_overview([])
        self.assertEqual(d["total"], 0)
        self.assertEqual(d["online_ratio"], 0.0)
        self.assertEqual(d["vendors"], [])
        self.assertEqual(d["subnets"], [])
        self.assertEqual(d["changes"], {})

    def test_none_input_is_safe(self):
        d = ui_logic.build_overview(None, changes=None, conflicts=None)
        self.assertEqual(d["total"], 0)

    def test_subnets_capped_by_top_n(self):
        results = [_dev(f"10.{i}.0.1") for i in range(10)]
        d = ui_logic.build_overview(results, top_n=4)
        self.assertEqual(len(d["subnets"]), 4)


class BuildSubnetStatsTest(unittest.TestCase):
    """`SubnetUtilizationDialog._analyze` 提取后的回归测试。"""

    def test_groups_by_24_and_sorts_by_utilization(self):
        results = [
            _dev("10.0.0.1", "online"), _dev("10.0.0.2", "online"),
            _dev("10.0.1.1", "online"), _dev("10.0.1.2", "offline"),
        ]
        subs = ui_logic.build_subnet_stats(results)
        self.assertEqual([s["subnet"] for s in subs], ["10.0.0.0/24", "10.0.1.0/24"])
        self.assertAlmostEqual(subs[0]["utilization"], 100.0)
        self.assertAlmostEqual(subs[1]["utilization"], 50.0)
        self.assertEqual(subs[1]["offline"], 1)

    def test_invalid_ip_is_skipped_not_fatal(self):
        results = [_dev("not-an-ip"), _dev("10.0.0.1")]
        subs = ui_logic.build_subnet_stats(results)
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0]["total"], 1)

    def test_empty(self):
        self.assertEqual(ui_logic.build_subnet_stats([]), [])

    def test_device_dist_is_display_text(self):
        """`device_dist` 是预拼的展示串（与 build_overview 的规范值不同）。"""
        results = [_dev("10.0.0.1", dclass="电脑"), _dev("10.0.0.2", dclass="电脑")]
        subs = ui_logic.build_subnet_stats(results)
        self.assertEqual(subs[0]["device_dist"], "电脑×2")


class OverviewPanelTest(unittest.TestCase):
    """渲染层：指标落地、惰性翻译、重填不泄漏。"""

    def setUp(self):
        from overview import OverviewPanel
        self.panel = OverviewPanel()

    def tearDown(self):
        self.panel.deleteLater()

    def _labels(self, block) -> list:
        """取一个区块里所有 QLabel 的文本（按加入顺序）。

        注意 `_hint()` 返回的是**裸 QLabel**（没有外层容器），而
        `QWidget.findChildren()` 不含控件自身 —— 所以必须单独判断一次，
        否则"提示文案"类断言会全部拿到空列表。
        """
        body = block[1]
        out = []
        for i in range(body.count()):
            w = body.itemAt(i).widget()
            if w is None:
                continue
            if isinstance(w, QLabel):
                out.append(w.text())
            for lab in w.findChildren(QLabel):
                out.append(lab.text())
        return out

    def test_clear_shows_placeholder(self):
        self.panel.clear()
        self.assertEqual(self.panel.card_total.value.text(), "—")
        self.assertEqual(self.panel.card_ratio.value.text(), "—")

    def test_kpi_values_render(self):
        self.panel.set_data(ui_logic.build_overview([
            _dev("10.0.0.1", "online"), _dev("10.0.0.2", "offline"),
        ]))
        self.assertEqual(self.panel.card_total.value.text(), "2")
        self.assertEqual(self.panel.card_online.value.text(), "1")
        self.assertEqual(self.panel.card_offline.value.text(), "1")
        self.assertEqual(self.panel.card_ratio.value.text(), "50.0%")

    def test_empty_data_falls_back_to_placeholder(self):
        self.panel.set_data(ui_logic.build_overview([]))
        self.assertEqual(self.panel.card_total.value.text(), "—")

    def test_none_data_is_safe(self):
        self.panel.set_data(None)
        self.assertEqual(self.panel.card_total.value.text(), "—")

    def test_device_class_labels_are_translated(self):
        """**核心回归**：规范值「电脑」在英文界面必须显示成 `PC`。

        修复前这里直接印规范值，英文界面会看到「电脑/打印机」。
        """
        data = ui_logic.build_overview([_dev("10.0.0.1", dclass="电脑")])
        self.panel.set_data(data)
        self.assertIn("电脑", self._labels(self.panel.block_classes))

        i18n.init("en-US")
        try:
            self.panel.set_data(data)
            texts = self._labels(self.panel.block_classes)
        finally:
            i18n.init("zh-CN")
        self.assertIn("PC", texts)
        self.assertNotIn("电脑", texts)

    def test_vendor_names_are_not_translated(self):
        """厂商名是专有名词，不该被 tr() 动过。"""
        self.panel.set_data(ui_logic.build_overview(
            [_dev("10.0.0.1", vendor="Dell Inc.")]))
        self.assertIn("Dell Inc.", self._labels(self.panel.block_vendors))

    def test_changes_block_lists_each_type(self):
        changes = [_Change(CHANGE_NEW_DEVICE), _Change(CHANGE_MAC_CHANGED)]
        self.panel.set_data(ui_logic.build_overview(
            [_dev("10.0.0.1")], changes=changes))
        texts = self._labels(self.panel.block_changes)
        self.assertIn("新增设备", texts)
        self.assertIn("MAC 变更", texts)
        self.assertNotIn("主机名变更", texts)  # 未出现的类型不占位

    def test_no_changes_shows_hint(self):
        self.panel.set_data(ui_logic.build_overview([_dev("10.0.0.1")]))
        self.assertIn("与上次扫描相比无变更", self._labels(self.panel.block_changes))

    def test_no_conflicts_shows_hint(self):
        self.panel.set_data(ui_logic.build_overview([_dev("10.0.0.1")]))
        self.assertIn("未发现冲突", self._labels(self.panel.block_risks))

    def test_subnet_bar_tone_reflects_utilization(self):
        """利用率色阶：>85% 标 bad，60–85% 标 warn。"""
        data = ui_logic.build_overview([
            _dev("10.0.0.1", "online"),          # 10.0.0.0/24 -> 100% (bad)
            _dev("10.1.0.1", "online"),
            _dev("10.1.0.2", "offline"),         # 10.1.0.0/24 -> 50% (good)
        ])
        self.panel.set_data(data)
        tones = {}
        body = self.panel.block_subnets[1]
        for i in range(body.count()):
            w = body.itemAt(i).widget()
            if w is None:
                continue
            for bar in w.findChildren(QProgressBar):
                label = w.findChildren(QLabel)[0].text()
                tones[label.split()[0]] = bar.property("tone")
        self.assertEqual(tones.get("10.0.0.0/24"), "bad")
        self.assertEqual(tones.get("10.1.0.0/24"), "good")

    def test_refill_does_not_leak_widgets(self):
        """反复 set_data 不能让区块里的控件越堆越多。"""
        data = ui_logic.build_overview([_dev("10.0.0.1", dclass="电脑")])
        for _ in range(5):
            self.panel.set_data(data)
        QApplication.instance().processEvents()
        counts = [self.panel.block_classes[1].count(),
                  self.panel.block_vendors[1].count()]
        self.panel.set_data(data)
        QApplication.instance().processEvents()
        self.assertEqual(
            [self.panel.block_classes[1].count(),
             self.panel.block_vendors[1].count()], counts,
            "重填后条目数变了，说明旧控件没被清掉")

    def test_clear_after_data_resets_blocks(self):
        self.panel.set_data(ui_logic.build_overview([_dev("10.0.0.1", dclass="电脑")]))
        self.panel.clear()
        self.assertIn("暂无数据", self._labels(self.panel.block_classes))
        self.assertEqual(self.panel.scope.text(), "")

    def test_more_kinds_than_top_n_shows_remainder_hint(self):
        results = [_dev(f"10.0.0.{i}", vendor=f"V{i}") for i in range(1, 9)]
        self.panel.set_data(ui_logic.build_overview(results, top_n=3))
        joined = " ".join(self._labels(self.panel.block_vendors))
        self.assertIn("另有 5 项未列出", joined)


class OverviewQssCoverageTest(unittest.TestCase):
    """概览用到的 objectName 必须在两套主题里都有样式，否则深色下漏白。"""

    #: overview.py 里出现的全部 objectName（含动态属性选择器）
    OBJECT_NAMES = (
        "overviewPanel", "overviewTitle", "overviewScope", "statCard",
        "statValue", "statLabel", "overviewBlock", "overviewBlockTitle",
        "overviewName", "overviewCount", "overviewHint", "overviewBar",
    )

    def test_every_object_name_is_styled_in_both_themes(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for obj in self.OBJECT_NAMES:
                self.assertIn(f"#{obj}", src,
                              f"{name} 缺少 #{obj} 样式（概览页会漏白/串色）")

    def test_tone_variants_exist_in_both_themes(self):
        """动态属性 tone 的每个取值都要有选择器，否则色调不生效。"""
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for tone in ("online", "offline", "accent", "warn", "bad", "good"):
                self.assertRegex(
                    src, rf'\[tone="{tone}"\]',
                    f"{name} 缺少 tone=\"{tone}\" 选择器")

    def test_view_toggle_is_styled_in_both_themes(self):
        for name in ("light.qss", "dark.qss"):
            src = _qss(name)
            for obj in ("viewToggle", "viewBtn"):
                self.assertIn(f"#{obj}", src, f"{name} 缺少 #{obj} 样式")


if __name__ == "__main__":
    unittest.main()
