# -*- coding: utf-8 -*-
"""主题切换后树项标记必须**整体**跟随（P0-1 回归）。

背景
----
`QTreeWidgetItem.setForeground()` 是 QSS 覆盖不到的地方，所以切换主题时必须由
Python 重新设色。第一轮界面改造只刷了**顶层项的第 0/1 列**：

- 服务 / WMI / NetBIOS **子项**没刷 —— 深色下仍是浅色蓝 `#2563EB`；
- **制造商列（第 4 列）** 没刷 —— 地址库命中的行同理。

`#2563EB` 在深色树底 `#252526` 上的对比度只有 **2.96:1**，低于 WCAG AA 要求的
4.5:1（正确色 `#4DA6FF` 是 5.99:1）。也就是说"深色下还是浅色蓝"不是审美问题，
是可读性缺陷。

本轮 P0-1 之所以被漏掉，**结构性原因就是没有任何测试断言"颜色随主题变化"** ——
这类问题肉眼很难发现（要点开行、看子项），只能靠断言守着。本文件补上。

夹具用真实的 `TreeMixin` + 真实的 `MainWindow._link_color`（以未绑定函数的形式
挂到宿主上），因此 `_link_color()` 一旦不再跟随主题，这里同样会挂。
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
from main_window import MainWindow
from main_window_tree import TreeMixin
from scanner.models import ScanResult
from theme_tokens import token

_app = None


def setUpModule():
    # 统一走 ensure_qt_app()：它保证进程里那个唯一的 application 对象是
    # QApplication 而不是 QCoreApplication，否则建 widget 会让进程直接 abort。
    # 详见 tests/_qt_app.py。
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


# ── WCAG 相对亮度 / 对比度 ────────────────────────────────────────────

def _relative_luminance(hex_color: str) -> float:
    """WCAG 2.x 相对亮度。`hex_color` 形如 "#2563EB"。"""
    channels = [int(hex_color[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]

    def _linearize(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (_linearize(c) for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: str, bg: str) -> float:
    """两个 hex 颜色之间的对比度（1.0 ~ 21.0）。"""
    a, b = _relative_luminance(fg), _relative_luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


# ── 夹具 ──────────────────────────────────────────────────────────────

class _Harness(TreeMixin, QTreeWidget):
    """最小宿主：真实 `TreeMixin` + 真实的 `MainWindow` 取色方法。

    把 `MainWindow._link_color` / `_muted_color` 以未绑定函数的形式挂上来，
    就能在**不构造整个 MainWindow** 的前提下测到真实取色逻辑 ——
    如果它们哪天不再跟随主题，这里的断言会直接失败。
    """

    _link_color = MainWindow._link_color
    _muted_color = MainWindow._muted_color

    def __init__(self, dark: bool = False):
        QTreeWidget.__init__(self)
        self.setColumnCount(13)
        self.table = self
        self.dark_mode = dark
        # `_refresh_theme_marks` / `_apply_row_marks` 依赖的这些状态，
        # 在 MainWindow 上由各个 Mixin 初始化；这里给最小可用的空值。
        self._ip_item_map = {}
        self._result_map = {}
        self._conflict_ips = {}
        self._conflicts = []
        self._change_map = {}
        self.favorites = None

    def _service_icon(self, proto):
        return None


def _matched_result(ip: str) -> ScanResult:
    """地址库命中 + 三类子项齐全的行 —— 覆盖全部会被 Python 设色的位置。"""
    return ScanResult(
        ip=ip,
        status="online",
        services=["HTTP", "SMB"],
        excel_matched=True,
        device_type="打印机",
        wmi_identified=True,
        wmi_manufacturer="Dell Inc.",
        wmi_model="OptiPlex 7080",
        netbios_identified=True,
        netbios_name="PC-01",
    )


def _plain_result(ip: str) -> ScanResult:
    """地址库**未命中**的行：第 4 列不该是链接色。"""
    return ScanResult(ip=ip, status="offline", services=["HTTP"])


def _snapshot(host: QTreeWidget, item) -> dict:
    """一行（含子项）上所有可能被 Python 设色的位置 → 颜色名。"""
    snap = {}
    for col in range(host.columnCount()):
        snap["top[%d]" % col] = item.foreground(col).color().name()
    # 状态列的图标是预渲染位图，也必须随主题重绘 —— 记下"有没有图标"。
    snap["top[1].icon"] = "none" if item.icon(1).isNull() else "icon"
    for i in range(item.childCount()):
        snap["child[%d]" % i] = item.child(i).foreground(0).color().name()
    return snap


class ThemeMarkPropagationTest(unittest.TestCase):
    """切主题必须把每一处 Python 设色的地方都刷到。"""

    def setUp(self):
        i18n.init("zh-CN")
        self._hosts = []

    def tearDown(self):
        for h in self._hosts:
            h.clear()
            h.deleteLater()
        i18n.init("zh-CN")

    def _build_fixture(self, dark: bool):
        """造两行（命中/未命中）并返回 (宿主, {ip: 快照})。"""
        host = _Harness(dark=dark)
        self._hosts.append(host)
        snaps = {}
        for result in (_matched_result("10.0.0.1"), _plain_result("10.0.0.2")):
            item = host._add_top_level_item(result)
            host._ip_item_map[result.ip] = item
            host._result_map[result.ip] = result
            snaps[result.ip] = _snapshot(host, item)
        return host, snaps

    # ── 核心不变量 ──

    def test_switch_theme_equals_building_dark_from_scratch(self):
        """切主题后的渲染结果，必须与"一开始就是深色"逐点一致。

        这条比逐点断言更强：凡是 `_set_item_data()` 会设色、而
        `_refresh_theme_marks()` 忘记刷新的位置，两份快照就会出现差异 ——
        包括以后新增的列或子项类型，不必再补断言。
        """
        host_light, _ = self._build_fixture(dark=False)
        _, dark_built = self._build_fixture(dark=True)

        host_light.dark_mode = True
        host_light._refresh_theme_marks()
        switched = {
            ip: _snapshot(host_light, host_light._ip_item_map[ip])
            for ip in dark_built
        }

        for ip, expected in dark_built.items():
            for key, want in expected.items():
                self.assertEqual(
                    switched[ip][key], want,
                    "切换主题后 %s 的 %s 与「直接以深色构建」不一致 —— "
                    "_refresh_theme_marks() 漏刷了这里" % (ip, key))

    def test_switch_theme_changes_every_sampled_spot(self):
        """反向断言：切主题后每一处采样点的颜色都必须真的变了。

        与上一条互补 —— 上一条怕"漏刷"，这一条怕"刷了个寂寞"（比如把颜色
        刷成同一个值）。
        """
        host, _ = self._build_fixture(dark=False)
        item = host._ip_item_map["10.0.0.1"]

        host.dark_mode = False
        host._refresh_theme_marks()
        light = _snapshot(host, item)

        host.dark_mode = True
        host._refresh_theme_marks()
        dark = _snapshot(host, item)

        self.assertGreaterEqual(
            len(light), 7,
            "采样点太少（%d 个），说明夹具没造出子项或列数不对，测试形同虚设"
            % len(light))

        # 只比对**确实由 Python 设色**的位置：第 0 / 1 / 4 列与全部子项。
        # 其余列（主机名、位置、备注…）刻意不设前景色，交给 QSS —— 它们在
        # `foreground()` 上读回来都是未设的默认黑，本就不该随主题变化。
        tracked = ["top[0]", "top[1]", "top[4]"]
        tracked += [k for k in light if k.startswith("child[")]
        for key in tracked:
            self.assertNotEqual(
                light[key], dark[key],
                "%s 在切主题前后颜色相同，没有跟随主题" % key)

    # ── P0-1 的两个具体位置 ──

    def test_service_and_identification_children_follow_theme(self):
        """P0-1 核心：服务 / WMI / NetBIOS 子项此前完全不跟随主题。"""
        host, _ = self._build_fixture(dark=False)
        item = host._ip_item_map["10.0.0.1"]
        self.assertGreater(item.childCount(), 0, "夹具没造出子项，测试无效")

        self.assertEqual(item.child(0).foreground(0).color().name(),
                         token("link", False).lower())

        host.dark_mode = True
        host._refresh_theme_marks()

        for i in range(item.childCount()):
            self.assertEqual(
                item.child(i).foreground(0).color().name(),
                token("link", True).lower(),
                "子项 #%d 切到深色后仍是浅色链接色（P0-1 回归）" % i)

    def test_manufacturer_column_follows_theme(self):
        """P0-1 核心：地址库命中的行，其制造商列此前不跟随主题。"""
        host, _ = self._build_fixture(dark=False)
        item = host._ip_item_map["10.0.0.1"]

        self.assertEqual(item.foreground(4).color().name(),
                         token("link", False).lower())

        host.dark_mode = True
        host._refresh_theme_marks()

        self.assertEqual(
            item.foreground(4).color().name(), token("link", True).lower(),
            "制造商列切到深色后仍是浅色链接色（P0-1 回归）")

    def test_unmatched_row_manufacturer_is_not_link_colored(self):
        """未命中的行不该被顺手刷成链接色。

        第 4 列的链接色是有含义的（= 地址库命中），刷新时必须按行重新判定，
        不能"看见第 4 列就刷"。
        """
        host, _ = self._build_fixture(dark=False)
        plain = host._ip_item_map["10.0.0.2"]

        host.dark_mode = True
        host._refresh_theme_marks()

        self.assertNotEqual(plain.foreground(4).color().name(),
                            token("link", True).lower(),
                            "未命中地址库的行被刷成了链接色")

    # ── 取色方法本身 ──

    def test_link_color_comes_from_tokens(self):
        host = _Harness(dark=False)
        self._hosts.append(host)
        host.dark_mode = False
        self.assertEqual(host._link_color().name(), token("link", False).lower())
        host.dark_mode = True
        self.assertEqual(host._link_color().name(), token("link", True).lower())

    def test_muted_color_comes_from_tokens(self):
        host = _Harness(dark=False)
        self._hosts.append(host)
        host.dark_mode = False
        self.assertEqual(host._muted_color().name(), token("muted", False).lower())
        host.dark_mode = True
        self.assertEqual(host._muted_color().name(), token("muted", True).lower())


class LinkColorContrastTest(unittest.TestCase):
    """链接色必须在各自主题的树底上达到 WCAG AA（4.5:1）。

    这是 P0-1 的**量化**判据：把"深色下必须换色"从主观判断变成可回归的数字。
    """

    #: 树底背景色，取自 `assets/styles/*.qss`。
    #: `test_backgrounds_still_match_the_stylesheets` 会校验它们没有和样式表脱节。
    DARK_TREE_BG = "#252526"   # dark.qss: alternate-background-color
    LIGHT_TREE_BG = "#FFFFFF"  # light.qss: background-color

    AA_NORMAL_TEXT = 4.5

    def test_dark_link_color_meets_aa(self):
        ratio = contrast_ratio(token("link", True), self.DARK_TREE_BG)
        self.assertGreaterEqual(
            round(ratio, 2), self.AA_NORMAL_TEXT,
            "深色链接色 %s 在 %s 上只有 %.2f:1"
            % (token("link", True), self.DARK_TREE_BG, ratio))

    def test_light_link_color_meets_aa(self):
        ratio = contrast_ratio(token("link", False), self.LIGHT_TREE_BG)
        self.assertGreaterEqual(
            round(ratio, 2), self.AA_NORMAL_TEXT,
            "浅色链接色 %s 在 %s 上只有 %.2f:1"
            % (token("link", False), self.LIGHT_TREE_BG, ratio))

    def test_light_theme_blue_would_fail_on_dark_background(self):
        """把"为什么深色必须换一个蓝"钉成断言。

        否则后人会觉得"两个主题共用一个蓝更省事"，把这个修复删掉。
        """
        ratio = contrast_ratio(token("link", False), self.DARK_TREE_BG)
        self.assertLess(ratio, self.AA_NORMAL_TEXT,
                        "浅色链接色在深色底上居然达标了？请重新评估这条修复")

    def test_backgrounds_still_match_the_stylesheets(self):
        """样式表里的树底若改了，上面的对比度断言就该重算 —— 这里守住。"""
        styles = os.path.join(ROOT, "assets", "styles")
        cases = (
            ("dark.qss", self.DARK_TREE_BG),
            ("light.qss", self.LIGHT_TREE_BG),
        )
        for filename, color in cases:
            path = os.path.join(styles, filename)
            with open(path, encoding="utf-8") as fh:
                qss = fh.read()
            self.assertIn(
                color.lower(), qss.lower(),
                "%s 里已找不到树底色 %s —— 对比度断言的基准需要更新"
                % (filename, color))


if __name__ == "__main__":
    unittest.main()
