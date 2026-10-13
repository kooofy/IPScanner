# -*- coding: utf-8 -*-
"""CVE 快照状态徽标 / 详情对话框（v2.1 §2.3 的 GUI 露出）。

为什么单独一个文件
------------------
CLI 侧（`ipscanner cve --status`）在 §2.3 已经守住了，但 GUI 侧多出两件事：

1. **文案与配色** —— 徽标必须在英文界面下也是英文（表驱动文案最容易漏
   `tr()`，`test_i18n_lazy` 只守"表本身有没有译"，守不住"函数有没有把表
   过 tr()"）；
2. **降级不许崩** —— 徽标是附加信息，读快照失败绝不能让主窗口起不来，
   但也**不能**假装一切正常（必须退化成"未知/不可用"）。

另外守「配色随主题」：徽标颜色由 Python 按 `theme_tokens` 语义色取，切主题
时不重刷就会在深色底上留一个浅色主题的绿字。
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests._qt_app import ensure_qt_app
ensure_qt_app()

from PyQt5.QtWidgets import QApplication, QLabel            # noqa: E402
from unittest import mock                                   # noqa: E402

import app_paths                                            # noqa: E402
import cve_status_mixin                                     # noqa: E402
import i18n                                                 # noqa: E402
import main_window                                          # noqa: E402
from scanner import cve_snapshot                            # noqa: E402
from theme_tokens import token                              # noqa: E402

ALL_STATES = (
    cve_snapshot.STATE_OK, cve_snapshot.STATE_STALE,
    cve_snapshot.STATE_UNKNOWN_AGE, cve_snapshot.STATE_EMPTY,
    cve_snapshot.STATE_MISSING, cve_snapshot.STATE_CORRUPT,
)


def _entry(i: int, kev: bool = False, epss=None) -> cve_snapshot.CveEntry:
    return cve_snapshot.CveEntry(
        cve_id="CVE-2021-%04d" % (4000 + i),
        cpe=("cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*",),
        kev=kev, epss=epss, epss_percentile=0.9, summary="示例",
    )


def _snap(state, n=3, source=cve_snapshot.SOURCE_SEED, age_days=1,
          generated_at=True, path="/tmp/cve_snapshot.json", checksum=None):
    """造一份指定状态的快照（entries 数、KEV/EPSS 计数都真实可算）。"""
    entries = [_entry(i, kev=(i == 0), epss=(0.5 if i < 2 else None))
               for i in range(n)]
    return cve_snapshot.CveSnapshot(
        entries=entries, state=state, source=source,
        schema=cve_snapshot.SCHEMA,
        generated_at=((datetime.now(timezone.utc) - timedelta(days=age_days))
                      if generated_at else None),
        age_days=(age_days if generated_at else None),
        checksum_verified=checksum, path=path,
    )


class BadgeTextTest(unittest.TestCase):
    """纯函数：状态 → 文案 / 提示 / 语义色（不需要窗口）。"""

    def setUp(self):
        i18n.init("zh-CN")

    def tearDown(self):
        i18n.init("zh-CN")

    def test_every_state_has_a_badge_text(self):
        for state in ALL_STATES:
            with self.subTest(state=state):
                self.assertTrue(cve_status_mixin.badge_text(state, 3))

    def test_ok_and_stale_carry_the_entry_count(self):
        """数据在的时候必须显示条数 —— "有多少可查"是用户唯一的量感。"""
        self.assertIn("3", cve_status_mixin.badge_text(cve_snapshot.STATE_OK, 3))
        self.assertIn("3", cve_status_mixin.badge_text(cve_snapshot.STATE_STALE, 3))

    def test_unknown_state_does_not_pretend(self):
        """未知状态不许硬套成 ok —— 宁可露怯也不猜。"""
        text = cve_status_mixin.badge_text("未来才有的状态", 3)
        self.assertNotIn("就绪", text)

    def test_every_state_has_a_hint(self):
        for state in ALL_STATES:
            with self.subTest(state=state):
                stats = _snap(state).stats()
                hint = cve_status_mixin.hint_text(stats)
                self.assertTrue(hint, "状态 %s 没有提示文案" % state)
                self.assertNotEqual(hint, cve_status_mixin.badge_text(state, 3),
                                    "提示与徽标同一句话 = 等于没有解释")

    def test_missing_and_corrupt_hints_say_what_to_do(self):
        """「无数据」必须说清后果与下一步 —— 这是 §2.3 最容易被含糊掉的一句。"""
        for state in (cve_snapshot.STATE_MISSING, cve_snapshot.STATE_CORRUPT,
                      cve_snapshot.STATE_EMPTY):
            with self.subTest(state=state):
                hint = cve_status_mixin.hint_text(_snap(state).stats())
                self.assertIn("CVE", hint)

    def test_stale_hint_mentions_updating(self):
        hint = cve_status_mixin.hint_text(_snap(cve_snapshot.STATE_STALE,
                                                age_days=99).stats())
        self.assertIn("99", hint, "过期提示里应带上实际天数")

    def test_token_names_are_real_tokens(self):
        """语义色令牌名必须真的存在于 theme_tokens —— 打错字会静默变灰。"""
        for state in ALL_STATES:
            with self.subTest(state=state):
                name = cve_status_mixin.token_name(state)
                self.assertTrue(token(name, False), "令牌 %r 不存在" % name)
                self.assertTrue(token(name, True), "令牌 %r 缺深色值" % name)

    def test_severity_mapping_is_ordered(self):
        """ok 用绿、旧/未知用琥珀、坏用红 —— 三档不许混。"""
        self.assertEqual(cve_status_mixin.token_name(cve_snapshot.STATE_OK),
                         "online")
        self.assertEqual(cve_status_mixin.token_name(cve_snapshot.STATE_STALE),
                         "warn")
        self.assertEqual(cve_status_mixin.token_name(cve_snapshot.STATE_CORRUPT),
                         "danger")

    def test_source_texts_are_distinct(self):
        data = cve_status_mixin.source_text(cve_snapshot.SOURCE_DATA)
        seed = cve_status_mixin.source_text(cve_snapshot.SOURCE_SEED)
        self.assertNotEqual(data, seed, "「用户更新版」与「内置种子」必须能分清")
        self.assertTrue(cve_status_mixin.source_text(cve_snapshot.SOURCE_NONE))

    def test_english_ui_has_no_chinese_left(self):
        """英文界面下徽标 / 提示 / 来源都不许留中文（表驱动文案的经典盲区）。"""
        i18n.init("en-US")
        for state in ALL_STATES:
            with self.subTest(state=state):
                for text in (cve_status_mixin.badge_text(state, 3),
                             cve_status_mixin.hint_text(_snap(state).stats())):
                    self.assertFalse(
                        any("\u4e00" <= ch <= "\u9fff" for ch in text),
                        "英文界面出现中文: %r" % text)
        for source in (cve_snapshot.SOURCE_DATA, cve_snapshot.SOURCE_SEED,
                       cve_snapshot.SOURCE_NONE):
            self.assertFalse(
                any("\u4e00" <= ch <= "\u9fff" for ch in
                    cve_status_mixin.source_text(source)))


class _WindowCase(unittest.TestCase):
    """真实 MainWindow，配置隔离到临时目录。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_cve_gui_")
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

    def _refresh_with(self, snap):
        with mock.patch.object(cve_status_mixin._snap, "load_snapshot",
                               return_value=snap):
            self.mw._refresh_cve_badge()


class BadgeWidgetTest(_WindowCase):
    """徽标控件本体：存在、随状态改文案、随主题改色、坏了不崩。"""

    def test_label_exists_in_the_status_bar(self):
        labels = self.mw.status_bar.findChildren(QLabel)
        self.assertIn(self.mw.cve_label, labels,
                      "徽标没被 addPermanentWidget —— 界面上看不到")
        self.assertEqual(self.mw.cve_label.objectName(), "cveLabel",
                         "objectName 变了 QSS 就配不上（light/dark 各有一条）")

    def test_startup_fills_the_badge(self):
        """启动就该有内容（哪怕只是「未安装」），空标签等于这个功能没做。"""
        self.assertTrue(self.mw.cve_label.text(),
                        "启动后徽标是空的 —— _refresh_cve_badge 没被调用")

    def test_text_and_tooltip_follow_state(self):
        self._refresh_with(_snap(cve_snapshot.STATE_STALE, n=7, age_days=99))
        self.assertIn("7", self.mw.cve_label.text())
        self.assertTrue(self.mw.cve_label.toolTip())
        self.assertIn("99", self.mw.cve_label.toolTip())

    def test_ok_is_green_missing_is_muted(self):
        self._refresh_with(_snap(cve_snapshot.STATE_OK))
        self.assertIn(token("online", self.mw.dark_mode),
                      self.mw.cve_label.styleSheet())
        self._refresh_with(_snap(cve_snapshot.STATE_MISSING))
        self.assertIn(token("muted", self.mw.dark_mode),
                      self.mw.cve_label.styleSheet())

    def test_corrupt_is_danger(self):
        self._refresh_with(_snap(cve_snapshot.STATE_CORRUPT, n=0))
        self.assertIn(token("danger", self.mw.dark_mode),
                      self.mw.cve_label.styleSheet())

    def test_color_follows_the_theme(self):
        """切主题必须重取色：浅色的绿字留在深色底上几乎不可见。

        ⚠ 走 `_set_dark_mode()` 而不是直接 `_apply_theme()`：前者先更新
        `dark_mode` 再刷界面，而徽标取色读的正是 `dark_mode` —— 直接调
        `_apply_theme(True)` 会拿到浅色令牌，测的就不是产品行为了。
        """
        light, dark = token("online", False), token("online", True)
        self.assertNotEqual(light, dark, "前提：该令牌两套主题取值不同")
        with mock.patch.object(cve_status_mixin._snap, "load_snapshot",
                               return_value=_snap(cve_snapshot.STATE_OK)):
            self.mw._set_dark_mode(False, save=False)
            self.assertIn(light, self.mw.cve_label.styleSheet())
            self.mw._set_dark_mode(True, save=False)
            self.assertIn(dark, self.mw.cve_label.styleSheet(),
                          "切到深色后徽标还在用浅色主题的绿")

    def test_read_failure_degrades_but_does_not_raise(self):
        """读快照炸了也不许把窗口带走，且必须显示「未知」而不是「就绪」。"""
        with mock.patch.object(cve_status_mixin._snap, "load_snapshot",
                               side_effect=RuntimeError("boom")):
            self.mw._refresh_cve_badge()          # 不抛即通过
        self.assertNotIn("就绪", self.mw.cve_label.text())
        self.assertTrue(self.mw.cve_label.text())


class DetailsDialogTest(_WindowCase):
    """详情对话框：事实给全、读失败给实话。"""

    def _show_and_capture(self, snap=None, side_effect=None):
        captured = {}
        kwargs = ({"side_effect": side_effect} if side_effect
                  else {"return_value": snap})
        with mock.patch.object(cve_status_mixin._snap, "load_snapshot", **kwargs):
            with mock.patch.object(cve_status_mixin, "msg_info",
                                   side_effect=lambda *a, **k: captured.update(
                                       title=a[1], text=a[2])):
                self.mw._show_cve_status()
        return captured

    def test_dialog_lists_all_the_facts(self):
        cap = self._show_and_capture(
            _snap(cve_snapshot.STATE_OK, n=5, checksum=True))
        self.assertEqual(cap["title"], i18n.tr("CVE 数据快照"))
        body = cap["text"]
        for needle in ("5", cve_status_mixin.source_text(cve_snapshot.SOURCE_SEED)):
            self.assertIn(needle, body)
        self.assertIn(app_paths.data_dir(), body,
                      "手动更新的放置路径没告诉用户 —— 用户还得自己去找")

    def test_checksum_states_are_distinguishable(self):
        ok = self._show_and_capture(_snap(cve_snapshot.STATE_OK, checksum=True))
        none = self._show_and_capture(_snap(cve_snapshot.STATE_OK, checksum=None))
        self.assertNotEqual(ok["text"], none["text"],
                            "「校验通过」与「未提供清单」必须是两句话")

    def test_unknown_age_omits_the_timestamp_line(self):
        cap = self._show_and_capture(_snap(cve_snapshot.STATE_UNKNOWN_AGE,
                                           generated_at=False))
        self.assertNotIn("None", cap["text"])

    def test_read_failure_says_so(self):
        cap = self._show_and_capture(side_effect=RuntimeError("boom"))
        self.assertEqual(cap["title"], i18n.tr("CVE 数据快照"))
        self.assertIn(i18n.tr("无法读取 CVE 快照状态（详见日志）。"), cap["text"])


class MenuWiringTest(_WindowCase):
    """菜单入口真的接上了（构造了 QAction 却没 addAction 是常见疏漏）。"""

    def _all_actions(self):
        out = []
        for top in self.mw.menuBar().actions():
            menu = top.menu()
            if menu is None:
                continue
            for act in menu.actions():
                out.append(act)
                sub = act.menu()
                if sub is not None:
                    out.extend(sub.actions())
        return out

    def test_cve_status_action_is_reachable(self):
        want = i18n.tr("CVE 数据快照...")
        texts = [a.text() for a in self._all_actions()]
        self.assertIn(want, texts)
