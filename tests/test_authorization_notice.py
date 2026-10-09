# -*- coding: utf-8 -*-
"""首次启动授权声明（CODE_REVIEW P2-14）。

背景
----
`README.md` 里早就有「免责声明」一节（由 `tests/test_scaffolding.py` 守着），
但**程序内没有任何提示** —— 用户装完双击就能扫全网段，从没被告知"只能扫你自己
拥有、或已获得明确书面授权的网络"。合规上，一句只写在 README 里的免责声明
几乎等于没有：README 是给想读的人看的，而这个警告必须给**每个**用户看到。

本轮加一个**只弹一次**的授权确认框：确认后写 `legal/notice_ack`，之后不再弹。

⚠️ 本文件守三件事
-----------------
1. **版本判定**（`ui_logic.needs_authorization_notice`）—— 纯函数，含升版/降级；
2. **只弹一次** —— 真 `MainWindow` + 临时数据目录：第一次弹、第二次不弹、
   拒绝则不记录；
3. **文案不能退化** —— 声明里必须出现「授权」「法律责任」「你自己拥有」这类
   关键词。文案漏了"授权"二字，这个弹窗就白弹了，而那种退化**不会有任何测试
   失败**，只有人工读一遍才发现。

🔴 另有一条结构性断言：`MainWindow.__init__` **绝不能**弹模态框。一旦弹了，
所有"建一个 MainWindow 看行为"的测试都会在无头环境（没人点按钮）里**永久挂死**
—— 表现为 CI 卡住而不是失败，是最难查的一类故障。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication, QMessageBox

import i18n
import main_window
import ui_logic
import ui_msg

_app = None


def setUpModule():
    global _app
    from tests._qt_app import ensure_qt_app
    _app = ensure_qt_app()


def tearDownModule():
    i18n.init("zh-CN")


class NoticeVersionTest(unittest.TestCase):
    """版本判定是纯函数，边界钉死。"""

    def test_never_acknowledged_needs_the_notice(self):
        for value in (0, None, "", "abc", -1):
            with self.subTest(value=value):
                self.assertTrue(
                    ui_logic.needs_authorization_notice(value),
                    "%r 应被判定为「从没确认过」" % (value,))

    def test_current_version_is_enough(self):
        self.assertFalse(
            ui_logic.needs_authorization_notice(ui_logic.NOTICE_VERSION))

    def test_bumping_the_version_asks_again(self):
        """声明升版后，确认过旧版的用户必须**重新看一次** —— 否则新增的免责
        条款对已装用户永远不可见，而那往往正是最要紧的一句。"""
        self.assertTrue(
            ui_logic.needs_authorization_notice(ui_logic.NOTICE_VERSION - 1))

    def test_newer_acknowledgement_does_not_ask_again(self):
        """用户回退旧版本程序时不该再弹：他已经同意过更新的条款了。"""
        self.assertFalse(
            ui_logic.needs_authorization_notice(ui_logic.NOTICE_VERSION + 1))

    def test_accepts_the_string_form_qsettings_may_return(self):
        """ini 后端有时把整数给回字符串。"""
        self.assertFalse(ui_logic.needs_authorization_notice(
            str(ui_logic.NOTICE_VERSION)))


class MsgConsentTest(unittest.TestCase):
    """`ui_msg.msg_consent` 本身：两个自定义按钮、默认按钮、Esc 视为未同意。

    `exec_()` 会阻塞，所以换成"记录 box 并返回"的替身；`clickedButton()` 也一并
    替身 —— 它才是"用户点了哪个按钮"的真实来源（`exec_` 的返回值不够用）。
    """

    ACCEPT = "同意测试"
    DECLINE = "退出测试"

    def setUp(self):
        self._orig_exec = QMessageBox.exec_
        self._orig_clicked = QMessageBox.clickedButton
        self._boxes = []
        self._click_text = None
        boxes = self._boxes

        def fake_exec(box):
            boxes.append(box)
            return 0

        def fake_clicked(box):
            want = self._click_text
            if want is None:
                return None
            for btn in box.buttons():
                if btn.text() == want:
                    return btn
            return None

        QMessageBox.exec_ = fake_exec
        QMessageBox.clickedButton = fake_clicked

    def tearDown(self):
        QMessageBox.exec_ = self._orig_exec
        QMessageBox.clickedButton = self._orig_clicked
        i18n.init("zh-CN")

    def _run(self, click_text):
        self._click_text = click_text
        return ui_msg.msg_consent(None, "标题", "正文", self.ACCEPT, self.DECLINE)

    def test_accept_click_returns_true(self):
        self.assertTrue(self._run(self.ACCEPT))

    def test_decline_click_returns_false(self):
        self.assertFalse(self._run(self.DECLINE))

    def test_closing_the_dialog_counts_as_declining(self):
        """Esc / 点标题栏关闭 → `clickedButton()` 为 None → 按未同意处理。"""
        self.assertFalse(self._run(None))

    def test_box_has_exactly_the_two_given_buttons(self):
        self._run(self.ACCEPT)
        box = self._boxes[0]
        self.assertEqual(sorted(b.text() for b in box.buttons()),
                         sorted([self.ACCEPT, self.DECLINE]))

    def test_accept_is_the_default_button(self):
        """默认必须落在"继续使用"上：落在"退出"上会误伤一路回车的用户。"""
        self._run(self.ACCEPT)
        box = self._boxes[0]
        self.assertEqual(box.defaultButton().text(), self.ACCEPT)

    def test_uses_the_warning_icon(self):
        self._run(self.ACCEPT)
        self.assertEqual(self._boxes[0].icon(), QMessageBox.Warning)


class _WindowCase(unittest.TestCase):
    """真 `MainWindow` + 临时数据目录（绝不碰用户的 `ipscanner.ini`）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipscanner_notice_")
        self._orig_data_dir = main_window.data_dir
        main_window.data_dir = lambda: self.tmp
        self._orig_consent = main_window.msg_consent
        self.prompts = []
        i18n.init("zh-CN")

    def tearDown(self):
        main_window.msg_consent = self._orig_consent
        main_window.data_dir = self._orig_data_dir
        i18n.init("zh-CN")

    def _build(self):
        mw = main_window.MainWindow()
        mw.show()
        QApplication.processEvents()
        return mw

    def _stub_consent(self, accept):
        """把 `main_window.msg_consent` 换成替身：记录参数 + 返回固定结果。

        ⚠️ 不 stub `QMessageBox.exec_`：`msg_consent` 里 `exec_()` 之后还要读
        `clickedButton()`，只换 `exec_` 拿不到"用户点了哪个按钮"。换掉整个函数
        反而更接近真实调用点。
        """
        prompts = self.prompts

        def fake(parent, title, text, accept_text, decline_text):
            prompts.append({"title": title, "text": text,
                            "accept": accept_text, "decline": decline_text})
            return accept

        main_window.msg_consent = fake


class FirstRunFlowTest(_WindowCase):

    def test_constructing_the_window_does_not_prompt(self):
        """🔴 最关键的一条：`MainWindow.__init__` 绝不能弹模态框。

        一旦弹了，所有"建一个 MainWindow 看行为"的测试都会在无头环境（没人点
        按钮）里永久挂死 —— 而且表现为 CI 卡住而不是失败，最难查。
        """
        self._stub_consent(True)
        mw = self._build()
        try:
            self.assertEqual(self.prompts, [],
                             "MainWindow() 构造期弹了模态对话框")
        finally:
            mw.close()

    def test_notice_shows_on_first_run_and_is_recorded(self):
        mw = self._build()
        self._stub_consent(True)
        try:
            self.assertTrue(mw.maybe_show_authorization_notice())
            self.assertEqual(len(self.prompts), 1, "首次启动没有弹授权声明")
            self.assertEqual(
                mw.settings.value("legal/notice_ack", 0, type=int),
                ui_logic.NOTICE_VERSION, "确认后没有记录版本号")
        finally:
            mw.close()

    def test_notice_does_not_show_again(self):
        mw = self._build()
        self._stub_consent(True)
        mw.maybe_show_authorization_notice()
        self.assertEqual(len(self.prompts), 1)
        mw.close()

        mw2 = self._build()
        try:
            self.assertTrue(mw2.maybe_show_authorization_notice())
            self.assertEqual(len(self.prompts), 1, "第二次启动又弹了授权声明")
        finally:
            mw2.close()

    def test_declining_is_not_recorded(self):
        mw = self._build()
        self._stub_consent(False)
        try:
            self.assertFalse(mw.maybe_show_authorization_notice(),
                             "用户拒绝时返回值应为 False（调用方据此退出）")
            self.assertEqual(
                mw.settings.value("legal/notice_ack", 0, type=int), 0,
                "用户没有同意却记下了确认")
        finally:
            mw.close()

    def test_prompt_text_carries_the_compliance_points(self):
        mw = self._build()
        self._stub_consent(True)
        try:
            mw.maybe_show_authorization_notice()
            self.assertEqual(len(self.prompts), 1)
            prompt = self.prompts[0]
            self.assertIn("授权", prompt["accept"],
                          "确认按钮没提「授权」—— 用户看不出自己在确认什么")
            self.assertTrue(prompt["decline"].strip(),
                            "没有提供「退出」这一项")
            self.assertIn("授权", prompt["text"])
        finally:
            mw.close()


class NoticeTextTest(_WindowCase):
    """声明文案的**合规要点**必须还在（纯文本断言）。"""

    def test_text_mentions_the_required_points(self):
        mw = self._build()
        try:
            text = mw._authorization_notice_text()
        finally:
            mw.close()
        for keyword in ("授权", "法律责任", "你自己拥有"):
            with self.subTest(keyword=keyword):
                self.assertIn(keyword, text,
                              "授权声明文案里少了「%s」" % keyword)

    def test_text_is_translated(self):
        """英文界面下必须给出英文 —— 中文声明对英文用户等于没提示。"""
        mw = self._build()
        try:
            i18n.init("zh-CN")
            zh = mw._authorization_notice_text()
            i18n.init("en-US")
            en = mw._authorization_notice_text()
            i18n.init("zh-CN")
        finally:
            mw.close()
        self.assertNotEqual(zh, en, "英文界面下授权声明没有翻译")
        self.assertIn("authorization", en.lower())


if __name__ == "__main__":
    unittest.main()
