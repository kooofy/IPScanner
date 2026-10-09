# -*- coding: utf-8 -*-
"""凭据采集对话框：WMI 管理员凭据 / 传输方式，SNMPv3 USM 用户参数。

两者都只回传明文凭据/口令，不负责持久化 —— 落盘（DPAPI 加密到本机配置）
由调用方负责。
"""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QLabel, QPushButton,
    QHBoxLayout, QComboBox, QCheckBox,
)

from i18n import tr
from scanner.snmp_v3 import (AUTH_NONE, AUTH_MD5, AUTH_SHA, PRIV_NONE, PRIV_AES,
                             SnmpV3User, auth_label, priv_label,
                             snmp_v3_get_system)
from scanner.wmi import (TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM,
                         transport_label)
from ui_msg import localize_buttons


class WmiCredentialDialog(QDialog):
    """采集 WMI 识别所需的管理员凭据与传输方式。

    密码以 QLineEdit(Password) 显示；勾选"保存凭据(加密)"后由调用方用 DPAPI 加密
    存入 ipscanner.ini。本对话框不负责持久化，只回传明文凭据。

    传输方式默认"自动"（先 DCOM，失败再试 WinRM）。若已知目标只开放 WinRM，
    选"仅 WinRM"可省掉一次必然失败的 DCOM 尝试（反之亦然），从而少等一个超时。
    """

    def __init__(self, parent=None, saved_username: str = "", saved_domain: str = "",
                 saved_transport: str = TRANSPORT_AUTO):
        super().__init__(parent)
        self.setWindowTitle(tr("WMI 设备识别 — 管理员凭据"))
        self.setMinimumWidth(400)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QFormLayout(self)

        self.user_edit = QLineEdit(saved_username)
        self.user_edit.setPlaceholderText(tr("如 administrator 或 user（不含域）"))
        layout.addRow(tr("用户名:"), self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText(tr("目标主机管理员密码"))
        layout.addRow(tr("密码:"), self.pass_edit)

        self.domain_edit = QLineEdit(saved_domain)
        self.domain_edit.setPlaceholderText(tr("域（可选，工作组可留空）"))
        layout.addRow(tr("域:"), self.domain_edit)

        # 传输方式：显示文本经 transport_label() 惰性翻译，
        # 用户数据（currentData）存语言无关的规范值 auto/dcom/winrm。
        self.transport_combo = QComboBox()
        for value in (TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM):
            self.transport_combo.addItem(transport_label(value), value)
        idx = self.transport_combo.findData(saved_transport)
        if idx < 0:
            idx = self.transport_combo.findData(TRANSPORT_AUTO)
        if idx >= 0:
            self.transport_combo.setCurrentIndex(idx)
        layout.addRow(tr("传输方式:"), self.transport_combo)

        self.save_check = QCheckBox(tr("保存凭据（DPAPI 加密到本机配置）"))
        layout.addRow(self.save_check)

        hint = QLabel(tr(
            "WMI 识别仅对 Windows 目标有效，且当前凭据需具管理员权限。\n"
            "DCOM 需开放 135 及动态 RPC 端口；WinRM 只需 5985/5986 单端口，跨网段更易通过。\n"
            "非域环境请填目标本机管理员账号。"
        ))
        hint.setObjectName("dialogHintSmall")
        hint.setWordWrap(True)
        layout.addRow(hint)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        localize_buttons(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_credentials(self):
        """返回 (username, password, domain, save, transport)。"""
        return (
            self.user_edit.text().strip(),
            self.pass_edit.text(),
            self.domain_edit.text().strip(),
            self.save_check.isChecked(),
            self.transport_combo.currentData() or TRANSPORT_AUTO,
        )


class SnmpV3CredentialDialog(QDialog):
    """采集 SNMPv3 USM 用户参数（用户名 / 认证 / 加密）。

    v3 相比 v2c 的价值就在于口令不再明文上网：团体字（community）等价于
    把密码写在信封外面，任何抓包的人都能直接看到。目标支持就该用 v3。

    口令以 QLineEdit(Password) 显示；勾选"保存配置"后由调用方用 DPAPI 加密
    存入 ipscanner.ini。本对话框不负责持久化，只回传明文口令。

    "测试"按钮会用当前参数对指定 IP 做一次真实 GET，把失败原因（用户名错 /
    口令错 / 目标没开 SNMP）直接显示出来 —— 比扫完一整段再猜原因快得多。
    """

    def __init__(self, parent=None, saved=None, saved_target: str = ""):
        super().__init__(parent)
        self.setWindowTitle(tr("SNMPv3 识别 — USM 用户"))
        self.setMinimumWidth(440)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        saved = saved or {}
        layout = QFormLayout(self)

        self.user_edit = QLineEdit(saved.get("username", ""))
        self.user_edit.setPlaceholderText(tr("如 snmpuser"))
        layout.addRow(tr("用户名:"), self.user_edit)

        # 协议下拉的显示文本经 auth_label()/priv_label() 惰性翻译，
        # 用户数据（currentData）存语言无关的规范值，绝不拿译文当依据。
        self.auth_combo = QComboBox()
        for value in (AUTH_NONE, AUTH_MD5, AUTH_SHA):
            self.auth_combo.addItem(auth_label(value), value)
        self.auth_combo.setCurrentIndex(max(
            0, self.auth_combo.findData(saved.get("auth_proto", AUTH_NONE))))
        layout.addRow(tr("认证协议:"), self.auth_combo)

        self.auth_edit = QLineEdit(saved.get("auth_key", ""))
        self.auth_edit.setEchoMode(QLineEdit.Password)
        self.auth_edit.setPlaceholderText(tr("认证口令，建议至少 8 位"))
        layout.addRow(tr("认证密码:"), self.auth_edit)

        self.priv_combo = QComboBox()
        for value in (PRIV_NONE, PRIV_AES):
            self.priv_combo.addItem(priv_label(value), value)
        self.priv_combo.setCurrentIndex(max(
            0, self.priv_combo.findData(saved.get("priv_proto", PRIV_NONE))))
        layout.addRow(tr("加密协议:"), self.priv_combo)

        self.priv_edit = QLineEdit(saved.get("priv_key", ""))
        self.priv_edit.setEchoMode(QLineEdit.Password)
        self.priv_edit.setPlaceholderText(tr("加密口令（可与认证口令相同）"))
        layout.addRow(tr("加密密码:"), self.priv_edit)

        # 加密必须建立在认证之上（RFC 3414）；没选认证就直接禁用加密，
        # 免得用户填完才发现用不上
        self.auth_combo.currentIndexChanged.connect(self._sync_priv_enabled)
        self._sync_priv_enabled()

        # ── 测试连接 ──
        test_row = QHBoxLayout()
        self.target_edit = QLineEdit(saved_target)
        self.target_edit.setPlaceholderText(tr("目标 IP，如 192.168.1.1"))
        test_row.addWidget(self.target_edit, 1)
        self.test_btn = QPushButton(tr("测试"))
        self.test_btn.clicked.connect(self._on_test)
        test_row.addWidget(self.test_btn)
        layout.addRow(tr("测试目标:"), test_row)

        # 颜色与字号交给 QSS（`QLabel#snmpTestResult` 及 `[ok]` 属性选择器）：
        # 本对话框拿不到主题标志，硬编码的绿/红在深色底上对比度不足。
        self.result_label = QLabel("")
        self.result_label.setObjectName("snmpTestResult")
        self.result_label.setWordWrap(True)
        layout.addRow(self.result_label)

        self.save_check = QCheckBox(tr("保存配置（DPAPI 加密口令到本机配置）"))
        layout.addRow(self.save_check)

        hint = QLabel(tr(
            "SNMPv3 用用户级认证/加密替代明文团体字，口令不再被中间人直接看到。\n"
            "认证支持 HMAC-MD5-96 / HMAC-SHA-96；加密仅支持 AES-128（不支持已废弃的 DES）。\n"
            "口令不足 8 位时部分设备会拒绝本地化密钥，建议至少 8 位。"
        ))
        hint.setObjectName("dialogHintSmall")
        hint.setWordWrap(True)
        layout.addRow(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        localize_buttons(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _sync_priv_enabled(self):
        """没启用认证就不能启用加密（RFC 3414）。"""
        auth_on = bool(self.auth_combo.currentData())
        self.priv_combo.setEnabled(auth_on)
        self.priv_edit.setEnabled(auth_on)
        if not auth_on:
            self.priv_combo.setCurrentIndex(0)
            self.priv_edit.clear()

    def _current_user(self) -> SnmpV3User:
        return SnmpV3User(
            username=self.user_edit.text().strip(),
            auth_proto=self.auth_combo.currentData() or AUTH_NONE,
            auth_key=self.auth_edit.text(),
            priv_proto=self.priv_combo.currentData() or PRIV_NONE,
            priv_key=self.priv_edit.text(),
        )

    def _on_test(self):
        """用当前参数对目标做一次真实 GET，把结论直接显示出来。"""
        ip = self.target_edit.text().strip()
        if not ip:
            self._set_result(tr("请先填写测试目标 IP"), ok=False)
            return
        user = self._current_user()
        err = user.validate()
        if err:
            self._set_result(err, ok=False)
            return

        self.result_label.setProperty("ok", "")
        self._repolish(self.result_label)
        self.result_label.setText(tr("测试中…"))
        # 单次 GET 最长 1.5s；模态对话框里短暂等待可以接受，
        # 换成线程反而要额外处理"测试还没回来、对话框已被关闭"的竞态
        self.setCursor(Qt.WaitCursor)
        try:
            info = snmp_v3_get_system(ip, user, timeout=1.5)
        finally:
            self.unsetCursor()

        if "error" in info:
            self._set_result(tr("测试失败：%s") % info["error"], ok=False)
        else:
            self._set_result(
                tr("连接成功：%s") % (info.get("sys_name")
                                     or info.get("sys_descr") or ip), ok=True)

    def _set_result(self, text: str, ok: bool):
        self.result_label.setProperty("ok", "true" if ok else "false")
        self._repolish(self.result_label)
        self.result_label.setText(text)

    @staticmethod
    def _repolish(widget):
        """改过动态属性后必须 unpolish/polish 一次，否则 QSS 不会重算 ——
        少了这两步，颜色会在第一次设置后"卡住"不变（与 `overview.set_tone` 同因）。"""
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)

    def get_config(self):
        """返回 (username, auth_proto, auth_key, priv_proto, priv_key, save)。"""
        return (
            self.user_edit.text().strip(),
            self.auth_combo.currentData() or AUTH_NONE,
            self.auth_edit.text(),
            self.priv_combo.currentData() or PRIV_NONE,
            self.priv_edit.text(),
            self.save_check.isChecked(),
        )
