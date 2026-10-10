# -*- coding: utf-8 -*-
"""设备定位对话框：输入 MAC / IP / 主机名 → 它接在哪台交换机的哪个口。

数据来自扫描时按需落库的交换机转发表（`history_store.save_port_map`）。
查不到时**如实说明是哪一种未知**并给出下一步动作 —— 延续本项目的诚实降级原则：
`locate_device()` 的 `reason` 是规范值，翻译发生在这一层。
"""
import re
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout,
)

from i18n import tr
from scanner.constants import locate_reason_hint, locate_reason_label
import history_store

# MAC 的常见写法：AA:BB:CC:DD:EE:FF / AA-BB-CC-DD-EE-FF
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")

# 点分四段 IPv4。**用正则而不是 `ipaddress.IPv4Address` + try/except**：
# 这里「不是 IP」是**正常分支**（用户输入的多数是主机名），为它写一个
# `except ValueError: pass` 会被 `tests/test_logging_policy.py` 的棘轮判为
# 新增静默吞异常。正则没有这个副作用，且同样拒绝 "999.1.1.1" / "01.2.3.4"。
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")


def classify_query(text: str):
    """把用户输入判成 ``('mac' | 'ip' | 'hostname', 值)``。

    自动判别而不是让用户先选类型：这三种写法彼此不重叠，判错的可能几乎为零，
    多一个下拉框只会多一步操作。
    """
    t = (text or "").strip()
    if _MAC_RE.match(t):
        return "mac", t
    if _IPV4_RE.match(t):
        return "ip", t
    return "hostname", t


def _fmt_time(ts) -> str:
    """时间戳 → 本地时间文本；取不到就返回空串（不抛异常，界面不该因此炸掉）。"""
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


class LocateDeviceDialog(QDialog):
    """「这台设备插在哪」—— 定位查询的界面入口。"""

    def __init__(self, parent=None, db_path=None, dark=False):
        super().__init__(parent)
        self.db_path = db_path
        self.dark = dark
        self.setWindowTitle(tr("设备定位"))
        self.setMinimumSize(560, 320)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── 顶部：查询输入 + 定位按钮 ──
        top = QHBoxLayout()
        top.setSpacing(6)
        top.addWidget(QLabel(tr("输入 MAC / IP / 主机名:")))
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText(tr("例如 AA:BB:CC:DD:EE:FF 或 192.168.1.50"))
        self.query_input.returnPressed.connect(self._do_locate)
        top.addWidget(self.query_input, 1)
        self.btn_locate = QPushButton(tr("定位"))
        self.btn_locate.clicked.connect(self._do_locate)
        top.addWidget(self.btn_locate)
        layout.addLayout(top)

        # ── 结果 ──
        self.result_label = QLabel("")
        self.result_label.setObjectName("dialogHint")
        self.result_label.setTextFormat(Qt.PlainText)
        self.result_label.setWordWrap(True)
        self.result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.result_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.addWidget(self.result_label, 1)

        # 查不到时才有内容：下一步该怎么做
        self.hint_label = QLabel("")
        self.hint_label.setObjectName("dialogHint")
        self.hint_label.setWordWrap(True)
        self.hint_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hint_label.setVisible(False)
        layout.addWidget(self.hint_label)

        # ── 底部 ──
        bottom = QHBoxLayout()
        bottom.addStretch()
        btn_close = QPushButton(tr("关闭"))
        btn_close.clicked.connect(self.accept)
        bottom.addWidget(btn_close)
        layout.addLayout(bottom)

        self.setLayout(layout)

    # ── 查询 ──

    def _do_locate(self):
        """按输入框内容查询。返回 `locate_device()` 的结果（供测试与调用方复用）。"""
        text = self.query_input.text().strip()
        if not text:
            self._show_message(tr("请输入 MAC、IP 或主机名。"))
            return None
        return self.locate(text)

    def locate(self, text: str):
        """查询并渲染。`text` 可为 MAC / IP / 主机名（自动判别）。"""
        kind, value = classify_query(text)
        r = history_store.locate_device(
            mac=value if kind == "mac" else "",
            ip=value if kind == "ip" else "",
            hostname=value if kind == "hostname" else "",
            db_path=self.db_path,
        )
        if r["found"]:
            self._show_found(r)
        else:
            self._show_not_found(r)
        return r

    # ── 渲染 ──

    def _show_message(self, text: str):
        self.result_label.setText(text)
        self.hint_label.setVisible(False)

    def _show_found(self, r):
        cur = r["current"]
        lines = [
            f"{tr('设备')}: {r['mac'] or '—'}",
            f"IP: {r['ip'] or '—'}   {tr('主机名')}: {r['hostname'] or '—'}",
            f"{tr('当前位置')}: {cur['switch_name'] or cur['switch_ip']} "
            f"{tr('端口')} {cur['port_name'] or '—'}",
            f"  {tr('快照')} #{cur['snapshot_id']} · {_fmt_time(cur['time'])}",
        ]
        prev = r["previous"]
        if prev:
            lines += [
                f"{tr('上次位置')}: {prev['switch_name'] or prev['switch_ip']} "
                f"{tr('端口')} {prev['port_name'] or '—'}",
                f"  {tr('快照')} #{prev['snapshot_id']} · {_fmt_time(prev['time'])}",
                f"{tr('已换过端口')}: {tr('是')}",
            ]
        else:
            lines.append(f"{tr('已换过端口')}: {tr('否')}")
        lines.append(
            f"{tr('端口名可信度')}: "
            + (tr("真实接口名") if r["port_confidence"] == "named"
               else tr("仅桥接端口号（不可信）")))
        self.result_label.setText("\n".join(lines))
        self.hint_label.setVisible(False)

    def _show_not_found(self, r):
        who = r["mac"] or r["ip"] or r["hostname"]
        self.result_label.setText(
            f"{tr('未定位到设备')}: {who}\n"
            f"{tr('原因')}: {locate_reason_label(r['reason'])}")
        hint = locate_reason_hint(r["reason"])
        self.hint_label.setText(f"{tr('提示')}: {hint}" if hint else "")
        self.hint_label.setVisible(bool(hint))
