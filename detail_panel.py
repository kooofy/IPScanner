# -*- coding: utf-8 -*-
"""设备详情面板（对应 docs/reviews/UI_REVIEW.md 的 P0-1）。

设计动机
--------
本应用原先只有「工具栏 + 一张 13 列表格」的单面板结构，**没有任何详情区域**。
所有富信息（WMI 硬件、NetBIOS、SNMP sysDescr、共享、OS 细节）只能挤在两个地方：

1. 表格单元格 —— 列宽有限，长字段被截断；
2. tooltip —— `_set_item_data` 里 IP 列的 tip 会拼到 10 段以上，实际不可读。

详情面板把这些字段按「身份 / 网络 / 系统 / 服务 / 风险」五组平铺展示，
长字段不再需要占用表格列，表格因此可以精简（见 P1-2 列预设）。

约定
----
- 所有显示文本经 `tr()` 惰性翻译，不预先拼接语言相关字符串；
- **配色一律走 QSS**（objectName 选择器），不在 Python 里硬编码颜色 ——
  否则深色主题下会出现"漏白"（见 docs/reviews/UI_REVIEW.md P2-2）。
"""
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QSizePolicy,
)

import asset_lifecycle
from scanner import (
    device_class_label, os_label, service_label, format_ports_display,
)
from scanner.wmi import transport_label
from i18n import tr
from ui_utils import (
    format_custom_fields, format_exposure_rows, format_warranty,
    warranty_status_text,
)


class DeviceDetailPanel(QWidget):
    """选中设备的完整画像。空选区时显示引导文案。"""

    #: 用户点击「重新扫描」→ 携带该设备 IP
    rescan_requested = pyqtSignal(str)
    #: 用户点击「复制」→ 携带整段纯文本
    copy_requested = pyqtSignal(str)
    #: 用户点击「编辑资产信息…」→ 携带该设备的**身份键**（v2.3 §3.4）。
    #: 面板只发信号、不弹对话框也不写库 —— 弹窗与写入由 `MainWindow` 负责
    #: （面板要能在无 `MainWindow` 的单测里独立构造）。
    asset_edit_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("detailPanel")
        self._ip = ""
        self._result = None
        self._conflict_notes = []
        self._change_notes = []
        self._timeline = []
        #: 该设备**当前仍开放**的端口暴露行（`trend_store.port_exposure()['open']`）。
        #: 由 `set_device(exposure=…)` 传入 —— 本面板**不碰数据库**。
        self._exposure = []
        #: 该设备的**台账行**（`history_store.get_asset()` 的结果，v2.3 §3.4）。
        #: 同样由 `set_device(asset=…)` 传入。空字典 = 这台设备还没有台账行
        #: （例如刚扫到、还没落过快照）⇒ 不显示「资产信息」分区，也不给编辑入口。
        self._asset = {}
        self._build()

    # ── 构建 ──────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 7, 10, 7)
        root.setSpacing(5)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.title = QLabel("")
        self.title.setObjectName("detailTitle")
        head.addWidget(self.title)
        head.addStretch(1)

        # 编辑入口放在最左（其余是"看/再扫"这类只读动作）—— 它是唯一会写库的
        # 按钮，位置独立一点不容易误点。仅在有台账行时可见（见 `_set_actions_visible`）。
        self.btn_asset_edit = QPushButton(tr("编辑资产信息…"))
        self.btn_asset_edit.setObjectName("detailAction")
        self.btn_asset_edit.setToolTip(
            tr("登记采购日期 / 保修到期 / 负责人 / 序列号 / 位置 / 自定义字段"))
        self.btn_asset_edit.clicked.connect(
            lambda: self.asset_edit_requested.emit(
                (self._asset or {}).get("identity_key", "")))
        head.addWidget(self.btn_asset_edit)

        self.btn_copy = QPushButton(tr("复制"))
        self.btn_copy.setObjectName("detailAction")
        self.btn_copy.setToolTip(tr("复制该设备的全部详情"))
        self.btn_copy.clicked.connect(self._on_copy)
        head.addWidget(self.btn_copy)

        self.btn_rescan = QPushButton(tr("重新扫描"))
        self.btn_rescan.setObjectName("detailAction")
        self.btn_rescan.setToolTip(tr("仅重新扫描该 IP"))
        self.btn_rescan.clicked.connect(lambda: self.rescan_requested.emit(self._ip))
        head.addWidget(self.btn_rescan)
        root.addLayout(head)

        sep = QFrame()
        sep.setObjectName("detailSep")
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        root.addWidget(sep)

        self.body = QGridLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setHorizontalSpacing(14)
        self.body.setVerticalSpacing(2)
        self.body.setColumnStretch(0, 0)
        self.body.setColumnStretch(1, 1)
        root.addLayout(self.body)

        self.hint = QLabel(tr("在上方结果中选择一台设备，这里会显示它的完整信息。"))
        self.hint.setObjectName("detailHint")
        self.hint.setWordWrap(True)
        root.addWidget(self.hint)

        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self._set_actions_visible(False)
        self.clear()

    # ── 对外接口 ──────────────────────────────────────────

    def clear(self):
        """清空选区，回到引导态。"""
        self._result = None
        self._ip = ""
        self._conflict_notes = []
        self._change_notes = []
        self._timeline = []
        self._exposure = []
        self._asset = {}
        self.title.setText("")
        self._clear_rows()
        self._set_actions_visible(False)
        self.hint.setVisible(True)

    def set_device(self, result, conflict_notes=None, change_notes=None,
                   timeline=None, exposure=None, asset=None):
        """展示一台设备的完整信息。

        :param result: `scanner.models.ScanResult`
        :param conflict_notes: 该设备命中的冲突描述列表（来自 conflict_detector）
        :param change_notes:   该设备命中的资产变更描述列表（来自 change_detector）
        :param timeline:       该设备在历史快照中的出现轨迹（来自 history_store
                               .device_timeline），每项形如
                               `{"time", "status", "ip", "mac"}`
        :param exposure:       该设备**当前仍开放**的端口暴露行（来自
                               `trend_store.port_exposure()['open']`），每项形如
                               `{"port", "since", "seconds", "baseline"}`。
                               🔴 `baseline` 为真的行必须显示成「**至少** N」
                               —— 见 `ui_utils.format_exposure_rows()`。
        :param asset:          该设备的**台账行**（`history_store.get_asset()`），
                               形如 `{"identity_key", "purchase_date",
                               "warranty_end", "owner", "serial",
                               "location_tree", "custom_json"}`。传 `None` /
                               空字典 = 还没有台账行，此时不显示「资产信息」分区、
                               也不给「编辑资产信息…」入口。
        """
        if result is None:
            self.clear()
            return
        self._result = result
        self._ip = result.ip or ""
        self._conflict_notes = list(conflict_notes or [])
        self._change_notes = list(change_notes or [])
        self._timeline = list(timeline or [])
        self._exposure = list(exposure or [])
        self._asset = dict(asset or {})

        self.hint.setVisible(False)
        self._set_actions_visible(True)
        self.title.setText(self._header_text(result))
        self._clear_rows()

        row = 0
        for section, entries, spanning in self._sections(
                result, self._conflict_notes, self._change_notes, self._timeline):
            row = self._add_section(row, section, entries, spanning)

        if row == 0:
            # 极端情况：设备只有 IP，没有任何可展示字段
            self._add_row(0, tr("信息"), tr("该设备暂无可展示的详细信息。"))
            row = 1
        # 把多余空间让给正文，避免面板被拉伸时行距异常
        self.body.setRowStretch(row, 1)

    # ── 内部：内容组织 ────────────────────────────────────

    def _header_text(self, r) -> str:
        parts = [r.ip or "—"]
        parts.append(tr("在线") if r.status == "online" else tr("离线"))
        if r.response_time and r.response_time > 0:
            parts.append(f"{round(r.response_time, 1)} ms")
        if r.discovery_method == "arp":
            parts.append(tr("ARP 探测发现"))
        elif r.discovery_method == "mdns":
            parts.append(tr("mDNS 发现"))
        return "  ·  ".join(parts)

    def _sections(self, r, conflict_notes, change_notes=None, timeline=None):
        """返回 [(分区名, [(标签, 值), ...], 是否整行文本), ...]，空分区由调用方跳过。"""
        identity = [
            (tr("主机名"), r.hostname),
            (tr("制造商"), r.vendor),
            (tr("设备类型"), device_class_label(r.device_class) or r.device_type),
            (tr("设备型号"), r.device_model),
            # 序列号**台账优先**：人工登记的序列号（`assets.serial`，v2.3 §3.4）
            # 比探测到的更可信（WMI 取不到序列号的机器很多，而资产标签上就印着）。
            # 台账为空才回落到扫描值 —— 两处各显示一份会让用户分不清哪个是真的。
            (tr("序列号"), self._asset.get("serial") or r.wmi_serial),
        ]

        network = [
            (tr("MAC 地址"), r.mac.upper() if r.mac else ""),
            (tr("开放端口"), format_ports_display(r.open_ports)[0]),
            (tr("共享文件夹"), ", ".join(r.shares) if r.shares else ""),
            # 探测方式只在确实扫出了端口时才有意义（离线主机显示它是噪音）
            (tr("端口探测方式"), {
                "connect": tr("TCP 全连接"), "syn": tr("TCP-SYN 半开"),
                "udp": tr("UDP"),
            }.get(r.scan_method, "") if r.open_ports else ""),
        ]

        system = [
            (tr("操作系统"), f"{os_label(r.os_guess)} {r.os_detail}".strip()),
            (tr("登录用户"), r.wmi_user or r.netbios_user),
            (tr("域 / 工作组"), r.wmi_domain or r.netbios_workgroup),
            (tr("处理器"), r.wmi_cpu),
            (tr("内存"), f"{round(r.wmi_ram_gb, 1)} GB" if r.wmi_ram_gb else ""),
            (tr("最近启动"), r.wmi_last_boot),
            (tr("识别通路"), transport_label(r.wmi_transport) if r.wmi_transport else ""),
            (tr("SNMP 名称"), r.snmp_sys_name),
            (tr("SNMP 描述"), r.snmp_sys_descr),
        ]

        # 服务用「整行文本」而非「标签/值」两栏：服务名本身就是内容，banner 只是
        # 补充。若按两栏渲染，无 banner 的服务（SMB、RDP 等很常见）会因为"值为空"
        # 被整行丢掉 —— 那恰好是用户最需要看到的信息。
        service = []
        for d in (r.service_details or []):
            proto = service_label(d.get("proto", ""))
            port = d.get("port", 0)
            banner = (d.get("banner") or "").strip()
            head = f"{proto}  {port}" if port else proto
            service.append(f"{head}  —  {banner}" if banner else head)
        if not service and r.services:
            service = [service_label(p) for p in r.services]

        risk = [(tr("冲突"), note) for note in conflict_notes]

        # 资产台账（v2.3 §3.4）：**标签/值两栏** —— 值都是短字段（日期、人名）。
        # 🔴 未填保修日期显示「未填」，**绝不**显示「已过期」（§3.4 验收 4）。
        ledger = []
        if self._asset:
            state = asset_lifecycle.warranty_state(self._asset.get("warranty_end"))
            ledger = [
                (tr("采购日期"), self._asset.get("purchase_date", "")),
                (tr("保修到期"), format_warranty(
                    state["end"], state["days_left"], state["status"])),
                (tr("负责人"), self._asset.get("owner", "")),
                (tr("位置"), self._asset.get("location_tree", "")),
                (tr("自定义字段"), format_custom_fields(
                    self._asset.get("custom_json", ""))),
            ]
            # 保修状态单独一行只在**不是"正常"**时出现：正常保修是默认预期，
            # 每台都印一个「正常」只是噪音，而「即将到期」必须显眼。
            if state["status"] not in (asset_lifecycle.WARRANTY_OK,
                                       asset_lifecycle.WARRANTY_UNSET):
                ledger.append((tr("保修状态"),
                               warranty_status_text(state["status"])))

        # 端口暴露（v2.3 §3.3）：**整行文本** —— 一行就是一句
        # 「端口 23 已开放 40.2 天」。起点是"首次观测"的行由
        # `ui_utils.format_exposure_rows()` 加上「至少」，
        # 🔴 绝不把它说成"端口就是那时候开的"。
        exposure = format_exposure_rows(self._exposure)

        # 变更与轨迹同样用「整行文本」渲染：内容本身就是一句话，拆成
        # 标签/值两栏只会让右栏被压窄、长句反复折行。
        # 轨迹按时间倒序（最近的在上）—— 用户关心"最近一次在不在"。
        change = list(change_notes or [])
        history = [self._format_timeline_entry(e) for e in (timeline or [])]
        history = [h for h in history if h]
        history.reverse()

        # 第三项为 True 表示该分区按「整行文本」渲染（不分标签/值两栏）。
        # 先滤掉"值为空"的行，再滤掉"滤完为空"的分区 —— 否则会出现
        # 只印出一个分区标题、下面空无一行的"空壳分区"。
        raw = [
            (tr("身份"), identity, False),
            (tr("网络"), network, False),
            (tr("系统"), system, False),
            (tr("资产信息"), ledger, False),
            (tr("服务"), service, True),
            (tr("变更"), change, True),
            (tr("历史轨迹"), history, True),
            (tr("端口暴露"), exposure, True),
            (tr("风险"), risk, False),
        ]
        visible = []
        for section, entries, spanning in raw:
            if spanning:
                kept = [e for e in entries if self._fmt(e)]
            else:
                kept = [(lab, val) for lab, val in entries if self._fmt(val)]
            if kept:
                visible.append((section, kept, spanning))
        return visible

    # ── 内部：渲染 ────────────────────────────────────────

    def _add_section(self, row, section, entries, spanning=False):
        head = QLabel(section)
        head.setObjectName("detailSection")
        self.body.addWidget(head, row, 0, 1, 2)
        row += 1
        if spanning:
            for text in entries:
                row = self._add_span_row(row, text)
        else:
            for label, value in entries:
                row = self._add_row(row, label, value)
        return row

    def _add_span_row(self, row, text):
        """整行文本（用于「服务」这类"内容本身就是键"的分区）。"""
        text = self._fmt(text)
        if not text:
            return row
        lab = QLabel(text)
        lab.setObjectName("detailValue")
        lab.setWordWrap(True)
        lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.body.addWidget(lab, row, 0, 1, 2)
        return row + 1

    def _add_row(self, row, label, value):
        text = self._fmt(value)
        if not text:
            return row
        lab = QLabel(label)
        lab.setObjectName("detailLabel")
        lab.setAlignment(Qt.AlignRight | Qt.AlignTop)
        lab.setWordWrap(False)
        val = QLabel(text)
        val.setObjectName("detailValue")
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.body.addWidget(lab, row, 0)
        self.body.addWidget(val, row, 1)
        return row + 1

    @staticmethod
    def _fmt(value) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        return "" if text in ("", "—", "-") else text

    @staticmethod
    def _format_timeline_entry(entry) -> str:
        """把一条快照记录格式化成一行轨迹文本：`时间  状态  IP`。

        时间戳解析失败时**只丢掉时间**、保留状态与 IP —— 一条没有时间的
        "在线/离线"记录仍比整行消失有用。
        """
        if not isinstance(entry, dict):
            return ""
        when = ""
        ts = entry.get("time")
        if ts:
            try:
                when = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
            except (ValueError, OSError, OverflowError, TypeError):
                when = ""
        state = tr("在线") if entry.get("status") == "online" else tr("离线")
        parts = [p for p in (when, state, entry.get("ip") or "") if p]
        return "   ".join(parts)

    def _clear_rows(self):
        while self.body.count():
            item = self.body.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

    def _set_actions_visible(self, visible: bool):
        self.btn_copy.setVisible(visible)
        self.btn_rescan.setVisible(visible)
        # 没有台账行就没有身份键可写（`update_asset_lifecycle()` 以 identity_key
        # 定位）—— 与其弹个必然报"找不到设备"的框，不如不给这个入口。
        self.btn_asset_edit.setVisible(
            bool(visible and (self._asset or {}).get("identity_key")))

    def _on_copy(self):
        self.copy_requested.emit(self._plain_text())

    def _plain_text(self) -> str:
        """整段纯文本（供复制 / 导出），与面板显示内容一致。"""
        if self._result is None:
            return ""
        lines = [self._header_text(self._result)]
        sections = self._sections(self._result, self._conflict_notes,
                                  self._change_notes, self._timeline)
        if not sections:
            # 与面板保持一致：没有任何可展示字段时给出明确说明，而不是只回一行 IP
            lines.append(tr("该设备暂无可展示的详细信息。"))
        for section, entries, spanning in sections:
            lines.append(f"[{section}]")
            if spanning:
                for text in entries:
                    lines.append(f"  {text}")
            else:
                for label, value in entries:
                    lines.append(f"  {label}: {value}")
        return "\n".join(lines)
