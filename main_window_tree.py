# -*- coding: utf-8 -*-
"""树控件操作混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import (
    QApplication, QMenu, QAction, QTreeWidgetItem, QStyle
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QIcon, QPainter, QBrush, QPen, QPixmap

from scanner import (ScanResult, PROTOCOL_PORTS, format_ports_display,
                     SVC_HTTP, SVC_HTTPS, SVC_FTP, SVC_RDP,
                     SVC_SNMP, SVC_SMB, SVC_MDNS, service_label,
                     device_class_label, os_label)
import audit_log
from change_detector import (
    CHANGE_NEW_DEVICE, CHANGE_DEVICE_GONE, CHANGE_IP_CHANGED,
    CHANGE_MAC_CHANGED, CHANGE_HOSTNAME_CHANGED, CHANGE_MAC_RANDOMIZED,
)
from conflict_detector import SEVERITY_HIGH
from ui_icons import get_pc_icons
from theme_tokens import token
from favorites import favorite_key, star_icon
from mac_library import MacMatcher
from oui_database import is_randomized_mac
import risk_rules
from styles import _FONT_CONSOLAS_10, _FONT_CONSOLAS_9, _FONT_YAHEI_BOLD_9
from ui_utils import _ip_to_int
from scanner.wmi import transport_label
from i18n import tr

# 顶层设备项上缓存的"服务子项渲染签名"存放槽位。
#
# 第 0 列（树列）的 UserRole 被 IP 数值排序键占用（见 _set_item_data），
# UserRole+1..+5 被子项的 proto/ip/descr/name/banner 占用，
# 因此 +6 是安全的空槽。存在项自身上（而不是另开一个 dict）的好处是
# 生命周期自动跟随项，清空表格时无需额外清理。
_ROLE_SVC_SIG = Qt.UserRole + 6

#: 顶层设备项的**规范 IP**（语言无关、且不受冲突标记前缀影响）。
#
# 为什么需要单独存：`_apply_conflict_mark` 会把 IP 列文本改成 `"⚠ 192.168.1.42"`，
# 于是任何"读第 0 列文本当 IP 用"的代码（右键菜单、内置工具、重扫）都会拿到
# 带前缀的脏字符串，进而在 `_launch_network_tool` / `_remote_power` 里拼出
# 非法的目标地址。存一份原始 IP 到独立 role，读取方一律走 `_item_ip()`。
_ROLE_DEV_IP = Qt.UserRole + 7

#: 顶层设备项的收藏键（`mac:…` 或 `ip:…`，见 favorites.favorite_key）。
#: 存在项上是为了让"收藏"筛选不必回查结果对象 —— 表格里只有渲染后的文本，
#: 拿不到 MAC/IP 之外的字段。
_ROLE_FAV_KEY = Qt.UserRole + 8

#: 顶层设备项命中的**变更类型列表**（规范代码，见 change_detector.CHANGE_*）。
#: 与 `_ROLE_FAV_KEY` 同理：筛选/角标只看行上已有的信息，不回查结果对象。
_ROLE_CHANGE = Qt.UserRole + 9

#: 顶层设备项的**基础 tooltip**（不含冲突/变更追加段）。
#:
#: 此前 `_apply_conflict_mark` 靠 `tip.split(tr(" | 冲突:"))[0]` 反向剥离自己
#: 追加过的内容 —— 一旦文案改动或多方都想追加，就会把别人的段落一起切掉。
#: 改为把 `_set_item_data` 生成的原始 tip 存进 role，最终 tooltip 由
#: `_apply_row_marks()` 从「基础段 + 冲突段 + 变更段」重新拼出。
_ROLE_BASE_TIP = Qt.UserRole + 10

#: 变更类型 → 行内角标字形。
#:
#: 只放**一个字形**、不放文字标签：IP 列宽约 90–110px，`10.1.0.5 ＋新增`
#: 会被直接截断成 `10.1.0.…`。完整描述交给 tooltip 与详情面板。
#: 用全角 `＋` 而不是半角 `+`：半角加号在 Consolas 下与 IP 里的数字同宽，
#: 视觉上会粘成一体。
_CHANGE_GLYPH = {
    CHANGE_NEW_DEVICE: "＋",
    CHANGE_IP_CHANGED: "↑",
    CHANGE_MAC_CHANGED: "⇄",
    CHANGE_HOSTNAME_CHANGED: "✎",
    CHANGE_DEVICE_GONE: "✗",
    # 随机 MAC 重现：用「循环」意象，与「被替换（⇄）」区分开 ——
    # 前者是同一台设备换了地址，后者是换了台设备。
    CHANGE_MAC_RANDOMIZED: "↻",
}

#: 变更类型的规范中文标签（与 `Change.type_label` 同源，但那边依赖 tr()，
#: 这里需要在**拼接 tooltip 时**也能拿到，故单独存一份规范中文、由 tr() 包装）。
_CHANGE_LABEL = {
    CHANGE_NEW_DEVICE: "新增设备",
    CHANGE_IP_CHANGED: "IP 变更",
    CHANGE_MAC_CHANGED: "MAC 变更",
    CHANGE_HOSTNAME_CHANGED: "主机名变更",
    CHANGE_DEVICE_GONE: "设备消失",
    CHANGE_MAC_RANDOMIZED: "随机 MAC 重现",
}

class ResultTreeItem(QTreeWidgetItem):
    """结果树项：重写 < 以支持按列的数值排序（IP / 响应时间 / 序号）。

    排序键统一存放在各列的 Qt.UserRole；默认按字符串比较（含回退数值解析）。
    """

    def __lt__(self, other):
        tree = self.treeWidget()
        if tree is None:
            return QTreeWidgetItem.__lt__(self, other)
        col = tree.header().sortIndicatorSection()
        a = self.data(col, Qt.UserRole)
        b = other.data(col, Qt.UserRole)
        if a is not None and b is not None:
            return a < b
        # 回退：尝试数值比较，否则按字符串
        ta = self.text(col)
        tb = other.text(col)
        try:
            return float(ta) < float(tb)
        except (ValueError, TypeError):
            return ta < tb



class TreeMixin:
    """树控件所有操作：填充行、服务子项、右键菜单、筛选、复制等。
    作为 Mixin 供 MainWindow 继承使用。
    """

    def _expand_all_items(self):
        """全选并展开所有结果项。"""
        self.table.selectAll()
        self.table.expandAll()

    def _collapse_all_items(self):
        """收起所有结果项。"""
        self.table.collapseAll()

    def _refresh_theme_marks(self):
        """主题切换后刷新树项上**由 Python 设色**的部分。

        QSS 覆盖不到 `QTreeWidgetItem` 的前景色，也覆盖不到预渲染的位图图标，
        所以这几处必须显式重设，否则切到深色后它们仍是浅色版的颜色。

        需要覆盖的位置必须与 `_set_item_data()` / `_add_service_children()` 对齐：

        - 顶层项第 0 列（`_apply_row_marks`：冲突红/橙、变更强调色、默认色）
        - 顶层项第 1 列（状态色 + 预渲染电脑图标）
        - 顶层项第 4 列（制造商列，仅地址库命中时才是链接色）
        - **所有子项**的第 0 列（服务 / WMI / NetBIOS，统一链接色）

        漏掉后两项就是 P0-1：深色下它们仍是浅色蓝 `#2563EB`，在 `#252526` 上只有
        2.96:1。回归测试 `tests/test_theme_marks.py` 用"切主题后的渲染结果必须与
        直接以深色构建逐点一致"守这个不变量 —— 以后新增列/子项类型会被自动覆盖。
        """
        online_icon, offline_icon = get_pc_icons(self.dark_mode)
        for ip, item in self._ip_item_map.items():
            result = self._result_map.get(ip)
            is_online = result.status == "online" if result is not None else None
            # 第 0 列的前景色由 _apply_row_marks 统一决定（冲突红/橙、变更强调色、
            # 否则默认色）。这里不要直接 setForeground(0, ...) —— 那会把变更角标
            # 的颜色在切主题时抹成默认色。
            self._apply_row_marks(item, ip)
            if is_online is not None:
                item.setForeground(1, QColor(token("online" if is_online else "offline",
                                                   self.dark_mode)))
                item.setIcon(1, online_icon if is_online else offline_icon)
                self._apply_favorite_mark(item, result)
                self._apply_manufacturer_mark(item, result)
            # 子项刷新**不能**受上面的条件限制：即使拿不到 result 也要把颜色刷回来。
            self._refresh_child_marks(item)

    def _apply_manufacturer_mark(self, item, result):
        """第 4 列（制造商）的链接色与字重。

        判据只有"地址库命中"一处，初次渲染与切主题刷新共用 —— 两处判据一旦漂移，
        切主题时就不知道该刷哪一行（漏刷即 P0-1，错刷会把未命中的行也标成链接色）。
        未命中时**不设**前景色：`_set_item_data()` 也从没设过，让 QSS 的默认文字色生效。
        """
        if result is not None and result.excel_matched and result.device_type:
            item.setForeground(4, self._link_color())
            item.setFont(4, _FONT_YAHEI_BOLD_9)

    def _refresh_child_marks(self, item):
        """把子项（服务 / WMI / NetBIOS）的前景色刷到当前主题。

        `_apply_row_marks()` 只管顶层项的第 0 列，不会递归到子项，所以必须单独走
        一遍。子项文本都画在第 0 列（`setFirstColumnSpanned` 跨列显示）且统一用
        链接色，因此这里不必区分类型。
        """
        color = self._link_color()
        for i in range(item.childCount()):
            child = item.child(i)
            if child is not None:
                child.setForeground(0, color)

    def _refresh_conflict_marks(self):
        """根据 _conflict_ips 刷新树视图中所有行的冲突标记。"""
        for ip, item in self._ip_item_map.items():
            self._apply_row_marks(item, ip)

    def _refresh_change_marks(self):
        """根据 _change_map 刷新树视图中所有行的变更角标。"""
        for ip, item in self._ip_item_map.items():
            self._apply_row_marks(item, ip)

    def _change_types_for(self, ip) -> list:
        """该 IP 命中的变更类型列表（规范代码，见 change_detector）。"""
        return list(getattr(self, "_change_map", {}).get(ip, ()))

    def _apply_row_marks(self, item, ip):
        """合成第 0 列的文本 / 前景色 / tooltip。

        冲突标记（`"⚠ "` 前缀）与变更角标（`"↑"` 后缀）都要改第 0 列文本，
        此前两者各自 `setText`/`setToolTip`，后调用的那个会把前一个的结果
        整个覆盖掉 —— 一台设备同时"有冲突"又"IP 变了"时必然丢一个标记。
        本函数从 role 里读取各项标记、一次性合成，因此不会互相踩。

        优先级：冲突（红/橙，更严重）> 变更（强调色）> 默认前景色。
        """
        base = item.data(0, _ROLE_DEV_IP) or ip or ""
        if not base:
            return
        conflict_types = getattr(self, "_conflict_ips", {}).get(base, [])
        change_types = self._change_types_for(base)

        text = f"⚠ {base}" if conflict_types else base
        glyph = "".join(_CHANGE_GLYPH.get(t, "") for t in change_types)
        if glyph:
            text += f" {glyph}"
        item.setText(0, text)

        if conflict_types:
            has_high = any(
                c.severity == SEVERITY_HIGH
                for c in self._conflicts
                if base in c.ips
            )
            item.setForeground(0, QColor(token("danger" if has_high else "warn",
                                               self.dark_mode)))
        elif change_types:
            item.setForeground(0, QColor(token("accent", self.dark_mode)))
        else:
            item.setForeground(0, self._default_fg_color())

        # tooltip 整体重算：基础段 + 冲突段 + 变更段。不做"追加/剥离"，
        # 因此不存在残留上一次标记的问题。
        parts = [item.data(0, _ROLE_BASE_TIP) or base]
        if conflict_types:
            tips = [f"[{c.severity_label}] {c.description}"
                    for c in self._conflicts if base in c.ips]
            parts.append(tr("冲突") + ": " + "; ".join(tips))
        if change_types:
            parts.append(
                tr("变更") + ": "
                + "; ".join(tr(_CHANGE_LABEL.get(t, t)) for t in change_types)
            )
        item.setToolTip(0, " | ".join(p for p in parts if p))

        # 风险列（P3-4）必须跟着这里一起刷：冲突一变，风险分数就变，而冲突正是
        # 本函数读的 `_conflict_ips`。放在别处就会出现"IP 列标红了、风险列还写着
        # 低风险"这种自相矛盾。切主题也走这条路径，所以自动跟上。
        self._apply_risk_mark(item, self._result_map.get(base))

    def _apply_risk_mark(self, item, result):
        """第 13 列（风险）：等级 + 分数，按等级取语义色。

        算法全在 `risk_rules.score_risk()`（纯逻辑、零 PyQt），这里只负责取色
        与落字。

        `result` 为 None 时**直接返回，不清空单元格** —— 首次渲染时
        `_result_map` 可能还没登记（生产路径先登记再建行，但测试夹具与将来的
        调用方未必），清空会把 `_set_item_data()` 刚写好的分数抹掉。

        ⚠️ 这一列是**由 Python 设色**的，所以 `_refresh_theme_marks()` 必须能刷到
        它。本函数只从 `_apply_row_marks()` 调用，初次渲染与切主题刷新共用同一条
        路径 —— `tests/test_theme_marks.py` 的「切主题 == 直接以深色构建」守着。
        """
        if result is None:
            return
        conflicts = [c for c in getattr(self, "_conflicts", [])
                     if result.ip in c.ips]
        risk = risk_rules.score_risk(result, conflicts)
        col = risk_rules.RISK_COLUMN
        item.setText(col, risk_rules.format_risk(risk))
        item.setToolTip(col, risk_rules.format_risk_tooltip(risk))
        item.setTextAlignment(col, Qt.AlignCenter)
        name = risk_rules.RISK_LEVEL_TOKEN.get(risk["level"])
        if name:
            item.setForeground(col, QColor(token(name, self.dark_mode)))

    def _default_fg_color(self):
        """返回当前主题的默认前景色（取自语义色令牌，见 theme_tokens）。"""
        return QColor(token("fg", self.dark_mode))

    # --- 表格操作 ---

    def _upsert_table_row(self, result: ScanResult):
        """新增或更新指定 IP 的项，避免同一 IP 重复显示"""
        # 详情面板按 IP 取回完整结果对象。维护成字典而非线性扫 all_results：
        # /16 网段下 all_results 可达 6.5 万条，键盘上下键切换选区时逐条线性
        # 查找会让选中反馈明显卡顿。
        self._result_map[result.ip] = result
        if result.ip in self._ip_item_map:
            item = self._ip_item_map[result.ip]
            self._update_item_data(item, result)
        else:
            item = self._add_top_level_item(result)
            self._ip_item_map[result.ip] = item
        # 增量应用筛选：离线终端边扫边隐藏（默认"仅在线"）
        item.setHidden(not self._item_matches_filter(item))

    def _add_top_level_item(self, result: ScanResult):
        item = ResultTreeItem()
        self.table.addTopLevelItem(item)
        self._set_item_data(item, result)
        self._add_service_children(item, result)
        return item

    def _update_item_data(self, item: QTreeWidgetItem, result: ScanResult):
        self._set_item_data(item, result)
        self._add_service_children(item, result)

    def _add_service_children(self, item: QTreeWidgetItem, result: ScanResult):
        """为设备项添加服务子项（展开后跨列显示），仿 Advanced IP Scanner 风格。

        子项内容完全由 result 的服务/WMI/NetBIOS 字段决定，因此先算一个签名：
        与上次渲染一致就直接返回，**不**执行 takeChildren()。

        旧实现每次都无条件 takeChildren() 全量重建，带来两个真实问题：
          - 已经展开的设备，其子项选中态与展开态在每次刷新时被清空；
          - 无谓的重建造成可感知的闪烁（扫描过程中每行都会被刷新一次）。
        """
        # 优先使用带 banner 的详细信息；旧结果无 details 时回退 services 列表
        details = result.service_details or []
        if not details and result.services:
            details = [{"proto": p, "port": PROTOCOL_PORTS.get(p.upper(), 0), "banner": ""}
                       for p in result.services]

        # 签名必须覆盖所有会影响子项内容的输入，包括**翻译后的**协议名 ——
        # 否则切换界面语言后签名不变，子项会停留在旧语言。
        sig = (
            tuple((d.get("proto", ""), service_label(d.get("proto", "")),
                   d.get("banner", "")) for d in details),
            bool(getattr(result, "wmi_identified", False)),
            result.wmi_manufacturer, result.wmi_model, result.wmi_serial,
            result.wmi_os, result.wmi_user,
            getattr(result, "wmi_transport", ""),
            bool(getattr(result, "netbios_identified", False)),
            result.netbios_name, result.netbios_workgroup,
            result.netbios_user, result.netbios_mac,
        )
        if item.data(0, _ROLE_SVC_SIG) == sig:
            return
        item.setData(0, _ROLE_SVC_SIG, sig)

        item.takeChildren()

        if (not details and not getattr(result, "wmi_identified", False)
                and not getattr(result, "netbios_identified", False)):
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            return
        # 即使没有服务子项，也要展示 WMI 识别结果，故此处统一标记为可展开
        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

        parent_index = self.table.indexFromItem(item)
        for idx, detail in enumerate(details):
            proto = detail.get("proto", "")
            banner = detail.get("banner", "")
            # proto 是语言无关的规范代码（见 scanner/constants.py），
            # 显示名必须经 service_label() 惰性翻译，不能直接 .upper()
            proto_label = service_label(proto)

            child = QTreeWidgetItem()
            # UserRole 元数据固定存于第 0 列（IP/树列，点击逻辑从此读取）
            child.setData(0, Qt.UserRole, "service")
            child.setData(0, Qt.UserRole + 1, proto)
            child.setData(0, Qt.UserRole + 2, result.ip)
            child.setData(0, Qt.UserRole + 5, banner)

            # 第 0 列是 IP 地址列，也是树列(tree column)。
            # 服务子项的图标+文本放第 0 列，并通过 setFirstColumnSpanned
            # 让子项从 IP 列左缘起跨所有列显示，仿 AIP 效果。
            icon = self._service_icon(proto)
            if icon:
                child.setIcon(0, icon)

            if banner:
                # 保持与 AIP 一致的子项格式：proto, banner
                # 例如 HTTPS 会显示为 "HTTPS, Tunnel is OpenSSL TLSv1.2: xxx"
                display = f"{proto_label}, {banner}"
            else:
                # 空 banner 时不再回退到 "port X"，与 AIP 保持一致：仅显示协议名
                display = proto_label
            child.setText(0, display)
            child.setForeground(0, self._link_color())
            child.setToolTip(0, display)
            child.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)

            # 跨列显示：子项文本从第 0 列(IP列)起横跨整行。
            # 注意：必须使用 QTreeView.setFirstColumnSpanned(row, parent_index, True) 才能生效。

            # SNMP 保留 sysName/sysDescr 供点击弹窗展示
            if proto.upper() == SVC_SNMP:
                child.setData(0, Qt.UserRole + 3, result.snmp_sys_descr)
                child.setData(0, Qt.UserRole + 4, result.snmp_sys_name)

            item.addChild(child)
            self.table.setFirstColumnSpanned(idx, parent_index, True)

        # WMI 远程识别结果（若有）：作为一条子项展示权威硬件/系统信息
        if getattr(result, "wmi_identified", False):
            wmi_child = QTreeWidgetItem()
            wmi_child.setData(0, Qt.UserRole, "wmi")
            wmi_child.setData(0, Qt.UserRole + 2, result.ip)
            parts = []
            if result.wmi_manufacturer:
                parts.append(result.wmi_manufacturer)
            if result.wmi_model:
                parts.append(result.wmi_model)
            if result.wmi_serial:
                parts.append(f"SN:{result.wmi_serial}")
            if result.wmi_os:
                parts.append(result.wmi_os)
            if result.wmi_user:
                parts.append(f"用户:{result.wmi_user}")
            if parts:
                wmi_text = "WMI, " + " · ".join(parts)
            else:
                wmi_text = tr("WMI, 已识别")
            _tv = getattr(result, "wmi_transport", "")
            if _tv:
                # 标注实际生效的通路（DCOM / WinRM）——排障时一眼看出走的哪条
                wmi_text += f" · {transport_label(_tv)}"
            wmi_child.setIcon(0, self.style().standardIcon(QStyle.SP_ComputerIcon))
            wmi_child.setText(0, wmi_text)
            wmi_child.setForeground(0, self._link_color())
            wmi_child.setToolTip(0, wmi_text)
            wmi_child.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
            idx = item.childCount()
            item.addChild(wmi_child)
            self.table.setFirstColumnSpanned(idx, parent_index, True)

        # NetBIOS 轻量识别结果（若有）：作为一条子项展示计算机名/工作组/用户/MAC
        if getattr(result, "netbios_identified", False):
            nb_child = QTreeWidgetItem()
            nb_child.setData(0, Qt.UserRole, "netbios")
            nb_child.setData(0, Qt.UserRole + 2, result.ip)
            parts = []
            if result.netbios_name:
                parts.append(result.netbios_name)
            if result.netbios_workgroup:
                parts.append(f"工作组:{result.netbios_workgroup}")
            if result.netbios_user:
                parts.append(f"用户:{result.netbios_user}")
            if result.netbios_mac:
                parts.append(f"MAC:{result.netbios_mac}")
            nb_text = "NetBIOS, " + " · ".join(parts) if parts else tr("NetBIOS, 已识别")
            nb_child.setIcon(0, self.style().standardIcon(QStyle.SP_ComputerIcon))
            nb_child.setText(0, nb_text)
            nb_child.setForeground(0, self._link_color())
            nb_child.setToolTip(0, nb_text)
            nb_child.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
            idx = item.childCount()
            item.addChild(nb_child)
            self.table.setFirstColumnSpanned(idx, parent_index, True)

        # IP 地址列 (col 0) 按内容自适应宽度，避免 IP 被截断
        self.table.resizeColumnToContents(0)
        # MAC 地址列 (col 3) 按内容自适应宽度，保证默认状态完整显示终端 MAC
        self.table.resizeColumnToContents(3)


    def _service_icon(self, proto: str):
        proto_upper = proto.upper()
        if proto_upper in (SVC_HTTP, SVC_HTTPS):
            return self._globe_icon()
        icon_map = {
            SVC_FTP: QStyle.SP_DirIcon,
            SVC_RDP: QStyle.SP_ComputerIcon,
            "SSH": QStyle.SP_CommandLink,
            "TELNET": QStyle.SP_CommandLink,
            SVC_SNMP: QStyle.SP_DriveNetIcon,
            SVC_SMB: QStyle.SP_DriveNetIcon,
            SVC_MDNS: QStyle.SP_DriveNetIcon,
        }
        sp = icon_map.get(proto_upper)
        if sp:
            return self.style().standardIcon(sp)
        return self._globe_icon()


    def _globe_icon(self) -> QIcon:
        # 首次构造后缓存，避免每个 HTTP/HTTPS 服务行都重绘 QPixmap（顶层已导入相关类）
        cache = getattr(self, "_globe_icon_cache", None)
        if cache is not None:
            return cache
        pm = QPixmap(20, 20)
        pm.fill(Qt.transparent)
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.Antialiasing, True)

        # 地球底色。色值走令牌 —— 该位图一次构造后缓存（`_globe_icon_cache`），
        # 不随主题重绘，所以令牌刻意浅深同值（见 theme_tokens 里 icon_globe 的说明）。
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor(token("icon_globe", self.dark_mode))))
        painter.drawEllipse(2, 2, 16, 16)

        # 经纬线
        painter.setPen(QPen(QColor(255, 255, 255, 180), 1))
        painter.setBrush(Qt.NoBrush)
        # 赤道
        painter.drawLine(2, 10, 18, 10)
        # 本初子午线
        painter.drawLine(10, 2, 10, 18)
        # 南北回归线
        painter.drawArc(4, 5, 12, 10, 0, 180 * 16)
        painter.drawArc(4, 5, 12, 10, 180 * 16, 180 * 16)

        painter.end()
        icon = QIcon(pm)
        self._globe_icon_cache = icon
        return icon



    def _set_item_data(self, item: QTreeWidgetItem, result: ScanResult):
        """设置/更新指定项的所有列内容"""
        # ── 列布局: 0=IP地址, 1=状态, 2=主机名, 3=MAC, 4=制造商, 5=位置, 6=使用者, 7=响应时间, 8=开放端口, 9=服务, 10=备注 ──

        # IP地址列 (col 0) — 同时是树列(tree column)，展开三角在此列
        item.setText(0, result.ip)
        item.setData(0, Qt.UserRole, _ip_to_int(result.ip))  # IP 数值排序键
        item.setData(0, _ROLE_DEV_IP, result.ip)             # 规范 IP（防冲突前缀污染）
        item.setFont(0, _FONT_CONSOLAS_10)
        item.setForeground(0, self._default_fg_color())

        # 工具提示：标注发现方式（ARP 探测发现的静默主机）
        tip = result.ip
        if result.discovery_method == "arp":
            tip += tr(" （ARP 主动探测发现 · 禁 Ping 但在线）")
        elif result.discovery_method == "mdns":
            tip += tr(" （mDNS 发现 · 组播发现设备）")
        if result.os_guess:
            tip += f" · OS: {os_label(result.os_guess)}"
            if result.os_detail:
                tip += f" ({result.os_detail})"
        if result.shares:
            tip += f" · 共享: {', '.join(result.shares)}"
        if result.device_class:
            tip += f" · 设备: {device_class_label(result.device_class)}"
            if result.device_model:
                tip += f" ({result.device_model})"
        if getattr(result, "wmi_identified", False):
            tip += f" · WMI: {result.wmi_manufacturer} {result.wmi_model}".rstrip()
            if result.wmi_os:
                tip += f" / {result.wmi_os}"
            if result.wmi_user:
                tip += f" · 登录: {result.wmi_user}"
            if result.wmi_serial:
                tip += f" · SN: {result.wmi_serial}"
        elif getattr(result, "wmi_error", ""):
            tip += f" · WMI: 失败（{result.wmi_error}）"
        if getattr(result, "netbios_identified", False):
            tip += f" · NetBIOS: {result.netbios_name}".rstrip()
            if result.netbios_workgroup:
                tip += f" / {result.netbios_workgroup}"
            if result.netbios_user:
                tip += f" · 登录: {result.netbios_user}"
            if result.netbios_mac:
                tip += f" · MAC: {result.netbios_mac}"
        elif getattr(result, "netbios_error", ""):
            tip += f" · NetBIOS: 失败（{result.netbios_error}）"
        # 存一份**基础 tooltip**：最终显示的 tooltip 由 `_apply_row_marks()`
        # 在它之上拼接冲突段/变更段，避免多方各自"追加-剥离"同一段文本。
        item.setData(0, _ROLE_BASE_TIP, tip)
        item.setToolTip(0, tip)

        # 状态列 (col 1)：预渲染电脑图标 (在线绿 / 离线灰) + 文字
        item.setData(1, Qt.UserRole, result.status)
        item.setData(1, Qt.DisplayRole, tr("在线") if result.status == "online" else tr("离线"))
        item.setTextAlignment(1, Qt.AlignCenter)
        online_icon, offline_icon = get_pc_icons(self.dark_mode)
        if result.status == "online":
            item.setForeground(1, QColor(token("online", self.dark_mode)))
            item.setIcon(1, online_icon)
        else:
            item.setForeground(1, QColor(token("offline", self.dark_mode)))
            item.setIcon(1, offline_icon)

        item.setText(2, result.hostname or "—")

        mac_text = result.mac.upper() if result.mac else "—"
        item.setText(3, mac_text)
        item.setFont(3, _FONT_CONSOLAS_10)

        manufacturer_text = "—"
        if result.vendor:
            manufacturer_text = result.vendor
        elif is_randomized_mac(result.mac):
            # 随机 MAC（本地管理位=1）的前缀不属于任何厂商，OUI 查询必然为空。
            # 这里刻意**不**显示成「—」：`—` 应该只表示"我们不知道"，
            # 而"随机 MAC"是一个**确定的事实**（这台设备开了隐私地址）。
            # 两者对用户的意义完全不同 —— 前者要排查，后者不用管。
            manufacturer_text = tr("随机 MAC")
        if result.device_type:
            # 已经有内容（厂商名 / 随机 MAC 标记）时用 " · " 拼接，与原有格式一致；
            # 否则直接显示设备类型。两段信息都保留，不互相吞掉。
            if manufacturer_text == "—":
                manufacturer_text = result.device_type
            else:
                manufacturer_text = f"{manufacturer_text} · {result.device_type}"
        item.setText(4, manufacturer_text)
        # 链接色与字重的判据集中在 _apply_manufacturer_mark()，与切主题刷新共用，
        # 避免两处判据漂移（漂移的后果见该函数的说明）。
        self._apply_manufacturer_mark(item, result)

        item.setText(5, result.location or "—")

        item.setText(6, result.user or "—")

        if result.response_time > 0:
            item.setData(7, Qt.DisplayRole, round(result.response_time, 1))
            item.setData(7, Qt.UserRole, round(result.response_time, 1))  # 响应时间数值排序键
            item.setTextAlignment(7, Qt.AlignCenter)
        else:
            item.setText(7, "—")
            item.setData(7, Qt.UserRole, float("inf"))  # 无响应排最后
            item.setTextAlignment(7, Qt.AlignCenter)

        # 开放端口列：仅列出端口号（Top N 合并，避免漏扫目标开几百端口撑爆表格）。
        # 完整端口列表由 tooltip 承载。
        ports_disp, ports_full = format_ports_display(result.open_ports)
        item.setText(8, ports_disp)
        item.setToolTip(8, ports_full if ports_full != "—" else tr("无开放端口"))
        item.setFont(8, _FONT_CONSOLAS_9)

        # 服务列必须与展开子项、详情面板同源：优先 services，缺失时回退
        # service_details 的 proto 列表。否则会出现"详情面板里明明有 SMB、
        # 但'有服务'筛选把该设备排除"这种自相矛盾的表现。
        svc = result.services or []
        if not svc and result.service_details:
            svc = [d.get("proto", "") for d in result.service_details if d.get("proto")]
        services_text = ", ".join(service_label(x) for x in svc) if svc else "—"
        item.setText(9, services_text)
        item.setData(9, Qt.UserRole, list(svc))

        # 操作系统列 (col 10)：TTL 推测族 + banner 版本
        os_text = ""
        if result.os_guess or result.os_detail:
            os_text = f"{os_label(result.os_guess)} {result.os_detail}".strip()
        item.setText(10, os_text or "—")

        # 设备类型列 (col 11)：指纹推断的设备类别 + 型号，便于一眼识别具体设备
        if result.device_class:
            class_text = device_class_label(result.device_class)
            if result.device_model:
                class_text = f"{class_text} · {result.device_model}"
            item.setText(11, class_text)
        else:
            item.setText(11, "—")

        item.setText(12, result.remark or "—")

        # 收藏星标（画在 IP 列的图标位，不污染文本 —— IP 列已经有冲突标记
        # 会加 "⚠ " 前缀，再叠一个 "★" 会既难读又难解析）
        self._apply_favorite_mark(item, result)

        # 变更角标：把命中的变更类型写到 role，再统一合成第 0 列文本。
        # 必须放在最后 —— `_apply_row_marks` 会重写第 0 列文本与前景色，
        # 早于上面那些 setText/setForeground 调用就会被它们覆盖。
        item.setData(0, _ROLE_CHANGE, self._change_types_for(result.ip))
        self._apply_row_marks(item, result.ip)
        # 风险列在这里**再**写一次：`_apply_row_marks` 是拿 `_result_map` 里的对象
        # 算分的，而首次渲染时调用方未必已经登记（见 `_apply_risk_mark` 的说明）。
        # 幂等，生产路径上两次结果相同。
        self._apply_risk_mark(item, result)

    def _apply_favorite_mark(self, item, result):
        """刷新单个设备项的收藏键与星标。"""
        item.setData(0, _ROLE_FAV_KEY, favorite_key(result))
        store = getattr(self, "favorites", None)
        if store is not None and store.is_favorite(result):
            item.setIcon(0, star_icon())
        else:
            item.setIcon(0, QIcon())

    def _refresh_favorite_marks(self):
        """收藏变更后刷新所有行的星标。"""
        for ip, item in self._ip_item_map.items():
            result = self._result_map.get(ip)
            if result is not None:
                self._apply_favorite_mark(item, result)


    def _item_matches_filter(self, item):
        """判断单个顶层项是否满足当前搜索 + 筛选条件。

        筛选身份是**规范 key**（见 `filter_bar.FILTERS`），不是翻译后的文本。
        旧实现拿 `tr("仅在线")` 的翻译结果去比较，英文界面下每次比较都要重新
        查表，且语言包一旦缺词条就会静默失配（筛选永远不生效）。
        """
        if not self._item_matches_key(item, getattr(self, "filter_key", "all")):
            return False
        search_text = self.search_input.text().lower().strip()
        if not search_text:
            return True
        row_text = ""
        # 搜索列**刻意不含**第 1 列（状态，图标列）与第 13 列（风险，派生分数）：
        # 搜"高"会命中所有高风险主机、搜"在线"会命中每一行，都是噪声而不是线索。
        for col in [0, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12]:
            row_text += item.text(col).lower() + " "
        return search_text in row_text

    def _visible_results(self) -> list:
        """当前筛选 + 搜索下**可见**的扫描结果 —— 界面上真正显示的那些行。

        「打印」一直是"所见即所得"（`_print_results` 跳过 `item.isHidden()`），
        但「导出」以前直接导出全量 `all_results`。默认筛选是「仅在线」，于是
        屏幕上只有在线设备、导出的文件里却塞满离线行 —— 用户完全无从理解
        （实测一次 `10.193.28.0/22` 扫描导出 1023 行，其中 952 行是离线）。
        现在两处统一走本方法，口径不会再分叉。

        顺序沿用 `all_results`（= 扫描顺序），而不是表格当前的排序：导出是数据
        产物，顺序稳定比"跟屏幕上一致"更重要。
        """
        out = []
        for result in self.all_results:
            item = self._ip_item_map.get(result.ip)
            # 表里没有对应行时无从判断可见性 —— 按"可见"处理，宁可多导出，
            # 也不因为一次映射缺失就静默丢掉用户的数据。
            if item is not None and item.isHidden():
                continue
            out.append(result)
        return out

    def _item_matches_key(self, item, key: str) -> bool:
        """单个筛选项的匹配规则（与界面语言无关）。"""
        if key == "online":
            return item.data(1, Qt.UserRole) == "online"
        if key == "offline":
            return item.data(1, Qt.UserRole) == "offline"
        if key == "services":
            return item.text(9) not in ("", "—")
        if key == "library":
            return item.text(4) not in ("", "—")
        if key == "conflict":
            ip = item.data(0, _ROLE_DEV_IP)
            return bool(ip and getattr(self, "_conflict_ips", {}).get(ip))
        if key == "change":
            # 读 role 而不是第 0 列文本：文本里是 `"↑"` 这类字形，既可能被
            # 语言/字体影响，也与"是否变更"不是一对一（可能有多个角标）。
            return bool(item.data(0, _ROLE_CHANGE))
        if key == "favorite":
            store = getattr(self, "favorites", None)
            fav = item.data(0, _ROLE_FAV_KEY)
            return bool(store is not None and fav and fav in store.keys())
        return True  # "all"

    def _compute_filter_counts(self) -> dict:
        """统计每个筛选项命中的行数（供筛选条上的计数）。

        刻意**不**考虑搜索框内容：搜索是"在当前筛选里再搜"，计数若跟着每次
        按键重算，/16 网段下每敲一个字符都要遍历 6.5 万行。
        """
        total = self.table.topLevelItemCount()
        counts = {"all": total, "online": 0, "offline": 0,
                  "services": 0, "conflict": 0, "change": 0,
                  "library": 0, "favorite": 0}
        store = getattr(self, "favorites", None)
        fav_keys = store.keys() if store is not None else set()
        for i in range(total):
            item = self.table.topLevelItem(i)
            if item.data(1, Qt.UserRole) == "online":
                counts["online"] += 1
            else:
                counts["offline"] += 1
            if item.text(9) not in ("", "—"):
                counts["services"] += 1
            if item.text(4) not in ("", "—"):
                counts["library"] += 1
            if item.data(0, _ROLE_CHANGE):
                counts["change"] += 1
            ip = item.data(0, _ROLE_DEV_IP)
            if ip and getattr(self, "_conflict_ips", {}).get(ip):
                counts["conflict"] += 1
            fav = item.data(0, _ROLE_FAV_KEY)
            if fav and fav in fav_keys:
                counts["favorite"] += 1
        return counts

    def _refresh_filter_counts(self):
        """把最新计数推给筛选条（仅在粗粒度事件后调用，见 _compute_filter_counts）。"""
        bar = getattr(self, "filter_bar", None)
        if bar is None:
            return
        counts = self._compute_filter_counts()
        bar.set_counts_visible(counts["all"] > 0)
        bar.set_counts(counts)

    def _filter_results(self):
        """根据搜索和筛选条件显示/隐藏顶层项（默认"在线"：扫描时只显示在线终端）"""
        for i in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(i)
            item.setHidden(not self._item_matches_filter(item))


    def _on_item_clicked(self, item, col):
        """点击树形项 → 如果是服务子项，打开对应服务"""
        kind = item.data(0, Qt.UserRole)
        if kind == "service":
            proto = item.data(0, Qt.UserRole + 1)
            ip = item.data(0, Qt.UserRole + 2)
            if proto and ip:
                if proto.upper() == SVC_SNMP:
                    descr = item.data(0, Qt.UserRole + 3) or ""
                    name = item.data(0, Qt.UserRole + 4) or ""
                    self._show_snmp_info(ip, name, descr)
                else:
                    self._open_service(proto, ip)


    # ── 内置网络工具 (P2) ──

    def _item_ip(self, item) -> str:
        """取树项对应的顶层设备 IP（服务子项上溯到父设备）。

        优先读 `_ROLE_DEV_IP`：冲突设备第 0 列文本是 `"⚠ <ip>"`，直接读文本会
        把警告前缀当成 IP 的一部分。
        """
        if item is None:
            return None
        while item.parent() is not None:
            item = item.parent()
        ip = item.data(0, _ROLE_DEV_IP)
        if ip:
            return ip
        # 回退：极少数手工构造、未走 _set_item_data 的项
        ip = item.text(0).strip()
        return ip or None

    def _selected_target(self) -> str:
        """当前选中设备 IP；无选中则返回 None。"""
        return self._item_ip(self.table.currentItem())


    def _update_stats(self):
        self._update_status_stats()

    def _clear_results(self):
        if self.all_results:
            self._audit(audit_log.CAT_RESULT, tr("清空结果"), f"清除 {len(self.all_results)} 条扫描结果")
        self.table.clear()
        self._ip_item_map.clear()
        self._result_map.clear()
        self.all_results.clear()
        self._conflicts.clear()
        self._conflict_ips.clear()
        self._changes.clear()
        getattr(self, "_change_map", {}).clear()
        # 清空后回到空状态引导页，并复位详情面板（否则会残留上一台设备的信息）
        self.detail_panel.clear()
        self.overview.clear()
        self._show_results_page(False)
        self._refresh_filter_counts()
        self._update_stats()
        self.act_export.setEnabled(False)
        self.act_clear.setEnabled(False)
        self.status_bar.showMessage(tr("已清空结果"))


    def _show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return

        top_item = item
        while top_item and top_item.parent():
            top_item = top_item.parent()
        if not top_item:
            return

        # 提前计算关键信息 (供复制 / 唤醒 / 地址库操作复用)
        # 走 _item_ip 而非读第 0 列文本：冲突设备的第 0 列是 "⚠ <ip>"，
        # 直接读文本会把警告前缀带进目标地址。
        ip = self._item_ip(top_item) or ""
        mac = self._item_text(top_item, 3)  # col 3 = MAC地址
        lib_dev = self.library.match(ip, mac)
        if not mac and lib_dev:
            mac = (lib_dev.get("mac") or "").strip()

        # 菜单按"动作语义"分组（docs/reviews/UI_REVIEW.md P2-3）。
        # 旧实现把 20+ 个动作平铺成一层：复制 4 项、工具 8 项、地址库 3 项…
        # 用户要在一条长菜单里逐行扫，且"复制 MAC"和"远程关机"视觉权重相同。
        menu = QMenu(self)

        _result = self._result_map.get(ip) if ip else None

        act_rescan = QAction(tr("重新扫描此 IP"), self)
        act_rescan.triggered.connect(lambda: self._rescan_single_item(top_item))
        menu.addAction(act_rescan)

        # 收藏（docs/reviews/UI_REVIEW.md P1-3）：轻量"常看这几台"，与 MAC 地址库（资产台账）不同
        if _result is not None:
            _is_fav = self.favorites.is_favorite(_result)
            act_fav = QAction(tr("取消收藏") if _is_fav else tr("加入收藏"), self)
            act_fav.triggered.connect(lambda: self._toggle_favorite(_result))
            menu.addAction(act_fav)

        menu.addSeparator()

        # ── 复制 ▸ ──
        copy_menu = menu.addMenu(tr("复制"))
        for _label, _col in ((tr("IP 地址"), 0), (tr("MAC 地址"), 3), (tr("主机名"), 2)):
            copy_menu.addAction(_label).triggered.connect(
                lambda _checked=False, c=_col: self._copy_item_cell(top_item, c)
            )
        copy_menu.addSeparator()
        copy_menu.addAction(tr("整行")).triggered.connect(
            lambda: self._copy_item_row(top_item)
        )

        # ── 连接 ▸：只列出该设备**确实开放**的服务，避免一屏点不通的入口 ──
        conn_menu = menu.addMenu(tr("连接"))
        _open_ports = set(_result.open_ports) if _result is not None else set()
        for _proto, _port in (("HTTP", 80), ("HTTPS", 443), ("FTP", 21)):
            if _port in _open_ports:
                conn_menu.addAction(_proto).triggered.connect(
                    lambda _checked=False, p=_proto: self._open_service(p, ip)
                )
        if 3389 in _open_ports:
            conn_menu.addAction(tr("远程桌面 (RDP)")).triggered.connect(
                lambda: self._open_service("RDP", ip)
            )
        for _label, _tool in ((tr("SSH"), "ssh"), (tr("Telnet"), "telnet"),
                              (tr("打开命令提示符"), "cmd")):
            conn_menu.addAction(_label).triggered.connect(
                lambda _checked=False, t=_tool: self._launch_network_tool(t, ip)
            )

        # ── 诊断 ▸ ──
        diag_menu = menu.addMenu(tr("诊断"))
        for _label, _tool in ((tr("Ping (持续)"), "ping"),
                              (tr("Tracert (路由追踪)"), "tracert")):
            diag_menu.addAction(_label).triggered.connect(
                lambda _checked=False, t=_tool: self._launch_network_tool(t, ip)
            )

        # ── 管理 ▸ ──
        admin_menu = menu.addMenu(tr("管理"))
        if mac:
            admin_menu.addAction(tr("唤醒 (WoL)")).triggered.connect(
                lambda: self._wake_on_lan(mac)
            )
        admin_menu.addAction(tr("WMI 识别 (管理员)...")).triggered.connect(
            lambda: self._run_wmi_identification([ip])
        )
        admin_menu.addAction(tr("NetBIOS 识别（轻量）")).triggered.connect(
            lambda: self._run_netbios_identification([ip])
        )
        admin_menu.addSeparator()
        admin_menu.addAction(tr("远程关机")).triggered.connect(
            lambda: self._remote_power("shutdown")
        )
        admin_menu.addAction(tr("远程重启")).triggered.connect(
            lambda: self._remote_power("reboot")
        )

        # ── 地址库 ▸ ──
        lib_menu = menu.addMenu(tr("地址库"))
        if lib_dev:
            lib_menu.addAction(tr("编辑地址库条目")).triggered.connect(
                lambda: self._edit_library_entry(lib_dev["id"])
            )
            lib_menu.addAction(tr("从地址库删除")).triggered.connect(
                lambda: self._delete_library_entry(lib_dev["id"])
            )
        else:
            lib_menu.addAction(tr("加入地址库...")).triggered.connect(
                lambda: self._add_to_library(ip, mac)
            )

        menu.exec_(self.table.viewport().mapToGlobal(pos))


    def _item_text(self, item, col: int) -> str:
        t = item.text(col).strip()
        return "" if t == "—" else t

    def _copy_item_cell(self, item, col):
        text = item.text(col)
        if text and text != "—":
            QApplication.clipboard().setText(text)
            self.status_bar.showMessage(f"已复制: {text}")

    def _copy_item_row(self, item):
        texts = []
        for col in range(self.table.columnCount()):
            texts.append(item.text(col))
        QApplication.clipboard().setText("\t".join(texts))
        self.status_bar.showMessage(tr("已复制整行"))


    def _rescan_single_item(self, item):
        ip = self._item_ip(item)
        if not ip:
            return
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()


    def _refresh_matches_from_library(self):
        """用当前地址库重新标注已有扫描结果 (导入/编辑地址库后调用)。

        用内存索引整库匹配一次，避免逐条查 SQLite（地址库变更属低频操作，
        但仍应保持 O(n) 的字典查找而非 O(n) 次数据库往返）。
        """
        matcher = MacMatcher.from_library(self.library)
        if matcher is None:
            return
        for r in self.all_results:
            matcher.apply_to(r)
            self._upsert_table_row(r)
        self._update_stats()

