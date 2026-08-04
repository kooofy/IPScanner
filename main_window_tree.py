# -*- coding: utf-8 -*-
"""树控件操作混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
from PyQt5.QtWidgets import (
    QApplication, QMenu, QAction, QTreeWidgetItem, QStyle
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QIcon, QPainter, QBrush, QPen, QPixmap

from scanner import ScanResult, PROTOCOL_PORTS, format_ports_display
import audit_log
from conflict_detector import SEVERITY_HIGH
from ui_icons import get_pc_icons
from styles import _ip_to_int, _FONT_CONSOLAS_10, _FONT_CONSOLAS_9, _FONT_YAHEI_BOLD_9
from i18n import tr

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

    def _refresh_conflict_marks(self):
        """根据 _conflict_ips 刷新树视图中所有行的冲突标记。"""
        for ip, item in self._ip_item_map.items():
            self._apply_conflict_mark(item, ip)

    def _apply_conflict_mark(self, item, ip):
        """为单个树项应用/清除冲突标记。"""
        ctypes = self._conflict_ips.get(ip, [])
        if ctypes:
            # 有冲突：IP 列文字改为橙红色，状态列追加警告
            has_high = any(
                c.severity == SEVERITY_HIGH
                for c in self._conflicts
                if ip in c.ips
            )
            color = QColor(220, 38, 38) if has_high else QColor(217, 119, 6)
            item.setForeground(0, color)
            # 在 IP 列追加大括号标记
            base_ip = ip
            item.setText(0, f"⚠ {base_ip}")
            # 工具提示追加冲突信息
            tips = []
            for c in self._conflicts:
                if ip in c.ips:
                    tips.append(f"[{c.severity_label}] {c.description}")
            existing_tip = item.toolTip(0) or ip
            # 去掉旧的冲突提示（如果有）
            if tr(" | 冲突:") in existing_tip:
                existing_tip = existing_tip.split(tr(" | 冲突:"))[0]
            item.setToolTip(0, f"{existing_tip} | 冲突: {'; '.join(tips)}")
        else:
            # 无冲突：恢复正常
            item.setText(0, ip)
            item.setForeground(0, self._default_fg_color())
            existing_tip = item.toolTip(0) or ip
            if tr(" | 冲突:") in existing_tip:
                existing_tip = existing_tip.split(tr(" | 冲突:"))[0]
                item.setToolTip(0, existing_tip)

    def _default_fg_color(self):
        """返回当前主题的默认前景色。"""
        if self.dark_mode:
            return QColor(255, 255, 255)
        return QColor(0, 0, 0)

    # --- 表格操作 ---

    def _upsert_table_row(self, result: ScanResult):
        """新增或更新指定 IP 的项，避免同一 IP 重复显示"""
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
        """为设备项添加服务子项（展开后跨列显示），仿 Advanced IP Scanner 风格"""
        item.takeChildren()

        # 优先使用带 banner 的详细信息；旧结果无 details 时回退 services 列表
        details = result.service_details or []
        if not details and result.services:
            details = [{"proto": p, "port": PROTOCOL_PORTS.get(p.upper(), 0), "banner": ""}
                       for p in result.services]
        if (not details and not getattr(result, "wmi_identified", False)
                and not getattr(result, "netbios_identified", False)):
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            return
        # 即使没有服务子项，也要展示 WMI 识别结果，故此处统一标记为可展开
        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        parent_index = self.table.indexFromItem(item)
        for idx, detail in enumerate(details):
            proto = detail.get("proto", "")
            port = detail.get("port", 0)
            banner = detail.get("banner", "")
            proto_upper = proto.upper()

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
                display = f"{proto_upper}, {banner}"
            else:
                # 空 banner 时不再回退到 "port X"，与 AIP 保持一致：仅显示协议名
                display = proto_upper
            child.setText(0, display)
            child.setForeground(0, self._link_color())
            child.setToolTip(0, display)
            child.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)

            # 跨列显示：子项文本从第 0 列(IP列)起横跨整行。
            # 注意：必须使用 QTreeView.setFirstColumnSpanned(row, parent_index, True) 才能生效。

            # SNMP 保留 sysName/sysDescr 供点击弹窗展示
            if proto_upper == tr("SNMP"):
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
            wmi_text = "WMI, " + " · ".join(parts) if parts else tr("WMI, 已识别")
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
        if proto_upper in (tr("HTTP"), tr("HTTPS")):
            return self._globe_icon()
        icon_map = {
            tr("FTP"): QStyle.SP_DirIcon,
            tr("RDP"): QStyle.SP_ComputerIcon,
            tr("SSH"): QStyle.SP_CommandLink,
            "TELNET": QStyle.SP_CommandLink,
            tr("SNMP"): QStyle.SP_DriveNetIcon,
            tr("SMB共享"): QStyle.SP_DriveNetIcon,
            tr("mDNS"): QStyle.SP_DriveNetIcon,
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

        # 地球底色
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor(59, 130, 246)))
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
        item.setFont(0, _FONT_CONSOLAS_10)
        item.setForeground(0, self._default_fg_color())

        # 工具提示：标注发现方式（ARP 探测发现的静默主机）
        tip = result.ip
        if result.discovery_method == "arp":
            tip += tr(" （ARP 主动探测发现 · 禁 Ping 但在线）")
        elif result.discovery_method == "mdns":
            tip += tr(" （mDNS 发现 · 组播发现设备）")
        if result.os_guess:
            tip += f" · OS: {result.os_guess}"
            if result.os_detail:
                tip += f" ({result.os_detail})"
        if result.shares:
            tip += f" · 共享: {', '.join(result.shares)}"
        if result.device_class:
            tip += f" · 设备: {result.device_class}"
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
        item.setToolTip(0, tip)

        # 状态列 (col 1)：预渲染电脑图标 (在线绿 / 离线灰) + 文字
        item.setData(1, Qt.UserRole, result.status)
        item.setData(1, Qt.DisplayRole, tr("在线") if result.status == "online" else tr("离线"))
        item.setTextAlignment(1, Qt.AlignCenter)
        online_icon, offline_icon = get_pc_icons()
        if result.status == "online":
            item.setForeground(1, QColor(22, 163, 74))
            item.setIcon(1, online_icon)
        else:
            item.setForeground(1, QColor(220, 38, 38))
            item.setIcon(1, offline_icon)

        item.setText(2, result.hostname or "—")

        mac_text = result.mac.upper() if result.mac else "—"
        item.setText(3, mac_text)
        item.setFont(3, _FONT_CONSOLAS_10)

        manufacturer_text = "—"
        has_manufacturer = False
        if result.vendor:
            manufacturer_text = result.vendor
            has_manufacturer = True
        if result.device_type:
            if has_manufacturer:
                manufacturer_text = f"{manufacturer_text} · {result.device_type}"
            else:
                manufacturer_text = result.device_type
                has_manufacturer = True
        item.setText(4, manufacturer_text)
        if result.excel_matched and result.device_type:
            item.setForeground(4, self._link_color())
            item.setFont(4, _FONT_YAHEI_BOLD_9)

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

        svc = result.services or []
        services_text = ", ".join(svc) if svc else "—"
        item.setText(9, services_text)
        item.setData(9, Qt.UserRole, list(svc))

        # 操作系统列 (col 10)：TTL 推测族 + banner 版本
        os_text = ""
        if result.os_guess or result.os_detail:
            os_text = (f"{result.os_guess} {result.os_detail}".strip())
        item.setText(10, os_text or "—")

        # 设备类型列 (col 11)：指纹推断的设备类别 + 型号，便于一眼识别具体设备
        if result.device_class:
            class_text = result.device_class
            if result.device_model:
                class_text = f"{class_text} · {result.device_model}"
            item.setText(11, class_text)
        else:
            item.setText(11, "—")

        item.setText(12, result.remark or "—")


    def _item_matches_filter(self, item):
        """判断单个顶层项是否满足当前搜索/筛选条件"""
        search_text = self.search_input.text().lower().strip()
        filter_type = self.filter_combo.currentText()

        show = True
        if filter_type == tr("仅在线"):
            status = item.data(1, Qt.UserRole)
            show = show and (status == "online")
        elif filter_type == tr("仅离线"):
            status = item.data(1, Qt.UserRole)
            show = show and (status == "offline")
        elif filter_type == tr("Excel已匹配"):
            type_text = item.text(4)
            show = show and (type_text != "—")
        elif filter_type == tr("有服务"):
            services_text = item.text(9)
            show = show and (services_text != "—")

        if show and search_text:
            row_text = ""
            for col in [0, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12]:
                row_text += item.text(col).lower() + " "
            show = search_text in row_text

        return show


    def _filter_results(self):
        """根据搜索和筛选条件显示/隐藏顶层项（默认"仅在线"：扫描时只显示在线终端）"""
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
                if proto == tr("SNMP"):
                    descr = item.data(0, Qt.UserRole + 3) or ""
                    name = item.data(0, Qt.UserRole + 4) or ""
                    self._show_snmp_info(ip, name, descr)
                else:
                    self._open_service(proto, ip)


    # ── 内置网络工具 (P2) ──

    def _item_ip(self, item) -> str:
        """取树项对应的顶层设备 IP（服务子项上溯到父设备）。"""
        if item is None:
            return None
        while item.parent() is not None:
            item = item.parent()
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
        self.all_results.clear()
        self._conflicts.clear()
        self._conflict_ips.clear()
        self._changes.clear()
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
        ip = self._item_text(top_item, 0)   # col 0 = IP地址
        mac = self._item_text(top_item, 3)  # col 3 = MAC地址
        lib_dev = self.library.match(ip, mac)
        if not mac and lib_dev:
            mac = (lib_dev.get("mac") or "").strip()

        menu = QMenu(self)

        act_copy_ip = QAction(tr("复制 IP"), self)
        act_copy_ip.triggered.connect(lambda: self._copy_item_cell(top_item, 0))
        menu.addAction(act_copy_ip)

        act_copy_mac = QAction(tr("复制 MAC"), self)
        act_copy_mac.triggered.connect(lambda: self._copy_item_cell(top_item, 3))
        menu.addAction(act_copy_mac)

        act_copy_host = QAction(tr("复制主机名"), self)
        act_copy_host.triggered.connect(lambda: self._copy_item_cell(top_item, 2))
        menu.addAction(act_copy_host)

        menu.addSeparator()

        act_copy_row = QAction(tr("复制整行"), self)
        act_copy_row.triggered.connect(lambda: self._copy_item_row(top_item))
        menu.addAction(act_copy_row)

        menu.addSeparator()

        act_rescan = QAction(tr("重新扫描此 IP"), self)
        act_rescan.triggered.connect(lambda: self._rescan_single_item(top_item))
        menu.addAction(act_rescan)

        if mac:
            act_wol = QAction(tr("唤醒 (WoL)"), self)
            act_wol.triggered.connect(lambda: self._wake_on_lan(mac))
            menu.addAction(act_wol)

        act_wmi_dev = QAction(tr("WMI 识别 (管理员)..."), self)
        act_wmi_dev.triggered.connect(lambda: self._run_wmi_identification([ip]))
        menu.addAction(act_wmi_dev)

        act_netbios_dev = QAction(tr("NetBIOS 识别（轻量）"), self)
        act_netbios_dev.triggered.connect(lambda: self._run_netbios_identification([ip]))
        menu.addAction(act_netbios_dev)

        # 工具子菜单：快速启动内置网络工具
        tool_menu = menu.addMenu(tr("工具"))
        for label, tool in [
            (tr("Ping (持续)"), "ping"),
            (tr("Tracert (路由追踪)"), "tracert"),
            (tr("Telnet"), "telnet"),
            (tr("SSH"), "ssh"),
            (tr("远程桌面 (RDP)"), "rdp"),
            (tr("打开命令提示符"), "cmd"),
            (tr("远程关机"), "shutdown"),
            (tr("远程重启"), "reboot"),
        ]:
            tool_menu.addAction(label).triggered.connect(
                lambda _checked=False, t=tool: (
                    self._remote_power(t) if t in ("shutdown", "reboot")
                    else self._launch_network_tool(t, ip)
                )
            )

        menu.addSeparator()

        if lib_dev:
            act_edit_lib = QAction(tr("编辑地址库条目"), self)
            act_edit_lib.triggered.connect(lambda: self._edit_library_entry(lib_dev["id"]))
            menu.addAction(act_edit_lib)

            act_del_lib = QAction(tr("从地址库删除"), self)
            act_del_lib.triggered.connect(lambda: self._delete_library_entry(lib_dev["id"]))
            menu.addAction(act_del_lib)
        else:
            act_add_lib = QAction(tr("加入地址库..."), self)
            act_add_lib.triggered.connect(lambda: self._add_to_library(ip, mac))
            menu.addAction(act_add_lib)

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
        ip = item.text(0)  # col 0 = IP地址
        if not ip:
            return
        self.range_input.setText(ip)
        self.ip_range_items = [ip]
        self._update_range_list()
        self._start_scan()


    def _refresh_matches_from_library(self):
        """用当前地址库重新标注已有扫描结果 (导入/编辑地址库后调用)"""
        if not self.library.is_loaded():
            return
        for r in self.all_results:
            m = self.library.match(r.ip, r.mac)
            if m:
                r.device_type = m.get("device_type", "")
                r.location = m.get("location", "")
                r.user = m.get("user", "")
                r.remark = m.get("remark", "")
                r.excel_matched = True
            self._upsert_table_row(r)
        self._update_stats()

