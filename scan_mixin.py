# -*- coding: utf-8 -*-
"""扫描相关操作混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
import sys
import re
import socket
import subprocess
import time
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QSpinBox, QComboBox
)
from PyQt5.QtCore import Qt
from scanner import (
    ScanResult, get_ports_for_level,
    scan_level_label, SVC_MDNS, merge_wmi, merge_netbios,
    count_ip_range, is_valid_range, is_ipv6_range, MAX_IPS_PER_RANGE, MAX_IPS_TOTAL,
    windows_ipconfig_subnets, parse_ip_range,
    throttle,
)
import audit_log
import ui_logic
import history_store
from app_logging import get_logger
from ui_threads import ScanThread, MdnsThread, WmiThread, NetbiosThread
from ui_dialogs import (
    WmiCredentialDialog, SnmpV3CredentialDialog, ConflictReportDialog,
    SubnetUtilizationDialog, ChangeReportDialog
)
from conflict_detector import (
    detect_conflicts, get_conflict_ips, SEVERITY_HIGH, SEVERITY_WARNING
)
from change_detector import detect_changes, get_change_summary
from ui_msg import localize_buttons, msg_info, msg_warn
from i18n import tr

_log = get_logger(__name__)


class ScanMixin:
    def _open_scan_settings(self):
        """弹出扫描设置对话框（超时 / 线程），由「扫描 > 扫描设置...」触发。"""
        dlg = QDialog(self)
        dlg.setWindowTitle(tr("扫描设置"))
        dlg.setMinimumWidth(240)
        _layout = QFormLayout(dlg)
        _to = QSpinBox(); _to.setRange(100, 5000); _to.setSingleStep(100)
        _to.setValue(self.timeout_spin.value())
        _th = QSpinBox(); _th.setRange(1, 500); _th.setSingleStep(10)
        _th.setValue(self.threads_spin.value())
        _layout.addRow(tr("超时 (ms):"), _to)
        _layout.addRow(tr("线程数:"), _th)
        _mode = QComboBox()
        _mode.addItems([tr("TCP 全连接"), tr("TCP SYN 半开"), tr("UDP 探测")])
        _mode_map = {tr("TCP 全连接"): "connect", tr("TCP SYN 半开"): "syn", tr("UDP 探测"): "udp"}
        _mode.setCurrentText(
            {v: k for k, v in _mode_map.items()}.get(self.tcp_scan_mode, tr("TCP 全连接"))
        )
        _layout.addRow(tr("端口探测方式:"), _mode)
        # 扫描礼貌档（v2.1 §2.4 GUI 露出）：与菜单子菜单同一组规范值。
        # 存/取的都是 `throttle.POLICY_NAMES` 里的规范名，**不是**显示文案。
        _tp = QComboBox()
        _tp_labels = {
            throttle.POLICY_FAST: tr("快速（不额外设限）"),
            throttle.POLICY_BALANCED: tr("均衡（温和限速）"),
            throttle.POLICY_POLITE: tr("礼貌（低速低并发）"),
        }
        _tp.addItems([_tp_labels[p] for p in throttle.POLICY_NAMES])
        _tp.setCurrentText(
            _tp_labels.get(self.throttle_policy, _tp_labels[throttle.POLICY_FAST]))
        _layout.addRow(tr("扫描礼貌档:"), _tp)
        _btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        localize_buttons(_btns)
        _btns.accepted.connect(dlg.accept)
        _btns.rejected.connect(dlg.reject)
        _layout.addRow(_btns)
        if dlg.exec_() == QDialog.Accepted:
            _old_to = self.timeout_spin.value()
            _old_th = self.threads_spin.value()
            _old_mode = self.tcp_scan_mode
            _old_tp = self.throttle_policy
            self.timeout_spin.setValue(_to.value())
            self.threads_spin.setValue(_th.value())
            self.tcp_scan_mode = _mode_map[_mode.currentText()]
            # 显示文案 → 规范名的反查表（与上面的 `_tp_labels` 同一处定义）
            _tp_inv = {v: k for k, v in _tp_labels.items()}
            self.throttle_policy = _tp_inv.get(
                _tp.currentText(), throttle.POLICY_FAST)
            self._sync_tcp_mode_menu()
            self._sync_throttle_menu()
            self._save_settings()
            # 审计：记录设置变更
            _changes = []
            if _old_to != _to.value():
                _changes.append(f"超时 {_old_to}→{_to.value()}ms")
            if _old_th != _th.value():
                _changes.append(f"线程 {_old_th}→{_th.value()}")
            if _old_mode != self.tcp_scan_mode:
                _changes.append(f"探测方式 {_old_mode}→{self.tcp_scan_mode}")
            if _old_tp != self.throttle_policy:
                _changes.append(f"礼貌档 {_old_tp}→{self.throttle_policy}")
            self._audit(
                audit_log.CAT_SYSTEM, tr("修改扫描设置"),
                " · ".join(_changes) if _changes else tr("无变化"),
            )

    # --- IP 范围管理 ---

    def _auto_detect_subnet(self):
        """自动检测本机网段并填入输入框。

        用 `_get_local_subnet()`（默认出口 IP 优先 + 解析网卡掩码），而**不是**
        `gethostbyname(gethostname())`。后者有两个真实缺陷：

        1. 多网卡 / VPN / Docker 环境下常解析到错误的网卡地址，甚至返回
           `127.0.0.1`，于是预填的网段根本不是本机所在网段；
        2. 它只能拼出 `/24`。真实网段是 `/22` 或 `/16` 时会少扫一大片，
           而且用户很难察觉（输入框里看着"挺对"）。
        """
        try:
            subnet = self._get_local_subnet()
            if subnet:
                self.range_input.setText(subnet)
                self.range_input.selectAll()
        except Exception as e:  # noqa: BLE001
            # 只是预填输入框失败，用户仍可手输网段，不影响可用性
            _log.debug("自动检测本机网段失败（可手动输入）: %s", e)

    def _get_default_local_ip(self):
        """获取本机默认出口 IPv4 地址（非 127.0.0.1）。"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def _get_local_subnet(self):
        """获取本机真实子网（含前缀长度），失败回退到 /24。"""
        import platform as _plat
        if _plat.system() == "Windows":
            return self._get_local_subnet_windows()
        else:
            return self._get_local_subnet_unix()

    def _get_local_subnet_windows(self):
        """Windows: 解析 ipconfig 输出（中英文 Windows 通用）。

        解析与命令执行统一复用 scanner.ping 的实现，与引擎侧
        get_local_subnets() 共用同一套规则，避免两处漂移。
        """
        pairs = windows_ipconfig_subnets()
        default_ip = self._get_default_local_ip()
        if pairs:
            # 优先使用默认出口 IP 所在网卡，避免多网卡时选错网段
            if default_ip:
                for ip, mask in pairs:
                    if ip == default_ip:
                        net, prefix = self._ip_mask_to_subnet(ip, mask)
                        if net:
                            return f"{net}/{prefix}"
            for ip, mask in pairs:
                if ip.startswith("127.") or self._is_virtual_adapter_ip(ip):
                    continue
                net, prefix = self._ip_mask_to_subnet(ip, mask)
                if net:
                    return f"{net}/{prefix}"
        if default_ip:
            parts = default_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _get_local_subnet_unix(self):
        """Linux/macOS: 解析 ip addr / ip route 输出。"""
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], timeout=5).decode()
        except Exception:
            try:
                out = subprocess.check_output(["ip", "addr", "show"], timeout=5).decode()
            except Exception:
                out = ""

        # 优先取默认路由的源 IP 和接口
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            default_ip = m.group(1)
            # 从 ip addr 中找对应接口的前缀长度
            try:
                addr_out = subprocess.check_output(["ip", "addr", "show"], timeout=5).decode()
                # 找包含此 IP 的行: "inet 192.168.1.1/24"
                for line in addr_out.splitlines():
                    if default_ip in line:
                        pm = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                        if pm:
                            return f"{pm.group(1)}/{pm.group(2)}"
            except Exception as e:  # noqa: BLE001
                # 拿不到前缀长度 → 退回 /24 猜测，下面就是该回退路径
                _log.debug("读取接口前缀长度失败，退回 /24 推测: %s", e)
            parts = default_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        # 回退：从 ip addr 取第一个非回环接口
        try:
            addr_out = subprocess.check_output(["ip", "addr", "show"], timeout=5).decode()
        except Exception:
            addr_out = out
        for line in addr_out.splitlines():
            pm = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if pm and not pm.group(1).startswith("127."):
                return f"{pm.group(1)}/{pm.group(2)}"

        # 最后回退
        default_ip = self._get_default_local_ip()
        if default_ip:
            parts = default_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    @staticmethod
    def _ip_mask_to_subnet(ip: str, mask: str):
        """由 IPv4 与子网掩码计算网段地址与前缀长度，失败返回 (None, 0)。"""
        return ui_logic.ip_mask_to_subnet(ip, mask)

    @staticmethod
    def _is_virtual_adapter_ip(ip: str) -> bool:
        """粗略判断是否为虚拟/容器网卡使用的私有网段（VirtualBox/Docker/链路本地等）。"""
        return ui_logic.is_virtual_adapter_ip(ip)

    def _get_c_class_subnet(self):
        """获取本机 IP 的 C 类子网 /24。"""
        ip = self._get_default_local_ip()
        if ip:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def _scan_local_subnet(self):
        """扫描本机所在子网：填入网段并**立即开始扫描**。"""
        self._scan_detected_subnet(
            self._get_local_subnet(), tr("无法获取本机 IP，请手动输入扫描范围。"))

    def _scan_c_class_subnet(self):
        """扫描 C 类子网：填入网段并**立即开始扫描**。"""
        self._scan_detected_subnet(
            self._get_c_class_subnet(), tr("无法获取本机 IP，请手动输入扫描范围。"))

    def _scan_detected_subnet(self, subnet, missing_msg: str):
        """探测到的网段 → 填入输入框 → 立即开扫（三个快捷入口共用）。

        🔴 改造前这里**只填不扫**（原注释写"仿 AIP"），结果是空状态主 CTA、
        工具栏「本机子网」、菜单项这三个入口点下去**界面上零变化**：

        - 启动时 `_auto_detect_subnet()` 已经把同一个网段填进输入框了，
          `setText()` 同样的文本不产生任何可见变化；
        - 唯一的反馈写进 `range_list_label`，而它在创建时就
          `setVisible(False)`（"保留兼容，但控件已隐藏"）；
        - 状态栏也不动。

        而按钮文案是「扫描本机所在子网」、空状态副标题写着"或**直接扫描**本机
        所在子网" —— 承诺与实现相反，用户只能以为程序坏了。现在按文案来：
        填好就开扫，可见反馈由扫描态摘要条（阶段 / 已扫 / 在线 / 用时 / 停止）提供。
        """
        if not subnet:
            msg_warn(self, tr("提示"), missing_msg)
            return
        if not self._fill_subnet_range(subnet):
            return          # 超出规模上限，`_fill_subnet_range` 已给出提示
        self._start_scan()

    def _fill_subnet_range(self, subnet: str) -> bool:
        """把网段填入范围输入框并加入待扫列表；返回**是否已进入待扫列表**。

        返回 False（网段非法、或超出规模上限）时网段**仍会填进输入框**，
        方便用户手工拆小后再扫 —— 但调用方不应继续开扫。

        ⚠️ 规模超限的提示必须在这里给。留给 `_start_scan` 的话，用户会连吃两个
        弹窗（"范围过大" + "请先添加至少一个 IP 范围"），后者会把真正的原因盖住。
        """
        self.range_input.setText(subnet)
        self.range_input.selectAll()
        if subnet in self.ip_range_items:
            self.range_input.setFocus()
            return True
        n = count_ip_range(subnet) if is_valid_range(subnet) else 0
        if n == 0:
            return False
        # 本机所在网段可能异常大（如 /8 的园区网）：超出上限时只填不加入。
        if n > MAX_IPS_PER_RANGE or self._total_ips() + n > MAX_IPS_TOTAL:
            msg_warn(
                self, tr("范围过大"),
                tr("本机网段 {subnet} 有 {n} 个 IP，超过单次上限 {limit} 个，"
                   "未加入待扫列表。\n\n请在输入框中拆成更小的范围"
                   "（如按 /24 分批）后再扫描。").format(
                    subnet=subnet, n=n, limit=MAX_IPS_PER_RANGE))
            return False
        self.ip_range_items.append(subnet)
        self._update_range_list()
        self.range_input.setFocus()
        return True

    def _total_ips(self) -> int:
        """待扫列表中的 IP 总数（只计数不构建列表，避免反复生成大列表）。"""
        return sum(count_ip_range(r) for r in self.ip_range_items)


    def _add_ip_range(self):
        text = self.range_input.text().strip()
        if not text:
            return

        # 一行内支持逗号 / 空格 / 换行 / 分号 / 制表符分隔多个网段 (类 Advanced IP Scanner)
        tokens = [t.strip() for t in re.split(r"[\s,;]+", text) if t.strip()]

        added, dup = 0, 0
        invalid = []
        ipv6 = []
        too_large = []
        over_total = []
        added_tokens = []
        total = self._total_ips()
        for tok in tokens:
            # 只解析、不构建 IP 列表：先算规模，超限的绝不进入待扫列表
            if not is_valid_range(tok):
                # IPv6 语法合法但本工具不支持。与"写错了"分开归类，
                # 否则用户看到同一句"无法解析"会以为是自己格式问题而反复试错。
                (ipv6 if is_ipv6_range(tok) else invalid).append(tok)
                continue
            n = count_ip_range(tok)
            if n > MAX_IPS_PER_RANGE:
                too_large.append(f"{tok}（{n} 个 IP）")
                continue
            if tok in self.ip_range_items:
                dup += 1
                continue
            if total + n > MAX_IPS_TOTAL:
                over_total.append(f"{tok}（{n} 个 IP）")
                continue
            self.ip_range_items.append(tok)
            added_tokens.append(tok)
            total += n
            added += 1

        if added > 0:
            self._update_range_list()
            self.range_input.clear()
            self.range_input.setFocus()
            # 审计：记录添加网段
            self._audit(audit_log.CAT_RANGE, tr("添加网段"), ", ".join(added_tokens))

        # 规模超限：必须明确告知用户，不能静默丢弃
        if too_large:
            msg_warn(
                self, tr("范围过大"),
                tr("以下网段的 IP 数超过单次上限 {limit} 个，已忽略：\n  {items}"
                   "\n\n请拆分为更小的范围（如按 /24 分批）后再扫描。").format(
                    limit=MAX_IPS_PER_RANGE, items="\n  ".join(too_large))
            )
        if over_total:
            msg_warn(
                self, tr("范围过大"),
                tr("加上以下网段后，待扫 IP 总数将超过上限 {limit} 个，已忽略：\n  {items}"
                   "\n\n请先清空部分网段，或分多次扫描。").format(
                    limit=MAX_IPS_TOTAL, items="\n  ".join(over_total))
            )

        if added == 0:
            if too_large or over_total:
                return
            # 全部无效或全部重复，未新增任何网段
            if ipv6:
                msg_warn(
                    self, tr("暂不支持 IPv6"),
                    tr("以下项是 IPv6 地址，本工具目前只支持 IPv4 扫描：\n  {items}"
                       "\n\n请改用 IPv4 网段（如 192.168.1.0/24）。").format(
                        items="\n  ".join(ipv6))
                )
            if invalid:
                msg_warn(
                    self, tr("格式错误"),
                    tr("以下项无法解析:\n  {items}"
                       "\n\n支持格式 (可一行多个, 用逗号/空格/换行分隔):\n"
                       "  192.168.1.0/24\n  192.168.1.1-254\n  192.168.1.1").format(
                        items="\n  ".join(invalid))
                )
            if not ipv6 and not invalid and dup:
                msg_info(self, tr("提示"), tr("这些网段都已添加过了"))
            return

        # 有成功添加时，仅对"重复 / 无效 / IPv6"做补充提示，避免无效输入被静默吞掉
        if dup or invalid or ipv6:
            msg = []
            if dup:
                msg.append(tr("已跳过 {n} 个重复网段").format(n=dup))
            if ipv6:
                msg.append(tr("以下项是 IPv6 地址，本工具目前只支持 IPv4 扫描，已忽略：\n  {items}").format(
                    items="\n  ".join(ipv6)))
            if invalid:
                msg.append(tr("以下项无法解析，已忽略:\n  {items}").format(
                    items="\n  ".join(invalid)))
            msg_info(self, tr("提示"), "\n".join(msg))

    def _clear_ranges(self):
        if self.ip_range_items:
            self._audit(audit_log.CAT_RANGE, tr("清空网段"), f"移除 {len(self.ip_range_items)} 个网段")
        self.ip_range_items.clear()
        self._update_range_list()

    def _scan_in_progress(self) -> bool:
        """是否已有扫描在跑。

        ⚠️ 不能只看 `self.scan_thread is not None` —— 它在 `__init__` 里是 None、
        开扫时被赋值，但**扫描结束不会置回 None**，所以"非空"只说明"本进程扫过
        至少一次"。只有 `isRunning()` 才是当前状态。
        """
        thread = getattr(self, "scan_thread", None)
        return bool(thread is not None and thread.isRunning())

    def _start_scan(self):
        # 🔴 防重复开扫。`_start_scan` 有 F5 / 菜单「开始扫描」/ 工具栏「扫描」/
        # 空状态两个 CTA / 「本机子网」/「C 类子网」等多个入口，而扫描期间**只有
        # 「扫描」按钮被禁用**，其余入口照样点得到。改造前那些入口最多只是
        # "填一下输入框"（无害），现在它们会真的开扫 —— 少了这道闸门就会并发跑
        # 两个 ScanThread，同一份结果表被两个线程同时 upsert。
        if self._scan_in_progress():
            self.status_bar.showMessage(tr("扫描正在进行中，请先停止或等待完成"))
            return

        if not self.ip_range_items:
            text = self.range_input.text().strip()
            if text:
                self._add_ip_range()
            if not self.ip_range_items:
                msg_warn(self, tr("提示"), tr("请先添加至少一个 IP 范围"))
                return

        # 规模兜底：网段可能来自旧配置或手工编辑的 ini，启动前再校验一次总量
        total_ips = self._total_ips()
        if total_ips > MAX_IPS_TOTAL:
            msg_warn(
                self, tr("范围过大"),
                tr("待扫 IP 总数为 {total}，超过上限 {limit} 个，已中止扫描。"
                   "\n\n请清空部分网段，或分多次扫描。").format(
                    total=total_ips, limit=MAX_IPS_TOTAL)
            )
            return
        if total_ips == 0:
            msg_warn(self, tr("提示"), tr("待扫列表中没有可解析的 IP，请检查网段格式。"))
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.act_export.setEnabled(False)
        self.act_clear.setEnabled(False)
        # 扫描态摘要条（docs/reviews/UI_REVIEW.md P0-2 后半）：阶段 / 已扫 / 在线 / 有服务 /
        # 用时 / [停止]。计数在 `_on_scan_result` 里累加，这里只负责复位。
        self._scan_online = 0
        self._scan_services = 0
        # 扫描计时（只给趋势观测的 duration_s 用；与界面展示无关）。
        # `perf_counter` 而非 `monotonic`：Windows 上后者分辨率可能差到 15.6ms。
        self._scan_started_at = time.perf_counter()
        self.scan_status.start(total_ips)
        # 切到结果页：让用户立刻看到表格在填充（空状态页只服务于"尚无结果"）
        self._show_results_page(True)
        self.table.setSortingEnabled(False)
        self.table.clear()
        self._ip_item_map.clear()
        self._result_map.clear()
        self.detail_panel.clear()

        self.scan_thread = ScanThread(
            self.ip_range_items,
            timeout_ms=self.timeout_spin.value(),
            max_threads=self.threads_spin.value(),
            scan_ports=self.port_scan_check.isChecked(),
            protocols=self.selected_protocols,
            tcp_scan_mode=self.tcp_scan_mode,
            mdns_discovery=self.mdns_check.isChecked(),
            ports=get_ports_for_level(self.scan_level) if self.port_scan_check.isChecked() else None,
            library=self.library,
            snmp_v3_user=self.snmp_v3_creds.to_user() if self.snmp_v3_creds.has_creds() else None,
            switch_map=self.switch_map_check.isChecked(),
            name_responder=self.responder_check.isChecked(),
            throttle_policy=self.throttle_policy,
        )
        # 启动即持久化当前扫描参数与网段 (P2-2)
        self._save_settings()
        self.scan_thread.progress.connect(self._on_scan_progress, Qt.QueuedConnection)
        self.scan_thread.phase_changed.connect(self._on_scan_phase, Qt.QueuedConnection)
        self.scan_thread.result_ready.connect(self._on_scan_result, Qt.QueuedConnection)
        self.scan_thread.finished_signal.connect(self._on_scan_finished, Qt.QueuedConnection)
        self.scan_thread.log_signal.connect(lambda msg: self.status_bar.showMessage(msg), Qt.QueuedConnection)
        # 审计：记录扫描开始
        # 礼貌档只在**非 fast** 时落审计：fast 是"改造前原样"，记了等于
        # 每条历史都多一句废话；非 fast 档会真实改变发包行为（限速/随机化），
        # 出了事要能从审计里还原"当时是什么档"（与 CLI 的 _audit_throttle 同口径）。
        _throttle_note = ""
        if self.throttle_policy != throttle.DEFAULT_POLICY:
            _throttle_note = tr(" · 礼貌档 ") + self.throttle_policy
        self._audit(
            audit_log.CAT_SCAN, tr("开始扫描"),
            f"范围: {', '.join(self.ip_range_items)} ({total_ips} 个IP) | "
            f"超时 {self.timeout_spin.value()}ms · 线程 {self.threads_spin.value()} · "
            f"端口扫描 {'开' if self.port_scan_check.isChecked() else '关'}"
            f"{tr(' · 级别 ') + scan_level_label(self.scan_level) if self.port_scan_check.isChecked() else ''}"
            f"{_throttle_note}",
        )
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_bar.showMessage(tr("正在停止扫描..."))
            self._audit(audit_log.CAT_SCAN, tr("停止扫描"), tr("用户手动中止扫描"))
            self.scan_thread.wait(3000)

    def _audit_scan_summary(self, status_counts=None):
        """写一条**结构化**扫描汇总事件（v2.2 §3.3 自查视图的唯一数据源）。

        与 `_audit(CAT_SCAN, tr("开始扫描"/"扫描完成"), ...)` 那两条本地化
        事件并存、互不替代：老 viewer 读人话，自查视图只读这条
        action=规范码 / detail=语言无关 JSON 的汇总。

        与 `cli._audit_scan_summary()` 同口径（键完全一致），
        GUI 与 CLI 两条扫描路径汇入同一张视图。

        任何异常只 warning：审计是旁路，不该让一次已完成的扫描判失败。
        """
        try:
            ranges = [
                {"range": r, "ips": count_ip_range(r)}
                for r in self.ip_range_items
            ]
            ports = (get_ports_for_level(self.scan_level)
                     if self.port_scan_check.isChecked() else None)
            audit_log.log_scan_summary({
                "ranges": ranges,
                "ips": sum(item["ips"] for item in ranges),
                "online": int((status_counts or {}).get("online", 0) or 0),
                "protocols": list(self.selected_protocols or []),
                "ports_scanned": len(ports) if ports else None,
                "throttle": self.throttle_policy or "",
                "source": "gui",
            })
        except Exception as e:  # noqa: BLE001
            _log.warning("写入扫描汇总审计失败（不影响本次扫描）: %s", e)

    def _toggle_protocol(self, proto, checked):
        """菜单勾选/取消协议，实时更新 selected_protocols 并提示。"""
        if checked:
            if proto not in self.selected_protocols:
                self.selected_protocols.append(proto)
        else:
            if proto in self.selected_protocols:
                self.selected_protocols.remove(proto)
        self.status_bar.showMessage(
            f"已选择协议: {', '.join(self.selected_protocols) if self.selected_protocols else tr('无')}"
        )

    def _set_tcp_mode(self, mode: str):
        """切换端口探测方式（全连接 / SYN 半开 / UDP）并持久化。"""
        self.tcp_scan_mode = mode
        self._sync_tcp_mode_menu()
        self._save_settings()
        _label = {"connect": tr("TCP 全连接"), "syn": tr("TCP SYN 半开"), "udp": tr("UDP 探测")}.get(mode, mode)
        _tip = ""
        if mode in ("syn", "udp"):
            _tip = tr("（需管理员权限；Windows 还需 Npcap，否则自动回退全连接）")
        self.status_bar.showMessage(f"端口探测方式: {_label}{_tip}")

    def _sync_tcp_mode_menu(self):
        """同步"端口探测方式"子菜单的勾选态到当前 tcp_scan_mode。"""
        for _a in self.tcp_mode_group.actions():
            _a.setChecked(_a.data() == self.tcp_scan_mode)

    def _set_scan_level(self, level: str):
        """切换扫描级别（快速/标准/全端口）并持久化，决定端口探测范围。"""
        if level not in ("quick", "standard", "all"):
            level = "quick"
        self.scan_level = level
        self._sync_scan_level_menu()
        self._save_settings()
        _label = scan_level_label(level)
        _n = len(get_ports_for_level(level))
        self.status_bar.showMessage(f"扫描级别: {_label} · 端口数 {_n}")

    def _sync_scan_level_menu(self):
        """同步"扫描级别"子菜单的勾选态到当前 scan_level。"""
        for _a in self.scan_level_group.actions():
            _a.setChecked(_a.data() == self.scan_level)

    def _set_throttle_policy(self, policy: str):
        """切换扫描礼貌档（v2.1 §2.4 GUI 露出）并持久化。

        这里**只动配置**，不碰进程态：档位在每次开扫时由 `ScanThread.run()`
        装进进程（`throttle.active_policy`），扫描一结束就恢复上一层档。
        要是顺手在这里装上，限速桶会漏到后续所有扫描上 —— 那正是
        `_PolicyContext` 注释里说的"悄悄把工具变慢"。
        """
        if policy not in throttle.POLICY_NAMES:
            policy = throttle.DEFAULT_POLICY
        self.throttle_policy = policy
        self._sync_throttle_menu()
        self._save_settings()
        _d = throttle.resolve_policy(policy).audit_detail()
        self.status_bar.showMessage(
            tr("扫描礼貌档: {name} · 包速率 {rate} · 并发 {conc} · 顺序随机化 {shuf}")
            .format(name=policy,
                    rate=_d["packets_per_minute"] or tr("不限"),
                    conc=_d["max_concurrency"] or tr("不限"),
                    shuf=tr("开") if _d["shuffle"] else tr("关")))

    def _sync_throttle_menu(self):
        """同步"扫描礼貌档"子菜单的勾选态到当前 throttle_policy。"""
        for _a in self.throttle_group.actions():
            _a.setChecked(_a.data() == self.throttle_policy)

    def _on_scan_progress(self, current, total, ip):
        self.scan_status.set_progress(current, total)
        self.status_bar.showMessage(f"扫描中 [{current}/{total}] {ip} ...")

    def _on_scan_phase(self, name, index, total):
        """阶段切换。`name` 是语言无关的规范值（`ping`/`arp`/`mdns`），
        翻译发生在 `ScanStatusBar.set_phase` 里。"""
        self.scan_status.set_phase(name, index, total)

    def _on_scan_result(self, result: ScanResult):
        # 地址库匹配已在扫描线程内完成（见 ScanThread._build_library_lookup：
        # 整库预加载为内存索引 + O(1) 查找），主线程只负责渲染。
        # 旧实现在此逐条查 SQLite，/16 网段会产生约 6.5 万次主线程查询并冻结界面。
        self._upsert_table_row(result)
        # 摘要条实时计数。引擎只对存活主机走富化回调（见 `_on_scan_finished`
        # 里那段说明），所以这里收到的必然是"扫出东西"的行。
        if result.status == "online":
            self._scan_online += 1
        if getattr(result, "services", None):
            self._scan_services += 1
        self.scan_status.set_counts(self._scan_online, self._scan_services)

    def _scan_trend_meta(self):
        """趋势观测的扫描元数据（v2.3 §3.2 接线）。

        与 `_audit_scan_summary()` 同源（都用 `ip_range_items` / `scan_level`），
        但**不是**同一份：那个进审计库（合规自查），这个进趋势库（画曲线）。
        没有它，`ranges_json` / `source` 等列就永远是空的，按网段曲线画不出来。
        """
        try:
            ports = (get_ports_for_level(self.scan_level)
                     if self.port_scan_check.isChecked() else None)
            started = getattr(self, "_scan_started_at", None)
            duration = (time.perf_counter() - started
                        if started is not None else None)
            return {
                "ranges": list(self.ip_range_items or []),
                "ports_scanned": len(ports) if ports else None,
                "duration_s": duration,
                "source": "gui",
            }
        except Exception as e:  # noqa: BLE001
            # 趋势是旁路：元数据取不到就不带，绝不拖累一次已完成的扫描。
            _log.warning("构造趋势元数据失败（本次不带）: %s", e)
            return None

    def _on_scan_finished(self, results):
        try:
            self.all_results = results
            # 变更检测：在保存新快照前，对比上一次快照
            self._run_change_detection(silent=True)
            # 保存历史快照用于对比 (P2-5)
            # 端口映射（若本次扫描采集过）随快照一并落库，供「定位查询」使用
            self._save_snapshot(
                results,
                switch_maps=getattr(self.scan_thread, "switch_maps", None),
                trend=self._scan_trend_meta())

            # 先关闭排序，避免批量添加时的性能问题
            self.table.setSortingEnabled(False)

            # 只渲染"还没有行"或"扫描末尾被 mDNS 就地改过"的结果。
            #
            # 旧实现无条件把 results 全量再 upsert 一遍，但每行在扫描过程中已经
            # 通过 result_callback 渲染过了 —— /16 网段就是 6.5 万次无谓重渲染。
            #
            # 两点必须同时成立才能这样收窄，已逐一核实：
            #   1. 离线主机从未被回调（引擎只对 alive 主机提交 enrich），
            #      所以它们必然不在 _ip_item_map 里，会走"新增"分支正常入表；
            #   2. mDNS（Phase 3）是唯一在回调之后仍会改动已渲染对象的地方，
            #      引擎已在那些结果上打了 mdns_updated（见 ScanResult.mdns_updated）。
            for result in results:
                if (result.ip not in self._ip_item_map
                        or getattr(result, "mdns_updated", False)):
                    self._upsert_table_row(result)
                    result.mdns_updated = False

            # 应用筛选（默认"在线"：扫描完成后隐藏离线终端）并刷新筛选条计数
            self._filter_results()
            self._refresh_filter_counts()

            # 端口探测方式回退告警（如 SYN/UDP 被系统拒绝后回退全连接）
            _warns = getattr(self.scan_thread.scanner, "warnings", []) if self.scan_thread else []
            if _warns:
                self.status_bar.showMessage("；".join(_warns))
                for _w in _warns:
                    print("[WARN]", _w)

            # 扫描被拒绝（如范围超限）导致 0 结果时明确弹窗，
            # 否则用户会误以为"这个网段里没有任何设备"。
            if _warns and not results:
                msg_warn(self, tr("扫描未执行"), "\n\n".join(_warns))

            # 恢复排序
            self.table.setSortingEnabled(True)

            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.act_export.setEnabled(True)
            self.act_clear.setEnabled(True)
            self.scan_status.finish()
            self._update_stats()
            # 审计：记录扫描完成
            _st = ui_logic.count_scan_status(results)
            self._audit(
                audit_log.CAT_SCAN, tr("扫描完成"),
                f"共 {_st['total']} 个IP · 在线 {_st['online']} · 离线 {_st['offline']} · "
                f"未知 {_st['unknown']}",
            )
            # v2.2 §3.3：自查视图用的**结构化**汇总事件。上面那条是给人看的
            # 本地化文本（tr() 结果入库），不能拿来聚合 —— 拿 tr() 结果作
            # 比较，切一次语言聚合就裂行。汇总事件 action 是规范码、
            # detail 是语言无关 JSON；记账失败被 _audit 系列吞掉，不拖累
            # 一次已完成的扫描。
            self._audit_scan_summary(_st)
            # 扫描完成后自动执行冲突检测（静默，仅更新标记和状态栏）
            self._run_conflict_detection(silent=True)
            # 概览页可见时同步刷新（不可见则跳过，避免白算一遍全量统计）
            self._refresh_overview_if_visible()
            self.status_bar.showMessage(tr("扫描完成"))
        except Exception as e:
            sys.stderr.write(f"[ERR] _on_scan_finished 异常: {e}\n")
            import traceback
            traceback.print_exc()
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.act_export.setEnabled(True)
            self.act_clear.setEnabled(True)
            self.scan_status.finish()
            self.status_bar.showMessage(f"扫描异常: {e}")

    def _run_conflict_detection(self, silent=False):
        """执行 IP 冲突检测。

        Args:
            silent: True 时仅更新树视图标记和状态栏，不弹对话框（扫描后自动调用）；
                    False 时弹出冲突报告对话框（菜单手动触发）。
        """
        if not self.all_results:
            if not silent:
                msg_info(self, tr("冲突检测"), tr("暂无扫描结果，请先执行扫描。"))
            return

        library = self.library if self.library.is_loaded() else None
        self._conflicts = detect_conflicts(self.all_results, library)
        self._conflict_ips = get_conflict_ips(self._conflicts)

        # 刷新树视图中所有行的冲突标记
        self._refresh_conflict_marks()

        # 更新统计栏与筛选条上的冲突计数
        self._update_stats()
        self._refresh_filter_counts()
        # 冲突数量是概览页「风险」区块的数据源，概览可见时一并刷新
        self._refresh_overview_if_visible()

        # 审计：记录冲突检测结果
        _cf = ui_logic.count_conflicts(self._conflicts)
        self._audit(
            audit_log.CAT_CONFLICT, tr("冲突检测"),
            f"严重 {_cf['high']} · 警告 {_cf['warning']} · 提示 {_cf['info']}"
            + (tr("（未发现冲突）") if not self._conflicts else ""),
        )

        if silent:
            # 静默模式：仅在状态栏提示冲突数量
            high = sum(1 for c in self._conflicts if c.severity == SEVERITY_HIGH)
            warn = sum(1 for c in self._conflicts if c.severity == SEVERITY_WARNING)
            if high or warn:
                parts = []
                if high:
                    parts.append(f"{high} 严重")
                if warn:
                    parts.append(f"{warn} 警告")
                self.status_bar.showMessage(f"冲突检测完成：{' · '.join(parts)}（菜单 → 扫描 → 冲突检测 查看详情）")
            return

        # 手动触发：弹出报告对话框
        if not self._conflicts:
            msg_info(self, tr("冲突检测"), tr("未检测到任何冲突，网络状态良好。"))
            return
        dlg = ConflictReportDialog(self._conflicts, parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _run_change_detection(self, silent=False):
        """执行资产变更检测：对比当前扫描结果与上一次快照。

        Args:
            silent: True 时仅更新状态栏（扫描后自动调用）；
                    False 时弹出变更报告对话框（菜单手动触发）。
        """
        if not self.all_results:
            if not silent:
                msg_info(self, tr("变更检测"), tr("暂无扫描结果，请先执行扫描。"))
            return

        # 加载最近一次快照作为"上次"基准
        try:
            snapshots = history_store.list_snapshots(self.history_db)
            if not snapshots:
                self._changes = []
                self._apply_change_index()
                if not silent:
                    msg_info(self, tr("变更检测"), tr("没有历史快照可供对比（首次扫描）。"))
                return
            last_snap = history_store.get_snapshot(snapshots[-1]["id"], self.history_db)
            prev_devices = last_snap["devices"] if last_snap else []
        except Exception:
            prev_devices = []

        if not prev_devices:
            self._changes = []
            self._apply_change_index()
            if not silent:
                msg_info(self, tr("变更检测"), tr("上次快照为空，无法对比。"))
            return

        self._changes = detect_changes(self.all_results, prev_devices)
        # 把变更折叠成按 IP 的索引，供行内角标与「变更」筛选使用。
        # 必须在扫描完成后的建行循环**之前**调用（_on_scan_finished 里
        # _run_change_detection 早于建行），否则新设备的行建出来时索引还是空的。
        self._apply_change_index()

        # 审计：记录变更检测
        summary = get_change_summary(self._changes)
        self._audit(audit_log.CAT_SCAN, tr("变更检测"), summary)

        if silent:
            # 静默模式：有严重/警告变更时在状态栏提示
            high = sum(1 for c in self._changes if c.severity == "high")
            warn = sum(1 for c in self._changes if c.severity == "warning")
            if high or warn:
                parts = []
                if high:
                    parts.append(f"{high} 严重")
                if warn:
                    parts.append(f"{warn} 警告")
                self.status_bar.showMessage(
                    f"资产变更：{' · '.join(parts)}（菜单 → 扫描 → 变更检测 查看详情）"
                )
            return

        # 手动触发：弹出报告对话框
        if not self._changes:
            msg_info(self, tr("变更检测"), tr("与上次扫描相比无任何变更，网络状态稳定。"))
            return
        dlg = ChangeReportDialog(self._changes, parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _apply_change_index(self):
        """重建变更索引，并刷新行内角标与筛选条计数。

        只做"重建 + 刷新"，不碰 `self._changes` —— 便于在检测的各个提前
        返回分支里复用（那些分支同样需要把旧角标清干净）。
        """
        self._rebuild_change_index()
        self._refresh_change_marks()
        self._refresh_filter_counts()


    def _show_subnet_utilization(self):
        """弹出子网利用率对话框。"""
        if not self.all_results:
            msg_info(self, tr("子网利用率"), tr("暂无扫描结果，请先执行扫描。"))
            return
        dlg = SubnetUtilizationDialog(self.all_results, parent=self, dark=self.dark_mode)
        dlg.exec_()

    def _run_mdns_discovery(self):
        """独立触发 mDNS/DNS-SD 组播发现（不依赖扫描），发现结果合并到树与 all_results。"""
        if self.mdns_thread and self.mdns_thread.isRunning():
            self.status_bar.showMessage(tr("mDNS 发现进行中..."))
            return
        self.mdns_thread = MdnsThread(timeout=2.5)
        self.mdns_thread.log_signal.connect(
            lambda m: self.status_bar.showMessage(m), Qt.QueuedConnection
        )
        self.mdns_thread.finished_signal.connect(
            self._on_mdns_finished, Qt.QueuedConnection
        )
        self.mdns_thread.start()

    def _on_mdns_finished(self, mdns_map: dict):
        """处理 mDNS 发现结果：合并到结果树与 all_results（去重）。"""
        try:
            self.table.setSortingEnabled(False)
            added = 0
            for ip, info in mdns_map.items():
                names = sorted(info.get("names", set()))
                services = sorted(info.get("services", set()))
                host = names[0].rstrip(".") if names else ""
                existing = next((r for r in self.all_results if r.ip == ip), None)
                if existing is None:
                    r = ScanResult(ip=ip, status="online",
                                   discovery_method="mdns", hostname=host)
                    self.all_results.append(r)
                else:
                    r = existing
                    r.status = "online"
                    if not r.discovery_method:
                        r.discovery_method = "mdns"
                    if not r.hostname and host:
                        r.hostname = host
                if services and SVC_MDNS not in r.services:
                    r.services.append(SVC_MDNS)
                    r.service_details.append({
                        "proto": SVC_MDNS, "port": 0, "banner": ", ".join(services)
                    })
                self._upsert_table_row(r)
                added += 1
            self._filter_results()
            self.table.setSortingEnabled(True)
            self._update_stats()
            if added:
                self.status_bar.showMessage(f"mDNS 发现 {added} 个设备（已合并到结果）")
                self.act_export.setEnabled(True)
            else:
                self.status_bar.showMessage(
                    tr("mDNS 未发现新设备（可能网内无 mDNS 设备 / 组播端口被占用）")
                )
        except Exception as e:
            sys.stderr.write(f"[ERR] _on_mdns_finished: {e}\n")
            self.status_bar.showMessage(f"mDNS 处理异常: {e}")

    # --- SNMPv3 用户配置 ---
    def _configure_snmp_v3(self):
        """配置 SNMPv3 USM 用户（认证/加密）。

        配置后扫描**优先**用 v3 识别设备；未配置则回退到 v2c 团体字探测。
        清空用户名即等于关闭 v3（回到 v2c）。
        """
        dlg = SnmpV3CredentialDialog(
            self,
            saved={
                "username": self.snmp_v3_creds.username,
                "auth_proto": self.snmp_v3_creds.auth_proto,
                "auth_key": self.snmp_v3_creds.auth_key,
                "priv_proto": self.snmp_v3_creds.priv_proto,
                "priv_key": self.snmp_v3_creds.priv_key,
            },
            saved_target=self._snmp_v3_test_target(),
        )
        if dlg.exec_() != QDialog.Accepted:
            return
        user, auth_proto, auth_key, priv_proto, priv_key, save = dlg.get_config()
        self.snmp_v3_creds.set(user, auth_proto, auth_key, priv_proto, priv_key)
        if save:
            self.snmp_v3_creds.save_to(self.settings)
        if user:
            self.status_bar.showMessage(tr("SNMPv3 用户已设置：%s") % user)
        else:
            self.status_bar.showMessage(
                tr("SNMPv3 未配置用户名，扫描将使用 v2c 团体字"))

    def _snmp_v3_test_target(self) -> str:
        """给"测试"按钮挑一个默认目标：首个网段的第一个地址。

        必须先 count_ip_range 计数再展开 —— 网段框里可能还留着半截输入，
        直接 parse_ip_range 展开未校验的范围会瞬间吃光内存。
        """
        if not self.ip_range_items:
            return ""
        first = self.ip_range_items[0]
        try:
            if count_ip_range(first) > MAX_IPS_PER_RANGE:
                return ""
            ips = parse_ip_range(first)
        except Exception as e:  # noqa: BLE001
            # 网段框里是半截输入（用户还没写完）属于正常情况，仅记 debug
            _log.debug("推导 SNMPv3 测试目标失败: %s", e)
            return ""
        return ips[0] if ips else ""

    # --- WMI 设备识别 ---
    def _run_wmi_identification(self, targets=None):
        """对目标 Windows 设备执行 WMI 识别。

        targets: IP 列表；为 None 时对全部在线、疑似 Windows 的设备批量识别。
        无凭据时弹窗采集；勾选保存则用 DPAPI 加密持久化到 ipscanner.ini。
        """
        # 1) 凭据采集（仅当内存中尚无有效凭据）
        if not self.wmi_creds.has_creds():
            dlg = WmiCredentialDialog(
                self, saved_username=self.wmi_creds.username,
                saved_domain=self.wmi_creds.domain,
                saved_transport=self.wmi_creds.transport,
            )
            if dlg.exec_() != QDialog.Accepted:
                return
            user, pwd, domain, save, transport = dlg.get_credentials()
            if not user or not pwd:
                msg_warn(self, tr("WMI 识别"), tr("用户名和密码不能为空"))
                return
            self.wmi_creds.set(user, pwd, domain, transport)
            if save:
                self.wmi_creds.save_to(self.settings)

        # 2) 确定目标
        _explicit = targets is not None
        targets = ui_logic.select_identification_targets(self.all_results, targets, tr("Windows"))
        if not targets:
            if not _explicit:
                msg_info(
                    self, tr("WMI 识别"),
                    tr("没有发现在线且疑似 Windows 的设备（需开放 135/445，或 TTL 推测为 Windows）。\n" "可先用普通扫描发现设备，再对选中设备执行 WMI 识别。")
                )
            else:
                msg_info(self, tr("WMI 识别"), tr("所选设备不在线，无法识别。"))
            return

        # 3) 后台线程逐台识别
        if self.wmi_thread and self.wmi_thread.isRunning():
            self.status_bar.showMessage(tr("WMI 识别进行中，请稍候..."))
            return
        self.status_bar.showMessage(f"WMI 识别启动：共 {len(targets)} 台设备...")
        self.wmi_thread = WmiThread(targets, self.wmi_creds)
        self.wmi_thread.progress_signal.connect(
            lambda i, t: self.status_bar.showMessage(f"WMI 识别 [{i}/{t}] ...")
        )
        self.wmi_thread.result_signal.connect(self._on_wmi_result)
        self.wmi_thread.finished_signal.connect(self._on_wmi_finished)
        self.wmi_thread.start()

    def _on_wmi_result(self, ip: str, wmi_dict: dict):
        """单台设备 WMI 结果回传：合并信息并刷新表格行。"""
        result = next((r for r in self.all_results if r.ip == ip), None)
        if result is None:
            return
        self._apply_wmi(result, wmi_dict)
        self._upsert_table_row(result)

    def _on_wmi_finished(self, summary: dict):
        ok = summary.get("ok", 0)
        fail = summary.get("fail", 0)
        total = summary.get("total", 0)
        msg = ui_logic.format_identify_summary("WMI", ok, fail, total, "权限/防火墙/非 Windows 等")
        self._audit(
            audit_log.CAT_DEVICE, tr("WMI 识别"),
            f"共 {total} 台 · 成功 {ok} · 失败 {fail}",
        )
        self.status_bar.showMessage(msg)
        self._update_stats()


    def _apply_wmi(self, result: ScanResult, d: dict):
        """把 WMI 查询结果合并进 ScanResult，并用权威信息补全设备指纹。"""
        merge_wmi(result, d)

    # --- NetBIOS 轻量识别（零凭据、不需管理员，作为 WMI 的轻量补充）---

    def _run_netbios_identification(self, targets=None):
        """对目标设备执行 NetBIOS 轻量识别（UDP/137 NBSTAT，零凭据、不需管理员）。

        targets: IP 列表；为 None 时对全部在线、疑似 Windows 的设备批量识别。
        无需凭据，直接启动后台线程逐台查询。
        """
        _explicit = targets is not None
        targets = ui_logic.select_identification_targets(self.all_results, targets, tr("Windows"))
        if not targets:
            if not _explicit:
                msg_info(
                    self, tr("NetBIOS 识别"),
                    tr("没有发现在线且疑似 Windows 的设备（需开放 135/445，或 TTL 推测为 Windows）。\n" "可先扫描发现设备，再对选中设备执行 NetBIOS 识别。")
                )
            else:
                msg_info(self, tr("NetBIOS 识别"), tr("所选设备不在线，无法识别。"))
            return

        if self.netbios_thread and self.netbios_thread.isRunning():
            self.status_bar.showMessage(tr("NetBIOS 识别进行中，请稍候..."))
            return
        self.status_bar.showMessage(f"NetBIOS 识别启动：共 {len(targets)} 台设备...")
        self.netbios_thread = NetbiosThread(targets, timeout=1.5)
        self.netbios_thread.progress_signal.connect(
            lambda i, t: self.status_bar.showMessage(f"NetBIOS 识别 [{i}/{t}] ...")
        )
        self.netbios_thread.result_signal.connect(self._on_netbios_result)
        self.netbios_thread.finished_signal.connect(self._on_netbios_finished)
        self.netbios_thread.start()

    def _on_netbios_result(self, ip: str, d: dict):
        """单台设备 NetBIOS 结果回传：合并信息并刷新表格行。"""
        result = next((r for r in self.all_results if r.ip == ip), None)
        if result is None:
            return
        self._apply_netbios(result, d)
        self._upsert_table_row(result)

    def _on_netbios_finished(self, summary: dict):
        ok = summary.get("ok", 0)
        fail = summary.get("fail", 0)
        total = summary.get("total", 0)
        msg = ui_logic.format_identify_summary("NetBIOS", ok, fail, total, "防火墙/非 Windows/未开放 137 等")
        self._audit(
            audit_log.CAT_DEVICE, tr("NetBIOS 识别"),
            f"共 {total} 台 · 成功 {ok} · 失败 {fail}",
        )
        self.status_bar.showMessage(msg)
        self._update_stats()

    def _apply_netbios(self, result: ScanResult, d: dict):
        """把 NetBIOS 查询结果合并进 ScanResult，并用权威信息补全设备指纹。"""
        merge_netbios(result, d)



