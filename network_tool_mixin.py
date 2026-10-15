# -*- coding: utf-8 -*-
"""内置网络工具与远程电源/WoL 混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
import ipaddress
import re
import subprocess
import shutil
import getpass
import locale
from PyQt5.QtWidgets import QInputDialog, QMessageBox
from PyQt5.QtCore import QUrl, QProcess
from PyQt5.QtGui import QDesktopServices
import audit_log
from app_logging import get_logger
from ui_msg import msg_ask, msg_info, msg_warn
from i18n import tr
from scanner.constants import SVC_FTP, SVC_HTTP, SVC_HTTPS, SVC_RDP
from ui_dialogs import SwitchPortDialog, WifiDialog

_log = get_logger(__name__)

# ── 目标校验（P0-4：命令注入防护）──────────────────────────────
# 背景：ping/tracert/telnet/ssh 的目标最终会被拼进 `cmd /k "<cmd>"`（Windows）
# 或终端模拟器的命令行（Linux/macOS）。若目标里含 `&`、`|`、`;`、`"` 等
# shell 元字符，用户输入的「目标」就能在宿主上执行任意命令。
# 对策：只接受 IPv4/IPv6 字面量或纯 ASCII 主机名，白名单之外一律拒绝。
_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SAFE_USER_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,62}$")


def _is_ip_literal(t: str) -> bool:
    """`t` 是否是 IPv4 / IPv6 字面量。

    ⚠️ `ipaddress` 没有"是不是 IP"的谓词接口，只能靠 `ip_address()` 抛
    `ValueError` 来判定 —— 所以这里**显式 `return False`**，而不是在调用点
    写 `except ValueError: pass`：后者语义是"吞掉异常继续往下走"，会被
    `tests/test_logging_policy.py` 的静默吞异常棘轮记一笔，且读代码的人
    分不清"预期内"与"漏处理"（v2.2 §3.4-c）。
    """
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def validate_target(target):
    """校验网络工具目标，返回 ``(ok, cleaned, reason)``。

    只允许 IP 字面量或主机名。空格、控制字符以及 ``& | ^ < > " ' ` $ ( ) ; % ! * ? ~ = \\``
    等可能被 cmd.exe / shell 解释的字符全部拒绝，从根本上消除命令注入。
    """
    if target is None:
        return False, "", "目标为空"
    t = str(target).strip()
    if not t:
        return False, "", "目标为空"
    if len(t) > 253:
        return False, "", "目标过长（超过 253 个字符）"
    # 空白与控制字符
    for ch in t:
        if ch.isspace() or ord(ch) < 32 or ord(ch) == 127:
            return False, "", "目标不能包含空白或控制字符"
    # IP 字面量（IPv6 含冒号，必须先于主机名白名单判断）
    if _is_ip_literal(t):
        return True, t, ""
    # 主机名：白名单字符集，且不能以连字符开头（避免被 ping/ssh 当成选项）
    if not _SAFE_HOSTNAME_RE.match(t):
        return False, "", "目标只能包含字母、数字、点、连字符和下划线"
    if t.endswith(".") or ".." in t:
        return False, "", "主机名格式不合法"
    if not re.search(r"[A-Za-z]", t):
        return False, "", "不是合法的 IP 地址或主机名"
    return True, t, ""


def validate_user(user):
    """校验 SSH 用户名，返回 ``(ok, cleaned, reason)``。

    用户名同样会被拼进 ``ssh <user>@<target>``，因此禁止空格与 shell 元字符。
    """
    if user is None:
        return False, "", "用户名为空"
    u = str(user).strip()
    if not u:
        return False, "", "用户名为空"
    if not _SAFE_USER_RE.match(u):
        return False, "", "用户名只能包含字母、数字、点、连字符和下划线"
    return True, u, ""


class NetworkToolMixin:

    def _validated_target(self, target, title):
        """校验目标，非法时弹窗 + 审计并返回 None（调用方应直接 return）。"""
        ok, cleaned, reason = validate_target(target)
        if ok:
            return cleaned
        msg_warn(
            self, title,
            tr("目标地址不合法，已阻止本次操作。")
            + f"\n\n{tr('目标')}: {target}\n{tr('原因')}: {reason}\n\n"
            + tr("为安全起见，目标只能是 IP 地址或主机名，\n"
                 "不允许包含空格、& | ; \" 等特殊字符。")
        )
        try:
            self._audit(audit_log.CAT_DEVICE, tr("网络工具目标被拒绝"),
                        f"目标 {target} · {reason}")
        except Exception as e:  # noqa: BLE001
            # 审计写入失败不能反过来打断"拒绝操作"这个安全动作
            _log.debug("记录目标被拒审计日志失败: %s", e)
        return None

    def _launch_network_tool(self, tool: str, target: str = None):
        """
        启动内置网络工具。跨平台：Windows/Linux/macOS 自动适配命令。
        """
        import platform as _plat
        _win = _plat.system() == "Windows"

        if not target:
            target = self._selected_target()
        if not target:
            text, ok = QInputDialog.getText(
                self, tr("选择目标"), f"请输入要执行「{tool.upper()}」的目标 IP 或主机名:"
            )
            if not ok or not text.strip():
                return
            target = text.strip()

        # P0-4：目标会拼进命令行，必须先校验
        target = self._validated_target(target, tr("选择目标"))
        if target is None:
            return

        if tool == "ping":
            cmd = f"ping -t {target}" if _win else f"ping {target}"
        elif tool == "tracert":
            cmd = f"tracert {target}" if _win else f"traceroute {target}"
        elif tool == "telnet":
            cmd = f"telnet {target}"
        elif tool == "ssh":
            user, ok = QInputDialog.getText(
                self, tr("SSH 连接"), tr("请输入登录用户名:"), text=getpass.getuser()
            )
            if not ok or not user.strip():
                return
            # P0-4：用户名同样进入命令行
            ok_user, user, reason = validate_user(user)
            if not ok_user:
                msg_warn(
                    self, tr("SSH 连接"),
                    tr("用户名不合法，已阻止本次连接。") + f"\n\n{tr('原因')}: {reason}"
                )
                return
            if not shutil.which("ssh"):
                if _win:
                    msg = tr("系统未安装 OpenSSH 客户端（ssh.exe）。\n"
                             "请在「设置 → 应用 → 可选功能」中启用「OpenSSH 客户端」后重试。")
                else:
                    msg = tr("系统未安装 SSH 客户端。请执行: sudo apt install openssh-client")
                msg_warn(self, tr("未找到 ssh"), msg)
                return
            cmd = f"ssh {user}@{target}"
        elif tool == "rdp":
            if _win:
                try:
                    subprocess.Popen(["mstsc.exe", f"/v:{target}"])
                    self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"RDP · 目标 {target}")
                    self.status_bar.showMessage(f"已启动 RDP: {target}")
                except Exception as e:
                    msg_warn(self, tr("启动失败"), f"无法启动远程桌面: {e}")
                return
            else:
                msg_info(self, tr("远程桌面"),
                    tr("RDP 为 Windows 专有功能。Linux/macOS 请使用 Remmina 或 FreeRDP 客户端。"))
                return
        elif tool == "cmd":
            if _win:
                cmd = f"title IPScanner 已连接 {target}"
            else:
                cmd = f"echo 'IPScanner connected to {target}'; exec $SHELL"
        else:
            return

        # 启动控制台
        try:
            if _win:
                subprocess.Popen(["cmd", "/k", cmd])
            else:
                # Linux/macOS: 在终端中运行
                if shutil.which("x-terminal-emulator"):
                    subprocess.Popen(["x-terminal-emulator", "-e", cmd])
                elif shutil.which("gnome-terminal"):
                    subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"{cmd}; exec bash"])
                elif shutil.which("xterm"):
                    subprocess.Popen(["xterm", "-e", cmd])
                elif shutil.which("open"):  # macOS
                    subprocess.Popen(["open", "-a", "Terminal", "--args", cmd])
                else:
                    msg_info(self, tr("启动网络工具"),
                        tr("未找到可用的终端模拟器。请在终端中手动执行:\n") + cmd)
                    return

            self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"{tool.upper()} · 目标 {target}")
            self.status_bar.showMessage(f"已启动 {tool.upper()}: {target}")
        except Exception as e:
            msg_warn(self, tr("启动失败"), f"无法启动 {tool.upper()}: {e}")

    def _remote_power(self, action: str):
        """
        远程关机 / 重启。
        Windows: shutdown /s /m 或 /r /m。
        Linux/macOS: ssh root@target shutdown 或 reboot。
        """
        import platform as _plat
        _win = _plat.system() == "Windows"

        target = self._selected_target()
        if not target:
            text, ok = QInputDialog.getText(
                self, tr("远程") + (tr("关机") if action == "shutdown" else tr("重启")),
                tr("请输入目标 IP 或主机名:")
            )
            if not ok or not text.strip():
                return
            target = text.strip()

        # P0-4：目标会作为参数传给 shutdown / ssh，必须先校验
        target = self._validated_target(
            target, tr("远程") + (tr("关机") if action == "shutdown" else tr("重启"))
        )
        if target is None:
            return

        _verb = tr("关机") if action == "shutdown" else tr("重启")
        reply = msg_ask(
            self, f"确认远程{_verb}",
            f"确定要向 {target} 发送远程{_verb}指令吗？\n"
            f"（目标上将立即{_verb}，未保存的工作可能丢失）",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        if _win:
            self._remote_power_windows(target, action, _verb)
        else:
            self._remote_power_unix(target, action, _verb)

    def _remote_power_windows(self, target, action, _verb):
        """Windows: shutdown 命令。"""
        _flag = "/s" if action == "shutdown" else "/r"
        cmd = ["shutdown", _flag, "/m", f"\\\\{target}", "/f", "/t", "0"]
        try:
            _enc = locale.getpreferredencoding(False) or "gbk"
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                encoding=_enc, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                self._audit(audit_log.CAT_DEVICE, f"远程{_verb}", f"目标 {target} · 指令已发送")
                msg_info(self, tr("指令已发送"), f"已向 {target} 发送远程{_verb}指令。")
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                self._audit(audit_log.CAT_DEVICE, f"远程{_verb}失败",
                            f"目标 {target} · 退出码 {proc.returncode}")
                msg_warn(
                    self, tr("远程") + _verb + tr("失败"),
                    f"向 {target} 发送{_verb}指令失败 (退出码 {proc.returncode})。\n"
                    + (_err + "\n\n" if _err else "")
                    + tr("常见原因：目标未授权、网络不可达、缺少权限，\n")
                    + tr("或本地未以管理员身份运行本程序。")
                )
        except Exception as e:
            msg_warn(self, tr("远程") + _verb + tr("失败"), f"执行远程{_verb}指令时出错: {e}")

    def _remote_power_unix(self, target, action, _verb):
        """Linux/macOS: 通过 SSH 执行 shutdown/reboot。"""
        if not shutil.which("ssh"):
            msg_warn(self, tr("未找到 ssh"),
                tr("远程关机需要 SSH。请安装 openssh-client 后重试。"))
            return

        _cmd = "shutdown -h now" if action == "shutdown" else "reboot"
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
                    "root@" + target, _cmd]
        try:
            proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                self._audit(audit_log.CAT_DEVICE, f"远程{_verb}", f"目标 {target} · SSH 指令已发送")
                msg_info(self, tr("指令已发送"),
                    f"已通过 SSH 向 {target} 发送远程{_verb}指令。")
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                msg_warn(self, tr("远程") + _verb + tr("失败"),
                    f"SSH 连接 {target} 失败：{_err}\n\n"
                    + tr("提示：目标需开启 SSH 且允许 root 登录，或配置免密 sudo。"))
        except Exception as e:
            msg_warn(self, tr("远程") + _verb + tr("失败"), f"执行失败: {e}")

    def _show_snmp_info(self, ip, name, descr):
        """点击 SNMP 服务子项 → 弹窗展示设备识别信息"""
        text = f"IP 地址: {ip}\n"
        if name:
            text += f"系统名称 (sysName): {name}\n"
        if descr:
            text += f"\n系统描述 (sysDescr):\n{descr}"
        else:
            text += tr("\n(未获取到 sysDescr)")
        msg_info(self, tr("SNMP 设备信息"), text)

    def _open_service(self, proto, ip):
        """根据协议打开浏览器 / 远程桌面。"""
        # P0-4：IP 会被拼进 URL / 传参给 mstsc，做一次防御性校验
        _ok, _clean, _ = validate_target(ip)
        if not _ok:
            return
        ip = _clean
        # proto 是语言无关的规范代码（见 scanner/constants.py），
        # 旧代码用 tr("HTTP") 比较，语言一换就会全部失配。
        _p = (proto or "").strip().upper()
        if _p == SVC_HTTP:
            QDesktopServices.openUrl(QUrl(f"http://{ip}"))
        elif _p == SVC_HTTPS:
            QDesktopServices.openUrl(QUrl(f"https://{ip}"))
        elif _p == SVC_FTP:
            QDesktopServices.openUrl(QUrl(f"ftp://{ip}"))
        elif _p == SVC_RDP:
            if not QProcess.startDetached("mstsc", [f"/v:{ip}"]):
                msg_info(
                    self, tr("远程桌面"),
                    f"未能自动启动远程桌面连接。\n请手动运行：mstsc /v:{ip}"
                )

    # ── 扫描历史 (P2-5) ──
    def _wake_on_lan(self, mac: str):
        """发送 Wake-on-LAN 魔术包 (6×0xFF + 16×MAC) 到广播地址。"""
        import socket as sock
        mac_clean = mac.replace("-", "").replace(":", "").replace(".", "").strip().upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            msg_warn(self, tr("WoL 唤醒"), f"MAC 地址格式无效，无法唤醒：\n{mac}")
            return
        try:
            mac_bytes = bytes.fromhex(mac_clean)
            packet = b"\xff" * 6 + mac_bytes * 16
            s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
            s.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)
            s.sendto(packet, ("255.255.255.255", 9))
            s.close()
            self.status_bar.showMessage(f"已向 {mac} 发送 WoL 魔术包")
            msg_info(
                self, tr("WoL 唤醒"),
                f"已向 {mac} 发送唤醒魔术包。\n\n请确保目标设备已开启 WOL：\n"
                + tr("• BIOS/UEFI 中启用 Wake on LAN\n"
                     "• 网卡属性中允许「允许此设备唤醒计算机」")
            )
        except Exception as e:
            msg_warn(self, tr("WoL 唤醒"), f"发送失败：{e}")

    def _show_switch_port_mapping(self):
        """弹出交换机端口映射对话框。"""
        self._audit(audit_log.CAT_DEVICE, tr("交换机端口映射"), tr("打开端口映射工具"))
        dlg = SwitchPortDialog(
            scan_results=self.all_results, parent=self, dark=self.dark_mode,
            snmp_v3_user=(self.snmp_v3_creds.to_user()
                          if self.snmp_v3_creds.has_creds() else None),
        )
        dlg.exec_()

    def _show_wifi_slice(self):
        """弹出无线切片对话框（v2.1 §2.2）。

        取数在对话框自己的后台线程里做（`netsh` 是子进程、主动扫描还要等射频），
        这里只负责打开它 —— 所以本方法**不会**冻界面。

        🔴 默认**只读系统缓存、不扰动射频**；要真扫一圈得在对话框里点
        「重新扫描（主动扰动射频）」。与 mDNS `listen_only` 同口径。
        """
        self._audit(audit_log.CAT_DEVICE, tr("无线切片"), tr("打开无线切片工具"))
        dlg = WifiDialog(parent=self, dark=self.dark_mode)
        dlg.exec_()

