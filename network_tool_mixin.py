# -*- coding: utf-8 -*-
"""内置网络工具与远程电源/WoL 混入类。从 main_window.py 拆分出来，通过 Mixin 模式供 MainWindow 继承。"""
import subprocess
import shutil
import getpass
import locale
from PyQt5.QtWidgets import QInputDialog, QMessageBox
from PyQt5.QtCore import QUrl, QProcess
from PyQt5.QtGui import QDesktopServices
import audit_log
from i18n import tr
from ui_dialogs import SwitchPortDialog

class NetworkToolMixin:
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
            if not shutil.which("ssh"):
                if _win:
                    msg = tr("系统未安装 OpenSSH 客户端（ssh.exe）。\n"
                             "请在「设置 → 应用 → 可选功能」中启用「OpenSSH 客户端」后重试。")
                else:
                    msg = tr("系统未安装 SSH 客户端。请执行: sudo apt install openssh-client")
                QMessageBox.warning(self, tr("未找到 ssh"), msg)
                return
            cmd = f"ssh {user.strip()}@{target}"
        elif tool == "rdp":
            if _win:
                try:
                    subprocess.Popen(["mstsc.exe", f"/v:{target}"])
                    self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"RDP · 目标 {target}")
                    self.status_bar.showMessage(f"已启动 RDP: {target}")
                except Exception as e:
                    QMessageBox.warning(self, tr("启动失败"), f"无法启动远程桌面: {e}")
                return
            else:
                QMessageBox.information(self, tr("远程桌面"),
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
                    QMessageBox.information(self, tr("启动网络工具"),
                        tr("未找到可用的终端模拟器。请在终端中手动执行:\n") + cmd)
                    return

            self._audit(audit_log.CAT_DEVICE, tr("启动网络工具"), f"{tool.upper()} · 目标 {target}")
            self.status_bar.showMessage(f"已启动 {tool.upper()}: {target}")
        except Exception as e:
            QMessageBox.warning(self, tr("启动失败"), f"无法启动 {tool.upper()}: {e}")

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

        _verb = tr("关机") if action == "shutdown" else tr("重启")
        reply = QMessageBox.question(
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
                QMessageBox.information(self, tr("指令已发送"), f"已向 {target} 发送远程{_verb}指令。")
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                self._audit(audit_log.CAT_DEVICE, f"远程{_verb}失败",
                            f"目标 {target} · 退出码 {proc.returncode}")
                QMessageBox.warning(
                    self, tr("远程") + _verb + tr("失败"),
                    f"向 {target} 发送{_verb}指令失败 (退出码 {proc.returncode})。\n"
                    + (_err + "\n\n" if _err else "")
                    + tr("常见原因：目标未授权、网络不可达、缺少权限，\n")
                    + tr("或本地未以管理员身份运行本程序。")
                )
        except Exception as e:
            QMessageBox.warning(self, tr("远程") + _verb + tr("失败"), f"执行远程{_verb}指令时出错: {e}")

    def _remote_power_unix(self, target, action, _verb):
        """Linux/macOS: 通过 SSH 执行 shutdown/reboot。"""
        if not shutil.which("ssh"):
            QMessageBox.warning(self, tr("未找到 ssh"),
                tr("远程关机需要 SSH。请安装 openssh-client 后重试。"))
            return

        _cmd = "shutdown -h now" if action == "shutdown" else "reboot"
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
                    "root@" + target, _cmd]
        try:
            proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                self._audit(audit_log.CAT_DEVICE, f"远程{_verb}", f"目标 {target} · SSH 指令已发送")
                QMessageBox.information(self, tr("指令已发送"),
                    f"已通过 SSH 向 {target} 发送远程{_verb}指令。")
                self.status_bar.showMessage(f"已发送远程{_verb}: {target}")
            else:
                _err = (proc.stderr or proc.stdout or "").strip()
                QMessageBox.warning(self, tr("远程") + _verb + tr("失败"),
                    f"SSH 连接 {target} 失败：{_err}\n\n"
                    + tr("提示：目标需开启 SSH 且允许 root 登录，或配置免密 sudo。"))
        except Exception as e:
            QMessageBox.warning(self, tr("远程") + _verb + tr("失败"), f"执行失败: {e}")

    def _show_snmp_info(self, ip, name, descr):
        """点击 SNMP 服务子项 → 弹窗展示设备识别信息"""
        text = f"IP 地址: {ip}\n"
        if name:
            text += f"系统名称 (sysName): {name}\n"
        if descr:
            text += f"\n系统描述 (sysDescr):\n{descr}"
        else:
            text += tr("\n(未获取到 sysDescr)")
        QMessageBox.information(self, tr("SNMP 设备信息"), text)

    def _open_service(self, proto, ip):
        """根据协议打开浏览器 / 远程桌面。"""
        if proto == tr("HTTP"):
            QDesktopServices.openUrl(QUrl(f"http://{ip}"))
        elif proto == tr("HTTPS"):
            QDesktopServices.openUrl(QUrl(f"https://{ip}"))
        elif proto == tr("FTP"):
            QDesktopServices.openUrl(QUrl(f"ftp://{ip}"))
        elif proto == tr("RDP"):
            if not QProcess.startDetached("mstsc", [f"/v:{ip}"]):
                QMessageBox.information(
                    self, tr("远程桌面"),
                    f"未能自动启动远程桌面连接。\n请手动运行：mstsc /v:{ip}"
                )

    # ── 扫描历史 (P2-5) ──
    def _wake_on_lan(self, mac: str):
        """发送 Wake-on-LAN 魔术包 (6×0xFF + 16×MAC) 到广播地址。"""
        import socket as sock
        mac_clean = mac.replace("-", "").replace(":", "").replace(".", "").strip().upper()
        if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
            QMessageBox.warning(self, tr("WoL 唤醒"), f"MAC 地址格式无效，无法唤醒：\n{mac}")
            return
        try:
            mac_bytes = bytes.fromhex(mac_clean)
            packet = b"\xff" * 6 + mac_bytes * 16
            s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
            s.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)
            s.sendto(packet, ("255.255.255.255", 9))
            s.close()
            self.status_bar.showMessage(f"已向 {mac} 发送 WoL 魔术包")
            QMessageBox.information(
                self, tr("WoL 唤醒"),
                f"已向 {mac} 发送唤醒魔术包。\n\n请确保目标设备已开启 WOL：\n"
                + tr("• BIOS/UEFI 中启用 Wake on LAN\n"
                     "• 网卡属性中允许「允许此设备唤醒计算机」")
            )
        except Exception as e:
            QMessageBox.warning(self, tr("WoL 唤醒"), f"发送失败：{e}")

    def _show_switch_port_mapping(self):
        """弹出交换机端口映射对话框。"""
        self._audit(audit_log.CAT_DEVICE, tr("交换机端口映射"), tr("打开端口映射工具"))
        dlg = SwitchPortDialog(
            scan_results=self.all_results, parent=self, dark=self.dark_mode
        )
        dlg.exec_()

