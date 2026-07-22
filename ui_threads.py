# -*- coding: utf-8 -*-
"""扫描线程：ScanThread（主扫描）与 MdnsThread（mDNS 发现）。"""
from PyQt5.QtCore import QThread, pyqtSignal

from scanner import NetworkScanner, ScanResult


class ScanThread(QThread):
    progress = pyqtSignal(int, int, str)   # current, total, current_ip
    result_ready = pyqtSignal(object)       # ScanResult
    finished_signal = pyqtSignal(list)      # all results
    log_signal = pyqtSignal(str)            # log message

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False,
                 protocols=None, tcp_scan_mode="connect", mdns_discovery=True, ports=None):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.protocols = protocols or []
        self.tcp_scan_mode = tcp_scan_mode
        self.mdns_discovery = mdns_discovery
        self.ports = ports
        self.scanner = NetworkScanner()

    def run(self):
        def on_progress(current, total, ip):
            self.progress.emit(current, total, ip)

        def on_result(result: ScanResult):
            self.result_ready.emit(result)

        self.log_signal.emit(f"开始扫描 {len(self.ip_ranges)} 个网段...")
        results = self.scanner.scan(
            self.ip_ranges,
            timeout_ms=self.timeout_ms,
            max_threads=self.max_threads,
            scan_ports_flag=self.scan_ports,
            protocols=self.protocols,
            tcp_scan_mode=self.tcp_scan_mode,
            mdns_discovery=self.mdns_discovery,
            ports=self.ports,
            progress_callback=on_progress,
            result_callback=on_result,
        )

        online = sum(1 for r in results if r.status == "online")
        self.log_signal.emit(f"扫描完成: 共 {len(results)} 个IP, {online} 个在线")
        _at = getattr(self.scanner, "last_adaptive_timeout", None)
        if _at and abs(_at - 0.5) > 1e-6:
            self.log_signal.emit(f"RTT 自适应端口超时已收敛至 {_at:.2f}s")
        self.finished_signal.emit(results)

    def stop(self):
        self.scanner.stop()


class MdnsThread(QThread):
    """独立的 mDNS/DNS-SD 网络发现线程（不扫描也能量全网 mDNS 设备）。"""
    finished_signal = pyqtSignal(dict)   # {ip: {"names": set, "services": set}}
    log_signal = pyqtSignal(str)

    def __init__(self, timeout: float = 2.5):
        super().__init__()
        self.timeout = timeout

    def run(self):
        try:
            from scanner import mdns_discover
        except ImportError:
            try:
                from .scanner import mdns_discover
            except ImportError:
                mdns_discover = None
        if mdns_discover is None:
            self.log_signal.emit("mDNS 模块不可用")
            self.finished_signal.emit({})
            return
        self.log_signal.emit("正在做 mDNS 组播发现...")
        result = mdns_discover(timeout=self.timeout)
        self.log_signal.emit(f"mDNS 发现完成: {len(result)} 个设备")
        self.finished_signal.emit(result)


class WmiThread(QThread):
    """对一批在线 Windows 设备执行 WMI 识别（后台线程，避免界面卡顿）。

    每台设备一次 PowerShell Get-CimInstance 调用；结果逐台回传，由主线程刷新表格。
    """

    progress_signal = pyqtSignal(int, int)        # current, total
    result_signal = pyqtSignal(str, object)       # ip, wmi dict
    finished_signal = pyqtSignal(dict)            # 汇总 {total, ok, fail}

    def __init__(self, targets, creds):
        super().__init__()
        self.targets = list(targets)
        self.creds = creds

    def run(self):
        from scanner import wmi_query
        total = len(self.targets)
        ok = fail = 0
        for i, ip in enumerate(self.targets, 1):
            try:
                d = wmi_query(
                    ip, self.creds.username, self.creds.password,
                    self.creds.domain, timeout=8.0,
                )
            except Exception as e:  # noqa: BLE001
                d = {"wmi_error": f"WMI 查询异常: {e}"}
            self.result_signal.emit(ip, d)
            if d.get("wmi_error"):
                fail += 1
            else:
                ok += 1
            self.progress_signal.emit(i, total)
        self.finished_signal.emit({"total": total, "ok": ok, "fail": fail})


class NetbiosThread(QThread):
    """对一批在线设备执行 NetBIOS 轻量识别（后台线程，避免界面卡顿）。

    逐台 UDP/137 NBSTAT 查询，零凭据、不需管理员；结果逐台回传，由主线程刷新。
    """

    progress_signal = pyqtSignal(int, int)        # current, total
    result_signal = pyqtSignal(str, object)       # ip, netbios dict
    finished_signal = pyqtSignal(dict)            # 汇总 {total, ok, fail}

    def __init__(self, targets, timeout: float = 1.5):
        super().__init__()
        self.targets = list(targets)
        self.timeout = timeout

    def run(self):
        from scanner import netbios_query
        total = len(self.targets)
        ok = fail = 0
        for i, ip in enumerate(self.targets, 1):
            try:
                d = netbios_query(ip, timeout=self.timeout)
            except Exception as e:  # noqa: BLE001
                d = {"netbios_error": f"NetBIOS 查询异常: {e}"}
            self.result_signal.emit(ip, d)
            if d.get("netbios_error"):
                fail += 1
            else:
                ok += 1
            self.progress_signal.emit(i, total)
        self.finished_signal.emit({"total": total, "ok": ok, "fail": fail})


class SwitchMapThread(QThread):
    """后台执行交换机 SNMP 端口映射，避免界面卡顿。"""

    log_signal = pyqtSignal(str)          # 进度文本
    finished_signal = pyqtSignal(object)  # SwitchInfo 对象

    def __init__(self, switch_ip: str, community: str = "public", timeout: float = 1.5):
        super().__init__()
        self.switch_ip = switch_ip
        self.community = community
        self.timeout = timeout

    def run(self):
        from switch_mapper import map_switch_ports
        try:
            info = map_switch_ports(
                self.switch_ip,
                community=self.community,
                timeout=self.timeout,
                progress_cb=lambda msg: self.log_signal.emit(msg),
            )
        except Exception as e:
            from switch_mapper import SwitchInfo
            info = SwitchInfo(ip=self.switch_ip, error=f"映射异常: {e}")
        self.finished_signal.emit(info)
