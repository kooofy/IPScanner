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
                 protocols=None, tcp_scan_mode="connect", mdns_discovery=True):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.protocols = protocols or []
        self.tcp_scan_mode = tcp_scan_mode
        self.mdns_discovery = mdns_discovery
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
            progress_callback=on_progress,
            result_callback=on_result,
        )

        online = sum(1 for r in results if r.status == "online")
        self.log_signal.emit(f"扫描完成: 共 {len(results)} 个IP, {online} 个在线")
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
