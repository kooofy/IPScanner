# -*- coding: utf-8 -*-
"""扫描线程：ScanThread（主扫描）与 MdnsThread（mDNS 发现）。"""
import threading

from PyQt5.QtCore import QThread, pyqtSignal

from bounded_pool import run_bounded
from scanner import NetworkScanner, ScanResult
from i18n import tr


class ScanThread(QThread):
    progress = pyqtSignal(int, int, str)   # current, total, current_ip
    result_ready = pyqtSignal(object)       # ScanResult
    finished_signal = pyqtSignal(list)      # all results
    log_signal = pyqtSignal(str)            # log message
    # phase_name（语言无关规范值）, index, total —— 供扫描摘要条显示"现在在干嘛"
    phase_changed = pyqtSignal(str, int, int)

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False,
                 protocols=None, tcp_scan_mode="connect", mdns_discovery=True, ports=None,
                 library=None, snmp_v3_user=None):
        super().__init__()
        self.ip_ranges = ip_ranges
        self.timeout_ms = timeout_ms
        self.max_threads = max_threads
        self.scan_ports = scan_ports
        self.protocols = protocols or []
        self.tcp_scan_mode = tcp_scan_mode
        self.mdns_discovery = mdns_discovery
        self.ports = ports
        self.library = library          # MacLibrary 实例（可选）：地址库自动匹配
        # SnmpV3User 或 None：为 None 时走 v2c 团体字探测（见 scanner.engine._identify_snmp）
        self.snmp_v3_user = snmp_v3_user
        self.scanner = NetworkScanner()

    def _build_library_lookup(self):
        """在本线程内把地址库预加载为内存索引，返回匹配回调（不可用时返回 None）。

        整库只读一次，之后每台设备都是 O(1) 字典查找；全程在扫描线程执行，
        GUI 主线程不再参与任何数据库查询。
        """
        if self.library is None:
            return None
        try:
            from mac_library import MacMatcher
            matcher = MacMatcher.from_library(self.library)
        except Exception as e:      # noqa: BLE001
            self.log_signal.emit(f"地址库载入失败，本次扫描跳过自动匹配: {e}")
            return None
        if matcher is None:
            return None
        self.log_signal.emit(f"地址库已载入 {matcher.size} 条，扫描时自动匹配")
        return matcher.apply_to

    def run(self):
        def on_progress(current, total, ip):
            self.progress.emit(current, total, ip)

        def on_result(result: ScanResult):
            self.result_ready.emit(result)

        def on_phase(name, index, total):
            self.phase_changed.emit(name, index, total)

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
            phase_callback=on_phase,
            library_lookup=self._build_library_lookup(),
            snmp_v3_user=self.snmp_v3_user,
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
            self.log_signal.emit(tr("mDNS 模块不可用"))
            self.finished_signal.emit({})
            return
        self.log_signal.emit(tr("正在做 mDNS 组播发现..."))
        result = mdns_discover(timeout=self.timeout)
        self.log_signal.emit(f"mDNS 发现完成: {len(result)} 个设备")
        self.finished_signal.emit(result)


class WmiThread(QThread):
    """对一批在线 Windows 设备执行 WMI 识别（后台线程，避免界面卡顿）。

    每台设备一次 PowerShell Get-CimInstance 调用；结果逐台回传，由主线程刷新表格。

    并发说明：早期实现是串行 for 循环，N 台设备最坏耗时 N × 单台超时（8s），
    20 台不可达主机要等约 160 秒。现改为有界线程池（默认 4 路并发），
    总耗时约 ceil(N / 4) × 单台耗时；结果仍是「完成一台回传一台」。

    ⚠️ 单台耗时上限取决于传输偏好（见 scanner.wmi）：
    `transport="auto"` 会在 DCOM 快速失败后再试 WinRM，故最坏为 2 × timeout（16s）；
    若首次尝试是"卡住"（耗尽预算）则不会换通路，仍是 1 × timeout。
    想稳定压低耗时可把 `creds.transport` 设为 "dcom" / "winrm" 单通路。

    并发度不宜过高：每次查询都会拉起一个 PowerShell 进程，且目标侧
    CIM/DCOM 连接数有限，4 路是稳妥值。
    """

    WMI_MAX_WORKERS = 4
    WMI_TIMEOUT = 8.0

    progress_signal = pyqtSignal(int, int)        # current, total
    result_signal = pyqtSignal(str, object)       # ip, wmi dict
    finished_signal = pyqtSignal(dict)            # 汇总 {total, requested, ok, fail, cancelled}

    def __init__(self, targets, creds, max_workers=None, timeout=None):
        super().__init__()
        self.targets = list(targets)
        self.creds = creds
        self.max_workers = max_workers or self.WMI_MAX_WORKERS
        self.timeout = timeout or self.WMI_TIMEOUT
        self._cancel = threading.Event()

    def stop(self):
        """请求取消：在跑的查询自然结束，尚未开始的任务直接跳过。"""
        self._cancel.set()

    def run(self):
        from scanner import wmi_query
        total = len(self.targets)
        state = {"ok": 0, "fail": 0, "done": 0}

        def _work(ip):
            return wmi_query(
                ip, self.creds.username, self.creds.password,
                self.creds.domain, timeout=self.timeout,
                transport=getattr(self.creds, "transport", None),
            )

        def _emit(ip, d, exc):
            # 注意：本回调在 run() 所在线程执行，emit 语义与串行版一致
            if exc is not None:
                d = {"wmi_error": f"WMI 查询异常: {exc}"}
            self.result_signal.emit(ip, d)
            if d.get("wmi_error"):
                state["fail"] += 1
            else:
                state["ok"] += 1
            state["done"] += 1
            self.progress_signal.emit(state["done"], total)

        run_bounded(
            self.targets, _work,
            max_workers=self.max_workers,
            on_result=_emit,
            cancel_event=self._cancel,
        )

        cancelled = self._cancel.is_set()
        processed = state["ok"] + state["fail"]
        self.finished_signal.emit({
            "total": processed if cancelled else total,
            "requested": total,
            "ok": state["ok"],
            "fail": state["fail"],
            "cancelled": cancelled,
        })


class NetbiosThread(QThread):
    """对一批在线设备执行 NetBIOS 轻量识别（后台线程，避免界面卡顿）。

    逐台 UDP/137 NBSTAT 查询，零凭据、不需管理员；结果逐台回传，由主线程刷新。

    并发说明：同 WmiThread，早期为串行（单台超时 1.5s，N 台最坏 1.5N 秒）。
    查询本身是轻量 UDP 数据报，无子进程开销，故并发度可以给得更高（默认 16）。
    """

    NETBIOS_MAX_WORKERS = 16
    NETBIOS_TIMEOUT = 1.5

    progress_signal = pyqtSignal(int, int)        # current, total
    result_signal = pyqtSignal(str, object)       # ip, netbios dict
    finished_signal = pyqtSignal(dict)            # 汇总 {total, requested, ok, fail, cancelled}

    def __init__(self, targets, timeout=None, max_workers=None):
        super().__init__()
        self.targets = list(targets)
        self.timeout = timeout or self.NETBIOS_TIMEOUT
        self.max_workers = max_workers or self.NETBIOS_MAX_WORKERS
        self._cancel = threading.Event()

    def stop(self):
        """请求取消：在跑的查询自然结束，尚未开始的任务直接跳过。"""
        self._cancel.set()

    def run(self):
        from scanner import netbios_query
        total = len(self.targets)
        state = {"ok": 0, "fail": 0, "done": 0}

        def _work(ip):
            return netbios_query(ip, timeout=self.timeout)

        def _emit(ip, d, exc):
            if exc is not None:
                d = {"netbios_error": f"NetBIOS 查询异常: {exc}"}
            self.result_signal.emit(ip, d)
            if d.get("netbios_error"):
                state["fail"] += 1
            else:
                state["ok"] += 1
            state["done"] += 1
            self.progress_signal.emit(state["done"], total)

        run_bounded(
            self.targets, _work,
            max_workers=self.max_workers,
            on_result=_emit,
            cancel_event=self._cancel,
        )

        cancelled = self._cancel.is_set()
        processed = state["ok"] + state["fail"]
        self.finished_signal.emit({
            "total": processed if cancelled else total,
            "requested": total,
            "ok": state["ok"],
            "fail": state["fail"],
            "cancelled": cancelled,
        })


class SwitchMapThread(QThread):
    """后台执行交换机 SNMP 端口映射，避免界面卡顿。"""

    log_signal = pyqtSignal(str)          # 进度文本
    finished_signal = pyqtSignal(object)  # SwitchInfo 对象

    def __init__(self, switch_ip: str, community: str = "public", timeout: float = 1.5,
                 snmp_v3_user=None):
        super().__init__()
        self.switch_ip = switch_ip
        self.community = community
        self.timeout = timeout
        # SnmpV3User 或 None：传入时改用 v3 遍历转发表，community 被忽略
        self.snmp_v3_user = snmp_v3_user

    def run(self):
        from switch_mapper import map_switch_ports
        try:
            info = map_switch_ports(
                self.switch_ip,
                community=self.community,
                timeout=self.timeout,
                progress_cb=lambda msg: self.log_signal.emit(msg),
                snmp_v3_user=self.snmp_v3_user,
            )
        except Exception as e:
            from switch_mapper import SwitchInfo
            info = SwitchInfo(ip=self.switch_ip, error=f"映射异常: {e}")
        self.finished_signal.emit(info)


class OuiUpdateThread(QThread):
    """OUI 数据库在线更新线程。"""
    log_signal = pyqtSignal(str)           # 进度消息
    progress_signal = pyqtSignal(int)      # 百分比 0-100
    finished_signal = pyqtSignal(object)   # dict: {success, count, path, error}

    def run(self):
        from oui_updater import update_oui_db

        def _progress(stage: str, percent: int, message: str):
            self.log_signal.emit(message)
            self.progress_signal.emit(percent)

        result = update_oui_db(progress_callback=_progress)
        self.finished_signal.emit(result)
