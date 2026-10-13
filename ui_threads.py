# -*- coding: utf-8 -*-
"""后台线程集合：把一切会阻塞界面的活儿挪出主线程。

扫描（`ScanThread`）、mDNS（`MdnsThread`）、WMI / NetBIOS 识别、
交换机转发表（`SwitchMapThread`）、OUI 库更新、历史查询与快照对比、
被动发现（`PassiveWatchThread`）—— 共同点只有一个：
**它们在主线程跑就会冻界面**，所以一律 QThread。
"""
import threading

from PyQt5.QtCore import QThread, pyqtSignal

from bounded_pool import run_bounded
from scanner import NetworkScanner, ScanResult, throttle
from app_logging import get_logger
from i18n import tr
import history_store

_log = get_logger(__name__)


class ScanThread(QThread):
    progress = pyqtSignal(int, int, str)   # current, total, current_ip
    result_ready = pyqtSignal(object)       # ScanResult
    finished_signal = pyqtSignal(list)      # all results
    log_signal = pyqtSignal(str)            # log message
    # phase_name（语言无关规范值）, index, total —— 供扫描摘要条显示"现在在干嘛"
    phase_changed = pyqtSignal(str, int, int)

    def __init__(self, ip_ranges, timeout_ms=1000, max_threads=100, scan_ports=False,
                 protocols=None, tcp_scan_mode="connect", mdns_discovery=True, ports=None,
                 library=None, snmp_v3_user=None, switch_map=False, name_responder=False,
                 throttle_policy=None):
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
        # 扫描末尾是否读取交换机转发表（供「定位查询」落库）。**默认关**：
        # 每台交换机 5 次 SNMP walk，且会在网络里产生额外 SNMP 流量，必须用户显式开启。
        self.switch_map = switch_map
        #: 采集到的各交换机端口映射（`history_store.save_port_map()` 能吃的 dict 列表）。
        #: 由 `run()` 在**本线程内**填充，主线程保存快照时取走落库 ——
        #: 绝不能在主线程做，那是 5×交换机数 次 SNMP 往返，会把界面冻住。
        self.switch_maps = []
        # 扫描末尾是否探测 LLMNR / NBNS 响应器（见 scanner/llmnr_nbns.py）。
        # **默认关**：与「读取交换机转发表」不同，它会往网络里**发组播/广播包**，
        # 必须用户显式开启。红线：只发一个查询包，不应答、不注册名字、不投毒。
        self.name_responder = name_responder
        # 扫描礼貌档（v2.1 §2.4 的 GUI 露出）：`throttle.POLICY_NAMES` 里的
        # 规范名，`None` = 不显式设档（解析成当前进程档）。GUI 设置菜单落的值
        # 经 MainWindow 透传到这里；不传则与改造前逐字节等价。
        self.throttle_policy = throttle_policy
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
        # 礼貌模式（v2.1 §2.4 GUI 露出）：整条扫描流水线跑在用户所选档位下。
        # 🔴 装在**本线程内**而不是主线程：`active_policy()` 装的是进程级状态，
        # 在主线程装的话 `with` 块根本找不到退出点，这份限速会漏到后续所有扫描
        # （"悄悄把工具变慢"）；装在扫描线程里，扫描一结束就恢复上一层档。
        # 装在 `scan()` 之前也必不可少：`prepare_targets()` /
        # `concurrency_for()` / `throttle_gate()` 都是在扫描过程中读当前档。
        with throttle.active_policy(throttle.resolve_policy(self.throttle_policy)):
            self._run_scan()

    def _run_scan(self):
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

        if self.switch_map and results:
            self.switch_maps = self._collect_switch_maps(results)

        # 名字响应器探测必须赶在 `finished_signal` **之前**：结果直接挂在
        # results 上，主线程收到信号后会立刻存快照（`_save_snapshot`），
        # 那时再补就来不及了。
        if self.name_responder and results:
            self._collect_responders(results)

        self.finished_signal.emit(results)

    def _collect_switch_maps(self, results):
        """在本线程内读取各交换机转发表（供「定位查询」落库）。

        只做采集，**不落库** —— 落库要等快照存好、拿到 snapshot_id 之后
        （见 `HistoryMixin._save_snapshot`）。采集失败不该让整次扫描白跑，
        但必须留痕，不能静默吞掉。
        """
        def on_progress(phase, current, total, message):
            self.phase_changed.emit(phase, current, total)
            if message:
                self.log_signal.emit(message)

        try:
            from topology_discovery import collect_switch_port_maps
            maps = collect_switch_port_maps(
                results, snmp_v3_user=self.snmp_v3_user,
                progress_callback=on_progress,
            )
        except Exception as e:      # noqa: BLE001
            _log.warning("读取交换机转发表失败: %s", e, exc_info=True)
            self.log_signal.emit(tr("读取交换机转发表失败: {err}").format(err=e))
            return []
        self.log_signal.emit(
            tr("转发表读取完成: {n} 台交换机").format(n=len(maps)))
        return maps

    def _collect_responders(self, results):
        """在本线程内探测 LLMNR / NBNS 响应器，把结果挂到 results 上。

        只探测、**不落库** —— 结果写进 `ScanResult.name_responder`，
        快照保存时经 `ui_logic.build_snapshot()` 落进 `security_findings`
        （与交换机转发表"采集与落库分开"是同一个理由）。

        红线（见 `scanner/llmnr_nbns.py`）：只发一个查询包，**不应答别人的
        查询、不注册名字、不伪造 MAC/IP、绝不投毒**。
        """
        self.phase_changed.emit("name_responder", 0, 1)
        try:
            from scanner.llmnr_nbns import apply_responders, probe_responders
            found = probe_responders()
        except Exception as e:      # noqa: BLE001
            # 探测失败只影响"有没有欺骗响应器"这一条结论，不该让整次扫描白跑；
            # 但它属于用户能感知的结果缺失，必须留痕。
            _log.warning("名字响应器探测失败: %s", e, exc_info=True)
            self.log_signal.emit(tr("名字响应器探测失败: {err}").format(err=e))
            self.phase_changed.emit("name_responder", 1, 1)
            return
        self.phase_changed.emit("name_responder", 1, 1)

        outside = apply_responders(results, found)
        inside = len(found) - len(outside)
        if not found:
            self.log_signal.emit(tr("未发现名字响应器"))
        else:
            self.log_signal.emit(
                tr("发现 {n} 个名字响应器").format(n=len(found)))
        if outside:
            # 不在本次扫描范围内的响应器**不伪造设备行**（快照记的是台账，
            # 塞一台没扫到的设备会让设备数失真），只写日志让人知道有这回事。
            _log.info("名字响应器不在本次扫描范围内（未计入快照）: %s",
                      ", ".join(outside))
            self.log_signal.emit(
                tr("其中 {n} 个不在本次扫描范围内，只记日志、不计入快照").format(
                    n=len(outside)))
        _log.debug("名字响应器探测：范围内 %d 个，范围外 %d 个", inside, len(outside))

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


class HistoryQueryThread(QThread):
    """历史条件查询：把 `history_store.query_history()` 挪到后台线程执行。

    **为什么需要它（实测）**：`query_history()` 会把**所有快照的所有设备行**取回来、
    在 Python 侧聚合成"每台设备一条"。默认保留 20 份快照、/16 网段下这是约 130 万行，
    耗时到秒级。此前它同步跑在 GUI 线程上，用户点「查询」界面会整段冻结 ——
    连"取消"都点不动，因为处理点击的也是那条被占住的线程。

    **取消**：`stop()` 置位后，`query_history` 在**分块取数的间隙**抛 `QueryCancelled`，
    所以取消能真正中断读盘，而不是等整张表读完再把结果丢掉。
    """

    finished_signal = pyqtSignal(list)   # 结果行
    failed = pyqtSignal(str)             # 查询失败原因
    cancelled_signal = pyqtSignal()      # 被 stop() 取消

    def __init__(self, filters, db_path=None, limit=None, offset=0):
        super().__init__()
        self.filters = dict(filters or {})
        self.db_path = db_path
        self.limit = limit
        self.offset = offset
        self._cancel = threading.Event()

    def stop(self):
        """请求取消（线程安全，可从 GUI 线程调用）。"""
        self._cancel.set()

    def run(self):
        try:
            rows = history_store.query_history(
                db_path=self.db_path, limit=self.limit, offset=self.offset,
                cancel_event=self._cancel, **self.filters)
        except history_store.QueryCancelled:
            self.cancelled_signal.emit()
            return
        except Exception as e:      # noqa: BLE001
            self.failed.emit(str(e))
            return
        if self._cancel.is_set():
            # 取消恰好在查询跑完的瞬间置位：按"已取消"处理，别把结果当成用户要的。
            self.cancelled_signal.emit()
            return
        self.finished_signal.emit(rows)


class SnapshotCompareThread(QThread):
    """读取两份快照并做差异对比（后台线程）。

    对比对话框此前在 `__init__` 里调 `load_all()` —— 把**全部**快照的设备明细都读
    进来，只为填两个下拉框和算一次 diff。默认 20 份快照、/16 网段下是百万行级读盘，
    打开对话框即卡住。现在下拉框只用 `list_snapshots()`（每份一行元信息），
    真正需要的两份快照到后台线程里按需读取。
    """

    finished_signal = pyqtSignal(list, float, float)   # diffs, base_time, target_time
    failed = pyqtSignal(str)

    def __init__(self, base_id, target_id, db_path=None):
        super().__init__()
        self.base_id = base_id
        self.target_id = target_id
        self.db_path = db_path

    def run(self):
        try:
            base = history_store.get_snapshot(self.base_id, self.db_path)
            target = history_store.get_snapshot(self.target_id, self.db_path)
            if not base or not target:
                self.failed.emit("快照不存在或已被保留上限裁剪")
                return
            from ui_utils import _compare_snapshots
            diffs = _compare_snapshots(base, target)
        except Exception as e:      # noqa: BLE001
            self.failed.emit(str(e))
            return
        self.finished_signal.emit(diffs, base["time"], target["time"])


class PassiveWatchThread(QThread):
    """一轮被动发现（后台线程）。

    **必须在后台线程跑**：mDNS 只听模式要占住 5353 听满 `mdns_timeout`，
    放主线程就是界面卡住那么久 —— 与扫描末尾的 mDNS 阶段同一个道理。

    线程**持有**调用方传进来的 `PassiveWatcher`（而不是每轮新建）：
    台账与「已知设备」集合要跨轮累积，否则每轮都会把整张 ARP 表重报成新设备。
    调用方在轮询期间不碰这个 watcher（靠 in-flight 判断保证），所以没有竞争。
    """

    finished_signal = pyqtSignal(list, list)   # 台账全部设备, 本次新出现
    log_signal = pyqtSignal(str)

    def __init__(self, watcher, mdns=True, mdns_active=False,
                 mdns_timeout=1.5):
        super().__init__()
        self.watcher = watcher
        self.mdns = mdns
        self.mdns_active = mdns_active
        self.mdns_timeout = mdns_timeout

    def run(self):
        try:
            ledger, fresh = self.watcher.poll(mdns=self.mdns,
                                              mdns_active=self.mdns_active,
                                              mdns_timeout=self.mdns_timeout)
        except Exception as e:  # noqa: BLE001
            # 被动发现失败只影响这一轮（网卡切换/权限不足都可能），
            # 不该把界面拖下水；留日志便于排查。
            _log.warning("被动发现失败: %s", e, exc_info=True)
            self.log_signal.emit(tr("被动发现失败: {err}").format(err=e))
            self.finished_signal.emit([], [])
            return
        self.finished_signal.emit(list(ledger), list(fresh))
