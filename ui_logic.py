# -*- coding: utf-8 -*-
"""从 MainWindow 提取的纯业务逻辑（无 PyQt5 / i18n 依赖，便于单元测试）。

这些函数原本内联在 main_window.py 的业务编排方法里，与 UI 控件耦合，
无法在无 PyQt5 环境下测试。提取到本模块后可独立覆盖业务规则：
- 子网/虚拟网卡判定
- WMI/NetBIOS 识别目标筛选
- 扫描结果状态统计
- 识别完成消息构造
- 冲突分级计数
- 历史快照构建
"""
import ipaddress
import time

from conflict_detector import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_WARNING
from change_detector import CHANGE_DEVICE_GONE
from scanner.constants import device_class_label


def ip_mask_to_subnet(ip: str, mask: str):
    """由 IPv4 与子网掩码计算网段地址与前缀长度，失败返回 (None, 0)。"""
    try:
        ip_parts = list(map(int, ip.split(".")))
        mask_parts = list(map(int, mask.split(".")))
        net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        prefix = sum(bin(m).count("1") for m in mask_parts)
        return ".".join(net_parts), prefix
    except Exception:
        return None, 0


def is_virtual_adapter_ip(ip: str) -> bool:
    """粗略判断是否为虚拟/容器网卡使用的私有网段（VirtualBox/Docker/链路本地等）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 169 and b == 254:                          # 169.254.0.0/16 链路本地(APIPA)
        return True
    if a == 172 and 16 <= b <= 31:                     # 172.16.0.0/12 Docker 默认桥
        return True
    if a == 192 and b == 168 and int(parts[2]) == 56:  # 192.168.56.0/24 VirtualBox Host-Only
        return True
    return False


def select_identification_targets(results, explicit_targets=None, windows_label="Windows"):
    """从扫描结果筛选需要 WMI/NetBIOS 识别的目标 IP 列表。

    - explicit_targets=None：自动筛选在线且疑似 Windows 的设备
      （os_guess == windows_label 或开放 135/445 端口）
    - explicit_targets=[ip,...]：只保留其中在线的 IP

    返回目标 IP 列表（可能为空）。调用方据原 explicit_targets 是否为 None 决定空时的提示文案。
    """
    online_ips = {r.ip for r in results if r.status == "online"}
    if explicit_targets is None:
        return [
            r.ip for r in results
            if r.status == "online" and (
                r.os_guess == windows_label
                or 135 in r.open_ports
                or 445 in r.open_ports
            )
        ]
    return [t for t in explicit_targets if t in online_ips]


def count_scan_status(results) -> dict:
    """统计扫描结果的在线/离线/未知数量。"""
    total = len(results)
    online = sum(1 for r in results if r.status == "online")
    offline = sum(1 for r in results if r.status == "offline")
    return {"total": total, "online": online, "offline": offline, "unknown": total - online - offline}


def format_elapsed(seconds) -> str:
    """把秒数格式化成 `mm:ss`（满 1 小时则 `h:mm:ss`）。

    负值/非数值一律按 0 处理 —— 计时起点由 `time.perf_counter()` 给出，正常
    不会倒退，但显示层不该因为一个异常值抛异常把整条扫描流程带崩。
    """
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        total = 0
    if total < 0:
        total = 0
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def format_identify_summary(kind: str, ok: int, fail: int, total: int, fail_reason: str = "") -> str:
    """构造 WMI/NetBIOS 识别完成消息。

    kind: "WMI" / "NetBIOS"；fail_reason: 有失败时括号内原因说明。
    """
    msg = f"{kind} 识别完成：{total} 台，成功 {ok} 台"
    if fail:
        msg += f"，失败 {fail} 台（{fail_reason}）"
    return msg


def count_conflicts(conflicts) -> dict:
    """按严重级别统计冲突数量。"""
    return {
        "high": sum(1 for c in conflicts if c.severity == SEVERITY_HIGH),
        "warning": sum(1 for c in conflicts if c.severity == SEVERITY_WARNING),
        "info": sum(1 for c in conflicts if c.severity == SEVERITY_INFO),
    }


def build_change_index(changes, results) -> dict:
    """把变更列表折叠成 `{ip: [变更类型, ...]}`，供行内角标与「变更」筛选。

    为什么按 **IP** 归并：角标是"贴在某一行上"的，而结果表格的行按 IP 组织；
    `Change` 虽然也带 mac，但 mac 只用于匹配、无法定位行。

    「设备消失」需要额外把关：那台设备本次不在结果里，**没有对应的行**。
    若直接按它的旧 IP 归并，而该 IP 已被另一台设备占用，角标就会错贴到那台
    新设备上（"这台明明在线，为什么标了消失？"）。因此只在"当前占用该 IP 的
    MAC 与变更记录的 MAC 一致、或无从判断"时才保留 —— 这样设备掉线（行还在，
    只是离线）时仍能正确标出，而 IP 被顶替时不会误标。

    Args:
        changes: `change_detector.Change` 列表。
        results: 当前扫描结果（`ScanResult` 列表，含离线项）。

    Returns:
        {ip: [规范变更类型, ...]}，同一 IP 的类型去重且保持首次出现顺序。
    """
    occupied = {}
    for r in results or []:
        ip = getattr(r, "ip", "")
        if ip:
            occupied[ip] = (getattr(r, "mac", "") or "").upper().strip()

    idx = {}
    for c in changes or []:
        ip = getattr(c, "ip", "")
        if not ip:
            continue
        if getattr(c, "change_type", "") == CHANGE_DEVICE_GONE:
            cur_mac = occupied.get(ip, "")
            _mac = (getattr(c, "mac", "") or "").upper().strip()
            if cur_mac and _mac and cur_mac != _mac:
                continue
        types = idx.setdefault(ip, [])
        ctype = getattr(c, "change_type", "")
        if ctype not in types:
            types.append(ctype)
    return idx


def build_snapshot(results, ts=None) -> dict:
    """把 ScanResult 列表转成历史快照 dict（与 history_store 存储结构一致）。"""
    if ts is None:
        ts = time.time()
    devices = []
    for r in results:
        devices.append({
            "ip": r.ip,
            "status": r.status,
            "mac": (r.mac or "").upper(),
            "hostname": r.hostname or "",
            "vendor": r.vendor or "",
            "device_class": r.device_class or "",
            "os_guess": r.os_guess or "",
            "open_ports": ",".join(str(p) for p in (r.open_ports or [])),
            "location": r.location or "",
            "user": r.user or "",
            "remark": r.remark or "",
            "wmi_identified": r.wmi_identified,
            "wmi_manufacturer": r.wmi_manufacturer or "",
            "wmi_model": r.wmi_model or "",
            "wmi_serial": r.wmi_serial or "",
            "wmi_os": r.wmi_os or "",
            "wmi_user": r.wmi_user or "",
            "wmi_domain": r.wmi_domain or "",
            "netbios_identified": r.netbios_identified,
            "netbios_name": r.netbios_name or "",
            "netbios_workgroup": r.netbios_workgroup or "",
            "netbios_user": r.netbios_user or "",
            "netbios_mac": r.netbios_mac or "",
        })
    return {"time": ts, "devices": devices}


#: 概览页各列表默认展示的条目数。
#: 概览的价值在"一眼看懂"，把 200 个厂商全列出来就又变回了明细表。
OVERVIEW_TOP_N = 5


def build_subnet_stats(results) -> list:
    """按 /24 聚合扫描结果，返回子网统计列表（按利用率降序）。

    从 `SubnetUtilizationDialog._analyze` 提取而来 —— 概览页也要这份数据，
    放在这里两处共用，避免"对话框算一套、概览算另一套"慢慢跑偏。

    注意：`device_dist` 里的设备类型是**显示用文案**（已经过
    `device_class_label`），因为它的唯一用途就是展示 —— 它已被预拼成
    `"电脑×3, 打印机×1"` 这样的整串，展示层没法再逐项翻译。
    这与 `build_overview` 的 `device_classes`（保留规范值）刻意不同：
    后者返回的是可逐项翻译的结构化对，翻译就该推迟到渲染时。
    """
    groups: dict = {}
    for r in results:
        try:
            # ip_network 本身就会对非法 IP 抛 ValueError，无需先做一次
            # ip_address 校验
            key = str(ipaddress.ip_network(f"{r.ip}/24", strict=False))
        except ValueError:
            continue
        g = groups.setdefault(key, {
            "ips": set(), "online": 0, "offline": 0, "devices": {}
        })
        g["ips"].add(r.ip)
        if r.status == "online":
            g["online"] += 1
            dtype = (device_class_label(getattr(r, "device_class", ""))
                     or getattr(r, "device_type", "") or "")
            g["devices"][dtype] = g["devices"].get(dtype, 0) + 1
        else:
            g["offline"] += 1

    subnets = []
    for subnet_str, g in groups.items():
        total = len(g["ips"])
        online = g["online"]
        pct = (online / total * 100) if total else 0
        dev_parts = [f"{k}×{v}" for k, v in
                     sorted(g["devices"].items(), key=lambda x: -x[1])]
        subnets.append({
            "subnet": subnet_str,
            "total": total,
            "online": online,
            "offline": g["offline"],
            "utilization": pct,
            "device_dist": ", ".join(dev_parts) if dev_parts else "",
        })
    subnets.sort(key=lambda s: -s["utilization"])
    return subnets


def _top_counter(counter: dict, top_n: int) -> list:
    """把 {名字: 次数} 排成 [(名字, 次数), ...]，按次数降序、同次数按名字稳定排序。"""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]


def build_overview(results, changes=None, conflicts=None,
                   top_n: int = OVERVIEW_TOP_N) -> dict:
    """汇总概览页需要的全部指标（纯函数，可脱离 Qt 单测）。

    对应 UI_REVIEW.md 的 P3-2：把原先只活在 `SubnetUtilizationDialog` 里的
    统计提升为常驻概览。**这里只算数据、不拼文案** —— 文案由 `overview.py`
    渲染时 `tr()`，否则英文界面会拿到一堆中文串。

    注意 `device_classes` 返回的是**规范值**（如「电脑」），不是显示名：
    与 `build_subnet_stats` 的 `device_dist` 不同（见其 docstring 说明为何
    那边必须提前翻译）。

    Returns:
        {
          "total"/"online"/"offline"/"unknown": int,
          "online_ratio": float,           # 0–100，无数据时为 0.0
          "services": int,                 # 有开放端口的**在线**设备数
          "ports": int,                    # 开放端口总数（同上，仅在线）
          "changes": {类型: 数量},          # 只含出现过的类型
          "conflicts": {"high"/"warning"/"info": int},
          "vendors": [(厂商, 台数), ...],    # 降序，最多 top_n 条
          "device_classes": [(规范类别, 台数), ...],
          "subnets": [...],                # 见 build_subnet_stats，最多 top_n 条
          "vendor_kinds": int,             # 去重后的厂商数（列表只显示前几条）
          "class_kinds": int,
        }
    """
    results = results or []
    status = count_scan_status(results)
    total = status["total"]
    online = status["online"]

    vendors: dict = {}
    classes: dict = {}
    services = 0
    ports = 0
    for r in results:
        if r.status != "online":
            continue
        vendor = (getattr(r, "vendor", "") or "").strip()
        if vendor:
            vendors[vendor] = vendors.get(vendor, 0) + 1
        # 保留规范值（不做 device_class_label）—— 展示层才翻译
        dtype = (getattr(r, "device_class", "")
                 or getattr(r, "device_type", "") or "").strip()
        if dtype:
            classes[dtype] = classes.get(dtype, 0) + 1
        _open = list(getattr(r, "open_ports", None) or [])
        if _open:
            services += 1
            ports += len(_open)

    change_counts: dict = {}
    for c in (changes or []):
        ctype = getattr(c, "change_type", "")
        if ctype:
            change_counts[ctype] = change_counts.get(ctype, 0) + 1

    return {
        "total": total,
        "online": online,
        "offline": status["offline"],
        "unknown": status["unknown"],
        "online_ratio": (online / total * 100) if total else 0.0,
        "services": services,
        "ports": ports,
        "changes": change_counts,
        "conflicts": count_conflicts(conflicts or []),
        "vendors": _top_counter(vendors, top_n),
        "device_classes": _top_counter(classes, top_n),
        "subnets": build_subnet_stats(results)[:top_n],
        "vendor_kinds": len(vendors),
        "class_kinds": len(classes),
    }