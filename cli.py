# -*- coding: utf-8 -*-
"""IPScanner 无头命令行接口（P0-5）。

设计目标
--------
1. **零 GUI 依赖**：不 import PyQt5，可在 Windows Server Core / Linux / 容器中运行。
2. **复用同一套引擎**：直接调用 ``scanner.NetworkScanner``、``change_detector``、
   ``history_store``、``mac_library``，因此 CLI 与 GUI 的扫描行为、地址库匹配、
   快照格式完全一致，不存在"两套实现漂移"的问题。
3. **面向自动化**：稳定的英文 JSON 字段名（不受界面语言影响）、语义化退出码、
   ``--quiet`` 静默模式、``diff --fail-on-change`` 可直接用于计划任务告警。

退出码
------
    0   成功
    1   运行错误（参数非法 / 范围超限 / 无有效结果且指定了 --fail-if-empty）
    2   diff 检测到资产变更且指定了 --fail-on-change（便于 cron/任务计划告警）
    3   环境错误（数据目录不可写等）

用法示例
--------
    python cli.py scan -r 192.168.1.0/24 --level quick
    python cli.py scan -r 10.0.0.0/24 --protocols HTTP,HTTPS,SNMP --format json -o out.json
    python cli.py scan -r 192.168.1.0/24 --save-snapshot --note "周一巡检"
    python cli.py diff -r 192.168.1.0/24 --fail-on-change
    python cli.py diff --from 3 --to 4
    python cli.py history --list
    python cli.py history --query --device-class 打印机 --format csv

SNMPv3（USM）
-------------
口令**只从环境变量读取**，不接受命令行参数 —— argv 会出现在进程列表
（``ps`` / 任务管理器）里，等于把凭据广播给同机所有用户。

    export IPSCANNER_SNMPV3_AUTH_KEY='认证口令'
    export IPSCANNER_SNMPV3_PRIV_KEY='加密口令'
    python cli.py scan -r 192.168.1.0/24 --snmpv3-user monitor \
        --snmpv3-auth sha --snmpv3-priv aes

环境变量名可用 ``--snmpv3-auth-env`` / ``--snmpv3-priv-env`` 改名，
便于在同一台机器上为不同目标准备不同凭据。
指定 ``--snmpv3-user`` 会**自动启用** SNMP 协议识别，无需再写 ``--protocols SNMP``。
"""
import argparse
import csv
import io
import json
import os
import sys
import time
import unicodedata

# 版本号唯一来源：version.py。不要在这里写死字面量，
# 否则与 GUI 关于对话框、spec 产物名会各说各话。
from version import __version__

# 退出码
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CHANGES = 2
EXIT_ENV = 3
#: `locate` 专用：查询执行成功，但**没定位到**（设备未知 / 未采集过转发表 …）。
#: 与 `EXIT_ERROR` 分开：那不是"命令出错"，是一个合法结论，脚本要能区分。
EXIT_NOT_FOUND = 4

# ── 输出字段（英文，语言无关） ──
_RESULT_COLUMNS = (
    "ip", "status", "hostname", "mac", "vendor", "response_time_ms",
    "open_ports", "services", "device_class", "device_model", "os",
    "location", "user", "remark", "discovery_method", "scan_method",
    "shares", "matched",
)

_SNAPSHOT_COLUMNS = (
    "id", "time", "time_str", "device_count", "note",
)

_HISTORY_COLUMNS = (
    "ip", "status", "mac", "hostname", "vendor", "device_class",
    "open_ports", "location", "user", "remark", "first_seen", "last_seen",
)

# 单条快照的设备清单：没有首见/末见时间，故用独立的列集合
_SNAPSHOT_DEVICE_COLUMNS = (
    "ip", "status", "mac", "hostname", "vendor", "device_class",
    "os_guess", "open_ports", "location", "user", "remark",
)


# ────────────────────────────── 输出工具 ──────────────────────────────

def _force_utf8_stdio():
    """把 stdout / stderr 切到 UTF-8。

    **为什么必须做**：Windows 上 stdout 被重定向到管道或文件时
    （CI、``> out.json``、``| jq``），Python 用**系统 ANSI 代码页**编码
    （英文系统是 cp1252），而 stdout 的默认错误处理器是 ``strict`` ——
    只要输出里有中文（设备名、device_class、表格、JSON 值），
    就会直接抛 ``UnicodeEncodeError`` 并以退出码 1 结束。
    本项目面向中文设备名，CLI 的定位又是"给脚本消费"，所以这是必踩的坑。

    stderr 默认是 ``backslashreplace``，不会崩，但中文会变成
    ``\\u51c6\\u5907...`` 这种转义垃圾，CI 日志基本没法看；
    一并切到 UTF-8 才有可读输出。

    **为什么是 reconfigure 而不是改 errors**：只放宽 errors 只是把中文
    变成 ``?``，仍然是坏数据；切编码才能保住内容。UTF-8 能编码任何
    合法字符，``errors="replace"`` 仅作为兜底（应对文件名解码产生的
    孤立代理项），保证"永不因输出而崩溃"。

    真正连着控制台时 Python 本就走 UTF-8（Windows 下经 WriteConsoleW），
    reconfigure 是幂等的；被替换成 StringIO（单测的 redirect_stdout）
    时没有 reconfigure 方法，静默跳过即可。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # StringIO 等测试替身没有 reconfigure；已关闭或不支持改编码的流
            # 也只能作罢 —— 都不影响后续写入。
            continue


def _disp_width(text: str) -> int:
    """字符串的终端显示宽度（CJK 全角按 2 计）。"""
    w = 0
    for ch in text:
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _pad(text: str, width: int) -> str:
    """按显示宽度左侧对齐补空格。"""
    return text + " " * max(0, width - _disp_width(text))


def _truncate(text: str, limit: int) -> str:
    """按显示宽度截断并加省略号。"""
    if _disp_width(text) <= limit:
        return text
    out, w = "", 0
    for ch in text:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if w + cw > limit - 1:
            break
        out += ch
        w += cw
    return out + "…"


def _cell(value, limit: int = 40) -> str:
    """把任意字段值渲染为单行单元格文本。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        text = ", ".join(str(v) for v in value)
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, float):
        text = f"{value:g}"
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    return _truncate(text, limit)


def render_table(records, columns, headers=None) -> str:
    """渲染为等宽文本表格。"""
    if not records:
        return "(empty)"
    headers = list(headers or columns)
    rows = [[_cell(r.get(c)) for c in columns] for r in records]
    widths = []
    for i, h in enumerate(headers):
        w = _disp_width(h)
        for row in rows:
            w = max(w, _disp_width(row[i]))
        widths.append(min(w, 40))

    def _line(cells):
        return "  ".join(_pad(c, widths[i]) for i, c in enumerate(cells)).rstrip()

    out = [_line(headers), "  ".join("-" * w for w in widths)]
    out.extend(_line(r) for r in rows)
    return "\n".join(out)


def render_csv(records, columns) -> str:
    """渲染为 CSV（UTF-8 BOM，Excel 直接双击不乱码）。"""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(list(columns))
    for r in records:
        row = []
        for c in columns:
            v = r.get(c, "")
            if isinstance(v, (list, tuple)):
                v = ";".join(str(x) for x in v)
            elif isinstance(v, bool):
                v = "yes" if v else "no"
            row.append(v if v is not None else "")
        writer.writerow(row)
    return "\ufeff" + buf.getvalue()


def render_json(payload) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def emit(text: str, output: str = None):
    """输出到文件或 stdout。写文件时使用 UTF-8 无 BOM（CSV 除外，其自带 BOM）。"""
    if output:
        enc = "utf-8-sig" if output.lower().endswith(".csv") else "utf-8"
        with open(output, "w", encoding=enc, newline="") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
        log(f"已写入 {output}")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def log(msg: str):
    """诊断信息一律走 stderr，保证 stdout 只承载结果数据（便于管道）。"""
    sys.stderr.write(msg + "\n")


def warn(msg: str):
    sys.stderr.write("警告: " + msg + "\n")


# ────────────────────────────── 记录转换 ──────────────────────────────

def result_to_record(r) -> dict:
    """把 ScanResult 转成语言无关的英文键字典。"""
    os_label = " ".join(x for x in (getattr(r, "os_guess", ""),
                                    getattr(r, "os_detail", "")) if x).strip()
    return {
        "ip": r.ip,
        "status": r.status,
        "hostname": r.hostname or "",
        "mac": r.mac or "",
        "vendor": r.vendor or "",
        "response_time_ms": round(r.response_time, 1) if r.response_time else 0.0,
        "open_ports": list(r.open_ports or []),
        "services": list(r.services or []),
        "device_class": getattr(r, "device_class", "") or getattr(r, "device_type", ""),
        "device_model": getattr(r, "device_model", ""),
        "os": os_label,
        "location": r.location or "",
        "user": r.user or "",
        "remark": r.remark or "",
        "discovery_method": getattr(r, "discovery_method", "") or (
            "ping" if r.status == "online" else ""
        ),
        "scan_method": getattr(r, "scan_method", ""),
        "shares": list(getattr(r, "shares", []) or []),
        "matched": bool(getattr(r, "excel_matched", False)),
    }


def _snapshot_devices(results) -> list:
    """构造 history_store.save_snapshot 所需的设备字典列表。

    探到 TLS 证书的设备会多带一个 `security_findings` 键（见
    `history_store.tls_cert_facts`）—— 与 GUI 走的是同一条落库路径，
    免得"命令行存的快照没有安全事实"。
    """
    from history_store import tls_cert_facts

    out = []
    for r in results:
        dev = {
            "ip": r.ip,
            "status": r.status,
            "mac": r.mac or "",
            "hostname": r.hostname or "",
            "vendor": r.vendor or "",
            "device_class": getattr(r, "device_class", "") or getattr(r, "device_type", ""),
            "os_guess": getattr(r, "os_guess", ""),
            "open_ports": ", ".join(str(p) for p in (r.open_ports or [])),
            "location": r.location or "",
            "user": r.user or "",
            "remark": r.remark or "",
        }
        facts = tls_cert_facts(getattr(r, "tls_cert", None))
        if facts:
            dev["security_findings"] = facts
        out.append(dev)
    return out


class _SnapResult:
    """把快照里的设备字典适配成 detect_changes 需要的对象接口。"""
    __slots__ = ("ip", "status", "mac", "hostname")

    def __init__(self, d: dict):
        self.ip = d.get("ip", "") or ""
        self.status = d.get("status", "") or ""
        self.mac = d.get("mac", "") or ""
        self.hostname = d.get("hostname", "") or ""


# ────────────────────────────── 扫描参数解析 ──────────────────────────────

def _resolve_ports(args):
    """返回端口列表；None 表示不做端口扫描。"""
    if getattr(args, "no_ports", False):
        return None
    raw = getattr(args, "ports", None)
    if raw:
        ports = []
        for part in str(raw).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"端口号非法: {part!r}")
            if not (0 < p < 65536):
                raise ValueError(f"端口号越界（应为 1-65535）: {p}")
            ports.append(p)
        if not ports:
            raise ValueError("--ports 未解析出任何有效端口")
        return sorted(set(ports))
    from scanner.constants import get_ports_for_level
    return list(get_ports_for_level(getattr(args, "level", "quick")))


def _resolve_protocols(args):
    raw = getattr(args, "protocols", "") or ""
    return [p.strip().upper() for p in raw.split(",") if p.strip()] or None


def _build_library_lookup(enabled: bool):
    """构建地址库内存索引回调；未启用或库为空时返回 None。"""
    if not enabled:
        return None
    try:
        from mac_library import MacMatcher, MacLibrary
        matcher = MacMatcher.from_library(MacLibrary())
    except Exception as e:  # noqa: BLE001
        warn(f"地址库载入失败，本次扫描跳过自动匹配: {e}")
        return None
    if matcher is None:
        log("地址库为空，本次扫描跳过自动匹配")
        return None
    log(f"地址库已载入 {matcher.size} 条，扫描时自动匹配")
    return matcher.apply_to


def _make_progress(enabled: bool):
    if not enabled:
        return None
    try:
        is_tty = sys.stderr.isatty()
    except Exception:
        is_tty = False
    state = {"last": 0.0}

    def _cb(current, total, ip):
        if not is_tty:
            return
        now = time.monotonic()
        # 限流：每 0.1s 或最后一台才刷新，避免刷屏拖慢扫描
        if current < total and now - state["last"] < 0.1:
            return
        state["last"] = now
        pct = (current / total * 100) if total else 100.0
        sys.stderr.write(f"\r扫描中 {pct:5.1f}%  {current}/{total}  {ip:<15}")
        sys.stderr.flush()
        if current >= total:
            sys.stderr.write("\r" + " " * 60 + "\r")
            sys.stderr.flush()

    return _cb


def _run_scan(args):
    """执行一次扫描，返回 (results, scanner)。

    参数非法 / 范围超限 / 用户中断时返回 ``(None, None)``（错误信息已写入 stderr），
    由调用方转成退出码 —— 这样 ``main()`` 对库调用方保持"只返回 int"的契约。
    """
    from scanner import NetworkScanner
    from scanner.range import (count_ip_range, is_ipv6_range,
                               MAX_IPS_PER_RANGE, MAX_IPS_TOTAL)

    try:
        ports = _resolve_ports(args)
    except ValueError as e:
        log(f"错误: {e}")
        return None, None

    protocols = _resolve_protocols(args)

    # SNMPv3：口令一律来自环境变量。参数非法要**在扫描开始前**就失败 ——
    # 否则会白扫一整个网段，才在末尾的日志里看到"密码没配"。
    snmp_v3_user, snmp_v3_error = _resolve_snmp_v3(args)
    if snmp_v3_error:
        log(f"错误: {snmp_v3_error}")
        return None, None
    if snmp_v3_user is not None:
        # 引擎只在协议列表含 SNMP 时才走 SNMP 识别路径。漏了这一步，
        # 配了 --snmpv3-user 也完全不生效 —— 最难查的"静默无效"。
        from scanner.constants import SVC_SNMP
        items = list(protocols or [])
        if not any(p.upper() == SVC_SNMP for p in items):
            items.append(SVC_SNMP)
        protocols = items
        log(f"SNMPv3 已启用：用户 {snmp_v3_user.username}，"
            f"安全级别 {snmp_v3_user.security_level()}")

    # 与 GUI/引擎一致：先只计数，超限时在构建任何列表之前就拒绝（避免 OOM）。
    # 放在这里而不是等引擎返回空列表，是为了给出精确的原因和干净的退出码。
    total_ips = 0
    for r in args.ranges:
        n = count_ip_range(r)
        if n <= 0:
            # IPv6 与"写错了"要分开报：前者语法合法，笼统说"无法解析"会
            # 让用户反复检查自己的格式，而真正的原因是工具不支持。
            if is_ipv6_range(r):
                log(f"错误: 「{r}」是 IPv6 范围，本工具目前只支持 IPv4 扫描。"
                    f"请改用 IPv4 网段（如 192.168.1.0/24）。")
            else:
                log(f"错误: 无法解析 IP 范围 {r!r}")
            return None, None
        if n > MAX_IPS_PER_RANGE:
            log(f"错误: 范围「{r}」包含 {n} 个地址，超过单次上限 {MAX_IPS_PER_RANGE} 个。"
                f"请拆分为更小的范围（如按 /24 分批）后重试。")
            return None, None
        if total_ips + n > MAX_IPS_TOTAL:
            log(f"错误: 扫描范围合计将超过 {MAX_IPS_TOTAL} 个地址（超出项：「{r}」）。"
                f"请缩小范围或分批扫描。")
            return None, None
        total_ips += n

    level_label = getattr(args, "level", "custom")
    if ports is None:
        port_label = "不扫端口"
    elif getattr(args, "ports", None):
        port_label = f"{len(ports)} 个端口（自定义）"
    else:
        port_label = f"{len(ports)} 个端口（{level_label}）"
    log(f"准备扫描 {total_ips} 个地址，{port_label}")

    scanner = NetworkScanner()
    t0 = time.monotonic()
    try:
        results = scanner.scan(
            ip_ranges=list(args.ranges),
            timeout_ms=getattr(args, "timeout", 1000),
            max_threads=getattr(args, "threads", 100),
            scan_ports_flag=ports is not None,
            protocols=protocols,
            tcp_scan_mode=getattr(args, "tcp_mode", "connect"),
            mdns_discovery=not getattr(args, "no_mdns", False),
            ports=ports,
            progress_callback=_make_progress(not getattr(args, "quiet", False)),
            library_lookup=_build_library_lookup(getattr(args, "library", False)),
            snmp_v3_user=snmp_v3_user,
        )
    except KeyboardInterrupt:
        scanner.stop()
        log("已中断")
        return None, None

    for w in getattr(scanner, "warnings", []) or []:
        warn(w)

    elapsed = time.monotonic() - t0
    online = sum(1 for r in results if r.status == "online")
    log(f"扫描完成：{len(results)} 个地址，{online} 台在线，耗时 {elapsed:.1f}s")
    return results, scanner


# ────────────────────────────── 子命令 ──────────────────────────────

def _collect_switch_maps(args, results):
    """读取各交换机转发表（`--switch-map`），返回落库用的 dict 列表。

    失败只告警、返回 None —— 转发表读不到（设备不支持 BRIDGE-MIB / 团体字权限不足）
    是常见情形，不该让一次已经成功的扫描因此判为失败。
    """
    from topology_discovery import collect_switch_port_maps

    snmp_v3_user, err = _resolve_snmp_v3(args)
    if err:
        warn(f"跳过转发表读取: {err}")
        return None

    def _progress(phase, current, total, message):
        if message and not getattr(args, "quiet", False):
            log(message)

    try:
        return collect_switch_port_maps(
            results, snmp_v3_user=snmp_v3_user, progress_callback=_progress)
    except Exception as e:  # noqa: BLE001
        warn(f"读取交换机转发表失败: {e}")
        return None

def cmd_scan(args) -> int:
    results, _scanner = _run_scan(args)
    if results is None:
        return EXIT_ERROR
    if not results:
        log("没有可输出的结果（扫描范围可能被拒绝或为空）")
        return EXIT_ERROR

    if args.online_only:
        results = [r for r in results if r.status == "online"]

    if not results:
        log("没有在线设备")
        if args.fail_if_empty:
            return EXIT_ERROR

    # 变更告警：基线必须在**保存本次快照之前**取到，否则拿到的就是自己
    notifiers = []
    notify_config = {}
    baseline_id = None
    if getattr(args, "notify", False):
        import notifier as _notifier
        notify_config = _notifier.load_config(
            getattr(args, "notify_config", None))
        notifiers = _notifier.build_notifiers(notify_config)
        if not notifiers:
            warn("已指定 --notify，但没有可用的通知渠道。"
                 "请检查通知配置（默认：数据目录下的 notify.json）")
        else:
            try:
                import history_store
                snaps = history_store.list_snapshots(db_path=_db_path(args))
                baseline_id = snaps[-1]["id"] if snaps else None
            except Exception as e:  # noqa: BLE001
                warn(f"读取历史快照失败，本次跳过变更对比: {e}")
                notifiers = []

    # 端口映射（可选）：在**保存快照之前**采集，存好快照后连同 snapshot_id 落库。
    # 没有 --save-snapshot 就没有可挂靠的快照，采集了也无处安放 —— 直接说明并跳过。
    switch_maps = None
    if getattr(args, "switch_map", False):
        if not args.save_snapshot:
            warn("已指定 --switch-map 但没有 --save-snapshot："
                 "端口映射必须挂在快照上，本次跳过转发表读取。")
        else:
            switch_maps = _collect_switch_maps(args, results)

    if args.save_snapshot:
        try:
            import history_store
            sid = history_store.save_snapshot(
                _snapshot_devices(results), note=args.note, db_path=_db_path(args)
            )
            log(f"已保存快照 #{sid}")
            if switch_maps:
                n = history_store.save_port_map(
                    sid, switch_maps, db_path=_db_path(args))
                log(f"已记录 {n} 条端口映射（来自 {len(switch_maps)} 台交换机）")
        except Exception as e:  # noqa: BLE001
            warn(f"保存快照失败: {e}")

    records = [result_to_record(r) for r in results]
    records.sort(key=lambda x: (x["status"] != "online",
                                _ip_sort_key(x["ip"])))

    if args.format == "json":
        emit(render_json({
            "version": __version__,
            "scanned_at": time.time(),
            "device_count": len(records),
            "online_count": sum(1 for r in records if r["status"] == "online"),
            "devices": records,
        }), args.output)
    elif args.format == "csv":
        emit(render_csv(records, _RESULT_COLUMNS), args.output)
    else:
        emit(render_table(records, _RESULT_COLUMNS), args.output)

    if notifiers:
        _notify_changes(results, baseline_id, notifiers, args, notify_config)
    return EXIT_OK


def _load_alert_policy(args, config):
    """从通知配置里编译告警策略。

    返回 ``(policy, store)``；``--no-policy`` 或配置里没有任何策略时返回
    ``(None, None)`` —— 调用方据此走「原样发送」的老路径，行为完全不变。
    """
    if getattr(args, "no_policy", False):
        return None, None
    import alert_policy as _policy
    policy = _policy.AlertPolicy.from_config(config)
    if not policy.enabled:
        return None, None
    return policy, policy.make_store()


def _log_suppressed(result) -> None:
    """把「哪些原因各抑制了几条」写进日志。

    **CLI 文案不翻译**（与 `cli.py` 里其它所有消息一致），因此这里用中文
    字面量而不是 `alert_policy.suppress_reason_label()`。
    """
    import alert_policy as _policy
    names = {
        _policy.SUPPRESS_MAINTENANCE: "维护窗口",
        _policy.SUPPRESS_MUTED: "静音",
        _policy.SUPPRESS_DEDUPED: "去重冷却",
    }
    parts = [f"{names.get(reason, reason)} {n} 条"
             for reason, n in sorted(result.count_by_reason().items())]
    log(f"告警策略抑制了 {len(result.suppressed)} 条变更"
        f"（{' / '.join(parts)}）")


def _notify_changes(results, baseline_id, notifiers, args, config=None) -> None:
    """对比基线快照并推送变更告警。

    **无变更时不发告警。** 定时任务每 30 分钟推一条"无变更"会把渠道变成噪音，
    真正需要被看见的变更反而会被淹没。同理，首次运行只告知"基线已建立"。

    有变更时还要再过一层**告警策略**（`alert_policy.py`：维护窗口 / 静音 /
    通知去重）。被抑制的条目不发送，但**照常留痕**，且**不影响退出码** ——
    「静音」是给人耳的，「退出码」是给机器的，CI 需要真实信号。
    """
    import change_detector as cd
    import history_store
    import notifier as _notifier

    policy, store = _load_alert_policy(args, config)
    suppressed_note = ""

    if baseline_id is None:
        if getattr(args, "save_snapshot", False):
            subject = "[IPScanner] 已建立基线快照"
            body = ("首次运行：本次结果已存为基线，未做变更对比。\n"
                    "从下一次扫描开始即可检测新增 / 消失 / 属性变更。")
        else:
            subject = "[IPScanner] 无历史基线"
            body = ("尚无历史快照可对比，本次未做变更检测。\n"
                    "请在扫描命令中加上 --save-snapshot 以建立基线。")
    else:
        try:
            baseline = history_store.get_snapshot(baseline_id, db_path=_db_path(args))
        except Exception as e:  # noqa: BLE001
            warn(f"读取基线快照 #{baseline_id} 失败: {e}")
            return
        previous = (baseline or {}).get("devices", [])
        changes = cd.detect_changes(results, previous)
        if not changes:
            log(f"变更对比（当前扫描 → 快照 #{baseline_id}）：无变更，不发送告警")
            return
        label = f"当前扫描 → 快照 #{baseline_id}"

        if policy is not None:
            decision = policy.evaluate(changes, store=store)
            if decision.suppressed:
                _log_suppressed(decision)
            if not decision.notify:
                warn(f"变更对比（{label}）：{cd.get_change_summary(changes)}"
                     f" —— 全部 {len(decision.suppressed)} 条被策略抑制，未发送告警")
                return
            changes = decision.notify
            suppressed_note = _policy_note(decision.suppressed)

        subject, body = _notifier.format_change_message(
            changes, cd.get_change_summary(changes), label=label)
        if suppressed_note:
            body = f"{body}\n\n{suppressed_note}"

    log(f"发送变更告警：{subject}")
    any_ok = False
    for name, ok, err in _notifier.send_all(notifiers, subject, body):
        if ok:
            any_ok = True
            log(f"  已发送 [{name}]")
        else:
            warn(f"  发送失败 [{name}]: {err}")

    # **发送成功才记账**：失败不记，下一轮会重试 —— 否则一次网络抖动
    # 就会让这条变更永远沉默（去重把它当成"已经报过了"）。
    if any_ok and policy is not None and store is not None and baseline_id is not None:
        from datetime import datetime
        now = datetime.now()
        store.record(changes, now)
        store.prune(now)
        store.save()


def _policy_note(suppressed) -> str:
    import alert_policy as _policy
    return _policy.render_suppression_note(suppressed)


def _ip_sort_key(ip: str):
    """IP 自然序（192.168.1.9 排在 192.168.1.10 之前）。"""
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(ip)))
    except Exception:
        return (1, ip)


def cmd_diff(args) -> int:
    import change_detector as cd
    import history_store

    # ── 模式 A：纯快照对比（不重新扫描） ──
    if args.from_id is not None or args.to_id is not None:
        db = _db_path(args)
        snaps = history_store.list_snapshots(db_path=db)
        ids = [s["id"] for s in snaps]
        if not ids:
            log("错误: 没有任何历史快照")
            return EXIT_ERROR
        from_id = args.from_id if args.from_id is not None else ids[-1]
        to_id = args.to_id if args.to_id is not None else ids[-1]
        old = history_store.get_snapshot(from_id, db_path=db)
        new = history_store.get_snapshot(to_id, db_path=db)
        if old is None:
            log(f"错误: 快照 #{from_id} 不存在")
            return EXIT_ERROR
        if new is None:
            log(f"错误: 快照 #{to_id} 不存在")
            return EXIT_ERROR
        current = [_SnapResult(d) for d in new["devices"]]
        previous = old["devices"]
        label = f"快照 #{from_id} → #{to_id}"
    else:
        # ── 模式 B：扫描当前网络并与快照对比 ──
        if not args.ranges:
            log("错误: 需要 -r/--range（或改用 --from/--to 比较两个快照）")
            return EXIT_ERROR
        results, _scanner = _run_scan(args)
        if results is None:
            return EXIT_ERROR
        db = _db_path(args)
        if args.save_snapshot:
            try:
                sid = history_store.save_snapshot(
                    _snapshot_devices(results), note=args.note, db_path=db
                )
                log(f"已保存快照 #{sid}")
            except Exception as e:  # noqa: BLE001
                warn(f"保存快照失败: {e}")

        snaps = history_store.list_snapshots(db_path=db)
        if args.against is not None:
            baseline_id = args.against
        elif snaps:
            baseline_id = snaps[-1]["id"]
        else:
            baseline_id = None

        if baseline_id is None:
            log("没有历史快照可对比（首次运行）。加 --save-snapshot 建立基线。")
            if args.fail_on_change:
                return EXIT_ERROR
            return EXIT_OK

        baseline = history_store.get_snapshot(baseline_id, db_path=db)
        if baseline is None:
            log(f"错误: 基线快照 #{baseline_id} 不存在")
            return EXIT_ERROR
        current = results
        previous = baseline["devices"]
        label = f"当前扫描 → 快照 #{baseline_id}"

    changes = cd.detect_changes(current, previous)
    summary = cd.get_change_summary(changes)
    log(f"变更对比（{label}）：{summary}")

    if args.format == "json":
        emit(render_json({
            "version": __version__,
            "baseline": label,
            "summary": summary,
            "change_count": len(changes),
            "changes": [{
                "type": c.change_type,
                "severity": c.severity,
                "ip": c.ip,
                "mac": c.mac,
                "hostname": c.hostname,
                "old_value": c.old_value,
                "new_value": c.new_value,
                "description": c.description,
            } for c in changes],
        }), args.output)
    else:
        if not changes:
            emit("无变更", args.output)
        else:
            rows = [{
                "severity": c.severity,
                "type": c.change_type,
                "ip": c.ip,
                "mac": c.mac,
                "hostname": c.hostname,
                "old": c.old_value,
                "new": c.new_value,
                "description": c.description,
            } for c in changes]
            emit(render_table(
                rows, ("severity", "type", "ip", "mac", "hostname",
                       "old", "new", "description")
            ), args.output)

    if changes and args.fail_on_change:
        return EXIT_CHANGES
    return EXIT_OK


def cmd_history(args) -> int:
    import history_store

    db = _db_path(args)

    if args.show is not None:
        snap = history_store.get_snapshot(args.show, db_path=db)
        if snap is None:
            log(f"错误: 快照 #{args.show} 不存在")
            return EXIT_ERROR
        devices = snap["devices"]
        if args.format == "json":
            emit(render_json({
                "id": args.show,
                "time": snap["time"],
                "time_str": _fmt_time(snap["time"]),
                "device_count": len(devices),
                "devices": devices,
            }), args.output)
        elif args.format == "csv":
            emit(render_csv(devices, _SNAPSHOT_DEVICE_COLUMNS), args.output)
        else:
            emit(render_table(devices, _SNAPSHOT_DEVICE_COLUMNS), args.output)
        return EXIT_OK

    if args.query:
        rows = history_store.query_history(
            device_class=args.device_class,
            network=args.network,
            ip_substr=args.ip,
            db_path=db,
        )
        if not rows:
            emit("无匹配记录" if args.format != "json" else render_json([]),
                 args.output)
            return EXIT_OK
        for r in rows:
            r["first_seen"] = _fmt_time(r.get("first_seen"))
            r["last_seen"] = _fmt_time(r.get("last_seen"))
        if args.format == "json":
            emit(render_json(rows), args.output)
        elif args.format == "csv":
            emit(render_csv(rows, _HISTORY_COLUMNS), args.output)
        else:
            emit(render_table(rows, _HISTORY_COLUMNS), args.output)
        return EXIT_OK

    # 默认：列出快照
    snaps = history_store.list_snapshots(db_path=db)
    for s in snaps:
        s["time_str"] = _fmt_time(s["time"])
    if args.format == "json":
        emit(render_json(snaps), args.output)
    elif args.format == "csv":
        emit(render_csv(snaps, _SNAPSHOT_COLUMNS), args.output)
    else:
        emit(render_table(snaps, _SNAPSHOT_COLUMNS) if snaps else "没有历史快照",
             args.output)
    return EXIT_OK


# ────────────────────────────── 定位查询 ──────────────────────────────

def _render_locate_text(r) -> str:
    """把 `locate_device()` 的结果排成人看的几行。

    文案**不翻译** —— 与 cli.py 里其它所有消息一致（本文件整体不走 i18n，
    `log`/`warn` 都是直写中文）。原因标签走共享助手，那是 GUI 也在用的同一份映射。
    """
    cur = r["current"]
    lines = [
        f"设备: {r['mac'] or '—'}",
        f"IP: {r['ip'] or '—'}   主机名: {r['hostname'] or '—'}",
        f"当前位置: {cur['switch_name'] or cur['switch_ip']} 端口 {cur['port_name'] or '—'}",
        f"  快照 #{cur['snapshot_id']} · {_fmt_time(cur['time'])}",
        "端口名可信度: " + (
            "真实接口名" if r["port_confidence"] == "named"
            else "仅桥接端口号（不可信，展示时请标注）"),
    ]
    prev = r["previous"]
    if prev:
        lines.append(
            f"上次位置: {prev['switch_name'] or prev['switch_ip']} "
            f"端口 {prev['port_name'] or '—'}")
        lines.append(
            f"  快照 #{prev['snapshot_id']} · {_fmt_time(prev['time'])}")
        lines.append("已换过端口: 是")
    else:
        lines.append("已换过端口: 否")
    return "\n".join(lines)


def cmd_locate(args) -> int:
    """回答「这台设备插在哪台交换机的哪个口」。

    **JSON 输出保持语言无关**（`reason` 是 `history_store.LOCATE_*` 规范值），
    text 输出才翻译、并附上「下一步怎么办」—— 脚本消费 JSON，人看 text。
    """
    import history_store
    from scanner.constants import locate_reason_hint, locate_reason_label

    r = history_store.locate_device(
        mac=args.mac or "", ip=args.ip or "", hostname=args.hostname or "",
        db_path=_db_path(args))

    if args.format == "json":
        out = dict(r)
        for key in ("current", "previous"):
            if out.get(key):
                out[key] = dict(out[key])
                out[key]["time_str"] = _fmt_time(out[key]["time"])
        emit(render_json(out), args.output)
        return EXIT_OK if r["found"] else EXIT_NOT_FOUND

    if not r["found"]:
        who = r["mac"] or r["ip"] or r["hostname"]
        lines = [f"未定位到设备: {who}",
                 f"原因: {locate_reason_label(r['reason'])}"]
        hint = locate_reason_hint(r["reason"])
        if hint:
            lines.append(f"提示: {hint}")
        emit("\n".join(lines), args.output)
        return EXIT_NOT_FOUND

    emit(_render_locate_text(r), args.output)
    return EXIT_OK


# ────────────────────────── 被动 / 持续发现 ──────────────────────────

#: 被动发现的来源 -> 人看的短标签。语义与 `ScanResult.to_dict()` 里的
#: 「ARP探测 / mDNS发现」一致，只是这里更短。
_WATCH_SOURCE_TEXT = {"arp": "ARP 表", "mdns": "mDNS"}


def _render_watch_text(ledger, fresh) -> str:
    """一次轮询的结果 → 人看的几行。文案**不翻译**（与 cli.py 其它消息一致）。"""
    lines = [f"台账设备: {len(ledger)} 台"]
    if not fresh:
        lines.append("本次新出现: 无")
        return "\n".join(lines)
    lines.append(f"本次新出现: {len(fresh)} 台")
    for r in sorted(fresh, key=lambda x: _ip_sort_key(x.ip)):
        src = _WATCH_SOURCE_TEXT.get(r.discovery_method, r.discovery_method or "—")
        tail = f"  {r.hostname}" if r.hostname else ""
        lines.append(f"  {r.ip:<15} {r.mac or '—':<17} {src}{tail}")
    return "\n".join(lines)


def _watch_payload(ledger, fresh, round_no=None) -> dict:
    """JSON 输出。字段名与取值**语言无关**，脚本可依赖。

    `round_no` 为 None（单次轮询）时带上完整 `devices`；
    持续轮询时只给本轮的增量 —— 每轮重发整张台账既浪费又难用。
    """
    def _one(r):
        return {"ip": r.ip, "mac": r.mac, "hostname": r.hostname,
                "vendor": r.vendor, "status": r.status,
                "discovery_method": r.discovery_method,
                "services": list(r.services)}

    payload = {
        "device_count": len(ledger),
        "new_count": len(fresh),
        "new_devices": [_one(r) for r in
                        sorted(fresh, key=lambda x: _ip_sort_key(x.ip))],
    }
    if round_no is None:
        payload["devices"] = [_one(r) for r in
                              sorted(ledger, key=lambda x: _ip_sort_key(x.ip))]
    else:
        payload["round"] = round_no
    return payload


def _watch_baseline(args) -> list:
    """「已知设备」基线 = 最近一次快照里的**设备列表**。

    给整份设备列表（而不是只给 IP）：`PassiveWatcher` 还需要主机名 / 厂商
    这些**指纹**字段，才能把"换了随机 MAC 的老设备"从"新设备"里分出来
    （路线图 §3 耦合提示 #11）。

    没有快照时基线为空 —— 那第一次轮询会把整张 ARP 表都报成"新设备"。
    这是**如实**的：库里确实没有它们的记录（与 locate 的 no_device 同一立场）。
    """
    import history_store
    try:
        return history_store.latest_devices(db_path=_db_path(args))
    except Exception as e:  # noqa: BLE001
        # 基线读不到不该让 watch 整体失败：退化成"没有基线"，
        # 结果偏保守（可能多报新设备），但功能仍然可用。
        warn(f"读取被动发现基线失败，本次不带基线运行: {e}")
        return []


def cmd_watch(args) -> int:
    """被动发现：**不发包**地看「最近谁在我身边出现过」。

    默认只做单次轮询（给 `scheduler` 定时调用用）；`--interval` 才进入持续轮询。

    **默认不写快照**：快照有 20 条硬上限（`history_store.prune`），
    每周期写一条会在十分钟内把真实扫描历史全冲掉。要落库得显式加
    `--save-snapshot`，且只允许单次轮询 —— 持续轮询 + 落库必然冲掉历史，
    这里直接拒绝而不是留个坑。
    """
    from scanner.passive import PassiveWatcher

    interval = getattr(args, "interval", None)
    looping = bool(interval)

    if looping and args.save_snapshot:
        warn("--interval（持续轮询）与 --save-snapshot 不能同时用："
             "每周期写一条快照会在十分钟内冲掉全部历史（快照上限 20 条）。"
             "要定时落库请用 `watch --once --save-snapshot` 交给 scheduler。")
        return EXIT_ERROR
    if looping and args.output:
        warn("--interval（持续轮询）下 --output 无意义（每轮都会覆盖），本次忽略。")

    watcher = PassiveWatcher(known_devices=_watch_baseline(args))

    def _cycle():
        return watcher.poll(mdns=not args.no_mdns,
                            mdns_active=args.mdns_active,
                            mdns_timeout=args.mdns_timeout)

    # ── 单次轮询（默认） ──
    if not looping:
        ledger, fresh = _cycle()
        if args.save_snapshot:
            _save_watch_snapshot(args, ledger)
        if args.format == "json":
            emit(render_json(_watch_payload(ledger, fresh)), args.output)
        else:
            emit(_render_watch_text(ledger, fresh), args.output)
        # `--fail-on-change` 与 diff 的语义保持一致：有新设备 → 退出码 2。
        return EXIT_CHANGES if (args.fail_on_change and fresh) else EXIT_OK

    # ── 持续轮询 ──
    limit = getattr(args, "count", 0) or 0
    rounds = 0
    total_new = 0
    try:
        while True:
            rounds += 1
            ledger, fresh = _cycle()
            total_new += len(fresh)
            if args.format == "json":
                sys.stdout.write(render_json(
                    _watch_payload(ledger, fresh, round_no=rounds)) + "\n")
            else:
                sys.stdout.write(f"[第 {rounds} 轮]\n"
                                 + _render_watch_text(ledger, fresh) + "\n")
            sys.stdout.flush()
            if limit and rounds >= limit:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        # Ctrl+C 是用户主动停止，属**正常结束路径**，不是错误。
        # 这里不能写成 `pass`：tests/test_logging_policy.py 的棘轮按**计数**
        # 卡静默处理器，补注释也过不了计数那一关。
        log("收到中断信号，正在停止持续发现…")
    log(f"持续发现已停止：共 {rounds} 轮，累计新出现 {total_new} 台设备。")
    return EXIT_OK


def _save_watch_snapshot(args, ledger):
    """把被动发现的台账存成一条快照（仅在显式 `--save-snapshot` 时调用）。"""
    import history_store
    devices = _snapshot_devices(sorted(ledger, key=lambda x: _ip_sort_key(x.ip)))
    note = args.note or "被动发现"
    try:
        sid = history_store.save_snapshot(devices, note=note,
                                          db_path=_db_path(args))
    except Exception as e:  # noqa: BLE001
        warn(f"保存快照失败: {e}")
        return
    log(f"已保存快照 #{sid}（{len(devices)} 台设备）")


# ────────────────────────────── 计划任务 ──────────────────────────────

def cmd_schedule(args) -> int:
    """注册 / 卸载 / 查询系统计划任务（Windows schtasks、POSIX crontab）。

    为什么做成 CLI 子命令而不是只在 GUI 里提供：无人值守的资产监控本身就发生在
    "没人开界面"的场景。把注册动作也放进 GUI，等于要求用户先开一次界面来配置
    "以后再也不要开界面"的任务 —— 说不通。CLI 里一条命令搞定，才配得上"自动化"。
    """
    import scheduler

    action = "register" if args.register else ("unregister" if args.unregister else "status")

    if not scheduler.is_supported():
        log("错误: 当前系统未找到可用的调度命令"
            "（Windows 需要 schtasks，Linux/macOS 需要 crontab）。")
        return EXIT_ERROR

    name = args.name or scheduler.DEFAULT_TASK_NAME

    if action == "status":
        ok, out = scheduler.query(name)
        if ok:
            log(f"计划任务「{name}」已注册。")
            if out:
                log(out)
            return EXIT_OK
        log(f"计划任务「{name}」未注册。")
        return EXIT_OK

    if action == "unregister":
        ok, msg = scheduler.unregister(name)
        if ok:
            log(f"已卸载计划任务「{name}」。")
            return EXIT_OK
        log(f"错误: 卸载失败: {msg}")
        return EXIT_ERROR

    # ── register ──
    ranges = [r for r in (args.ranges or []) if r and str(r).strip()]
    if not ranges:
        log("错误: 注册计划任务需要至少一个 -r/--range。")
        return EXIT_ERROR

    # 频率/时间参数非法要在调用系统调度器**之前**就拦下 —— schtasks 会把这些
    # 报成含糊的 "参数错误"，用户根本对不上是哪一项写错了。
    try:
        scheduler.validate_schedule(args.freq, args.interval, args.at)
    except scheduler.ScheduleError as e:
        log(f"错误: {e}")
        return EXIT_ERROR

    cli_args = scheduler.build_scan_argv(
        ranges, level=args.level, save_snapshot=True,
        note=args.note or "", notify=not args.no_notify,
    )
    # --db / --notify-config 若显式给了，要一并固化进任务命令行，
    # 否则计划任务运行时用的是默认数据目录，与用户手动扫描的库对不上。
    if getattr(args, "db", None):
        cli_args += ["--db", args.db]
    if getattr(args, "notify_config", None):
        cli_args += ["--notify-config", args.notify_config]
    if args.quiet:
        cli_args.append("--quiet")

    exe, prefix = scheduler.default_executable()
    command = scheduler.build_task_command(exe, prefix, cli_args)

    ok, msg = scheduler.register(
        name, command, args.freq, interval=args.interval,
        at=args.at, run_highest=args.highest,
    )
    if not ok:
        log(f"错误: 注册计划任务失败: {msg}")
        return EXIT_ERROR
    log(f"已注册计划任务「{name}」。")
    log(f"  执行命令: {command}")
    log(f"  触发规则: {_describe_schedule(args)}")
    return EXIT_OK


def _describe_schedule(args) -> str:
    """把调度参数渲染成一句人类可读的说明（仅用于日志）。"""
    import scheduler
    if args.freq == scheduler.FREQ_DAILY:
        return f"每天 {args.at}"
    if args.freq == scheduler.FREQ_HOURLY:
        return f"每 {args.interval} 小时"
    return f"每 {args.interval} 分钟"


def _fmt_time(ts) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except Exception:
        return ""


def _db_path(args):
    """历史快照数据库路径（None 表示用默认数据目录下的 scan_history.db）。"""
    return getattr(args, "db", None)


# ────────────────────────────── SNMPv3（USM） ──────────────────────────────

# 口令存放的环境变量名。**口令绝不走 argv** —— argv 会出现在进程列表
# （ps / 任务管理器）里，同机任何用户都能看到，等于把凭据广播出去。
SNMPV3_AUTH_KEY_ENV = "IPSCANNER_SNMPV3_AUTH_KEY"
SNMPV3_PRIV_KEY_ENV = "IPSCANNER_SNMPV3_PRIV_KEY"

# 命令行上的候选值。"none" 映射回空串（=不启用）。
# DES 故意保留在候选里：让 scanner.snmp_v3.validate() 给出
# 「已废弃且标准库无 DES，请改用 AES-128」这条**有理由**的错误，
# 而不是 argparse 那句不解释原因的 "invalid choice"。
_AUTH_CHOICES = ("none", "md5", "sha")
_PRIV_CHOICES = ("none", "aes", "des")


def _read_secret_env(name: str) -> str:
    """从环境变量读取口令；未设置时返回空串（是否合法交给 validate 统一判定）。"""
    return os.environ.get(name, "") or ""


def _resolve_snmp_v3(args):
    """把命令行参数 + 环境变量组装成 ``SnmpV3User``。

    返回 ``(user, error)``：
      * ``(None, None)``    —— 未启用 SNMPv3（没给 ``--snmpv3-user``）；
      * ``(None, "原因")``  —— 参数非法，调用方应报错并返回退出码 1；
      * ``(user, None)``    —— 组装成功。
    """
    from scanner.snmp_v3 import SnmpV3User

    username = getattr(args, "snmpv3_user", None)
    if not username:
        return None, None

    auth_raw = (getattr(args, "snmpv3_auth", None) or "none").lower()
    priv_raw = (getattr(args, "snmpv3_priv", None) or "none").lower()
    auth_proto = "" if auth_raw == "none" else auth_raw
    priv_proto = "" if priv_raw == "none" else priv_raw

    auth_env = getattr(args, "snmpv3_auth_env", None) or SNMPV3_AUTH_KEY_ENV
    priv_env = getattr(args, "snmpv3_priv_env", None) or SNMPV3_PRIV_KEY_ENV

    user = SnmpV3User(
        username=username,
        auth_proto=auth_proto,
        auth_key=_read_secret_env(auth_env),
        priv_proto=priv_proto,
        priv_key=_read_secret_env(priv_env),
    )

    err = user.validate()
    if err:
        # 补一句「口令该从哪个变量来」：最常见的失败是变量名拼错或忘了 export，
        # 只报「必须提供认证密码」的话，用户会去翻命令行而不是翻环境变量。
        # 但**只有**在「结构本身没问题、纯粹是口令没给」时才补 ——
        # 否则会把「priv 没配 auth」这种结构性错误也误报成「口令缺失」，指错方向。
        if priv_proto and not auth_proto:
            pass          # 结构性错误：priv 必须建立在 auth 之上，与口令无关
        elif auth_proto and not user.auth_key:
            err += f"（环境变量 {auth_env} 为空或未设置）"
        elif priv_proto and not user.priv_key:
            err += f"（环境变量 {priv_env} 为空或未设置）"
        return None, err
    return user, None


def _add_snmp_v3_args(parser):
    """给会发起扫描的子命令（scan / diff）挂上 SNMPv3 参数。

    选项名刻意用 ``--snmpv3-auth-env`` 而不是 ``--snmpv3-auth-key-env``：
    argparse 默认做**前缀缩写**匹配，``--snmpv3-auth-key`` 会被当成
    ``--snmpv3-auth-key-env`` 的缩写而**静默接受**，于是用户一个笔误
    就把真口令写进了 argv（进程列表可见），而且还不生效。
    改成 ``-env`` 结尾后，``--snmpv3-auth-key`` 不匹配任何选项，
    会直接报 unrecognized arguments，用户立刻会去重看帮助。
    """
    parser.add_argument("--snmpv3-user", metavar="用户名",
                        help="启用 SNMPv3（USM）并指定用户名")
    parser.add_argument("--snmpv3-auth", choices=_AUTH_CHOICES, default="none",
                        help="SNMPv3 认证协议（默认 none；口令从环境变量读取）")
    parser.add_argument("--snmpv3-priv", choices=_PRIV_CHOICES, default="none",
                        help="SNMPv3 加密协议（默认 none；须同时启用认证）")
    parser.add_argument("--snmpv3-auth-env", metavar="变量名",
                        default=SNMPV3_AUTH_KEY_ENV,
                        help=f"存放认证口令的环境变量名（默认 {SNMPV3_AUTH_KEY_ENV}）")
    parser.add_argument("--snmpv3-priv-env", metavar="变量名",
                        default=SNMPV3_PRIV_KEY_ENV,
                        help=f"存放加密口令的环境变量名（默认 {SNMPV3_PRIV_KEY_ENV}）")


# ────────────────────────────── 参数定义 ──────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    import scheduler as _sched

    common = argparse.ArgumentParser(add_help=False)
    # default=SUPPRESS：子解析器不会用 None 覆盖主解析器已解析到的 --lang
    # （argparse 的已知行为：子解析器的默认值会写回同一个 namespace）。
    common.add_argument("--lang", choices=("zh-CN", "en-US"),
                        default=argparse.SUPPRESS,
                        help="界面/导出语言（默认跟随系统）")
    common.add_argument("--db", metavar="文件", default=argparse.SUPPRESS,
                        help="历史快照数据库路径（默认使用程序数据目录下的 scan_history.db）")

    p = argparse.ArgumentParser(
        prog="ipscanner",
        description="IPScanner 无头命令行：网段扫描、资产变更对比、历史查询。",
        epilog="退出码: 0 成功 / 1 错误 / 2 检测到变更(--fail-on-change) / 3 环境错误 / "
               "4 未定位到设备(locate)",
        parents=[common],
    )
    p.add_argument("--version", action="version",
                   version=f"IPScanner CLI {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="命令")

    # ── scan ──
    sp = sub.add_parser("scan", help="扫描网段并输出结果", parents=[common],
                        description="扫描一个或多个 IP 范围，输出设备清单。")
    sp.add_argument("-r", "--range", action="append", required=True,
                    dest="ranges", metavar="范围",
                    help="IP 范围，可重复。支持 192.168.1.0/24、192.168.1.1-254、单个 IP")
    sp.add_argument("--level", choices=("quick", "standard", "all"), default="quick",
                    help="端口扫描级别（默认 quick=常用 21 个端口）")
    sp.add_argument("--ports", metavar="列表",
                    help="自定义端口，逗号分隔（覆盖 --level），如 80,443,3389")
    sp.add_argument("--no-ports", action="store_true", help="完全跳过端口扫描（最快）")
    sp.add_argument("--protocols", metavar="列表", default="",
                    help="应用层协议识别，逗号分隔，如 HTTP,HTTPS,FTP,RDP,SNMP")
    sp.add_argument("--tcp-mode", choices=("connect", "syn", "udp"), default="connect",
                    help="端口探测方式（syn/udp 需管理员权限，默认 connect）")
    sp.add_argument("--no-mdns", action="store_true", help="关闭 mDNS 组播发现")
    sp.add_argument("--timeout", type=int, default=1000, metavar="毫秒",
                    help="ping 超时毫秒（默认 1000）")
    sp.add_argument("--threads", type=int, default=100, metavar="N",
                    help="ping 并发线程数（默认 100）")
    sp.add_argument("--online-only", action="store_true", help="只输出在线设备")
    sp.add_argument("--library", action="store_true", help="启用地址库自动匹配（读 mac_library.db）")
    sp.add_argument("--save-snapshot", action="store_true", help="把本次结果存为历史快照")
    sp.add_argument("--note", metavar="备注", help="快照备注（配合 --save-snapshot）")
    sp.add_argument("--switch-map", action="store_true",
                    help="扫描末尾读取各交换机转发表，记录设备与端口的对应关系"
                         "（需配合 --save-snapshot；需要 SNMP，每台交换机 5 次 walk）")
    sp.add_argument("--notify", action="store_true",
                    help="检测到资产变更时推送告警（需先配置通知渠道）")
    sp.add_argument("--notify-config", metavar="文件",
                    help="通知配置文件路径（默认：数据目录下的 notify.json）")
    sp.add_argument("--no-policy", action="store_true",
                    help="忽略告警策略（维护窗口 / 静音 / 去重），所有变更都发送")
    sp.add_argument("--fail-if-empty", action="store_true", help="无任何结果时返回退出码 1")
    sp.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table",
                    help="输出格式（默认 table）")
    sp.add_argument("-o", "--output", metavar="文件", help="写入文件而非 stdout")
    sp.add_argument("-q", "--quiet", action="store_true", help="静默模式，不输出进度")
    sp.set_defaults(func=cmd_scan)

    # ── diff ──
    dp = sub.add_parser("diff", help="对比资产变更", parents=[common],
                        description="扫描当前网络并与历史快照对比，或直接对比两个快照。")
    dp.add_argument("-r", "--range", action="append", dest="ranges", metavar="范围",
                    help="IP 范围，可重复（与 --from/--to 二选一）")
    dp.add_argument("--against", type=int, metavar="ID",
                    help="对比的基线快照 ID（默认最近一次快照）")
    dp.add_argument("--from", dest="from_id", type=int, metavar="ID",
                    help="纯快照对比：起始快照 ID")
    dp.add_argument("--to", dest="to_id", type=int, metavar="ID",
                    help="纯快照对比：结束快照 ID")
    dp.add_argument("--level", choices=("quick", "standard", "all"), default="quick")
    dp.add_argument("--ports", metavar="列表")
    dp.add_argument("--no-ports", action="store_true")
    dp.add_argument("--protocols", metavar="列表", default="")
    dp.add_argument("--tcp-mode", choices=("connect", "syn", "udp"), default="connect")
    dp.add_argument("--no-mdns", action="store_true")
    dp.add_argument("--timeout", type=int, default=1000, metavar="毫秒")
    dp.add_argument("--threads", type=int, default=100, metavar="N")
    dp.add_argument("--library", action="store_true")
    dp.add_argument("--save-snapshot", action="store_true")
    dp.add_argument("--note", metavar="备注")
    dp.add_argument("--fail-on-change", action="store_true",
                    help="检测到任何变更时返回退出码 2（便于计划任务告警）")
    dp.add_argument("-f", "--format", choices=("text", "json"), default="text")
    dp.add_argument("-o", "--output", metavar="文件")
    dp.add_argument("-q", "--quiet", action="store_true")
    dp.set_defaults(func=cmd_diff)

    # ── history ──
    hp = sub.add_parser("history", help="查看历史快照 / 聚合查询", parents=[common],
                        description="列出历史快照、导出指定快照，或跨快照聚合查询设备。")
    hp.add_argument("--list", action="store_true", help="列出快照（默认行为）")
    hp.add_argument("--show", type=int, metavar="ID", help="导出指定快照的设备清单")
    hp.add_argument("--query", action="store_true", help="跨快照聚合查询设备")
    hp.add_argument("--device-class", metavar="类型", help="按设备类型过滤（子串匹配）")
    hp.add_argument("--network", metavar="网段", help="按网段过滤，如 192.168.1.0/24")
    hp.add_argument("--ip", metavar="关键字", help="按 IP 子串过滤")
    hp.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    hp.add_argument("-o", "--output", metavar="文件")
    hp.set_defaults(func=cmd_history)

    # ── locate ──
    lp = sub.add_parser("locate", help="定位设备接在哪台交换机的哪个端口",
                        parents=[common],
                        description="按 MAC / IP / 主机名，查这台设备接在交换机的哪个口，"
                                    "以及与上一次相比是否换过端口。"
                                    "数据来自扫描时（--switch-map）落库的交换机转发表。")
    grp = lp.add_mutually_exclusive_group(required=True)
    grp.add_argument("--mac", metavar="MAC", help="设备 MAC（推荐：IP 会被 DHCP 回收后换台机器）")
    grp.add_argument("--ip", metavar="IP", help="设备 IP")
    grp.add_argument("--hostname", metavar="主机名", help="设备主机名")
    lp.add_argument("-f", "--format", choices=("text", "json"), default="text")
    lp.add_argument("-o", "--output", metavar="文件")
    lp.set_defaults(func=cmd_locate)

    # ── watch ──
    wp = sub.add_parser("watch", help="被动发现：不发包地看最近谁在网络上出现过",
                        parents=[common],
                        description="读本机 ARP 表 + 监听 mDNS 组播，并入一份内存台账，"
                                    "只报「新出现」的设备（ARP 条目会过期，"
                                    "报「消失」是假阳性）。默认不发任何网络包"
                                    "（mDNS 走只听模式）；默认也不写快照 —— "
                                    "快照上限 20 条，持续轮询会把历史冲掉。"
                                    "定时落库请用 --once --save-snapshot。")
    wp.add_argument("--mdns-timeout", type=float, default=2.5, metavar="秒",
                    help="监听 mDNS 组播的时长（默认 2.5）")
    # `--once` 与 `--interval` 互斥：默认（两个都不给）就是单次轮询，
    # `--once` 是把它**显式写出来** —— 注册到 scheduler 里时能自解释，
    # 也让「为什么这次只跑一遍」在命令本身里就看得见。
    wp_mode = wp.add_mutually_exclusive_group()
    wp_mode.add_argument("--once", action="store_true",
                         help="只轮询一次后退出（默认行为；显式写法便于定时任务自解释）")
    wp_mode.add_argument("--interval", type=float, metavar="秒",
                         help="持续轮询间隔（秒）；给了就进入持续轮询")
    wp.add_argument("--count", type=int, default=0, metavar="N",
                    help="持续轮询最多跑 N 轮（0 = 不限，默认 0）")
    wp.add_argument("--no-mdns", action="store_true",
                    help="完全不碰 mDNS，只读 ARP 表（最快，~几十毫秒）")
    wp.add_argument("--mdns-active", action="store_true",
                    help="mDNS 改用主动查询（会发组播包，发现更全；"
                         "默认只听不发，零发包）")
    wp.add_argument("--save-snapshot", action="store_true",
                    help="把台账存为一条快照（默认不存；只能配合单次轮询）")
    wp.add_argument("--note", metavar="备注", help="快照备注（配合 --save-snapshot）")
    wp.add_argument("--fail-on-change", action="store_true",
                    help="本次有新设备时以退出码 2 结束（便于脚本判断）")
    wp.add_argument("-f", "--format", choices=("text", "json"), default="text")
    wp.add_argument("-o", "--output", metavar="文件")
    wp.set_defaults(func=cmd_watch)

    # ── schedule ──
    cp = sub.add_parser("schedule", help="注册/卸载/查询定时扫描计划任务",
                        parents=[common],
                        description="把「扫描 + 存快照 + 变更告警」注册为系统计划任务"
                                    "（Windows schtasks / Linux·macOS crontab），"
                                    "实现无人值守的资产变更监控。")
    grp = cp.add_mutually_exclusive_group(required=True)
    grp.add_argument("--register", action="store_true", help="注册（或覆盖）计划任务")
    grp.add_argument("--unregister", action="store_true", help="删除计划任务")
    grp.add_argument("--status", action="store_true", help="查询计划任务是否存在")
    cp.add_argument("-r", "--range", action="append", dest="ranges", metavar="范围",
                    help="IP 范围，可重复（--register 时必填）")
    cp.add_argument("--name", metavar="任务名",
                    help=f"计划任务名（默认「{_sched.DEFAULT_TASK_NAME}」）")
    cp.add_argument("--freq", choices=("minute", "hourly", "daily"), default="daily",
                    help="扫描频率（默认 daily）")
    cp.add_argument("--interval", type=int, default=1, metavar="N",
                    help="间隔：minute=每 N 分钟(1-1439)、hourly=每 N 小时(1-23)")
    cp.add_argument("--at", metavar="HH:MM", default="09:00",
                    help="daily 频率的执行时刻（默认 09:00）")
    cp.add_argument("--level", choices=("quick", "standard", "all"), default="quick",
                    help="端口扫描级别（默认 quick）")
    cp.add_argument("--note", metavar="备注", help="快照备注")
    cp.add_argument("--no-notify", action="store_true",
                    help="定时任务不发送变更告警（默认会发）")
    cp.add_argument("--notify-config", metavar="文件",
                    help="通知配置文件路径（默认：数据目录下的 notify.json）")
    cp.add_argument("--highest", action="store_true",
                    help="以最高权限运行（SYN 半开扫描 / ARP 主动探测需要管理员权限）")
    cp.add_argument("-q", "--quiet", action="store_true", help="定时任务静默运行")
    cp.set_defaults(func=cmd_schedule)

    # scan 与 diff 都会真正发起扫描，因此都需要 SNMPv3 参数。
    # 放在最后统一挂载，避免两处 add_argument 各写一遍、日后再漂移。
    for _sub in (sp, dp):
        _add_snmp_v3_args(_sub)

    return p


def main(argv=None) -> int:
    # 必须早于 build_parser()：argparse 的 --help 里含中文 metavar（如「用户名」），
    # 在 cp1252 下会直接崩在 parse_args 内部，用户连帮助都看不到。
    _force_utf8_stdio()

    parser = build_parser()
    args = parser.parse_args(argv)

    # 日志初始化（早于 i18n，这样 i18n 失败才有地方记录）。
    # console=False：CLI 的 stdout 是给脚本消费的数据、stderr 是进度文本，
    # 都不应被日志混入；诊断信息统一落到数据目录下的 ipscanner.log。
    import app_logging
    app_logging.setup(console=False)
    _log = app_logging.get_logger(__name__)

    # 初始化 i18n（必须在加载语言相关常量之前）
    try:
        import i18n
        i18n.init(getattr(args, "lang", None))
    except Exception as e:  # noqa: BLE001
        # 此前是静默 pass：语言包损坏/缺失时界面会整体退回源语言，
        # 用户只会觉得"语言选项没生效"，完全无从排查。
        _log.warning("i18n 初始化失败，本次运行将使用源语言: %s", e, exc_info=True)

    # 数据目录可写性自检：提前给出明确错误，而不是在扫描中途炸掉
    try:
        from app_paths import data_dir, data_dir_label, data_dir_source
        data_dir()          # 触发探测（必要时创建目录），失败在下面统一处理
        if data_dir_source() in ("user", "temp"):
            log(f"提示: 程序目录不可写，数据目录已回退到 {data_dir_label()}")
    except Exception as e:  # noqa: BLE001
        _log.error("无法确定数据目录: %s", e, exc_info=True)
        log(f"错误: 无法确定数据目录: {e}")
        return EXIT_ENV

    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        log("已中断")
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK
    except Exception as e:  # noqa: BLE001
        _log.error("命令执行失败: %s", e, exc_info=True)
        log(f"错误: {e}")
        if os.environ.get("IPSCANNER_DEBUG"):
            import traceback
            traceback.print_exc()
        return EXIT_ERROR
    finally:
        # 关闭 SQLite 连接并做 WAL checkpoint，否则残留 -wal/-shm，
        # 且最后一批写入仍在 WAL 里（脚本拷走 .db 会以为数据丢了）。
        # 放 finally：中断 / 异常 / SystemExit 路径也必须执行清理。
        # db_util.shutdown() 契约上不抛异常，不会污染退出码。
        import db_util
        db_util.shutdown()


if __name__ == "__main__":
    sys.exit(main())
