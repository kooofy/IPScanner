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
    python cli.py scan -iL targets.txt --level quick
    python cli.py scan -r 10.0.0.0/24 --protocols HTTP,HTTPS,SNMP --format json -o out.json
    python cli.py scan -r 192.168.1.0/24 --save-snapshot --note "周一巡检"
    python cli.py diff -r 192.168.1.0/24 --fail-on-change
    python cli.py diff --from 3 --to 4
    python cli.py history --list
    python cli.py history --query --device-class 打印机 --format csv
    python cli.py audit --window 168
    python cli.py nagios --crit-new 3          # Nagios/Icinga 插件（退出码 0/1/2/3）

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
from dataclasses import dataclass

# 版本号唯一来源：version.py。不要在这里写死字面量，
# 否则与 GUI 关于对话框、spec 产物名会各说各话。
from version import __version__

# 礼貌模式（v2.1 §2.4）。放在顶层 import 而非函数内：`build_parser()` 在
# 模块 import 期就要读 `throttle.POLICY_NAMES` / `DEFAULT_POLICY` 来拼
# `--help`；而且 throttle 本身零 PyQt 零三方，import 成本可忽略。
from scanner import throttle

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

# 资产表（1.1-③）：一行一台设备，按 identity_key 去重。identity_key 是资产维度
# 的主键（MAC 优先），故放在首位；services / seen_count 是资产表独有的列。
_ASSET_COLUMNS = (
    "identity_key", "ip", "status", "mac", "hostname", "vendor",
    "device_class", "os_guess", "open_ports", "services",
    "location", "user", "remark", "first_seen", "last_seen", "seen_count",
)

#: 表格视图在 `_ASSET_COLUMNS` 之外**多一列**「身份来源」—— 让人一眼看出这台
#: 是靠 MAC 还是靠指纹认回来的（v2.0 §2.1：降级身份必须可解释）。
#: CSV 与 JSON **不加**这列：它们是给脚本/表格软件吃的，要规范字段，
#: 不要翻译后的展示串（JSON 里本来就有原始 `fingerprint` 字段）。
_ASSET_TABLE_COLUMNS = _ASSET_COLUMNS + ("identity_source",)

#: assets 表格的中文表头。CLI 输出**不随语言切换**（本工具的定位是「脚本可解析」，
#: 表头就是给人看的固定中文；要机器可读请用 `-f json`）。
_ASSET_TABLE_HEADERS = ("身份键", "IP", "状态", "MAC", "主机名", "厂商",
                        "设备类型", "操作系统", "开放端口", "服务", "位置",
                        "使用者", "备注", "首见", "末见", "次数", "身份来源")


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

    探到 TLS 证书、名字响应器或 SMB 事实的设备会多带一个 `security_findings`
    键（见 `history_store.tls_cert_facts` / `responder_facts` / `smb_facts`）——
    与 GUI 走的是同一条落库路径，免得"命令行存的快照没有安全事实"。
    """
    from history_store import responder_facts, smb_facts, tls_cert_facts

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
        facts += responder_facts(getattr(r, "name_responder", None))
        facts += smb_facts(getattr(r, "smb", None))
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


def _read_target_file(path):
    """从文件读扫描目标（``-iL``，nmap 习惯）：每行一个 CIDR/IP。

    跳过空行与 ``#`` 开头的注释行。返回 ``(targets, error)``：
    * 文件不存在 / 是目录 / 读不了 / 不是 UTF-8 → 带路径的错误；
    * 某一行不是合法 IPv4 范围 → 错误里**逐行列出行号与原文**
      （IPv6 单独说明，因为那类用户真正的问题是"本工具只扫 IPv4"）；
    * 单行超过 65536 上限 → 同样带行号（总量上限由 ``_run_scan`` 统一把关）；
    * 整个文件没有任何有效目标 → 明说，绝不返回空列表让上层静默扫 0 个。

    逐行校验复用引擎的 ``count_ip_range()`` —— 与 ``-r`` 的值同一套口径，
    不存在"命令行能过、文件里不能过"的双标。
    """
    from scanner.range import (MAX_IPS_PER_RANGE, count_ip_range,
                               is_ipv6_range)

    if not path:
        return [], "-iL/--target-file 需要文件路径"
    # 先判目录：Windows 上 open(目录) 抛的是 PermissionError 而不是
    # IsADirectoryError，光靠 except 分支在两边对不上。
    if os.path.isdir(path):
        return [], f"目标文件是目录：{path}"
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return [], f"目标文件不存在：{path}"
    except UnicodeDecodeError:
        return [], f"目标文件不是 UTF-8 文本：{path}"
    except OSError as e:
        return [], f"目标文件读不了（{path}）：{e}"

    def _short(text: str) -> str:
        return text if len(text) <= 60 else text[:57] + "..."

    targets = []
    bad = []
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        n = count_ip_range(line)
        if n <= 0:
            if is_ipv6_range(line):
                bad.append(f"第 {lineno} 行「{_short(line)}」是 IPv6 范围，"
                           f"本工具目前只支持 IPv4 扫描")
            else:
                bad.append(f"第 {lineno} 行「{_short(line)}」不是合法的 IP 范围")
            continue
        if n > MAX_IPS_PER_RANGE:
            bad.append(f"第 {lineno} 行「{_short(line)}」包含 {n} 个地址，"
                       f"超过单次上限 {MAX_IPS_PER_RANGE} 个")
            continue
        targets.append(line)
    if bad:
        return [], ("目标文件有以下行无法使用：\n  "
                    + "\n  ".join(bad) + f"\n（文件：{path}）")
    if not targets:
        return [], (f"目标文件里没有有效目标（{path}）—— "
                    f"空行与 # 开头的注释行都会被跳过")
    return targets, ""


def _merge_targets(args):
    """合并 ``-r`` 与 ``-iL`` 两个来源的目标，返回 ``(ranges, error)``。

    v2.2 §3.2：两者**至少其一**（也可并用，``-r`` 在前、文件行在后）。
    文件目标的逐行校验（含行号）在 ``_read_target_file`` 完成；
    合并后的总量上限由 ``_run_scan`` 的既有循环统一把关 —— 同一套限额，
   不管目标从哪个渠道来。
    """
    ranges = [r for r in (getattr(args, "ranges", None) or [])
              if r and str(r).strip()]
    target_file = getattr(args, "target_file", None)
    if target_file:
        file_targets, error = _read_target_file(target_file)
        if error:
            return [], error
        ranges.extend(file_targets)
    if not ranges:
        return [], ("请用 -r/--range 指定扫描范围，或用 -iL/--target-file "
                    "从文件读取目标（两者至少其一，也可并用）")
    return ranges, ""


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


def _resolve_throttle(args):
    """从 args 解析礼貌档；档名非法要**在扫描前**就失败。

    放在这里而不是等 argparse 的 `choices`：库调用方（直接构造 args 命名空间）
    可能绕过 choices。真正扫出去才发现档位写错，等于白扫一个网段。
    """
    from scanner import throttle
    raw = getattr(args, "throttle", None)
    try:
        return throttle.resolve_policy(raw)
    except ValueError as e:
        raise ValueError(f"错误: {e}") from None


def _audit_throttle(policy, args=None, db_path=None) -> None:
    """把本次扫描用的礼貌档落审计库（v2.1 §2.4 验收项之一）。

    🔴 `detail` 里只放**语言无关规范值**（`throttle.audit_detail()` 产出），
    绝不落 `tr()` 结果 —— 否则切一次界面语言，历史审计的含义就变了。
    写审计失败只告警：审计是旁路，不该让一次已经成功的扫描因此判失败。
    """
    if db_path is None and args is not None:
        db_path = _db_path(args)
    try:
        import audit_log
        from scanner import throttle
        audit_log.log_event(
            audit_log.CAT_SCAN, "扫描节流档位",
            json.dumps(throttle.audit_detail(policy), sort_keys=True),
            db_path=db_path,
        )
    except Exception as e:  # noqa: BLE001
        warn(f"记录礼貌档到审计日志失败（不影响本次扫描）: {e}")


def _audit_scan_summary(args, ranges, total_ips, online, ports, protocols,
                        policy=None, db_path=None) -> None:
    """把本次扫描写入**结构化**审计汇总（v2.2 §3.3 自查视图的数据源）。

    与 GUI `ScanMixin._audit_scan_summary()` **同口径**（键完全一致）——
    CLI 与 GUI 两条扫描路径汇入同一张视图。

    🔴 detail 只放**语言无关值**（网段串 / 计数 / 协议规范码）。既有扫描
    事件的 action/detail 是 `tr()` 结果（给人看的），拿它们聚合就是拿
    tr() 结果作比较 —— 切一次界面语言，聚合结果随语言漂移。

    写审计失败只告警：审计是旁路，不该让一次已经成功的扫描判失败。
    """
    if db_path is None:
        db_path = _db_path(args)
    try:
        from scanner.range import count_ip_range
        import audit_log
        audit_log.log_scan_summary({
            "ranges": [{"range": r, "ips": count_ip_range(r)}
                       for r in ranges or []],
            "ips": total_ips,
            "online": online,
            "protocols": list(protocols or []),
            "ports_scanned": len(ports) if ports else None,
            "throttle": policy.name if policy is not None else "",
            "source": "cli",
        }, db_path=db_path)
    except Exception as e:  # noqa: BLE001
        warn(f"记录扫描汇总到审计日志失败（不影响本次扫描）: {e}")


def _run_scan(args):
    """执行一次扫描，返回 (results, scanner)。

    参数非法 / 范围超限 / 用户中断时返回 ``(None, None)``（错误信息已写入 stderr），
    由调用方转成退出码 —— 这样 ``main()`` 对库调用方保持"只返回 int"的契约。
    """
    from scanner import NetworkScanner
    from scanner.range import (count_ip_range, is_ipv6_range,
                               MAX_IPS_PER_RANGE, MAX_IPS_TOTAL)

    # 目标来源合并（v2.2 §3.2）：-r 与 -iL 至少其一。放在最前面 ——
    # 文件读失败要**在**其它参数解析 / 扫描构建之前就给出带行号的错误，
    # 而不是等用户看到"无法解析 IP 范围"再去猜是哪来的。
    ranges, range_error = _merge_targets(args)
    if range_error:
        log(f"错误: {range_error}")
        return None, None
    args.ranges = ranges

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

    # 凭据档册（v2.0 §2.3）：按目标 IP 选 SNMP 凭据。与上面的全局 SNMPv3
    # 是"并存、档册优先"的关系 —— 档册覆盖到的目标用档册的凭据，没配档册时
    # 完全走历史路径。档册启用时同样要把 SNMP 加进协议列表，否则引擎不做识别。
    credential_book, cred_error = _resolve_credential_book(args)
    if cred_error:
        log(f"错误: {cred_error}")
        return None, None
    if credential_book is not None:
        from scanner.constants import SVC_SNMP as _SVC
        items = list(protocols or [])
        if not any(p.upper() == _SVC for p in items):
            items.append(_SVC)
        protocols = items
        log(f"凭据档已启用：{len(credential_book)} 档（按目标网段选择）")

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

    # 礼貌模式（v2.1 §2.4）：档位在整个扫描期间保持激活 ——
    # `--threads` 之外，端口探测的顺序随机化与令牌桶限速都从这里取档。
    # fast 档下三件事全是 no-op，因此不传 `--throttle` 与改造前逐字节等价。
    policy = _resolve_throttle(args)
    if policy.name != throttle.DEFAULT_POLICY:
        log(f"礼貌模式：{policy.describe()}")

    scanner = NetworkScanner()
    t0 = time.monotonic()
    with throttle.active_policy(policy):
        try:
            results = scanner.scan(
                ip_ranges=list(args.ranges),
                timeout_ms=getattr(args, "timeout", 1000),
                # ping 阶段是发包最密集的一环（每 IP 一个 ICMP/ARP），
                # 所以礼貌档的并发上限夹在这里最有效。
                max_threads=throttle.concurrency_for(
                    getattr(args, "threads", 100)),
                scan_ports_flag=ports is not None,
                protocols=protocols,
                tcp_scan_mode=getattr(args, "tcp_mode", "connect"),
                mdns_discovery=not getattr(args, "no_mdns", False),
                ports=ports,
                progress_callback=_make_progress(not getattr(args, "quiet", False)),
                library_lookup=_build_library_lookup(getattr(args, "library", False)),
                snmp_v3_user=snmp_v3_user,
                credential_book=credential_book,
            )
        except KeyboardInterrupt:
            scanner.stop()
            log("已中断")
            return None, None

    _audit_throttle(policy, args)

    for w in getattr(scanner, "warnings", []) or []:
        warn(w)

    elapsed = time.monotonic() - t0
    online = sum(1 for r in results if r.status == "online")
    # v2.2 §3.3：自查视图的结构化汇总。放在这里（而非 _audit_throttle 旁）
    # 是因为要等 online 数算出来；记录的是**实际用过**的协议列表
    # （可能被 SNMPv3 / 凭据档追加过），不是用户原话。
    _audit_scan_summary(args, args.ranges, total_ips, online, ports,
                        protocols, policy=policy)
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


def _collect_responders(args, results):
    """探测 LLMNR / NBNS 响应器（`--name-responder`），把结果挂到 results 上。

    与 `_collect_switch_maps` 不同，这里**不要求** `--save-snapshot`：
    转发表只有落库一个去处，而"有没有欺骗响应器"这件事本身就能用一行日志
    回答（那正是命令行用户最想要的）。没给 `--save-snapshot` 时只是不落库。

    红线（见 `scanner/llmnr_nbns.py`）：只发一个查询包，不应答别人的查询、
    不注册名字、不伪造 MAC/IP、**绝不投毒**。
    """
    from scanner.llmnr_nbns import apply_responders, probe_responders

    try:
        found = probe_responders()
    except Exception as e:  # noqa: BLE001
        warn(f"名字响应器探测失败: {e}")
        return
    outside = apply_responders(results, found)
    if not found:
        log("未发现名字响应器（干净网络应有的结果）")
        return
    for ip in sorted(found):
        protos = ", ".join(sorted(p.upper() for p in found[ip]))
        log(f"名字响应器: {ip} 应答了不存在的主机名（{protos}）")
    if outside:
        # 不在扫描范围内的响应器**不伪造设备行**，只提示 —— 快照记的是台账，
        # 塞一台没扫到的设备会让设备数失真。
        log(f"其中 {len(outside)} 个不在本次扫描范围内，未计入快照: "
            + ", ".join(outside))


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

    # 名字响应器（可选）：同样在**保存快照之前**采集 —— 结果挂在 results 上，
    # 快照保存时经 `_snapshot_devices` 一并落库（见该函数）。与转发表不同，
    # 这里不要求 --save-snapshot：探测结果本身就能用日志回答。
    if getattr(args, "name_responder", False):
        _collect_responders(args, results)

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

    # 暴露面（v2.1 §2.3）：按**当前筛选之后**的 results 走，不另读全量
    # —— 铁律：附加段跟随筛选（见 tests/test_export_filter.py 的坑）。
    exposure_payload = None
    if getattr(args, "exposure", False):
        from scanner import exposure as _exposure
        exposure_payload = _exposure.match_results(results)

    if args.format == "json":
        payload = {
            "version": __version__,
            "scanned_at": time.time(),
            "device_count": len(records),
            "online_count": sum(1 for r in records if r["status"] == "online"),
            "devices": records,
        }
        if exposure_payload is not None:
            # 键固定英文、值全为规范值（scanner/exposure.py 的语言无关 to_dict）。
            payload["exposure"] = exposure_payload.to_dict()
        emit(render_json(payload), args.output)
    elif args.format == "csv":
        emit(render_csv(records, _RESULT_COLUMNS), args.output)
        if exposure_payload is not None:
            # CSV 是给程序读的：末尾塞一段中文文本会污染解析，所以明确
            # **不**输出并说明去哪儿拿 —— 静默丢弃才是坑。
            warn("--exposure 在 --format csv 下不输出（会破坏 CSV 结构）；"
                 "请改用 --format json（exposure 字段）或 table（末尾段）。")
    else:
        body = render_table(records, _RESULT_COLUMNS)
        if exposure_payload is not None:
            body = body + "\n" + _render_exposure_text(exposure_payload)
        emit(body, args.output)

    if notifiers:
        _notify_changes(results, baseline_id, notifiers, args, notify_config)
    _deliver_report(args, baseline_id)
    return EXIT_OK


def _deliver_report(args, baseline_id) -> None:
    """扫描收尾时按需生成报表（v2.0 §2.2 的「定时投递」链路）。

    ⚠ **刻意做成扫描内部的一个收尾动作**，而不是"两条命令串起来"：
    schtasks 的 `/TR` 只收单条命令、cron 每行也只有一条，串联要么需要包装脚本
    （多一个要分发的文件），要么在注册时拼 `&&`（schtasks 不认）。
    放进 scan 内部 → 一次进程、无包装脚本、与 `--notify` 同一位置。

    报表生成失败**绝不**影响扫描本身（扫描已经完成、快照已经落库）——
    只是 `warn` 一句，退出码仍是成功。
    """
    report = (getattr(args, "report", "") or "").strip().lower()
    if not report:
        return
    import history_store
    import report_engine

    try:
        out = (getattr(args, "report_output", "") or "").strip()
        if not out:
            from app_paths import data_dir
            out = os.path.join(
                data_dir(), "report_%s_%s.html"
                % (report, time.strftime("%Y%m%d_%H%M%S")))
        db = _db_path(args)

        if report == "changes":
            import change_detector as cd
            snaps = history_store.list_snapshots(db_path=db)
            ids = [s["id"] for s in snaps]
            to_id = ids[-1] if ids else None
            from_id = ids[-2] if len(ids) >= 2 else to_id
            if to_id is None or from_id is None:
                warn("没有足够快照生成变更报表，跳过。")
                return
            old = history_store.get_snapshot(from_id, db_path=db)
            new = history_store.get_snapshot(to_id, db_path=db)
            if old is None or new is None:
                warn("变更报表所需快照不存在，跳过。")
                return
            changes = cd.detect_changes(
                [_SnapResult(d) for d in new["devices"]], old["devices"])
            html_out = report_engine.render_report("changes", changes=changes)
        else:
            rows = history_store.list_assets(db_path=db)
            html_out = report_engine.render_report(report, assets=rows)

        with open(out, "w", encoding="utf-8") as f:
            f.write(html_out)
        log("已生成报表 → %s（%d 字节）" % (out, len(html_out)))
    except Exception as e:  # noqa: BLE001  — 报表失败不该让整个扫描失败
        warn("生成报表失败（扫描本身不受影响）: %s" % e)


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
        if not (args.ranges or getattr(args, "target_file", None)):
            log("错误: 需要 -r/--range 或 -iL/--target-file"
                "（或改用 --from/--to 比较两个快照）")
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


# ────────────────────────────── 资产表 ──────────────────────────────

def _fingerprint_identified(row) -> bool:
    """这台资产的**身份键是不是只能靠指纹得到**（而非 MAC/IP 直接算得出）。

    判据：把该行记录的 MAC/IP 丢回 `identity_key()`，若得到的键与
    `assets.identity_key` 相同，说明它就是靠 MAC/IP 认的（指纹只是顺手登记的
    线索而已）；不同则说明身份是**跨随机 MAC 认回来的**。

    没有 `identity_key()` 可用（不该发生）时退回 False —— 宁可少标，不误导。
    """
    import history_store
    key = (row.get("identity_key") or "").strip()
    if not key:
        return False
    if history_store.is_fingerprint_key(key):
        return True
    direct = history_store.identity_key(row.get("mac", ""), row.get("ip", ""))
    return bool(direct) and direct != key


def cmd_assets(args) -> int:
    """列举资产表（一行一台设备，按 MAC 身份键去重合并后的当前状态）。

    资产表是 1.1 新增的"资产维度"视图：与 `history --query` 按 IP 聚合 `devices`
    不同，这里按 identity_key（MAC 优先）读 `assets`，换过 IP 的设备只算一台。

    **JSON 输出保持语言无关**（字段即 `assets` 表里的规范值，device_class 是源串），
    text 输出才翻译、并附 human-readable 首见/末见时间 —— 脚本消费 JSON，人看 text。
    """
    import history_store

    db = _db_path(args)

    if args.count:
        n = history_store.asset_count(
            device_class=args.device_class,
            network=args.network,
            ip_substr=args.ip,
            db_path=db,
        )
        if args.format == "json":
            emit(render_json({"count": n}), args.output)
        else:
            emit(str(n), args.output)
        return EXIT_OK

    rows = history_store.list_assets(
        device_class=args.device_class,
        network=args.network,
        ip_substr=args.ip,
        limit=args.limit,
        offset=args.offset,
        db_path=db,
    )
    if not rows:
        emit("无资产记录" if args.format != "json" else render_json([]), args.output)
        return EXIT_OK
    for r in rows:
        r["first_seen"] = _fmt_time(r.get("first_seen"))
        r["last_seen"] = _fmt_time(r.get("last_seen"))
        # 身份来源（展示用，**不改** r["fingerprint"]）—— JSON 仍拿原始哈希，
        # 人看的 table 用这一列说清「这台是靠 MAC 还是靠指纹认的」。
        #
        # ⚠ 判据不是「有没有指纹」（几乎每台有主机名的设备都会登记指纹），
        #   而是「**这把键是不是只能靠指纹得到**」 —— 即键与该行 MAC 直接算出的
        #   键不同。否则会给一台老老实实用 MAC 的 PC 错标成「指纹」。
        r["identity_source"] = ("指纹" if _fingerprint_identified(r) else "MAC/IP")
    if args.format == "json":
        emit(render_json(rows), args.output)
    elif args.format == "csv":
        emit(render_csv(rows, _ASSET_COLUMNS), args.output)
    else:
        emit(render_table(rows, _ASSET_TABLE_COLUMNS, _ASSET_TABLE_HEADERS),
             args.output)
    return EXIT_OK


def cmd_export(args) -> int:
    """导出资产表为互操作格式（Nmap XML / Zabbix LLD / NetBox CSV / Oxidized router.db）。

    纯文件导出：读 ``assets``（1.1 读路径，与 `assets` 子命令同源），调
    ``interop_export.export_interop`` 写出，**零网络、零新依赖、语言无关**。
    导出的全是规范值（status→online/offline、device_class→中文源串），
    供别的系统解析，绝不落 ``tr()`` 展示串。

    详见 `docs/ROADMAP_V1.9.md` §1.2 与 `interop_export.py`。
    """
    import history_store
    import interop_export

    db = _db_path(args)
    rows = history_store.list_assets(
        device_class=args.device_class,
        network=args.network,
        ip_substr=args.ip,
        limit=args.limit,
        offset=args.offset,
        db_path=db,
    )
    if args.output:
        interop_export.export_interop(args.format, rows, args.output)
        log(f"已导出 {len(rows)} 台资产 → {args.output}（格式: {args.format}）")
    else:
        sys.stdout.buffer.write(interop_export.build_interop(args.format, rows))
        sys.stdout.buffer.flush()
        log(f"已导出 {len(rows)} 台资产（格式: {args.format}，已写入 stdout）")
    return EXIT_OK


# ────────────────────────── 报表引擎 ──────────────────────────

def cmd_report(args) -> int:
    """把台账渲染成**版式可编辑**的 HTML 报表（v2.0 §2.2）。

    三种内置模板（也可用 ``--template-file`` 指定任意模板文件）：

    * ``assets``   资产清单：一行一台设备（读 ``list_assets``）；
    * ``changes``  变更摘要：两份快照之间发生了什么（读 ``detect_changes``）；
    * ``exposure`` 暴露面摘要：按「开放端口 + 服务」聚合，看谁开了什么。

    **语言无关**：报表里的值一律落规范值（status → online/offline、
    device_class → 中文源串、时间 → ISO），模板文案由模板文件承载、不进语言包 ——
    与 ``export``（互操作导出）同口径。详见 ``report_engine.py``。
    """
    import history_store
    import report_engine

    kind = args.template
    db = _db_path(args)

    # 自定义模板文件（_--template-file_）优先于内置模板。
    template_text = None
    if args.template_file:
        try:
            with open(args.template_file, encoding="utf-8") as f:
                template_text = f.read()
        except OSError as e:
            log("错误: 无法读取模板文件 %s：%s" % (args.template_file, e))
            return EXIT_ERROR
        if not template_text.strip():
            log("错误: 模板文件为空: %s" % args.template_file)
            return EXIT_ERROR

    # ── 数据装配 ──
    if kind == "changes":
        import change_detector as cd

        snaps = history_store.list_snapshots(db_path=db)
        ids = [s["id"] for s in snaps]
        if not ids:
            log("错误: 没有任何历史快照，无法生成变更报表")
            return EXIT_ERROR
        from_id = args.from_id if args.from_id is not None else (
            ids[-2] if len(ids) >= 2 else ids[-1])
        to_id = args.to_id if args.to_id is not None else ids[-1]
        old = history_store.get_snapshot(from_id, db_path=db)
        new = history_store.get_snapshot(to_id, db_path=db)
        if old is None:
            log("错误: 快照 #%s 不存在" % from_id)
            return EXIT_ERROR
        if new is None:
            log("错误: 快照 #%s 不存在" % to_id)
            return EXIT_ERROR
        changes = cd.detect_changes([_SnapResult(d) for d in new["devices"]],
                                    old["devices"])
        log("变更报表基线: 快照 #%s → #%s（%d 条变更）"
            % (from_id, to_id, len(changes)))
        html_out = report_engine.render_report(
            "changes", changes=changes, template_text=template_text,
            generated_at=args.generated_at)
    else:
        rows = history_store.list_assets(
            device_class=args.device_class,
            network=args.network,
            ip_substr=args.ip,
            limit=args.limit,
            offset=args.offset,
            db_path=db,
        )
        log("报表数据: %d 台资产（模板 %s）" % (len(rows), kind))
        html_out = report_engine.render_report(
            kind, assets=rows, template_text=template_text,
            generated_at=args.generated_at)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html_out)
        log(f"已生成报表 → {args.output}（{len(html_out)} 字节）")
    else:
        sys.stdout.write(html_out)
        if not html_out.endswith("\n"):
            sys.stdout.write("\n")
    return EXIT_OK


# ────────────────────────── 凭据配置档 ──────────────────────────

def cmd_credentials(args) -> int:
    """列出 / 校验凭据配置档（v2.0 §2.3）。

    **绝不回显明文口令**：只显示档名、作用域、协议，以及敏感值是否
    以 ``env:VAR`` 引用（引用显示为 ``env:VAR``，且只在 ``--format json``
    里附 ``resolved: true/false`` 表"这个变量当前解析得出值"）。
    直接写进配置的明文**不打印**（避免终端日志泄露）。
    """
    from credentials import (default_config_path, load_profiles,
                             PROTO_SNMP_V1, PROTO_SNMP_V2C, PROTO_SNMP_V3,
                             PROTO_WMI, protocol_label)

    path = args.file or default_config_path()
    profiles = load_profiles(path)
    if not profiles:
        log(f"错误: 凭据文件 {path!r} 不存在或没有任何凭据档")
        return EXIT_ERROR
    if args.proto:
        profiles = [c for c in profiles if c.protocol == args.proto]
        if not profiles:
            log(f"没有 {protocol_label(args.proto)} 协议的凭据档")
            return EXIT_ERROR

    # 敏感字段名（按协议）—— 用于"是否 env: 引用 / 能否解析"的判定。
    # SNMP v1/v2c 只有 community；v3 有 auth_key/priv_key；WMI 有 password。
    def _secrets_of(cred):
        if cred.protocol in (PROTO_SNMP_V1, PROTO_SNMP_V2C):
            return [("community", cred.community)]
        if cred.protocol == PROTO_SNMP_V3:
            return [("auth_key", cred.auth_key), ("priv_key", cred.priv_key)]
        if cred.protocol == PROTO_WMI:
            return [("password", cred.password)]
        return []

    def _secret_state(raw: str):
        """返回 (是否 env: 引用, 是否有值)。**不返回明文**。"""
        if not raw:
            return False, False
        if isinstance(raw, str) and raw.startswith("env:"):
            from notifier import resolve_secret
            return True, bool(resolve_secret(raw))
        return False, True   # 明文：有值（但不打印具体内容）

    if args.format == "json":
        import json as _json
        payload = {"path": path, "profiles": []}
        for cred in profiles:
            item = {
                "name": cred.name,
                "scope": list(cred.scope),
                "protocol": cred.protocol,
                "username": cred.username,
                "domain": cred.domain,
                "auth_proto": cred.auth_proto,
                "priv_proto": cred.priv_proto,
            }
            for field, raw in _secrets_of(cred):
                is_env, has_value = _secret_state(raw)
                item[field] = {"env": is_env, "resolved": has_value}
            payload["profiles"].append(item)
        text = _json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        lines = [f"凭据文件: {path}", f"共 {len(profiles)} 档"]
        for cred in profiles:
            lines.append("")
            lines.append(f"  ● {cred.name or '(未命名)'}  [{protocol_label(cred.protocol)}]")
            lines.append(f"    作用域: {', '.join(cred.scope) or '(未配)'}")
            if cred.username:
                who = cred.username
                if cred.domain:
                    who = f"{cred.domain}\\{who}"
                lines.append(f"    账户: {who}")
            for field, raw in _secrets_of(cred):
                is_env, has_value = _secret_state(raw)
                if not raw:
                    lines.append(f"    {field}: (未配)")
                elif is_env:
                    state = "已解析" if has_value else "环境变量未设置/为空"
                    # 显示 env:VAR 引用本身（变量名不敏感），但不显示值
                    lines.append(f"    {field}: {raw}（{state}）")
                else:
                    lines.append(f"    {field}: ****（明文，建议改用 env: 引用）")
        text = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        log(f"已写出凭据清单 → {args.output}")
    else:
        sys.stdout.write(text + "\n")
    return EXIT_OK


# ────────────────────────── Nmap XML 读入 ──────────────────────────

def cmd_import(args) -> int:
    """读入外部 Nmap XML（``nmap -oX``）并入资产表。

    🔴 **语义警告（ROADMAP §3 点名的风险）**：Nmap 的 host 状态机与本项目的
    ``status`` **不是一回事** —— Nmap ``up`` = 「至少一个探针有回应」，
    ``down`` = 「所有探针无回应（也可能只是被屏蔽）」。本命令按字面映射
    （`up`→online / `down`→offline / 其它→未知），并在结果里保留原样的
    ``nmap_state`` 与 ``source=nmap``，使「谁说的」永远可追。

    默认只**预演**（``--dry-run``），确认无误后加 ``--save`` 才写库 ——
    导入是**批量写**，不能一敲回车就改台账。

    详见 `docs/ROADMAP_V1.9.md` §6（补丁轨道）。
    """
    import interop_export
    import history_store

    try:
        with open(args.input, "rb") as f:
            raw = f.read()
    except OSError as e:
        log(f"错误: 无法读取 {args.input}: {e}")
        return EXIT_ENV

    rows = interop_export.parse_nmap_xml(raw)
    if not rows:
        log(f"未从 {args.input} 解析出任何主机（文件为空或不是 Nmap XML）")
        return EXIT_ERROR

    up = sum(1 for r in rows if r["status"] == "online")
    down = sum(1 for r in rows if r["status"] == "offline")
    unknown = len(rows) - up - down
    log(f"解析到 {len(rows)} 台主机：up {up} / down {down} / 未知 {unknown}")

    if args.format == "json":
        emit(json.dumps({"data": rows}, ensure_ascii=False, indent=2),
             args.output)
    elif args.format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["ip", "mac", "hostname", "status", "nmap_state",
                    "open_ports", "services", "os_guess"])
        for r in rows:
            w.writerow([r["ip"], r["mac"], r["hostname"], r["status"],
                        r["nmap_state"], r["open_ports"], r["services"],
                        r["os_guess"]])
        emit(buf.getvalue(), args.output)
    else:
        # table：人看的预览。两列状态都列出来，避免把 Nmap 的判定
        # 误读成我们的扫描结论（这正是本命令最容易出错的地方）。
        head = ("IP", "MAC", "主机名", "状态", "Nmap 状态", "端口")
        body = [(r["ip"] or "—", r["mac"] or "—", r["hostname"] or "—",
                 r["status"] or "未知", r["nmap_state"] or "—",
                 r["open_ports"] or "—") for r in rows]
        widths = [max(len(str(x)) for x in col)
                  for col in zip(head, *body)] if body else [len(h) for h in head]
        lines = ["  ".join(h.ljust(w) for h, w in zip(head, widths))]
        lines.append("  ".join("-" * w for w in widths))
        for row in body:
            lines.append("  ".join(str(c).ljust(w)
                                   for c, w in zip(row, widths)))
        emit("\n".join(lines) + "\n", args.output)

    if not args.save:
        log("以上为预演（未写库）。确认无误后加 --save 写入资产表。")
        return EXIT_OK

    payload = [{"ip": r["ip"], "mac": r["mac"], "hostname": r["hostname"],
                "status": r["status"], "open_ports": r["open_ports"],
                "services": r["services"], "os_guess": r["os_guess"]}
               for r in rows]
    sid = history_store.save_snapshot(
        payload, note=f"Nmap XML 导入：{args.input}", db_path=_db_path(args))
    log(f"已写入快照 #{sid}：{len(payload)} 台设备")
    return EXIT_OK


# ────────────────────────── 端口利用率 ──────────────────────────

def cmd_ports(args) -> int:
    """每台交换机各端口的接入设备数 / 空闲口（「还有几个口可用」）。

    数据来自**最近一次**扫描落库的交换机转发表 —— 而采集转发表要显式加
    ``scan --switch-map``（**默认关**，见 `docs/ROADMAP_V1.9.md` §6）。

    🔴 因此本命令在**没有数据**时必须说清「是没采过，不是没有设备」，
    并给出下一步该敲什么 —— 否则用户看到空表会得出「我的交换机一个口都没用」
    这个**与事实相反**的结论。

    ⚠ 只报**下限**（有设备的端口数），不编造利用率百分比：转发表里没有空闲口，
    而 `ifNumber` 含环路口 / 聚合口 / vlan 口，拿它当物理端口总数会算错。
    """
    import history_store

    u = history_store.port_utilization(db_path=_db_path(args))
    reason = u["reason"]

    if reason:
        # 规范值 → 人看的说明 + **下一步动作**（不要只说"没有数据"）
        hint, action = _PORT_UTIL_REASON.get(
            reason, ("没有可用的交换机端口数据。", ""))
        log(hint)
        if action:
            log(action)
        if args.format == "json":
            emit(json.dumps(u, ensure_ascii=False, indent=2), args.output)
        return EXIT_OK

    if args.format == "json":
        emit(json.dumps(u, ensure_ascii=False, indent=2), args.output)
        return EXIT_OK

    switches = u["switches"]
    if args.format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["switch_ip", "switch_name", "status", "port_name",
                    "port_source", "device_count", "devices"])
        for sw in switches:
            if sw["status"] != "ok":
                w.writerow([sw["switch_ip"], sw["switch_name"], "error",
                            "", "", "", sw["error"]])
                continue
            for p in sw["ports"]:
                devs = "; ".join(d["ip"] or d["mac"] for d in p["devices"])
                w.writerow([sw["switch_ip"], sw["switch_name"], "ok",
                            p["port_name"], p["port_source"],
                            p["device_count"], devs])
        emit(buf.getvalue(), args.output)
    else:
        lines = []
        for sw in switches:
            if sw["status"] != "ok":
                lines.append(f"{sw['switch_name']} ({sw['switch_ip']}) "
                             f"— 读取失败：{sw['error'] or '未知原因'}")
                lines.append("")
                continue
            lines.append(
                f"{sw['switch_name']} ({sw['switch_ip']}) —— "
                f"{sw['used_port_count']} 个口在用 / 共接入 "
                f"{sw['device_count']} 台设备")
            head = ("端口", "设备数", "接入设备")
            body = []
            for p in sw["ports"]:
                name = p["port_name"] or "(未知端口)"
                if p["port_source"] == "bridge_port":
                    name += " [仅端口号，不确]"
                devs = ", ".join(d["ip"] or d["mac"] for d in p["devices"])
                body.append((name, str(p["device_count"]), devs))
            if not body:
                lines.append("  （转发表可用，但没有记录到任何设备）")
            else:
                widths = [max(len(str(x)) for x in col)
                          for col in zip(head, *body)]
                lines.append("  " + "  ".join(h.ljust(w)
                                              for h, w in zip(head, widths)))
                for row in body:
                    lines.append("  " + "  ".join(str(c).ljust(w)
                                                  for c, w in zip(row, widths)))
            lines.append("")
        lines.append("⚠ 只统计「接了什么」，不含空闲口 —— 转发表里没有空闲口的记录。")
        emit("\n".join(lines) + "\n", args.output)

    if args.output:
        log(f"已导出端口利用率 → {args.output}")
    return EXIT_OK


#: 端口利用率「没有数据」的原因 → (说明, 下一步动作)。规范值来自
#: `history_store.LOCATE_*`，语言无关；文案只在这里翻译（仓库铁律）。
_PORT_UTIL_REASON = {
    "no_snapshot": (
        "还没有任何扫描记录。",
        "请先跑一次扫描（如 `ipscanner scan -r <网段> --save-snapshot`）。",
    ),
    "no_switch_data": (
        "有扫描记录，但从未采集过交换机转发表。",
        "采集需显式开启：`ipscanner scan -r <网段> --save-snapshot --switch-map`"
        "（默认关闭，因为它需要交换机 SNMP 可达）。",
    ),
    "switch_scan_failed": (
        "采集过交换机，但每一台都取不到转发表。",
        "多为 SNMP 不可达 / community 不对；可加 `--community <口令>` 重试。",
    ),
}


# ────────────────────────── 扫描活动自查（v2.2 §3.3） ──────────────────────────

#: 自查「没有数据」的原因（`audit_log.REASON_NO_RECORDS` 规范值，语言无关）
#: → (说明, 下一步动作)。🔴 **必须**给下一步：只说「没有记录」会让用户以为
#: 「这段时间没扫过网」，而真相可能只是「汇总从 v2.2 才开始记录」。
_AUDIT_REASON_TEXT = {
    "no_records": (
        "所选时间窗内没有任何扫描汇总记录。",
        "结构化汇总自 v2.2 起才随每次扫描自动写入 —— 更早的扫描不在其内。"
        "先跑一次 `ipscanner scan -r <网段>`，再回来查就有数据了。",
    ),
}


def cmd_audit(args) -> int:
    """扫描活动自查：过去一段时间向哪些网段发起过多少次扫描（v2.2 §3.3）。

    数据源是 `audit_log` 里**结构化**的扫描汇总（`SUM_ACTION` 行），不是给人
    看的自由文本 detail —— 后者的 action/detail 是 `tr()` 结果，拿它聚合等于
    拿 `tr()` 结果作比较，切一次界面语言结论就漂移（铁律）。

    退出码恒为 0：自查命令里「没记录」不是失败，是要说清的事实。

    ⚠ 审计库与历史快照库是**两个文件**，所以本命令**不认** `--db`（那个是
    历史快照库）——避免把审计查询指到 scan_history.db 上得出空结论。
    """
    import audit_log

    if getattr(args, "db", None):
        # common 父解析器带来的 --db 指的是**历史快照库**；审计库是另一个
        # 文件。 silently 忽略会让用户以为查的是他指定的库 ⇒ 明说不采纳。
        warn("--db 只对历史快照类命令有效；审计库固定用程序数据目录下的 "
             "audit_log.db，本参数已忽略。")

    window = getattr(args, "window", "24")
    hours = None if window == "all" else int(window)
    s = audit_log.activity_summary(hours)

    if args.format == "json":
        emit(render_json(s), args.output)
        return EXIT_OK

    if s["reason"]:
        hint, action = _AUDIT_REASON_TEXT.get(
            s["reason"], ("没有可用的扫描活动数据。", ""))
        lines = [hint]
        if action:
            lines.append("下一步：" + action)
        emit("\n".join(lines) + "\n", args.output)
        return EXIT_OK

    win = ("全部历史" if s["window_hours"] is None
           else "过去 %g 小时" % s["window_hours"])
    lines = ["扫描活动自查（%s）" % win]
    lines.append("  扫描 %d 次 · 涉及 %d 个网段 · 累计覆盖 %d 个地址 · "
                 "在线设备 %d 台次" % (
                     s["scan_count"], s["range_count"], s["total_ips"],
                     s["total_online"]))
    lines.append("  其中扫了端口 %d 次 · 发包估算约 %d 个（下限）" % (
        s["port_scan_count"], s["estimated_probes"]))
    lines.append("  协议：" + ("、".join(
        "%s ×%d" % (p, c) for p, c in sorted(
            s["protocols"].items(), key=lambda kv: (-kv[1], kv[0])))
        if s["protocols"] else "均未指定（只做默认主机发现）"))
    lines.append("  礼貌档：" + ("、".join(
        "%s ×%d" % (t, c) for t, c in sorted(
            s["throttles"].items(), key=lambda kv: (-kv[1], kv[0])))
        if s["throttles"] else "未记录"))
    lines.append("  网段（按最近一次倒序）：")
    for a in s["ranges"]:
        lines.append("    %s  %d 次  累计 %d 个地址  发包估算约 %d 个" % (
            a["range"], a["scans"], a["ips"], a["estimated_probes"]))
    lines.append("⚠ 发包数是**估算下限**（主机发现 + 在线设备端口探测），"
                 "不含 ARP / mDNS / 按需 enrich，不是包计数器读数。")
    emit("\n".join(lines) + "\n", args.output)
    return EXIT_OK


# ────────────────────────── 在线率趋势（v2.3 §3.2） ──────────────────────────

_TREND_REASON_TEXT = {
    "no_records": (
        "所选时间窗内没有任何趋势观测记录。",
        "趋势观测自 v2.3 起才随每次扫描自动写入 —— 更早的扫描不在其内。"
        "先跑一次 `ipscanner scan -r <网段>`，再回来查就有数据了。",
    ),
    "out_of_window": (
        "库里有趋势记录，但都不在所选时间窗内。",
        "把 --window 放大（30d / all），或先跑一次扫描。",
    ),
}


def _fmt_trend_ts(ts, granularity="raw"):
    """趋势点的时间标签。`day` 粒度只到日，`raw` 到分钟。

    ⚠️ 按**本地时区**（`time.localtime`）与 `trend_store._day_key()` 同口径 ——
    用 UTC 会让"今天"在东八区偏 8 小时，与用户的日历对不上。
    """
    fmt = "%Y-%m-%d" if granularity == "day" else "%Y-%m-%d %H:%M"
    return time.strftime(fmt, time.localtime(ts))


def _fmt_duration(seconds):
    """秒 → 人话。`None` 一律说"样本不足" —— 不拿 0 冒充结果。

    分档逻辑在 `trend_store.duration_parts()`（**只有一份**），
    避免 CLI 与 GUI 各写一套而漂移。
    """
    import trend_store

    value, unit = trend_store.duration_parts(seconds)
    if unit == trend_store.DURATION_UNIT_NONE:
        return "样本不足"
    fmt = {trend_store.DURATION_UNIT_SECOND: "%.0f 秒",
           trend_store.DURATION_UNIT_MINUTE: "%.1f 分钟",
           trend_store.DURATION_UNIT_HOUR: "%.1f 小时",
           trend_store.DURATION_UNIT_DAY: "%.1f 天"}
    return fmt[unit] % value


def cmd_trend(args) -> int:
    """在线率趋势：把「每次扫描的规模与在线率」按时间排成曲线（v2.3 §3.2）。

    数据源是 `trend_observations` —— 🔴 **不是** `devices`：
    `prune(max_keep=20)` 只留 20 份快照，且 `devices` 靠 `ON DELETE CASCADE`
    跟着删 ⇒ 拿它画曲线会「随时间自己变短」。趋势行无外键、不参与 prune，
    这是它能跨过 20 份上限存活的唯一原因（见 `docs/ROADMAP_V2.3.md` §4）。

    退出码恒为 0：「这段时间没数据」不是失败，是要说清的事实 ——
    照 v2.2 §3.3 的口径 **给 reason + 下一步，不给一张会误导的空表**。
    """
    import history_store
    import trend_store

    window = getattr(args, "window", "24h")
    granularity = getattr(args, "granularity", "raw")
    db_path = getattr(args, "db", None)
    since = trend_store.window_start(window=window)
    rows = history_store.read_scan_trend(since_ts=since, db_path=db_path)
    series = trend_store.online_ratio_series(rows, granularity=granularity)

    if not rows:
        # 🔴 区分「库里根本没有」与「有、但都不在窗口内」—— 两者的下一步
        #    完全不同（前者该去跑扫描，后者该放大窗口），报成同一种会误导。
        reason = (trend_store.REASON_OUT_OF_WINDOW
                  if history_store.read_scan_trend(db_path=db_path)
                  else trend_store.REASON_NO_RECORDS)
    elif not series:
        reason = trend_store.REASON_OUT_OF_WINDOW
    else:
        reason = None

    # 事件流：稳定性（抖动 / MTBF / MTTR）与首现设备。
    # 它们读 `asset_events`，曲线读 `trend_observations` —— 两张表，
    # 但都**不参与 prune**，所以时间窗口径一致。
    events = history_store.read_asset_events(since_ts=since, db_path=db_path)
    stab = trend_store.stability(events)
    newcomers = trend_store.first_seen_devices(events, limit=10)
    payload = {
        "window": window,
        "window_hours": trend_store.normalize_hours(window),
        "granularity": granularity,
        "samples": len(series),
        "points": series,
        "stability": stab,
        "new_devices": newcomers,
        "reason": reason,
    }
    if args.format == "json":
        emit(render_json(payload), args.output)
        return EXIT_OK

    if reason:
        hint, action = _TREND_REASON_TEXT.get(reason, ("没有可用的趋势数据。", ""))
        lines = [hint]
        if action:
            lines.append("下一步：" + action)
        emit("\n".join(lines) + "\n", args.output)
        return EXIT_OK

    win = ("全部历史" if payload["window_hours"] is None
           else "过去 %g 小时" % payload["window_hours"])
    ratios = [p["ratio"] for p in series]
    lines = ["在线率趋势（%s · 粒度 %s）" % (win, granularity)]
    lines.append("  观测 %d 次 · 当前 %.1f%% · 均值 %.1f%% · 最低 %.1f%% · 最高 %.1f%%" % (
        len(series), ratios[-1] * 100.0, sum(ratios) / len(ratios) * 100.0,
        min(ratios) * 100.0, max(ratios) * 100.0))
    lines.append("  %-18s %7s %7s %9s" % ("时间", "总数", "在线", "在线率"))
    for p in series:
        lines.append("  %-18s %7d %7d %8.1f%%" % (
            _fmt_trend_ts(p["time"], granularity), p["total"], p["online"],
            p["ratio"] * 100.0))
    lines.append("  稳定性：翻转 %d 次 · 掉线 %d 次 · MTBF %s（样本 %d）· "
                 "MTTR %s（样本 %d）" % (
                     stab["flips"], stab["failures"],
                     _fmt_duration(stab["mtbf_seconds"]), stab["mtbf_samples"],
                     _fmt_duration(stab["mttr_seconds"]), stab["mttr_samples"]))
    if stab["reason"] == trend_store.REASON_INSUFFICIENT_SAMPLES:
        lines.append("  ⚠ MTBF 要同一台设备掉线 ≥2 次才统计得出；且这是**扫描采样**"
                     "近似 —— 短于扫描间隔的抖动根本看不到，"
                     "「翻转 0 次」只说明没看见，不等于稳定。")
    if newcomers:
        lines.append("  新出现设备 %d 台（最多列 10 台）：" % len(newcomers))
        for d in newcomers:
            lines.append("    %-16s %-20s %s" % (
                d["ip"] or d["identity_key"], d["mac"] or "-",
                _fmt_trend_ts(d["ts"])))
    emit("\n".join(lines) + "\n", args.output)
    return EXIT_OK


# ────────────────────────── Nagios 插件契约（v2.2 §3.4-a） ──────────────────────────

def cmd_nagios(args) -> int:
    """Nagios / Icinga / Zabbix / Checkmk 插件入口（v2.2 §3.4-a）。

    🔴 **本子命令的退出码是 Nagios 语义**（0 OK / 1 WARNING / 2 CRITICAL /
    3 UNKNOWN），与其它子命令的 0/1/2/3（成功/错误/有变更/环境错）**不同** ——
    这是插件规范的硬要求，不能两全；因此**独立子命令**、绝不改既有语义。
    详见 `nagios_check` 模块文档。

    一次性执行、不常驻、不开端口：被监控系统按需拉起一个短命进程。
    """
    import nagios_check

    result = nagios_check.check_once(
        db_path=_db_path(args),
        max_age_hours=args.max_age_hours,
        warn_new=args.warn_new, crit_new=args.crit_new,
        warn_identity=args.warn_identity, crit_identity=args.crit_identity,
    )
    if args.format == "json":
        emit(render_json(result), args.output)
    else:
        emit(nagios_check.render_plugin_line(result) + "\n", args.output)
    return result["code"]


# ────────────────────────── CVE 快照 / 暴露面（v2.1 §2.3） ──────────────────────────

#: 快照 state 规范值 → (状态说明, 下一步动作)。规范值来自
#: `scanner.cve_snapshot` 的 `STATE_*`（语言无关），文案只在这里出
#: （铁律：规范值不翻译、`tr()` 结果不写回 scanner/）。
#: 🔴 每个非 ok 状态都**必须**带下一步动作：只报「无数据」会让用户以为
#: 「查过了，没有漏洞」—— 那是与事实相反的结论（模型文档 §1 原则 3）。
_CVE_STATE_TEXT = {
    "ok": ("快照可用且新鲜。", ""),
    "stale": ("快照已过期，结论按过期数据给出，可能漏掉新公布的 CVE。",
              "用 tools/build_cve_snapshot.py 重新生成，"
              "把 cve_snapshot.json（连同摘要清单）放进数据目录。"),
    "unknown-age": ("快照没有可用的生成时间，新鲜度未知，无法判断新旧。",
                    "同上。没有 generated_at 的快照没法判断新旧。"),
    "empty": ("快照能读，但里面没有任何条目 —— 等于无数据可查。",
              "同上。"),
    "missing": ("数据目录与程序内置路径下都没有 CVE 快照。",
                "同上。内置种子只覆盖少量高知名度 CVE，"
                "不要指望它长期有效。"),
    "corrupt": ("CVE 快照读不出来（结构不符或摘要不匹配），已拒绝加载。",
                "同上。摘要清单（cve_snapshot.sha256）要与数据文件"
                "同目录；手动改过 json 就会让摘要校验失败。"),
}

#: 快照 source 规范值 → 人看的来源说明（`SOURCE_*`，同样语言无关）。
_CVE_SOURCE_TEXT = {
    "data-dir": "数据目录（用户更新版）",
    "seed": "程序内置种子（覆盖面很窄）",
    "online-download": "在线下载（已校验 SHA256）",
    "none": "无",
}

#: 在线更新结果原因（`cve_updater.REASON_*` 规范值）→ 人看的说明（v2.2 §3.1）。
_CVE_UPDATE_REASON_TEXT = {
    "ok": "更新完成。",
    "no-url": "尚未配置下载地址（默认常量还是占位符）——"
              "请手动把新的 cve_snapshot.json 放进数据目录。",
    "download-failed": "下载失败（网络不可达 / 超时 / 地址无效）。"
                       "已保留现有数据。",
    "too-large": "下载内容超过大小上限，已丢弃。请检查地址是否正确。",
    "checksum-failed": "下载内容的 SHA256 与清单不一致，已丢弃并保留现有数据。",
    "invalid": "下载回来的内容不是可用的快照，已丢弃并保留现有数据。",
    "write-failed": "写入数据目录失败（磁盘空间 / 权限），已保留现有数据。",
    "no-manifest": "服务器上没有可用的 SHA256 清单，出于安全默认拒绝安装。",
    "unknown": "结果无法识别（详见日志）。",
}


def cmd_cve_update(args) -> int:
    """`cve --update`：**唯一**联网的 CVE 动作（v2.2 §3.1）。

    🔴 只有显式给 `--update` 才会走到这里 —— 别的 cve 用法（`--status` /
    `--product`）全程不联网这条承诺**不变**。

    退出码：成功 0；失败 1（与"没有可用数据"同一档，**不**新增码位 ——
    监控脚本已经在用 0/1/2/3，"这次没更成"不是环境错也不是"有变更"）。

    失败**只提示不报错退出**：下载失败不影响任何既有功能，把它做成红字
    会让 cron 里的一次网络抖动变成一封告警邮件。
    """
    from cve_updater import update_snapshot
    from scanner import cve_snapshot as snap

    url = (getattr(args, "url", "") or "").strip() or snap.DEFAULT_SNAPSHOT_URL
    result = update_snapshot(
        url,
        require_checksum=not getattr(args, "no_checksum", False),
    )

    reason = str(result.get("reason") or "unknown")
    if args.format == "json":
        emit(render_json(result), args.output)
    else:
        text = _CVE_UPDATE_REASON_TEXT.get(reason, _CVE_UPDATE_REASON_TEXT["unknown"])
        lines = [f"CVE 快照在线更新：{text}"]
        if result.get("bytes"):
            lines.append("  下载：%d 字节" % result["bytes"])
        if result.get("ok"):
            lines.append("  条目：%d 条" % (result.get("entry_count") or 0))
            lines.append("  摘要校验：通过")
            lines.append("  写入：%s" % (result.get("path") or ""))
        emit("\n".join(lines), args.output)

    if not result.get("ok"):
        warn(_CVE_UPDATE_REASON_TEXT.get(
            reason, _CVE_UPDATE_REASON_TEXT["unknown"]))
        return EXIT_ERROR
    return EXIT_OK


def _render_cve_status_text(stats: dict) -> str:
    """`cve --status` 的文本形态。字段名来自 `CveSnapshot.stats()`（英文键），
    但值是给人看的，所以逐字段翻成本文件统一的文案。"""
    state = str(stats.get("state") or "")
    desc, action = _CVE_STATE_TEXT.get(state, ("快照状态无法识别。", ""))
    lines = [f"CVE 快照：{desc}"]
    lines.append("  来源：%s" % _CVE_SOURCE_TEXT.get(
        str(stats.get("source") or ""), str(stats.get("source") or "无")))
    if stats.get("path"):
        lines.append("  文件：%s" % stats["path"])
    gen = stats.get("generated_at")
    if gen:
        age = stats.get("age_days")
        age_txt = "（%s 天前，上限 %s 天）" % (age, stats.get("max_age_days")) \
            if age is not None else ""
        lines.append("  生成于：%s%s" % (gen, age_txt))
    lines.append("  条目：%d 条（其中 KEV %d 条、有 EPSS 分值 %d 条）" % (
        stats.get("entry_count") or 0, stats.get("kev_count") or 0,
        stats.get("epss_scored_count") or 0))
    verified = stats.get("checksum_verified")
    lines.append("  摘要校验：%s" % {
        True: "通过", False: "不匹配（已拒绝加载）",
        None: "无摘要清单，未校验",
    }.get(verified, "未知"))
    if stats.get("skipped_records"):
        lines.append("  ⚠ 有 %d 条记录不可用，已跳过"
                     % stats["skipped_records"])
    if action:
        lines.append("  下一步：%s" % action)
    return "\n".join(lines) + "\n"


def _cve_hint_text(hit) -> list:
    """一个 `ExposureHit` 的文本行（含它的候选 CVE）。"""
    ver = " %s" % hit.version if hit.version else ""
    lines = ["  %s  %s%s（证据：%s）" % (hit.ip, hit.product, ver,
                                        _CVE_EVIDENCE_TEXT.get(
                                            hit.evidence, hit.evidence))]
    for c in hit.candidates:
        tags = []
        if c.kev:
            tags.append("KEV")
        if c.epss is not None:
            tags.append("EPSS %.4f" % c.epss)
        if c.epss_percentile is not None:
            tags.append("分位 %.1f%%" % (c.epss_percentile * 100))
        head = "    %s" % c.cve_id
        if tags:
            head += "  [%s]" % " / ".join(tags)
        lines.append(head)
        if c.summary:
            lines.append("      %s" % _truncate(c.summary, 90))
    return lines


#: 证据来源规范值（`exposure.EVIDENCE_*`）→ 人看的说明。
_CVE_EVIDENCE_TEXT = {
    "banner": "服务 banner",
    "snmp": "SNMP sysDescr",
    "http": "HTTP 响应",
}


def _render_exposure_text(report) -> str:
    """`scan --exposure` 的文本段。

    🔴 措辞硬约束（与 `scanner/exposure.py` 同一套，AST 测试连本函数一起扫）：
    只准说「**匹配到**候选」，不准说「已验证 / 可利用 / 存在漏洞」。
    这段话的全部含义是：这台机器上跑的产品，在本地快照里有已知条目。
    """
    st = report.snapshot_state
    desc, action = _CVE_STATE_TEXT.get(st, ("快照状态无法识别。", ""))
    head = ["暴露面（本地 CVE 快照匹配到的候选，不是漏洞结论）：%s" % desc]
    if report.age_days is not None:
        head.append("  快照：%s，%d 天前生成，共 %d 条" % (
            _CVE_SOURCE_TEXT.get(report.snapshot_source, report.snapshot_source),
            report.age_days, report.entry_count))
    if report.verdict == _exposure_verdict_no_data():
        head.append("  ⚠ 没有数据可查，因此无结论 —— 这不代表没有漏洞。")
        if action:
            head.append("  下一步：%s" % action)
        return "\n".join(head) + "\n"
    if not report.hits:
        head.append("  已对照快照逐台检查，没有匹配到任何候选。")
        head.append("  ⚠ 「没有匹配」同样不等于「没有漏洞」：只认得出快照里"
                    "出现过的产品，识别也不含版本比对。")
        return "\n".join(head) + "\n"
    head.append("  匹配到 %d 台设备、%d 个产品（按严重程度排序）："
                % (len(report.matched_hosts), len(report.hits)))
    lines = list(head)
    for hit in report.hits:
        lines.extend(_cve_hint_text(hit))
    return "\n".join(lines) + "\n"


def _exposure_verdict_no_data() -> str:
    """`no-data` 规范值的惰性取用（import 放函数内，与 cli.py 其它 scanner
    依赖一致；也让 `cli.py` 顶层 import 表保持零 PyQt 零 scanner 子模块）。"""
    from scanner.exposure import VERDICT_NO_DATA
    return VERDICT_NO_DATA


def cmd_cve(args) -> int:
    """CVE 快照诊断 / 手工产品查询（v2.1 §2.3）。

    * `--status`（或不带参数时的默认动作）：快照健康状况 + 下一步动作；
    * `--product "产品 版本"`：按**与扫描完全相同**的识别口径
      （`exposure.cpe_for_product()`）查这个产品的候选 CVE。

    🔴 全程**不联网**：只读本地快照文件。快照更新靠用户手动跑
    `tools/build_cve_snapshot.py`（模型文档 §9.3：脚本自己也不上网抓）。

    退出码：快照不可用（缺失/损坏/0 条）→ 1，否则 0。过期（`stale`）算
    可用 —— 数据在、只是旧，提示说清即可，不该让监控脚本误报故障。
    """
    from scanner import cve_snapshot as snap

    # v2.2 §3.1：`--update` 是**唯一**联网分支，且必须显式给出才走。
    # 放在最前面：它的语义是"动作"而不是"查询"，与 --status/--product 并列。
    if getattr(args, "update", False):
        return cmd_cve_update(args)

    snapshot = snap.load_snapshot()
    stats = snapshot.stats()

    product = (getattr(args, "product", "") or "").strip()
    if product:
        return _cve_product_lookup(product, snapshot, args)

    if args.format == "json":
        emit(render_json(stats), args.output)
    else:
        emit(_render_cve_status_text(stats), args.output)

    if not snapshot.usable:
        # 不可用 = 真的没数据可查。过期不算（见 docstring）。
        warn("没有可用的 CVE 数据：%s" % _CVE_STATE_TEXT.get(
            snapshot.state, ("状态 %s" % snapshot.state, ""))[0])
        return EXIT_ERROR
    return EXIT_OK


def _cve_product_lookup(product: str, snapshot, args) -> int:
    """`cve --product` 的落地：产品名 → 粗粒度 CPE → 候选 CVE。"""
    from scanner import cve_snapshot as snap
    from scanner import exposure

    resolved = exposure.cpe_for_product(product)
    if resolved is None:
        # 认不出来就说"认不出来"，不猜：猜一个错 CPE 会给用户一个
        # 空列表，让他以为"这个产品没有已知 CVE"。
        log("认不出这个产品名（%s），因此无从匹配。" % product)
        log("可识别的产品见 `scanner/exposure.py` 的提示表，"
            "或直接用 `ipscanner scan --exposure` 看整网结果。")
        return EXIT_ERROR

    name, cpe, version = resolved
    if not snapshot.usable:
        desc, action = _CVE_STATE_TEXT.get(
            snapshot.state, ("状态 %s" % snapshot.state, ""))
        log("没有可用的 CVE 数据：%s" % desc)
        if action:
            log("下一步：%s" % action)
        return EXIT_ERROR
    if snapshot.state == snap.STATE_STALE:
        log("⚠ 快照已过期（%d 天前生成），可能漏掉新公布的 CVE。"
            % (snapshot.age_days or 0))

    candidates = snap.find_candidates(snapshot, cpe)

    if args.format == "json":
        emit(render_json({
            "product": name,
            "version": version,
            "cpe": cpe,
            "query": product,
            "matched": bool(candidates),
            "candidates": [c.to_dict() for c in candidates],
        }), args.output)
    elif candidates:
        # 表头与命中行**同走 emit**（同一条输出流）：否则加 `-o` 时
        # 表头进 stderr、命中行进文件，读到的东西是半截的。
        lines = ["%s%s 匹配到 %d 条候选 CVE（粗粒度产品级，不含版本比对）："
                 % (name, (" " + version) if version else "", len(candidates))]
        lines.extend(_cve_hint_text(_FakeHit(name, version, cpe, candidates)))
        emit("\n".join(lines) + "\n", args.output)
    else:
        emit("%s%s：快照里没有匹配到这个产品的条目（不等于没有漏洞）。\n"
             % (name, (" " + version) if version else ""), args.output)
    return EXIT_OK


@dataclass(frozen=True)
class _FakeHit:
    """`_cve_hint_text()` 只用到 ip/product/version/evidence/candidates
    这几个字段，product 查询没有 ip，就地造一个同形对象复用渲染。"""

    product: str
    version: str
    cpe: str
    candidates: tuple

    @property
    def ip(self) -> str:
        return "(手工查询)"

    @property
    def evidence(self) -> str:
        from scanner.exposure import EVIDENCE_BANNER
        return EVIDENCE_BANNER


# ────────────────────────── 拓扑文本导出 ──────────────────────────

def cmd_topology(args) -> int:
    """发现并导出网络拓扑为可读文本（tree / markdown / ascii）。

    先扫描 ``--range`` 拿到设备清单，再走 `discover_topology` 抽拓扑
    （交换机/路由器/网关/终端及其端口与协议），最后用
    `topology_discovery.render_topology_text` 渲染。纯文本、语言无关，
    不依赖图形坐标 —— 与建议书 §1.3「拓扑可读性包」一致。

    手工校正（``topology_overrides.json``：钉住 / 隐藏 / 备注）在渲染前叠加，
    与扫描结果解耦 —— 见 `topology_overrides` 模块。

    详见 `docs/ROADMAP_V1.9.md` §1.3。
    """
    from topology_discovery import discover_topology, render_topology_text

    results, _scanner = _run_scan(args)
    if results is None:
        return EXIT_ERROR
    if not results:
        log("没有可输出的结果（扫描范围可能被拒绝或为空）")
        return EXIT_ERROR

    gateway = getattr(args, "gateway", "") or ""
    snmp_v3_user, snmp_v3_error = _resolve_snmp_v3(args)
    if snmp_v3_error:
        log(f"错误: {snmp_v3_error}")
        return EXIT_ERROR

    topo = discover_topology(
        results,
        gateway_ip=gateway,
        enable_snmp_probe=not getattr(args, "no_snmp", False),
        snmp_v3_user=snmp_v3_user,
    )

    # ── 手工校正（钉住 / 隐藏 / 备注）：显式 --overrides 或数据目录默认文件 ──
    import topology_overrides as tov
    ov_path = getattr(args, "overrides", None)
    if ov_path:
        ovs = tov.load(ov_path)
    elif not getattr(args, "no_overrides", False):
        ovs = tov.load()          # 数据目录下的 topology_overrides.json（缺失=空）
    else:
        ovs = tov.TopologyOverrides()
    if not ovs.is_empty():
        topo, _pinned = tov.apply_overrides(topo, ovs)
        log(f"已应用手工校正：{len(ovs.nodes)} 个节点 / {len(ovs.links)} 条链路")

    text = render_topology_text(topo, args.format, gateway)
    emit(text, args.output)
    if args.output:
        log(f"已导出拓扑（{args.format}）→ {args.output}："
            f"{len(topo.nodes)} 个节点 / {len(topo.links)} 条链路")
    else:
        log(f"拓扑（{args.format}）：{len(topo.nodes)} 个节点 / "
            f"{len(topo.links)} 条链路")
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


def _render_ipv6_text(ledger):
    """IPv6 可见性小节（v2.0 §2.4）。没有任何设备带 IPv6 地址时返回 None。

    **措辞必须说清是「可见性」不是「资产清单」**：本工具只扫 IPv4，
    这里列的是「本机 NDP 缓存里、且与已有 IPv4 设备 MAC 对上的 IPv6 地址」。
    一个 /64 有 2^64 个地址，「盘点 IPv6」在语义上不成立。
    """
    from scanner.ndp import sort_ipv6

    rows = [(r, sort_ipv6(r.ipv6_addresses))
            for r in ledger if getattr(r, "ipv6_addresses", None)]
    if not rows:
        return None
    out = [f"IPv6 可见性: {len(rows)} 台设备带 IPv6 地址"
           "（只做可见性，不是 IPv6 资产清单）"]
    for r, addrs in sorted(rows, key=lambda t: _ip_sort_key(t[0].ip)):
        tail = f"  {r.hostname}" if r.hostname else ""
        out.append(f"  {r.ip:<15} {r.mac or '—':<17}{tail}")
        for a in addrs:
            out.append(f"      {a}")
    return "\n".join(out)


def _watch_payload(ledger, fresh, round_no=None) -> dict:
    """JSON 输出。字段名与取值**语言无关**，脚本可依赖。

    `round_no` 为 None（单次轮询）时带上完整 `devices`；
    持续轮询时只给本轮的增量 —— 每轮重发整张台账既浪费又难用。
    """
    def _one(r):
        return {"ip": r.ip, "mac": r.mac, "hostname": r.hostname,
                "vendor": r.vendor, "status": r.status,
                "discovery_method": r.discovery_method,
                "services": list(r.services),
                # v2.0 §2.4：挂靠到本设备上的 IPv6 地址（可见性，非资产清单）。
                # 字段名语言无关，脚本可依赖；没开 --ipv6 时恒为空列表。
                "ipv6_addresses": list(getattr(r, "ipv6_addresses", []) or [])}

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

    # 礼貌模式（v2.1 §2.4）：`--mdns-active` / `--ipv6-probe` 会发包，
    # 所以 watch 也认这个档；纯只听模式下它是纯 no-op（fast 档本来就是）。
    policy = _resolve_throttle(args)
    policy_ctx = throttle.active_policy(policy)

    def _cycle():
        return watcher.poll(mdns=not args.no_mdns,
                            mdns_active=args.mdns_active,
                            mdns_timeout=args.mdns_timeout,
                            ipv6=getattr(args, "ipv6", False),
                            ipv6_probe=getattr(args, "ipv6_probe", False))

    try:
        # ── 单次轮询（默认） ──
        if not looping:
            ledger, fresh = _cycle()
            if args.save_snapshot:
                _save_watch_snapshot(args, ledger)
            if args.format == "json":
                emit(render_json(_watch_payload(ledger, fresh)), args.output)
            else:
                body = _render_watch_text(ledger, fresh)
                v6 = _render_ipv6_text(ledger)
                if v6:
                    body = body + "\n" + v6
                emit(body, args.output)
            # `--fail-on-change` 与 diff 的语义保持一致：有新设备 → 退出码 2。
            return EXIT_CHANGES if (args.fail_on_change and fresh) else EXIT_OK

        # ── 持续轮询 ──
        limit = getattr(args, "count", 0) or 0
        rounds = 0
        total_new = 0
        while True:
            rounds += 1
            ledger, fresh = _cycle()
            total_new += len(fresh)
            if args.format == "json":
                sys.stdout.write(render_json(
                    _watch_payload(ledger, fresh, round_no=rounds)) + "\n")
            else:
                body = _render_watch_text(ledger, fresh)
                v6 = _render_ipv6_text(ledger)
                if v6:
                    body = body + "\n" + v6
                sys.stdout.write(f"[第 {rounds} 轮]\n" + body + "\n")
            sys.stdout.flush()
            if limit and rounds >= limit:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        # Ctrl+C 是用户主动停止，属**正常结束路径**，不是错误。
        # 这里不能写成 `pass`：tests/test_logging_policy.py 的棘轮按**计数**
        # 卡静默处理器，补注释也过不了计数那一关。
        log("收到中断信号，正在停止持续发现…")
    finally:
        # 礼貌档必须退出还原，否则限速桶会漏到进程里后续所有 watch 上。
        policy_ctx.__exit__()
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
    # v2.0 §2.2：扫描后生成报表 —— 纯追加（不传 --report 时 build_delivery_argv
    # 返回空列表，`build_task_command` 的输出与 2.2 之前逐字节一致）。
    cli_args += scheduler.build_delivery_argv(
        getattr(args, "report", ""), getattr(args, "report_output", ""))
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


def _resolve_credential_book(args):
    """按 ``--credentials`` 载入凭据档册（v2.0 §2.3）。

    返回 ``(book, error)``：
      * ``(None, None)``      —— 未指定 ``--credentials``（行为与历史一致）；
      * ``(None, "原因")``    —— 文件读不到 / 一档都没有（调用方报错退 1）；
      * ``(book, None)``      —— 载入成功。

    显式指定了文件却读不到是**硬错误**：用户期望用它，静默降级成"无凭据"
    会让每台设备都报"无可用凭据"，根因被藏起来。
    """
    path = getattr(args, "credentials", None)
    if not path:
        return None, None
    from credentials import CredentialBook, load_profiles
    profiles = load_profiles(path)
    if not profiles:
        return None, f"凭据文件 {path!r} 不存在或没有任何凭据档"
    return CredentialBook(profiles), None


def _add_credentials_arg(parser):
    """给会发起扫描的子命令挂上 ``--credentials``（凭据档册路径）。"""
    parser.add_argument(
        "--credentials", metavar="文件",
        help="凭据配置档（JSON，按网段选 SNMP/WMI 凭据；"
             "默认数据目录下的 credentials.json）")


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
    sp.add_argument("-r", "--range", action="append",
                    dest="ranges", metavar="范围",
                    help="IP 范围，可重复。支持 192.168.1.0/24、192.168.1.1-254、单个 IP"
                         "（与 -iL 至少其一，可并用）")
    sp.add_argument("-iL", "--target-file", metavar="文件",
                    help="从文件读扫描目标（nmap 习惯）：每行一个 CIDR/IP，"
                         "空行与 # 开头的注释行跳过（与 -r 至少其一，可并用）")
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
    # 礼貌模式（v2.1 §2.4）。不放 choices 里的具体解释：档位定义在
    # `scanner.throttle.POLICIES`，这里只做一项 —— 让 `--help` 自己列得出。
    sp.add_argument("--throttle", metavar="档位",
                    default=throttle.DEFAULT_POLICY,
                    help=f"扫描礼貌档（{'/'.join(throttle.POLICY_NAMES)}，"
                         f"默认 {throttle.DEFAULT_POLICY} = 不额外设限，"
                         f"与改造前一致）")
    sp.add_argument("--online-only", action="store_true", help="只输出在线设备")
    # 暴露面（v2.1 §2.3）。默认关：它要多读一个本地快照文件，而且
    # 结论是**启发式**（粗粒度产品级匹配），不该在每次扫描里默认出现。
    sp.add_argument("--exposure", action="store_true",
                    help="扫描末尾追加「暴露面」段：把每台设备认出的产品对照"
                         "本地 CVE 快照，列出匹配到的候选 CVE"
                         "（全程不联网；粗粒度产品级，不含版本比对）")
    sp.add_argument("--library", action="store_true", help="启用地址库自动匹配（读 mac_library.db）")
    sp.add_argument("--save-snapshot", action="store_true", help="把本次结果存为历史快照")
    sp.add_argument("--note", metavar="备注", help="快照备注（配合 --save-snapshot）")
    sp.add_argument("--switch-map", action="store_true",
                    help="扫描末尾读取各交换机转发表，记录设备与端口的对应关系"
                         "（需配合 --save-snapshot；需要 SNMP，每台交换机 5 次 walk）")
    sp.add_argument("--name-responder", action="store_true",
                    help="扫描末尾编一个不存在的主机名，查一次 LLMNR/NBNS，"
                         "记录谁给肯定应答（会向网络发送组播/广播包；"
                         "配合 --save-snapshot 才会写进快照）")
    sp.add_argument("--notify", action="store_true",
                    help="检测到资产变更时推送告警（需先配置通知渠道）")
    sp.add_argument("--notify-config", metavar="文件",
                    help="通知配置文件路径（默认：数据目录下的 notify.json）")
    sp.add_argument("--no-policy", action="store_true",
                    help="忽略告警策略（维护窗口 / 静音 / 去重），所有变更都发送")
    sp.add_argument("--report", choices=("assets", "changes", "exposure"),
                    default="", metavar="模板",
                    help="扫描收尾时生成 HTML 报表（assets/changes/exposure）。"
                         "与 --notify 同位置执行，供定时任务一条命令完成"
                         "「扫描 → 存快照 → 出报表」")
    sp.add_argument("--report-output", metavar="文件",
                    help="报表输出路径（省略则写到数据目录下带时间戳的文件名）")
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
    dp.add_argument("-iL", "--target-file", metavar="文件",
                    help="从文件读扫描目标（每行一个 CIDR/IP；与 -r 至少其一）")
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
    # diff 内部同样走一次扫描（`_run_scan`），所以礼貌档对它同样生效 ——
    # 否则"对比两次扫描"里有一次是全速的，档位记录会自相矛盾。
    dp.add_argument("--throttle", metavar="档位",
                    default=throttle.DEFAULT_POLICY,
                    help=f"扫描礼貌档（{'/'.join(throttle.POLICY_NAMES)}，"
                         f"默认 {throttle.DEFAULT_POLICY}）")
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

    # ── assets ──
    ap = sub.add_parser("assets", help="列举资产表（一行一台设备）", parents=[common],
                        description="按 MAC 身份键去重后的资产清单（1.1 新增）。"
                                    "与 history 按 IP 聚合不同，换过 IP 的设备只算一台。")
    ap.add_argument("--device-class", metavar="类型", help="按设备类型过滤（子串匹配）")
    ap.add_argument("--network", metavar="网段", help="按网段过滤，如 192.168.1.0/24")
    ap.add_argument("--ip", metavar="关键字", help="按 IP 子串过滤")
    ap.add_argument("--limit", type=int, default=None, metavar="N",
                    help="最多返回 N 条（按末见时间降序截取）")
    ap.add_argument("--offset", type=int, default=0, metavar="N", help="跳过前 N 条（翻页）")
    ap.add_argument("--count", action="store_true", help="只输出资产总数（应用上述过滤）")
    ap.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    ap.add_argument("-o", "--output", metavar="文件")
    ap.set_defaults(func=cmd_assets)

    # ── export ──
    xp = sub.add_parser("export", help="导出资产表为互操作格式", parents=[common],
                        description="把资产表（assets）导出为 Nmap XML / Zabbix LLD JSON / "
                                    "NetBox 设备 CSV / Oxidized router.db，供外部系统集成。"
                                    "纯文件导出，语言无关。")
    xp.add_argument("--format", "-f",
                    choices=("nmap", "zabbix", "netbox", "oxidized"),
                    required=True, metavar="格式",
                    help="导出格式：nmap / zabbix / netbox / oxidized")
    xp.add_argument("-o", "--output", metavar="文件",
                    help="输出文件路径（省略则写到 stdout）")
    xp.add_argument("--device-class", metavar="类型", help="按设备类型过滤（子串匹配）")
    xp.add_argument("--network", metavar="网段", help="按网段过滤，如 192.168.1.0/24")
    xp.add_argument("--ip", metavar="关键字", help="按 IP 子串过滤")
    xp.add_argument("--limit", type=int, default=None, metavar="N",
                    help="最多导出 N 条（按末见时间降序截取）")
    xp.add_argument("--offset", type=int, default=0, metavar="N", help="跳过前 N 条（翻页）")
    xp.set_defaults(func=cmd_export)

    # ── report ──
    rp = sub.add_parser("report", help="生成版式可编辑的 HTML 报表",
                        parents=[common],
                        description="把台账渲染成 HTML 报表。内置模板："
                                    "assets（资产清单）/ changes（变更摘要）/ "
                                    "exposure（暴露面摘要）。"
                                    "模板是数据文件（assets/report_templates/*.html），"
                                    "可复制到数据目录改一份即生效；也可用 "
                                    "--template-file 指定任意模板。"
                                    "报表值语言无关（status→online/offline）。")
    rp.add_argument("--template", "-t", choices=("assets", "changes", "exposure"),
                    default="assets", metavar="模板",
                    help="内置模板名：assets / changes / exposure（默认 assets）")
    rp.add_argument("--template-file", metavar="文件", default=None,
                    help="自定义模板文件路径（省略则用内置模板）")
    rp.add_argument("--from", dest="from_id", type=int, default=None, metavar="N",
                    help="变更报表的起始快照 id（仅 changes 模板用）")
    rp.add_argument("--to", dest="to_id", type=int, default=None, metavar="N",
                    help="变更报表的结束快照 id（仅 changes 模板用，默认最新）")
    rp.add_argument("--generated-at", metavar="时间", default=None,
                    help="覆盖报表里的生成时间（便于可复现输出 / 测试）")
    rp.add_argument("-o", "--output", metavar="文件",
                    help="输出文件路径（省略则写到 stdout）")
    rp.add_argument("--device-class", metavar="类型", help="按设备类型过滤（子串匹配）")
    rp.add_argument("--network", metavar="网段", help="按网段过滤，如 192.168.1.0/24")
    rp.add_argument("--ip", metavar="关键字", help="按 IP 子串过滤")
    rp.add_argument("--limit", type=int, default=None, metavar="N",
                    help="最多纳入 N 台设备（按末见时间降序截取）")
    rp.add_argument("--offset", type=int, default=0, metavar="N", help="跳过前 N 条（翻页）")
    rp.set_defaults(func=cmd_report)

    # ── credentials ──
    crp = sub.add_parser("credentials",
                         help="查看/校验凭据配置档（按网段选 SNMP 凭据）",
                         parents=[common],
                         description="列出凭据配置档（JSON），或校验某一档的 "
                                     "env: 引用是否已解析。凭据档把「按网段用不同"
                                     "只读账户」变成可配置的一组对象；"
                                     "敏感值写成 env:VAR_NAME，明文不落盘。"
                                     "配置文件默认在数据目录的 credentials.json。")
    crp.add_argument("--file", metavar="文件", default=None,
                     help="凭据文件路径（省略则用数据目录下的 credentials.json）")
    crp.add_argument("--proto", choices="snmp_v1 snmp_v2c snmp_v3 wmi".split(),
                     default=None, help="只列该协议的档")
    crp.add_argument("-f", "--format", choices=("table", "json"), default="table",
                     help="输出格式（默认 table）")
    crp.add_argument("-o", "--output", metavar="文件", help="写到文件（省略则写 stdout）")
    crp.set_defaults(func=cmd_credentials)

    # ── import ──
    ip_ = sub.add_parser("import", help="读入外部 Nmap XML 并入资产表",
                         parents=[common],
                         description="解析 `nmap -oX` 产出的 XML，把主机并入资产表。"
                                     "⚠ Nmap 的 up/down 与本项目 status 语义不同："
                                     "up 只表示「有探针回应」、down 可能是被屏蔽；"
                                     "结果里保留原样的 nmap_state 与 source=nmap。"
                                     "默认只预演，加 --save 才写库。")
    ip_.add_argument("input", metavar="文件", help="Nmap XML 文件路径（nmap -oX 的产物）")
    ip_.add_argument("--save", action="store_true",
                     help="真正写入资产表（省略则只预览，不改台账）")
    ip_.add_argument("-f", "--format", choices=("table", "json", "csv"),
                     default="table", help="预览输出格式（默认 table）")
    ip_.add_argument("-o", "--output", metavar="文件",
                     help="把解析结果写到文件（省略则写 stdout）")
    ip_.set_defaults(func=cmd_import)

    # ── ports ──
    pp = sub.add_parser("ports", help="每台交换机各端口的接入设备数 / 空闲口",
                        parents=[common],
                        description="按最近一次扫描落库的交换机转发表，汇总每台交换机"
                                    "各端口接了几台设备（「还有几个口可用」）。"
                                    "⚠ 数据依赖 `scan --switch-map`（默认关）；"
                                    "没有数据时会说明是「没采过」并给出下一步命令，"
                                    "不会给你一张会误导的空表。"
                                    "⚠ 只报有设备的端口数，不含空闲口 —— "
                                    "转发表里没有空闲口的记录。")
    pp.add_argument("-f", "--format", choices=("table", "json", "csv"),
                    default="table", help="输出格式（默认 table）")
    pp.add_argument("-o", "--output", metavar="文件",
                    help="写到文件（省略则写 stdout）")
    pp.set_defaults(func=cmd_ports)

    # ── audit（v2.2 §3.3 扫描活动自查） ──
    aup = sub.add_parser(
        "audit", parents=[common],
        help="扫描活动自查：过去向哪些网段发起过多少次扫描",
        description="只读审计日志里的**结构化**扫描汇总，回答"
                    "「过去这段时间我向哪些网段发起过多少次扫描」。"
                    "🔴 汇总自 v2.2 起才随每次扫描自动写入；时间窗内没有记录时"
                    "会说明原因并给出下一步命令，不会给一张会误导的空表。"
                    "⚠ 不认 --db（那是历史快照库）—— 审计库固定用程序数据目录。")
    aup.add_argument("--window", choices=("24", "168", "all"), default="24",
                     help="时间窗：24 / 168（=7 天）/ all（全部历史），默认 24")
    aup.add_argument("-f", "--format", choices=("table", "json"),
                     default="table", help="输出格式（默认 table）")
    aup.add_argument("-o", "--output", metavar="文件",
                     help="写到文件（省略则写 stdout）")
    aup.set_defaults(func=cmd_audit)

    # ── trend（v2.3 §3.2 在线率趋势） ──
    # `choices` 直接取 `trend_store` 的常量：避免 CLI 与 GUI 两处各写一份而漂移。
    import trend_store

    trp = sub.add_parser(
        "trend", parents=[common],
        help="在线率趋势：把每次扫描的规模与在线率排成曲线",
        description="读趋势观测表，回答「这段时间的在线率是怎么变的」。"
                    "🔴 数据源是**独立的趋势表**，不是快照里的 devices —— "
                    "快照上限 20 份、会被 prune 冲掉，画不了长期曲线（见 "
                    "docs/ROADMAP_V2.3.md §4）。趋势自 v2.3 起随每次扫描自动写入；"
                    "时间窗内没有记录时会说明原因并给出下一步命令。")
    trp.add_argument("--window", choices=trend_store.WINDOW_CHOICES, default="24h",
                     help="时间窗：24h / 7d / 30d / all，默认 24h")
    trp.add_argument("--granularity", choices=trend_store.GRANULARITY_CHOICES,
                     default="raw",
                     help="粒度：raw（每次观测一个点）/ day（按自然日聚合），默认 raw")
    trp.add_argument("-f", "--format", choices=("table", "json"),
                     default="table", help="输出格式（默认 table）")
    trp.add_argument("-o", "--output", metavar="文件",
                     help="写到文件（省略则写 stdout）")
    trp.set_defaults(func=cmd_trend)

    # ── nagios（v2.2 §3.4-a 插件契约） ──
    np_ = sub.add_parser(
        "nagios", parents=[common],
        help="Nagios/Icinga 插件：一次性检查，用退出码表达状态",
        description="把「有新设备 / 设备身份变了」做成符合 Nagios 插件规范的检查："
                    "一次性执行、单行输出（`STATUS - 说明 | perfdata`）、"
                    "退出码 0/1/2/3 = OK/WARNING/CRITICAL/UNKNOWN，"
                    "可直接 drop-in 到 Nagios / Icinga / Zabbix / Checkmk。"
                    "🔴 本子命令的退出码是 **Nagios 语义**，与其它子命令不同。"
                    "🔴 不常驻、不开端口、不联网 —— 数据源是本机历史快照库。"
                    "⚠ 数据过期或没有快照时报 UNKNOWN（**不猜成 OK**）；"
                    "只有一次快照时报 OK 并说明「尚无基线」。")
    np_.add_argument("--max-age-hours", type=float, default=24.0,
                     metavar="小时",
                     help="最近快照超过这个年龄即 UNKNOWN（默认 24；数据不可信时不猜）")
    np_.add_argument("--warn-new", type=int, default=1, metavar="台",
                     help="新增设备达到该数量报 WARNING（默认 1）")
    np_.add_argument("--crit-new", type=int, default=5, metavar="台",
                     help="新增设备达到该数量报 CRITICAL（默认 5，优先于 WARNING）")
    np_.add_argument("--warn-identity", type=int, default=1, metavar="台",
                     help="设备身份变动（MAC 变更 / 随机 MAC）达到该数量报 WARNING（默认 1）")
    np_.add_argument("--crit-identity", type=int, default=3, metavar="台",
                     help="设备身份变动达到该数量报 CRITICAL（默认 3）")
    np_.add_argument("-f", "--format", choices=("plugin", "json"),
                     default="plugin",
                     help="输出格式：plugin（Nagios 单行，默认）/ json")
    np_.add_argument("-o", "--output", metavar="文件",
                     help="写到文件（省略则写 stdout）")
    np_.set_defaults(func=cmd_nagios)

    # ── cve（v2.1 §2.3） ──
    cvp = sub.add_parser("cve", help="CVE 快照诊断 / 候选查询（全程不联网）",
                         parents=[common],
                         description="查看本地 CVE 快照的状态，或按产品名查询"
                                     "匹配到的候选 CVE。"
                                     "🔴 只读本地快照文件，不发起任何网络请求；"
                                     "快照更新靠 tools/build_cve_snapshot.py "
                                     "手动生成后放进数据目录。"
                                     "⚠ 结论一律是「匹配到的候选」，不是漏洞结论。")
    cvp.add_argument("--status", action="store_true",
                     help="输出快照健康状况（省略 --product 时的默认动作）")
    cvp.add_argument("--product", metavar="产品[ 版本]",
                     help='按产品名查候选 CVE，如 "Apache httpd 2.4.41"；'
                          "识别口径与扫描完全相同")
    # v2.2 §3.1：**唯一**会联网的 CVE 动作，必须显式点它。
    cvp.add_argument("--update", action="store_true",
                     help="🔴 从配置的地址**联网**下载并校验 CVE 快照后安装"
                          "（本命令其它用法一律不联网）")
    cvp.add_argument("--url", metavar="地址", default="",
                     help="配合 --update：覆盖默认下载地址（联调 / 自建镜像用）")
    cvp.add_argument("--no-checksum", action="store_true",
                     help="配合 --update：放宽「必须校验 SHA256」的要求"
                          "（仅联调用，生产勿用）")
    cvp.add_argument("-f", "--format", choices=("table", "json"),
                     default="table", help="输出格式（默认 table）")
    cvp.add_argument("-o", "--output", metavar="文件",
                     help="写到文件（省略则写 stdout）")
    cvp.set_defaults(func=cmd_cve)

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
    wp.add_argument("--ipv6", action="store_true",
                    help="同时读本机 IPv6 邻居缓存（NDP），把地址挂到已有 "
                         "IPv4 设备上（按 MAC 关联，不新建资产）。"
                         "默认关；开启后本身零发包。只做「可见性」，"
                         "不是 IPv6 资产清单。")
    wp.add_argument("--ipv6-probe", action="store_true",
                    help="读 NDP 前先向 ff02::1 发一次 ICMPv6 echo（唯一会发包的"
                         "一步，让设备回邻居通告；需要管理员/root）。"
                         "默认关。仅在 --ipv6 时有意义。")
    wp.add_argument("--save-snapshot", action="store_true",
                    help="把台账存为一条快照（默认不存；只能配合单次轮询）")
    wp.add_argument("--note", metavar="备注", help="快照备注（配合 --save-snapshot）")
    # watch 默认只读（零发包），但只要给了 --mdns-active / --ipv6-probe
    # 就同样该讲礼貌，所以这里也认这个档；纯只听模式下它是 no-op。
    wp.add_argument("--throttle", metavar="档位",
                    default=throttle.DEFAULT_POLICY,
                    help=f"发包礼貌档（{'/'.join(throttle.POLICY_NAMES)}，"
                         f"默认 {throttle.DEFAULT_POLICY}；只影响 --mdns-active / "
                         f"--ipv6-probe 的发包节奏）")
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
    cp.add_argument("--report", choices=("assets", "changes", "exposure"),
                    default="", metavar="模板",
                    help="每次扫描后生成 HTML 报表（assets/changes/exposure）。"
                         "与扫描在同一个任务里完成，无需包装脚本")
    cp.add_argument("--report-output", metavar="文件",
                    help="报表输出路径（省略则写到数据目录下带时间戳的文件名）")
    cp.add_argument("-q", "--quiet", action="store_true", help="定时任务静默运行")
    cp.set_defaults(func=cmd_schedule)

    # ── topology ──
    tp = sub.add_parser("topology",
                        help="发现并导出网络拓扑为可读文本",
                        parents=[common],
                        description="扫描网段并发现拓扑（交换机/路由器/网关/终端"
                                    "及其端口与协议），再渲染成 tree / markdown / "
                                    "ascii 文本。纯文本、语言无关。")
    tp.add_argument("-r", "--range", action="append", required=True,
                    dest="ranges", metavar="范围",
                    help="IP 范围，可重复。支持 192.168.1.0/24、192.168.1.1-254、单个 IP")
    tp.add_argument("--level", choices=("quick", "standard", "all"), default="quick",
                    help="端口扫描级别（默认 quick=常用 21 个端口）")
    tp.add_argument("--ports", metavar="列表",
                    help="自定义端口，逗号分隔（覆盖 --level），如 80,443,3389")
    tp.add_argument("--no-ports", action="store_true", help="完全跳过端口扫描（最快）")
    tp.add_argument("--protocols", metavar="列表", default="",
                    help="应用层协议识别，逗号分隔，如 HTTP,HTTPS,FTP,RDP,SNMP")
    tp.add_argument("--tcp-mode", choices=("connect", "syn", "udp"), default="connect",
                    help="端口探测方式（syn/udp 需管理员权限，默认 connect）")
    tp.add_argument("--timeout", type=int, default=1000, metavar="毫秒",
                    help="ping 超时毫秒（默认 1000）")
    tp.add_argument("--threads", type=int, default=100, metavar="N",
                    help="ping 并发线程数（默认 100）")
    tp.add_argument("--library", action="store_true", help="启用地址库自动匹配（读 mac_library.db）")
    tp.add_argument("--gateway", metavar="IP", default="",
                    help="指定本机网关 IP（分层根；省略则按连接数推断）")
    tp.add_argument("--no-snmp", action="store_true",
                    help="不做 SNMP 探测（更快，但交换机可能识别不全）")
    tp.add_argument("--format", "-f", choices=("tree", "markdown", "ascii"),
                    default="tree", help="文本格式（默认 tree）")
    tp.add_argument("--overrides", metavar="文件",
                    help="手工校正文件（钉住/隐藏/备注，JSON）；"
                         "省略则用数据目录的 topology_overrides.json（若有）")
    tp.add_argument("--no-overrides", action="store_true",
                    help="忽略数据目录里的默认校正文件（只用手工校正层时用）")
    tp.add_argument("-o", "--output", metavar="文件", help="写入文件而非 stdout")
    tp.add_argument("-q", "--quiet", action="store_true", help="静默模式，不输出进度")
    tp.set_defaults(func=cmd_topology)

    # scan / diff / topology 都会真正发起扫描，因此都需要 SNMPv3 参数。
    # 放在最后统一挂载，避免两处 add_argument 各写一遍、日后再漂移。
    for _sub in (sp, dp, tp):
        _add_snmp_v3_args(_sub)
        _add_credentials_arg(_sub)

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
