# -*- coding: utf-8 -*-
"""端口→服务映射表：常用端口清单（quick 级）与端口显示名。

为什么外置
----------
``COMMON_PORTS`` 与 ``_PORT_NAME_TEXT`` 原先写死在
``scanner/constants.py`` 里 —— 加一个端口、改一个显示名都要发一次版。
映射是**数据**不是逻辑，因此外置成 ``port_services.json``，更新策略与
``service_fingerprints.json`` / ``oui.db`` 一致：**优先 ``data_dir()``
（用户可更新）→ 回退 ``resource_dir()``（内置）→ 模块内兜底表**（三层，
缺一不可）。

稳健性（对照 ``service_fingerprints`` 的判据）
--------------------------------------------
数据文件缺失 / 损坏 / 结构不符，都**不能**让"映射表坏了"升级成"扫描失败"：
- 读不到文件或 JSON 非法 → **整套**回退内置兜底表；
- ``ports`` / ``names`` 某一张结构不符（不是数组 / 不是对象 / 是空集合）
  → **只回退那一张**，另一张照常生效；
- 单条条目畸形（端口不是 1-65535 的整数、显示名为空、键解析不出端口号）
  → 跳过该条并留痕，其余条目照常生效；
- 绝不静默变空表让上层"看起来正常其实什么都没扫"。

i18n 约定
---------
``names`` 的值是**显示文本原文**（中文源串），只在**显示时**由调用方过
``tr()``（见 ``scanner.constants.port_name``）。它们**绝不参与比较** ——
比较一律用端口号本身或 ``SVC_*`` 规范代码。因此把这张表外置不会动摇
「规范值语言无关」这条铁律。
"""
import json
import os
import threading

from app_logging import get_logger
from app_paths import data_dir, resource_dir

_log = get_logger(__name__)

DATA_FILENAME = "port_services.json"


# ── 内置兜底表 ────────────────────────────────────────────────────
# 数据文件三层都不可用时的最小可用集。与 constants.py 里原有的字面量一致
# （外置只是搬家，不改默认行为）。
_FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                   993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

_FALLBACK_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 500: "IKE",
    514: "Syslog", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5353: "mDNS", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

_cache = None  # (tuple[int, ...], dict[int, str])
_cache_lock = threading.Lock()


def data_path() -> str:
    """返回实际使用的数据文件路径（用户更新版优先）。"""
    user_path = os.path.join(data_dir(), DATA_FILENAME)
    if os.path.exists(user_path):
        return user_path
    return os.path.join(resource_dir(), DATA_FILENAME)


def _valid_port(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) \
        and 1 <= value <= 65535


def _read_ports(raw) -> tuple:
    """解析常用端口数组；单条畸形只跳过它自己。"""
    ports = []
    seen = set()
    for item in raw:
        try:
            port = int(item)
        except (TypeError, ValueError):
            _log.warning("端口映射 %s 的 ports 含非整数项 %r，已跳过",
                         data_path(), item)
            continue
        if not _valid_port(port):
            _log.warning("端口映射 %s 的 ports 含越界端口 %r，已跳过",
                         data_path(), item)
            continue
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return tuple(ports)


def _read_names(raw) -> dict:
    """解析端口→显示名对象；单条畸形只跳过它自己。"""
    names = {}
    for key, value in raw.items():
        try:
            port = int(str(key).strip())
        except (TypeError, ValueError):
            _log.warning("端口映射 %s 的 names 键 %r 不是端口号，已跳过",
                         data_path(), key)
            continue
        if not _valid_port(port):
            _log.warning("端口映射 %s 的 names 键 %r 越界，已跳过",
                         data_path(), key)
            continue
        text = str(value).strip() if value is not None else ""
        if not text:
            _log.warning("端口映射 %s 中端口 %d 的显示名为空，已跳过",
                         data_path(), port)
            continue
        names[port] = text
    return names


def _load():
    """读文件并校验，返回 ``(ports_tuple, names_dict)``（进程内缓存）。"""
    global _cache
    if _cache is not None:
        return _cache
    with _cache_lock:
        if _cache is not None:
            return _cache
        path = data_path()
        ports = None
        names = None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("顶层不是 JSON 对象")
            raw_ports = data.get("ports")
            raw_names = data.get("names")
            if raw_ports is None and raw_names is None:
                raise ValueError("ports / names 都不存在")
            if raw_ports is not None:
                if not isinstance(raw_ports, list):
                    _log.warning("端口映射 %s 的 ports 不是数组，该表回退内置", path)
                else:
                    ports = _read_ports(raw_ports)
                    if not ports:
                        _log.warning("端口映射 %s 的 ports 为空，该表回退内置", path)
                        ports = None
            if raw_names is not None:
                if not isinstance(raw_names, dict):
                    _log.warning("端口映射 %s 的 names 不是对象，该表回退内置", path)
                else:
                    names = _read_names(raw_names)
                    if not names:
                        _log.warning("端口映射 %s 的 names 为空，该表回退内置", path)
                        names = None
        except FileNotFoundError:
            _log.warning("端口映射文件不存在（%s），改用内置表", path)
        except Exception as e:  # noqa: BLE001
            _log.warning("端口映射读取失败（%s）：%s，改用内置表", path, e)
        if ports is None:
            ports = tuple(_FALLBACK_PORTS)
        if names is None:
            names = dict(_FALLBACK_NAMES)
        _cache = (ports, names)
        return _cache


def common_ports() -> list:
    """当前生效的常用端口列表（用户更新版优先，缺省回退内置）。"""
    return list(_load()[0])


def port_names() -> dict:
    """当前生效的 {端口: 显示名原文}（显示时才由调用方 tr()）。"""
    return dict(_load()[1])


def raw_port_name(port) -> str:
    """端口 -> 显示名原文（未翻译）；未知端口返回空串。"""
    try:
        key = int(port)
    except (TypeError, ValueError):
        return ""
    return _load()[1].get(key, "")


def reload() -> None:
    """丢弃缓存，下次调用重新读盘（映射文件更新后调用）。"""
    global _cache
    with _cache_lock:
        _cache = None


def counts() -> tuple:
    """(常用端口数, 显示名条数) —— 供 UI / 诊断展示。"""
    ports, names = _load()
    return len(ports), len(names)
