# -*- coding: utf-8 -*-
"""服务版本指纹库：把一段 banner 文本映射到 ``(服务, 产品, 版本)``。

为什么规则要放在外部数据文件
----------------------------
banner 正则是"识别准确率"的核心，也是更新最频繁的部分 —— 新版本号、新产品
变体、新的默认 banner 几乎每季度都在变。写死在代码里意味着每补一条指纹都要
发一次版。因此规则放在 ``service_fingerprints.json``，查找策略与 ``oui.db``
一致：**优先 ``data_dir()``（用户可更新）→ 回退 ``resource_dir()``（内置）**。

稳健性
------
数据文件缺失 / 损坏 / 正则写错，都**不能**让"指纹库坏了"升级成"扫描失败"：
- 读不到文件 → 退回内置的 `_FALLBACK_RULES`（覆盖最常见的几种协议）；
- 单条规则正则非法 → 跳过该条并留痕，其余规则照常生效；
- 匹配过程本身不抛异常，最坏情况只是"识别不出产品/版本"。

i18n 约定
---------
``service`` 一律是**语言无关的 ASCII 规范代码**（与 scanner/constants.py 的
``SVC_*`` 对应），绝不放翻译后的显示文本；显示由调用方走 ``service_label()``。
"""
import json
import os
import re
import threading
from typing import List, NamedTuple, Optional, Union

from app_logging import get_logger
from app_paths import data_dir, resource_dir

_log = get_logger(__name__)

DATA_FILENAME = "service_fingerprints.json"


class Fingerprint(NamedTuple):
    """一条命中的指纹。"""

    service: str
    product: str = ""
    version: str = ""
    os_hint: str = ""

    @property
    def display(self) -> str:
        """人类可读的展示串：'产品 版本'，两者都无时退回服务名。"""
        parts = [p for p in (self.product, self.version) if p]
        if parts:
            return " ".join(parts)
        return self.service


class _Rule(NamedTuple):
    service: str
    product: str
    regex: "re.Pattern"
    version: Union[int, str, None]
    os_hint: str
    ports: frozenset


# ── 内置兜底规则 ────────────────────────────────────────────────────
# 数据文件不可用时的最小可用集。刻意保持精简（只覆盖最常见协议），
# 完整的规则集在 service_fingerprints.json 里。
_FALLBACK_RULES = [
    {"service": "SSH", "product": "OpenSSH",
     "pattern": r"SSH-[0-9.]+-OpenSSH[_-]([A-Za-z0-9._]+)", "version": 1},
    {"service": "SSH", "product": "", "pattern": r"^SSH-[0-9.]+"},
    {"service": "HTTP", "product": "Apache httpd", "pattern": r"Apache/([0-9.]+)", "version": 1},
    {"service": "HTTP", "product": "nginx", "pattern": r"nginx/([0-9.]+)", "version": 1},
    {"service": "HTTP", "product": "", "pattern": r"HTTP/[0-9.]+"},
    {"service": "FTP", "product": "vsftpd", "pattern": r"vsFTPd ([0-9.]+)", "version": 1},
    {"service": "FTP", "product": "", "pattern": r"^220[- ]"},
    {"service": "SMTP", "product": "Postfix", "pattern": r"Postfix"},
    {"service": "SMTP", "product": "", "pattern": r"^220[- ]"},
    {"service": "POP3", "product": "", "pattern": r"^\+OK"},
    {"service": "IMAP", "product": "", "pattern": r"^\* OK"},
    {"service": "MySQL", "product": "MariaDB", "pattern": r"MariaDB"},
    {"service": "MySQL", "product": "MySQL", "pattern": r"^([0-9]+\.[0-9]+\.[0-9]+)"},
    {"service": "VNC", "product": "VNC", "pattern": r"RFB ([0-9.]+)", "version": 1},
]

_rules_cache: Optional[List[_Rule]] = None
_cache_lock = threading.Lock()


def data_path() -> str:
    """返回实际使用的数据文件路径（用户更新版优先）。"""
    user_path = os.path.join(data_dir(), DATA_FILENAME)
    if os.path.exists(user_path):
        return user_path
    return os.path.join(resource_dir(), DATA_FILENAME)


def _read_raw_rules() -> List[dict]:
    """读取规则原始列表；任何失败都回退到内置兜底集。"""
    path = data_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules") if isinstance(data, dict) else None
        if isinstance(rules, list) and rules:
            return rules
        _log.warning("指纹库 %s 中没有有效规则，改用内置兜底规则", path)
    except FileNotFoundError:
        _log.warning("指纹库文件不存在（%s），改用内置兜底规则", path)
    except Exception as e:  # noqa: BLE001
        _log.warning("指纹库读取失败（%s）：%s，改用内置兜底规则", path, e)
    return _FALLBACK_RULES


def _compile(rules) -> List[_Rule]:
    """把原始规则编译成 ``_Rule``；单条非法只跳过它自己。"""
    out: List[_Rule] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        pattern = item.get("pattern")
        if not pattern:
            continue
        try:
            rx = re.compile(str(pattern), re.IGNORECASE)
        except re.error as e:
            # 正则写错只是少一条规则，绝不能让它把整个指纹库带崩
            _log.warning("忽略非法指纹正则 %r: %s", pattern, e)
            continue
        ports = item.get("ports")
        try:
            port_set = frozenset(int(p) for p in ports) if ports else frozenset()
        except (TypeError, ValueError):
            port_set = frozenset()
        out.append(_Rule(
            service=str(item.get("service") or ""),
            product=str(item.get("product") or ""),
            regex=rx,
            version=item.get("version"),
            os_hint=str(item.get("os_hint") or ""),
            ports=port_set,
        ))
    return out


def load_rules() -> List[_Rule]:
    """返回编译后的规则表（进程内缓存，首次调用时惰性加载）。"""
    global _rules_cache
    if _rules_cache is None:
        with _cache_lock:
            if _rules_cache is None:
                _rules_cache = _compile(_read_raw_rules())
    return _rules_cache


def reload() -> None:
    """丢弃缓存，下次调用重新读盘（指纹库更新后调用）。"""
    global _rules_cache
    with _cache_lock:
        _rules_cache = None


def rule_count() -> int:
    """当前生效的规则条数（供 UI / 诊断展示）。"""
    return len(load_rules())


def _extract_version(match: "re.Match", spec) -> str:
    """按组序号 / 组名取版本号；取不到返回空串（不抛异常）。"""
    if spec is None:
        return ""
    try:
        value = match.group(spec)
    except (IndexError, re.error, TypeError):
        return ""
    return (value or "").strip() if value else ""


def _make(rule: _Rule, match: "re.Match") -> Fingerprint:
    return Fingerprint(
        service=rule.service,
        product=rule.product,
        version=_extract_version(match, rule.version),
        os_hint=rule.os_hint,
    )


def fingerprint_banner(banner: str, port: Optional[int] = None) -> Optional[Fingerprint]:
    """把一段 banner 文本映射为指纹；无法识别返回 None。

    按**数据文件中的顺序**逐条匹配，命中即止；``ports`` 非空的规则只在其
    声明端口上参与匹配（例如 FTP/SMTP 的 "220" 欢迎行长得一样，靠端口区分）。

    因此数据文件的顺序即优先级：**产品专属规则在前，通用/兜底规则在后**。
    """
    if not banner:
        return None
    text = str(banner)
    for rule in load_rules():
        if rule.ports and port not in rule.ports:
            continue
        m = rule.regex.search(text)
        if m:
            return _make(rule, m)
    return None
