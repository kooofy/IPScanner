# -*- coding: utf-8 -*-
"""凭据配置档（v2.0 §2.3）：把 SNMP / WMI 凭据从"全局单一值"升级成
"带作用域的一组对象"，并按目标 IP 做**最长前缀匹配**选档。

设计要点
--------
* **零 PyQt / 零第三方依赖 / 零网络** —— 纯决策层，便于单元测试与 CLI 复用。
* **作用域是 CIDR 列表**：一档可覆盖多个网段（如 ``["10.1.0.0/16",
  "172.16.0.0/12"]``）。``for_target(ip)`` 在**所有档**的所有 CIDR 里取
  前缀最长的那条，更长 = 更具体 = 更优先。
* **敏感值绝不落盘明文**：沿用 ``notifier.py`` 的既有约定，值可写成
  ``env:VAR_NAME``，实际口令从环境变量读取（``resolve_secret`` 复用同一实现）。
* **选不到就返回 None，绝不回落 ``public``** —— 静默回落会让用户以为
  "扫过了"，其实用的是猜的团体字。调用方拿到 None 时必须明确报
  "该目标无可用凭据"。
* **纯增量**：本模块只做"选档"，不改任何既有扫描函数的默认值。没有配置档
  文件时 ``load_profiles()`` 返回空列表，``for_target()`` 返回 None，
  调用方按原有逻辑走（老用户零感知）。

持久化
------
配置文件默认放在 ``app_paths.data_dir()/credentials.json``（与
``notify.json`` / ``scan_history.db`` 同目录），格式::

    {"profiles": [
        {"name": "办公网", "scope": ["10.1.0.0/16"],
         "protocol": "snmp_v2c", "community": "env:OFFICE_SNMP"},
        {"name": "机房", "scope": ["10.1.2.0/24", "10.2.0.0/16"],
         "protocol": "snmp_v3", "username": "monitor",
         "auth_proto": "sha", "auth_key": "env:IDC_AUTH",
         "priv_proto": "aes", "priv_key": "env:IDC_PRIV"},
        {"name": "域内 PC", "scope": ["10.1.3.0/24"],
         "protocol": "wmi", "username": "CORP\\ro", "password": "env:PC_PASS"}
    ]}

文件不存在 / 损坏 / 结构不对时一律**静默降级为空配置**（不抛异常）——
与 ``notifier.load_config`` 同口径：配置缺失只该导致"无凭据可用"这一条
明确告警，不该让整个扫描任务失败。
"""
import ipaddress
import json
import os
from typing import Optional

from app_logging import get_logger
from notifier import resolve_secret

_log = get_logger(__name__)

#: 配置文件名（数据目录下）。与 notify.json 同目录、同风格。
CONFIG_FILENAME = "credentials.json"

# ── 协议规范值（语言无关；绝不把 tr() 结果存进配置或用于比较） ──
PROTO_SNMP_V1 = "snmp_v1"
PROTO_SNMP_V2C = "snmp_v2c"
PROTO_SNMP_V3 = "snmp_v3"
PROTO_WMI = "wmi"
PROTOCOLS = (PROTO_SNMP_V1, PROTO_SNMP_V2C, PROTO_SNMP_V3, PROTO_WMI)

#: SNMP 团体字类协议（v1/v2c 用明文团体字）
_SNMP_COMMUNITY_PROTOS = (PROTO_SNMP_V1, PROTO_SNMP_V2C)

#: 协议显示名（惰性 —— import 期不许调 tr()，用模块级 __getattr__ 兜底，
#: 与 i18n 既有约定一致）。见 tests/test_i18n_lazy.py。
_PROTOCOL_TEXT = {
    PROTO_SNMP_V1: "SNMP v1",
    PROTO_SNMP_V2C: "SNMP v2c",
    PROTO_SNMP_V3: "SNMP v3",
    PROTO_WMI: "WMI",
}


def protocol_label(proto: str) -> str:
    """协议规范值 → 显示名。未知值原样返回（不抹成空）。"""
    from i18n import tr
    return tr(_PROTOCOL_TEXT.get(proto, proto))


def default_config_path() -> str:
    """凭据配置文件路径：数据目录下的 credentials.json。"""
    import app_paths
    return os.path.join(app_paths.data_dir(), CONFIG_FILENAME)


# ══════════════════════════════════════════════════════════════════════
#  Credential —— 单个凭据档
# ══════════════════════════════════════════════════════════════════════

class Credential:
    """一个凭据档：作用域 + 协议 + 账户/团体字。

    ``scope`` 是 CIDR 字符串列表；``nets`` 是其解析后的 ``ip_network`` 列表
    （解析失败的条目被跳过并留痕，不影响其余网段）。
    """

    __slots__ = ("name", "scope", "protocol", "community", "username",
                 "password", "domain", "auth_proto", "auth_key",
                 "priv_proto", "priv_key", "nets")

    def __init__(self, name: str = "", scope=None, protocol: str = PROTO_SNMP_V2C,
                 community: str = "", username: str = "", password: str = "",
                 domain: str = "", auth_proto: str = "", auth_key: str = "",
                 priv_proto: str = "", priv_key: str = ""):
        self.name = name or ""
        self.scope = list(scope) if scope else []
        self.protocol = protocol if protocol in PROTOCOLS else PROTO_SNMP_V2C
        self.community = community or ""
        self.username = username or ""
        self.password = password or ""
        self.domain = domain or ""
        self.auth_proto = auth_proto or ""
        self.auth_key = auth_key or ""
        self.priv_proto = priv_proto or ""
        self.priv_key = priv_key or ""
        self.nets = _parse_scope(self.scope, self.name)

    # ── 选择 ──

    def match_prefixlen(self, addr) -> int:
        """若 ``addr`` 落在本档任一网段内，返回**最长**匹配前缀长度；否则 -1。

        ``addr`` 为 ``ipaddress.ip_address``（IPv4/IPv6 皆可）。跨版本
        （v4 地址对 v6 网段）一律不匹配 —— ``ipaddress`` 的 ``in`` 会自己
        处理好版本，但显式判断更省事也更快。
        """
        best = -1
        for net in self.nets:
            if net.version != addr.version:
                continue
            if addr in net:
                if net.prefixlen > best:
                    best = net.prefixlen
        return best

    # ── 便捷判定 ──

    def is_snmp_community(self) -> bool:
        return self.protocol in _SNMP_COMMUNITY_PROTOS

    def resolved_community(self) -> str:
        """解析团体字（支持 ``env:VAR``）。"""
        return resolve_secret(self.community)

    def resolved_password(self) -> str:
        return resolve_secret(self.password)

    def resolved_auth_key(self) -> str:
        return resolve_secret(self.auth_key)

    def resolved_priv_key(self) -> str:
        return resolve_secret(self.priv_key)

    def to_dict(self) -> dict:
        """回写成配置 dict（保留 ``env:`` 引用原样，**不**解析成明文）。"""
        return {
            "name": self.name,
            "scope": list(self.scope),
            "protocol": self.protocol,
            "community": self.community,
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "auth_proto": self.auth_proto,
            "auth_key": self.auth_key,
            "priv_proto": self.priv_proto,
            "priv_key": self.priv_key,
        }

    def to_snmp_v3_user(self):
        """把本档转成 ``scanner.snmp_v3.SnmpV3User``（口令已解析 env:）。

        仅对 ``snmp_v3`` 档有意义；对其它协议返回 ``None``（调用方据此判定
        "这档不是 v3"）。**延迟导入**：``snmp_v3`` 会引入更多常量和 tr()，
        顶层导入会把凭据模块和 SNMP 协议层绑死，且拖慢只读配置的场景。
        """
        if self.protocol != PROTO_SNMP_V3:
            return None
        from scanner.snmp_v3 import SnmpV3User
        return SnmpV3User(
            username=self.username,
            auth_proto=self.auth_proto,
            auth_key=self.resolved_auth_key(),
            priv_proto=self.priv_proto,
            priv_key=self.resolved_priv_key(),
        )

    def __repr__(self):  # pragma: no cover - 仅调试
        return f"Credential(name={self.name!r}, scope={self.scope!r}, proto={self.protocol!r})"


def _parse_scope(scope, name: str = ""):
    """把 CIDR 字符串列表解析成 ``ip_network`` 列表；坏条目跳过并留痕。"""
    out = []
    for item in scope or []:
        s = str(item).strip()
        if not s:
            continue
        try:
            out.append(ipaddress.ip_network(s, strict=False))
        except ValueError as e:
            # 坏网段只影响这一条，不该让整档失效；但必须留痕，否则用户
            # 以为配了却永远匹配不上，会当成"凭据不生效"来排查。
            _log.warning("凭据档 %r 的作用域 %r 不是合法 CIDR，已跳过: %s",
                         name, s, e)
    return out


# ══════════════════════════════════════════════════════════════════════
#  配置读写
# ══════════════════════════════════════════════════════════════════════

def load_profiles(path: Optional[str] = None):
    """读取凭据档列表。文件不存在/损坏/结构不对 → 返回 ``[]``（不抛）。"""
    p = path or default_config_path()
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:  # noqa: BLE001
        _log.warning("凭据配置读取失败 %s: %s", p, e)
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("profiles")
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append(Credential(
            name=str(item.get("name") or ""),
            scope=item.get("scope") or [],
            protocol=str(item.get("protocol") or PROTO_SNMP_V2C),
            community=str(item.get("community") or ""),
            username=str(item.get("username") or ""),
            password=str(item.get("password") or ""),
            domain=str(item.get("domain") or ""),
            auth_proto=str(item.get("auth_proto") or ""),
            auth_key=str(item.get("auth_key") or ""),
            priv_proto=str(item.get("priv_proto") or ""),
            priv_key=str(item.get("priv_key") or ""),
        ))
    return out


def save_profiles(profiles, path: Optional[str] = None):
    """写入凭据档列表。返回 ``(是否成功, 错误信息)``。"""
    p = path or default_config_path()
    payload = {"profiles": [c.to_dict() for c in (profiles or [])]}
    try:
        parent = os.path.dirname(p)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return True, ""
    except Exception as e:  # noqa: BLE001
        _log.warning("凭据配置写入失败 %s: %s", p, e)
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════
#  选择层（本项的核心 API）
# ══════════════════════════════════════════════════════════════════════

def select_for_target(ip: str, profiles, protocol: Optional[str] = None):
    """在所有档里按**最长前缀匹配**为 ``ip`` 选一档。

    参数
    ----
    ip:        目标 IPv4/IPv6 字符串。
    profiles:  ``Credential`` 列表（通常来自 ``load_profiles()``）。
    protocol:  非空时只考虑该协议的档（如只想要 ``snmp_v2c`` 的团体字）。

    返回 ``(credential, None)`` 或 ``(None, 原因)``。

    🔴 **绝不回落 ``public``**：没有任何档覆盖该目标时返回 ``None``，并给出
    可直接展示的原因（"没有凭据档覆盖该目标" / "该目标无 X 协议的凭据档"）。
    调用方必须把 None 当成"该目标无可用凭据"明确上报，而不是拿猜的团体字硬撞。
    """
    reason_no_match = "没有凭据档覆盖该目标"
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None, f"目标地址无效: {ip}"

    best = None
    best_plen = -1
    for cred in profiles or []:
        if protocol and cred.protocol != protocol:
            continue
        plen = cred.match_prefixlen(addr)
        if plen > best_plen:
            best_plen = plen
            best = cred

    if best is None:
        if protocol and profiles:
            return None, f"该目标无 {protocol_label(protocol)} 协议的凭据档"
        return None, reason_no_match
    return best, None


class CredentialBook:
    """一次扫描用的凭据册：装配好所有档，按目标查询。

    存在的意义是把"读配置 + 选档"合成一个对象，避免在热路径（每台设备）
    里反复读盘。构造时加载一次，之后 ``for_target`` 只做内存匹配。
    """

    def __init__(self, profiles=None, path: Optional[str] = None):
        if profiles is None:
            profiles = load_profiles(path)
        self.profiles = list(profiles or [])

    def __len__(self):
        return len(self.profiles)

    def for_target(self, ip: str, protocol: Optional[str] = None):
        """``select_for_target`` 的实例方法形式。"""
        return select_for_target(ip, self.profiles, protocol)

    def has_any(self) -> bool:
        """是否配置了任何档。用于区分"用户没配"与"配了但没覆盖"两种情况。"""
        return bool(self.profiles)

    def communities_for(self, ip: str):
        """给某目标返回 SNMP 团体字候选列表（v1/v2c 档的值，已解析 env:）。

        用途：让 v2c 探测用**该目标专属**的团体字，而不是全局
        ``public/private/""``。没配档时返回 ``[]``（**不是**默认列表）——
        由调用方决定要不要退回历史默认。
        """
        cred, _ = self.for_target(ip)
        if cred is None or not cred.is_snmp_community():
            return []
        val = cred.resolved_community()
        return [val] if val else []
