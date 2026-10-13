# -*- coding: utf-8 -*-
"""无线切片（v2.1 §2.2）：当前关联 + 可见 BSS + 信道拥塞 + 漫游时间线 + SSID↔子网。

为什么要这一片、以及它的边界
----------------------------
建议书原话是「无线层（**只切一小片**）」，并把 Windows 的 monitor 模式判为
死路（`PRODUCT_ADVISORY.md` §9）。所以本模块**不做**站点勘测、不做抓包、
不做信号热图，只回答四个**已经能回答**的问题：

1. **我现在连的是哪个 AP / 哪个 SSID**（当前关联：SSID / BSSID / 波段 / 信道 /
   信号 / 速率）；
2. **我周围有哪些 AP、挤在哪几个信道**（可见 BSS 列表 → 信道占用）；
3. **这台机器的无线什么时候连过、断过、连失败过**（`WLAN-AutoConfig` 事件日志）；
4. **这个 SSID/BSSID 对应哪个网段**（与既有 IPv4/IPv6 子网做关联提示）。

**不做清单**（与 ndp.py 同一种诚实）：不扫无线、不做 monitor、不解析 802.11 帧、
不画热图、不跨平台等价（**Windows 独占**，非 Windows 明确返回「本平台无此能力」）。

两层取数
--------
- **主路径**：`ctypes` 直调 `wlanapi.dll`（`WlanOpenHandle` / `WlanEnumInterfaces`
  / `WlanQueryInterface` / `WlanGetNetworkBssList`）。`ctypes` 是**标准库**，
  不破「不加依赖」铁律；而且返回的是**结构化数值**（信号质量、中心频率），
  **不受系统语言影响** —— 这是它做主路径的真正理由。
- **降级路径**：`netsh wlan show interfaces` / `show networks mode=bssid` 的**文本解析**。
  文本随系统语言变，所以走**标签表（zh-CN + en-US）+ 形状兜底**，而不是固定列宽：

  🔴 **绝不按固定列宽切片**。本机实测：`SSID 1 : QZTJXX` 的冒号前**只有一个空格**，
  而 `名称                   : WLAN` 前面有十几个 —— 任何"按 2+ 空格切列"的规则都会
  在第一种行上静默错位。判定规则是「**第一个半角/全角冒号**切分 + 键名去空白后查表」。

零 PyQt / 零第三方 / 零网络
---------------------------
🔴 本模块**不 import `socket` / `urllib` / `requests` / `ssl`**，也不 import
`scanner.util` / `scanner.ping`（那两个 import 了 `socket`）—— 自己的 `_run()`
只有十几行、`ipconfig` 解析只有几十行，值得为「可证明不出网」各重写一遍。
（`ipaddress` 是纯计算模块，`python -S -c "import ipaddress"` 不会带出 `socket`。）
`wlanapi` 的扫描/查询是**本机 API 调用**，`netsh` / `wevtutil` / `ipconfig` 是
**本机命令**，都不发 IP 包。

🔴 **主动扫描要显式触发**：`WlanGetNetworkBssList` 只读**上次扫描的缓存**；
要刷新得调 `WlanScan`（让无线电真的去扫一圈）。`scan_networks()` 因此默认**不调**
`WlanScan`，只有 `refresh=True` 时才调 —— 与 mDNS 的 `listen_only`、LLMNR 探测的
「默认不发包」同口径。
"""
import ctypes
import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app_logging import get_logger

_log = get_logger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_SUBPROCESS_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ── 规范值（语言无关；**文案不在这里**，调用方按规范值取自己的显示名） ──────

#: 取数来源。
SOURCE_WLANAPI = "wlanapi"      # 主路径：结构化 API
SOURCE_NETSH = "netsh"          # 降级：文本解析
SOURCE_NONE = "none"            # 拿不到
SOURCE_WEVTUTIL = "wevtutil"    # 漫游时间线：读事件日志（只读，不写）

#: 关联状态（netsh 的「已连接 / connected」→ `connected`）。
STATE_CONNECTED = "connected"
STATE_DISCONNECTED = "disconnected"
STATE_UNKNOWN = "unknown"

#: 能力不可用的原因（规范值）。`ok` 之外的每个值调用方都要给"下一步"。
REASON_OK = "ok"
REASON_NOT_WINDOWS = "not-windows"
REASON_NO_WLANAPI = "no-wlanapi"        # 没有 wlanapi.dll（老系统 / 精简版）
REASON_SERVICE_STOPPED = "service-stopped"   # WlanSvc 没跑（错误码 1062）
REASON_NO_ADAPTER = "no-adapter"        # 有 API 但没有无线网卡
REASON_QUERY_FAILED = "query-failed"

#: `WifiSnapshot.notes` 的规范值（**调用方自己给显示文案**，本模块不产文案）。
#: 每一项独立降级 → 界面要说清"哪一项没拿到、为什么"。
NOTE_NO_INTERFACE = "no-interface"      # 当前关联都读不到
NOTE_DISCONNECTED = "disconnected"      # 有网卡，但没连上
NOTE_NO_BSS = "no-bss"                  # 一个可见 AP 都没有（radio 关/服务停）
NOTE_NO_ROAMING_LOG = "no-roaming-log"  # 读不到事件日志（非 Windows/无权限/空）
NOTE_NO_SUBNET = "no-subnet"            # 连上了，但网卡 ↔ 网段没关联上
ALL_NOTES = (NOTE_NO_INTERFACE, NOTE_DISCONNECTED, NOTE_NO_BSS,
             NOTE_NO_ROAMING_LOG, NOTE_NO_SUBNET)

#: 波段（规范值）。`2.4GHz` 是**显示用不到**的紧凑写法，GUI 自己加空格。
BAND_24 = "2.4GHz"
BAND_5 = "5GHz"
BAND_6 = "6GHz"
BAND_UNKNOWN = "unknown"

#: 漫游事件类型（规范值）。数字是 `WLAN-AutoConfig` 的 EventID。
ROAM_ATTEMPT = "attempt"        # 8000 开始尝试
ROAM_ASSOCIATED = "associated"  # 8001 关联成功
ROAM_FAILED = "failed"          # 8002 关联失败
ROAM_DISCONNECTED = "disconnected"  # 8003 断开

_ROAM_EVENT_IDS = {
    "8000": ROAM_ATTEMPT,
    "8001": ROAM_ASSOCIATED,
    "8002": ROAM_FAILED,
    "8003": ROAM_DISCONNECTED,
}

#: 事件日志通道。只读，不改。
ROAM_CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"

#: 本机命令的输出编码：`netsh` 在管道下实测是 UTF-8，但**其它中文 Windows 上
#: 可能是 cp936**（`wevtutil` 本机实测就是 cp936）—— 逐个试。
#: ⚠️ cp1252 **不放进这里**：它是单字节全映射（256 个码位全有定义）、永不失败，
#: 放进来会让它后面的兜底变成不可达代码。它作为**循环外的兜底**存在（见
#: `decode_output`）。
_DECODE_CANDIDATES = ("utf-8", "cp936")

#: 最大漫游事件条数（GUI 时间线用不了更多，日志本身可能上万条）。
MAX_ROAM_EVENTS = 200

#: 无线网卡 ↔ 网段的关联依据（`WifiSnapshot.subnet_match` 用它）。
#: 🔴 定义必须早于 `WifiSnapshot`（dataclass 字段默认值在类体求值）。
MATCH_BY_NAME = "name"          # 适配器名直接命中
MATCH_BY_KEYWORD = "keyword"    # 靠"无线适配器"特征词命中
MATCH_BY_NONE = "none"          # 关联不上（如实说，不硬凑）


# ── 输出结构 ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WifiCapability:
    """本机有没有「无线切片」能力；不可用时 `reason` 说明为什么。"""

    supported: bool
    reason: str = REASON_OK
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"supported": self.supported, "reason": self.reason,
                "detail": self.detail}


@dataclass
class WifiInterface:
    """一块无线网卡的当前状态（已连接时才有 SSID/BSSID/波段/信道/信号）。"""

    name: str = ""
    description: str = ""
    guid: str = ""
    mac: str = ""
    state: str = STATE_UNKNOWN
    ssid: str = ""
    bssid: str = ""
    band: str = BAND_UNKNOWN
    channel: Optional[int] = None
    radio_type: str = ""
    auth: str = ""
    cipher: str = ""
    rx_mbps: Optional[int] = None
    tx_mbps: Optional[int] = None
    signal_percent: Optional[int] = None
    rssi_dbm: Optional[int] = None
    profile: str = ""
    radio_hardware_on: Optional[bool] = None
    radio_software_on: Optional[bool] = None
    source: str = SOURCE_NONE

    @property
    def connected(self) -> bool:
        return self.state == STATE_CONNECTED

    @property
    def display_name(self) -> str:
        """给人看的名字：优先 netsh 的连接名（"WLAN"），否则退回描述。

        🔴 两条取数路径能给的字段不一样：`netsh` 给「名称」（连接名），
        `wlanapi` **只有** `strInterfaceDescription`。所以界面别直接读 `.name`
        （走 wlanapi 时它是空串），一律读这个属性。
        """
        return self.name or self.description or self.guid or "?"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "description": self.description, "guid": self.guid,
            "mac": self.mac, "state": self.state, "ssid": self.ssid,
            "bssid": self.bssid, "band": self.band, "channel": self.channel,
            "radio_type": self.radio_type, "auth": self.auth,
            "cipher": self.cipher, "rx_mbps": self.rx_mbps,
            "tx_mbps": self.tx_mbps, "signal_percent": self.signal_percent,
            "rssi_dbm": self.rssi_dbm, "profile": self.profile,
            "radio_hardware_on": self.radio_hardware_on,
            "radio_software_on": self.radio_software_on, "source": self.source,
            # 派生字段：省得 CLI/GUI 各自重写一遍"name 空就用 description"。
            "display_name": self.display_name,
        }


@dataclass
class WifiBss:
    """一个可见的 BSS（= 一个 AP 的一个射频）。

    `ssid` 为空串是**真实情况**（隐藏 SSID），不是解析失败 —— 所以这里不用
    `Optional`：区分「隐藏」与「没解析到」靠 `ssid_known` 字段。
    """

    ssid: str = ""
    ssid_known: bool = True
    bssid: str = ""
    band: str = BAND_UNKNOWN
    channel: Optional[int] = None
    signal_percent: Optional[int] = None
    radio_type: str = ""
    auth: str = ""
    cipher: str = ""
    source: str = SOURCE_NONE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid, "ssid_known": self.ssid_known, "bssid": self.bssid,
            "band": self.band, "channel": self.channel,
            "signal_percent": self.signal_percent,
            "radio_type": self.radio_type, "auth": self.auth,
            "cipher": self.cipher, "source": self.source,
        }


@dataclass(frozen=True)
class RoamEvent:
    """漫游/关联时间线上的一条事件。

    ⚠️ `reason_text` 是**操作系统给的原文**（随系统语言变），本模块不翻译、
    也不拿它做判断 —— 判断只看 `kind` 与 `reason_code`。
    """

    timestamp: Optional[datetime]
    kind: str
    ssid: str = ""
    reason_code: str = ""
    reason_text: str = ""
    event_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": (self.timestamp.isoformat() if self.timestamp else None),
            "kind": self.kind, "ssid": self.ssid, "reason_code": self.reason_code,
            "reason_text": self.reason_text, "event_id": self.event_id,
        }


@dataclass(frozen=True)
class ChannelLoad:
    """某个信道上压着多少 AP —— 这就是「信道拥塞」的全部内容。

    `overlapping` 只对 2.4 GHz 有意义：那里 1/6/11 之外的信道会**相互重叠**，
    「同信道有几台」低估了实际干扰。判据用标准的「±4 信道内算重叠」。
    """

    band: str
    channel: int
    ap_count: int
    overlapping: int = 0
    strongest_signal: Optional[int] = None
    is_current: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "band": self.band, "channel": self.channel, "ap_count": self.ap_count,
            "overlapping": self.overlapping,
            "strongest_signal": self.strongest_signal,
            "is_current": self.is_current,
        }


@dataclass
class WifiSnapshot:
    """一次取数的聚合结果（GUI / 报告只消费这一个对象）。

    每一项都带**自己的来源**：主路径与降级路径可以同时只有一半成功，
    所以不能用一个全局 `source` 把它们糊在一起。
    """

    capability: WifiCapability
    interface: Optional[WifiInterface] = None
    interface_source: str = SOURCE_NONE
    bss_list: List[WifiBss] = field(default_factory=list)
    bss_source: str = SOURCE_NONE
    roam_events: List[RoamEvent] = field(default_factory=list)
    roam_source: str = SOURCE_NONE
    #: 与无线网卡**关联上**的网段（`link_subnets` 的产物）。
    subnets: List[str] = field(default_factory=list)
    #: 本机全部 IPv4 网段（关联不上时用户仍需要看到它，才知道该手工核对什么）。
    all_subnets: List[str] = field(default_factory=list)
    #: 关联依据：`name` / `keyword` / `none`（`none` 表示**没关联上**，如实说）。
    subnet_match: str = MATCH_BY_NONE
    notes: List[str] = field(default_factory=list)

    def channel_loads(self) -> List[ChannelLoad]:
        """当前关联所在波段的信道占用（没连上就用可见 AP 最多的那个波段）。"""
        band = None
        channel = None
        if self.interface is not None and self.interface.connected:
            band, channel = self.interface.band, self.interface.channel
        return channel_loads(self.bss_list, band=band, current_channel=channel)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability.to_dict(),
            "interface": self.interface.to_dict() if self.interface else None,
            "interface_source": self.interface_source,
            "bss_list": [b.to_dict() for b in self.bss_list],
            "bss_source": self.bss_source,
            "roam_events": [e.to_dict() for e in self.roam_events],
            "roam_source": self.roam_source,
            "subnets": list(self.subnets),
            "all_subnets": list(self.all_subnets),
            "subnet_match": self.subnet_match,
            "channel_loads": [c.to_dict() for c in self.channel_loads()],
            "notes": list(self.notes),
        }


# ── 子进程 / 解码（刻意不 import scanner.util：那边有 socket） ───────────

def decode_output(raw: bytes) -> str:
    """本机命令输出 → 文本。UTF-8 → cp936 → cp1252 兜底。

    🔴 不写死单一编码：`netsh` 在管道下实测 UTF-8，而同一台机器上 `wevtutil`
    实测 cp936 —— **同一台机器上两个命令的编码都不一样**，写死必错一边。
    """
    for cand in _DECODE_CANDIDATES:
        try:
            return raw.decode(cand)
        except (UnicodeDecodeError, LookupError):
            continue
    # 兜底保证「永远返回 str、永不抛」：cp1252 单字节全映射，走到这里说明前两种
    # 都不是合法编码、内容已经是乱码了 —— 别再挑编码，如实把字节摊成字符。
    return raw.decode("cp1252", errors="replace")


def _run(cmd: Sequence[str], timeout: float = 12) -> str:
    """跑一条本机命令并返回文本；失败返回空串（**不抛**）。

    失败只 `debug`：`netsh` 不可用是**预期内**的降级路径（非 Windows、
    精简系统、服务被停），调用方靠"返回空"走到诚实降级，不需要告警刷屏。
    """
    try:
        proc = subprocess.run(list(cmd), capture_output=True, timeout=timeout,
                              creationflags=_SUBPROCESS_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        _log.debug("命令执行失败 %s: %s", list(cmd)[:3], e)
        return ""
    return decode_output(proc.stdout)


# ── 文本解析：标签表 + 第一个冒号切分 ────────────────────────────────────

def _norm_key(key: str) -> str:
    """键名归一：**去掉所有空白**（含全角空格）后小写。

    样本里同一个键有 `接收速率(Mbps)` 与 `传输速率 (Mbps)` 两种写法，
    还有 `已配置     QoS MSCS` 这种中间夹空白的 —— 去空白比对才稳。
    """
    return re.sub(r"\s+", "", key).replace("\u3000", "").lower()


#: netsh 文案 → 规范字段名。**这是匹配表，不是显示表** —— 不进 i18n。
_IFACE_KEYS = {
    "name": "name", "description": "description", "guid": "guid",
    "physicaladdress": "mac", "macaddress": "mac",
    "interfacetype": "iface_type",
    "state": "state",
    "ssid": "ssid",
    "apbssid": "bssid", "bssid": "bssid", "networkbssid": "bssid",
    "band": "band",
    "channel": "channel", "channelnumber": "channel",
    "radiotype": "radio_type", "phytype": "radio_type",
    "authentication": "auth",
    "cipher": "cipher", "encryption": "cipher",
    "connectionmode": "conn_mode",
    # 英文 netsh 原文：`Receive rate (Mbps)` / `Transmit rate (Mbps)`（去空白后比对）。
    "receiverate(mbps)": "rx_mbps", "transmitrate(mbps)": "tx_mbps",
    "signal": "signal",
    "rssi": "rssi",
    "profile": "profile",
    "radiostate": "radio_state",
    "interfacename": "iface_name",
    "networktype": "network_type",
    "basicrates(mbps)": "basic_rates",
    "otherrates(mbps)": "other_rates",
}

#: 中文文案（netsh 随系统语言变，所以中文单独一张，键是**原文**）。
_IFACE_KEYS_ZH = {
    "名称": "name", "说明": "description",
    "物理地址": "mac", "界面类型": "iface_type",
    "状态": "state", "波段": "band",
    "通道": "channel", "频道": "channel",
    "无线电类型": "radio_type",
    "身份验证": "auth", "密码": "cipher", "加密": "cipher",
    "连接模式": "conn_mode",
    "接收速率(mbps)": "rx_mbps", "传输速率(mbps)": "tx_mbps",
    "信号": "signal", "配置文件": "profile",
    "无线电状态": "radio_state", "接口名称": "iface_name",
    "网络类型": "network_type",
    "基本速率(mbps)": "basic_rates", "其他速率(mbps)": "other_rates",
}

#: 中文原文 → 规范字段（键同样去空白 + 小写后再查）。
_IFACE_KEYS_ZH_NORM = {_norm_key(k): v for k, v in _IFACE_KEYS_ZH.items()}


def _field_of(key: str) -> Optional[str]:
    """netsh 键名 → 规范字段名；认不出返回 `None`（**不抛**）。

    认不出是**正常情况**：`netsh` 会带一堆我们不需要的键（QoS、速率集…），
    换个系统语言还会有更多。忽略它们，剩下的字段照样能用。
    """
    norm = _norm_key(key)
    return _IFACE_KEYS.get(norm) or _IFACE_KEYS_ZH_NORM.get(norm)


_KV_RE = re.compile(r"^(?P<indent>[ \t\u3000]*)(?P<key>[^:：]+?)[ \t\u3000]*[:：][ \t\u3000]*(?P<value>.*)$")
_SSID_HEAD_RE = re.compile(r"^[ \t]*SSID\s+(?P<n>\d+)\s*[:：]\s*(?P<value>.*)$")
_BSSID_HEAD_RE = re.compile(r"^[ \t]*BSSID\s+(?P<n>\d+)\s*[:：]\s*(?P<value>.*)$")
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_PERCENT_RE = re.compile(r"^(\d{1,3})\s*%$")
_INT_RE = re.compile(r"^-?\d+$")


def _iter_kv(text: str):
    """逐行产出 `(indent, key, value)`；无法切成键值对的行产出 `(indent, None, line)`。"""
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        m = _KV_RE.match(line)
        if m is None:
            yield len(line) - len(line.lstrip()), None, line.strip()
            continue
        yield len(m.group("indent")), m.group("key"), m.group("value").strip()


def _to_int(value: str) -> Optional[int]:
    s = (value or "").strip()
    return int(s) if _INT_RE.match(s) else None


def _to_percent(value: str) -> Optional[int]:
    m = _PERCENT_RE.match((value or "").strip())
    if m is None:
        return None
    n = int(m.group(1))
    return n if 0 <= n <= 100 else None


def _to_state(value: str) -> str:
    """关联状态 → 规范值。中英文都认；认不出 → `unknown`（**不猜**）。"""
    s = _norm_key(value)
    if s in ("已连接", "connected"):
        return STATE_CONNECTED
    if s in ("已断开连接", "disconnected", "未连接"):
        return STATE_DISCONNECTED
    if s in ("正在连接", "正在断开连接", "authenticating", "associating",
             "disconnecting", "discovering"):
        # 过渡态：**不当作已连接**（此时 SSID 可能还是上一次的）
        return STATE_DISCONNECTED
    return STATE_UNKNOWN


def band_for_frequency_khz(freq_khz: int) -> str:
    """中心频率（kHz）→ 波段。"""
    mhz = freq_khz / 1000.0
    if 2400 <= mhz <= 2500:
        return BAND_24
    if 5150 <= mhz <= 5895:
        return BAND_5
    if 5925 <= mhz <= 7125:
        return BAND_6
    return BAND_UNKNOWN


def channel_for_frequency_khz(freq_khz: int) -> Optional[int]:
    """中心频率（kHz）→ 信道号。算不出来返回 `None`（不猜一个看起来合理的数）。

    公式是 802.11 标准里那三条：
    * 2.4 GHz：`ch = (MHz - 2407) / 5`，信道 14 = 2484 MHz 单独处理；
    * 5 GHz  ：`ch = (MHz - 5000) / 5`；
    * 6 GHz  ：`ch = (MHz - 5950) / 5`。
    """
    mhz = freq_khz / 1000.0
    if 2400 <= mhz <= 2500:
        if abs(mhz - 2484) < 1:
            return 14
        ch = round((mhz - 2407) / 5.0)
        return ch if 1 <= ch <= 13 else None
    if 5150 <= mhz <= 5895:
        ch = round((mhz - 5000) / 5.0)
        return ch if ch >= 1 else None
    if 5925 <= mhz <= 7125:
        ch = round((mhz - 5950) / 5.0)
        return ch if ch >= 1 else None
    return None


def band_of_text(value: str) -> str:
    """netsh 的波段文案（`5 GHz` / `2.4 GHz`）→ 规范值。"""
    m = re.search(r"(\d+(?:\.\d+)?)", value or "")
    if m is None:
        return BAND_UNKNOWN
    try:
        num = float(m.group(1))
    except ValueError:
        return BAND_UNKNOWN
    if abs(num - 2.4) < 0.3:
        return BAND_24
    if abs(num - 5) < 0.5:
        return BAND_5
    if abs(num - 6) < 0.5:
        return BAND_6
    return BAND_UNKNOWN


def parse_interfaces(text: Any) -> List[WifiInterface]:
    """`netsh wlan show interfaces` 文本 → 网卡列表。

    解析规则（**不按列宽切片**，见模块 docstring）：
    1. 每行用**第一个**半角/全角冒号切成 `键 : 值`；
    2. 键名去空白后查标签表（中英文都在表里）；
    3. 认不出的键**直接忽略** —— 换语言/换版本只会少字段，不会错位；
    4. 出现 `名称`（`name`）字段即开始一条新记录（多网卡时 netsh 依次列出）；
    5. 无冒号的续行（如无线电状态的「软件 开」）并入**上一个键**的值。
    """
    text = _as_text(text)
    iface: Optional[WifiInterface] = None
    out: List[WifiInterface] = []
    last_field: Optional[str] = None

    for indent, key, value in _iter_kv(text):
        if key is None:                       # 无冒号的续行
            if iface is not None and last_field == "radio_state":
                _apply_radio_state(iface, value)
            continue
        field_name = _field_of(key)
        if field_name is None:
            last_field = None
            continue
        if field_name == "name":
            if iface is not None:
                out.append(iface)
            iface = WifiInterface(name=value)
        if iface is None:                     # 还没遇到「名称」就出现的键：忽略
            last_field = None
            continue
        _assign(iface, field_name, value)
        last_field = field_name
    if iface is not None:
        out.append(iface)
    return out


def _apply_radio_state(iface: WifiInterface, value: str) -> None:
    """`无线电状态: 硬件 开` + 续行 `软件 开` → 两个布尔。"""
    s = _norm_key(value)
    if "硬件" in s or "hardware" in s:
        iface.radio_hardware_on = ("开" in s) or ("on" in s)
    elif "软件" in s or "software" in s:
        iface.radio_software_on = ("开" in s) or ("on" in s)


def _assign(iface: WifiInterface, field_name: str, value: str) -> None:
    if field_name == "name":
        iface.name = value
    elif field_name == "description":
        iface.description = value
    elif field_name == "guid":
        iface.guid = value
    elif field_name == "mac":
        iface.mac = value.lower()
    elif field_name == "state":
        iface.state = _to_state(value)
    elif field_name == "ssid":
        iface.ssid = value
    elif field_name == "bssid":
        iface.bssid = value.lower() if _MAC_RE.match(value or "") else ""
    elif field_name == "band":
        iface.band = band_of_text(value)
    elif field_name == "channel":
        iface.channel = _to_int(value)
    elif field_name == "radio_type":
        iface.radio_type = value
    elif field_name == "auth":
        iface.auth = value
    elif field_name == "cipher":
        iface.cipher = value
    elif field_name == "rx_mbps":
        iface.rx_mbps = _to_int(value)
    elif field_name == "tx_mbps":
        iface.tx_mbps = _to_int(value)
    elif field_name == "signal":
        iface.signal_percent = _to_percent(value)
    elif field_name == "rssi":
        iface.rssi_dbm = _to_int(value)
    elif field_name == "profile":
        iface.profile = value
    elif field_name == "radio_state":
        _apply_radio_state(iface, value)


def parse_networks(text: Any) -> List[WifiBss]:
    """`netsh wlan show networks mode=bssid` 文本 → BSS 列表。

    结构是两层的：`SSID n : <名字>` 下面是这一组 BSS 共有的属性
    （网络类型 / 身份验证 / 加密），`BSSID n : <MAC>` 下面是该射频自己的属性
    （信号 / 无线电类型 / 波段 / 频道）。所以解析要**同时记住当前 SSID 组与
    当前 BSS**：组级属性给组内每个 BSS 打底，BSS 级属性覆盖它。
    """
    text = _as_text(text)
    out: List[WifiBss] = []
    group: Dict[str, str] = {}
    current: Optional[WifiBss] = None

    def _flush():
        if current is not None:
            out.append(current)

    for _indent, key, value in _iter_kv(text):
        if key is None:
            continue
        # `_iter_kv` 已按**第一个**冒号切分，所以这里把 key/value 合回去只为了
        # 复用同一套正则：`SSID 1` + `:` + `QZTJXX` → `SSID 1:QZTJXX`。
        # 🔴 不需要再额外判 `key.startswith("ssid")` —— 正则锚在行首，
        # `名称 : SSID 1:x` 这种行**不会**误判成组头。
        if _SSID_HEAD_RE.match("%s:%s" % (key, value)):
            _flush()
            current = None
            group = {"ssid": value}
            continue
        m_bssid = _BSSID_HEAD_RE.match("%s:%s" % (key, value))
        if m_bssid:
            _flush()
            current = WifiBss(
                ssid=group.get("ssid", ""),
                ssid_known=bool(group.get("ssid", "")),
                bssid=m_bssid.group("value").strip().lower(),
                auth=group.get("auth", ""),
                cipher=group.get("cipher", ""),
            )
            continue
        field_name = _field_of(key)
        if field_name is None:
            continue
        if current is None:                   # 组级属性
            if field_name in ("auth", "cipher", "network_type", "ssid"):
                group[field_name] = value
            continue
        if field_name == "signal":
            current.signal_percent = _to_percent(value)
        elif field_name == "radio_type":
            current.radio_type = value
        elif field_name == "band":
            current.band = band_of_text(value)
        elif field_name == "channel":
            current.channel = _to_int(value)
        elif field_name == "auth":
            current.auth = value
            group["auth"] = value
        elif field_name == "cipher":
            current.cipher = value
            group["cipher"] = value
        elif field_name == "bssid":
            current.bssid = value.lower() if _MAC_RE.match(value or "") else current.bssid
    _flush()
    # 去掉明显不是 MAC 的 BSSID（隐藏 SSID 组里可能出现空行/异常行）
    return [b for b in out if b.bssid]


def _as_text(value: Any) -> str:
    """接受 `str` 或 `bytes`（真实调用路径给的是 bytes）。"""
    if isinstance(value, bytes):
        return decode_output(value)
    return value if isinstance(value, str) else ""


# ── 信道拥塞（纯函数） ──────────────────────────────────────────────────

#: 2.4 GHz 的重叠判据：信道号相差 ≤4 就会互相干扰（1/6/11 是唯一互不重叠的三组）。
_OVERLAP_SPAN = 4


def channel_loads(bss: Sequence[WifiBss], *, band: Optional[str] = None,
                  current_channel: Optional[int] = None) -> List[ChannelLoad]:
    """按信道统计 AP 数（这就是「信道拥塞」）。

    `band=None` 时用**出现最多的那个波段**（用户通常关心自己连的那个；
    调用方一般显式传当前关联的波段）。

    2.4 GHz 额外给 `overlapping`：把 ±4 信道内的 AP 全算上 —— 只看同信道
    会低估干扰，而"哪条信道最空"正是用户想知道的那件事。
    """
    #: 🔴 先一次性把 `channel` 从 `Optional[int]` 收窄成 `int`（pyright 不会因为
    #: 列表推导里的 `is not None` 就收窄元素类型），后面就不用到处写 `int(...)`。
    known: List[Tuple[int, WifiBss]] = [(int(b.channel), b) for b in bss
                                        if b.channel is not None]
    if not known:
        return []
    if band is None:
        counts: Dict[str, int] = {}
        for _ch, item in known:
            counts[item.band] = counts.get(item.band, 0) + 1
        band = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
    known = [(ch, b) for ch, b in known if b.band == band]
    by_channel: Dict[int, List[WifiBss]] = {}
    for ch, item in known:
        by_channel.setdefault(ch, []).append(item)
    loads = []
    for ch in sorted(by_channel):
        group = by_channel[ch]
        signals = [b.signal_percent for b in group if b.signal_percent is not None]
        overlapping = 0
        if band == BAND_24:
            # 同频 + 邻频（±4）都算干扰源，所以必然 ≥ 本信道 AP 数。
            overlapping = sum(1 for other_ch, _b in known
                              if abs(other_ch - ch) <= _OVERLAP_SPAN)
        loads.append(ChannelLoad(
            band=band, channel=ch, ap_count=len(group),
            overlapping=overlapping if band == BAND_24 else 0,
            strongest_signal=max(signals) if signals else None,
            is_current=(current_channel is not None
                        and ch == int(current_channel)),
        ))
    return loads


def quietest_channel(loads: Sequence[ChannelLoad], *, band: str) -> Optional[int]:
    """当前波段里最空的信道（并列时取信道号小的）。

    只看 2.4 GHz 的「非重叠三信道」（1/6/11）：在一个 1–13 全重叠的波段里
    推荐信道 3 是**错**的建议（它和 1、6 都撞）。5/6 GHz 没有重叠问题，
    直接取 AP 最少的。
    """
    if not loads:
        return None
    if band == BAND_24:
        candidates = [c for c in loads if c.channel in (1, 6, 11)]
        if not candidates:
            return None
    else:
        candidates = list(loads)
    best = min(candidates, key=lambda c: (c.ap_count, c.channel))
    return best.channel


# ── wlanapi（ctypes 主路径） ────────────────────────────────────────────

#: `WlanQueryInterface` 的 opcode。
_OPCODE_CURRENT_CONNECTION = 7
_OPCODE_CHANNEL_NUMBER = 8

#: `WLAN_INTERFACE_STATE`：只有 1 是"已连接"。
_INTERFACE_STATE_CONNECTED = 1
_INTERFACE_STATE_NAMES = {
    0: STATE_DISCONNECTED,   # not_ready
    1: STATE_CONNECTED,      # connected
    2: STATE_CONNECTED,      # ad_hoc（也是连上了，只是拓扑不同）
    3: STATE_DISCONNECTED,   # disconnecting
    4: STATE_DISCONNECTED,   # disconnected
    5: STATE_DISCONNECTED,   # associating（过渡态，不当作已连接）
    6: STATE_DISCONNECTED,   # discovering
    7: STATE_DISCONNECTED,   # authenticating
}

_ERROR_SERVICE_NOT_RUNNING = 1062

_BSS_TYPE_ANY = 3


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    def __str__(self) -> str:                       # pragma: no cover - 仅调试
        d4 = "".join("%02x" % b for b in self.Data4)
        return "{%08x-%04x-%04x-%s-%s}" % (self.Data1, self.Data2, self.Data3,
                                           d4[:4], d4[4:])


class _DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_ulong), ("ucSSID", ctypes.c_ubyte * 32)]

    def text(self) -> str:
        n = min(int(self.uSSIDLength), 32)
        return bytes(bytearray(self.ucSSID[:n])).decode("utf-8", errors="replace")


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", _GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_uint)]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    #: 变长结构：`InterfaceInfo` 只有 1 个元素，按 `dwNumberOfItems` 手工偏移。
    _fields_ = [("dwNumberOfItems", ctypes.c_ulong), ("dwIndex", ctypes.c_ulong),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1)]


class _WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("dot11Ssid", _DOT11_SSID), ("dot11BssType", ctypes.c_uint),
                ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11PhyType", ctypes.c_uint),
                ("uDot11PhyIndex", ctypes.c_ulong),
                ("wlanSignalQuality", ctypes.c_ulong),
                ("ulRxRate", ctypes.c_ulong), ("ulTxRate", ctypes.c_ulong)]


class _WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("bSecurityEnabled", ctypes.c_int), ("bOneXEnabled", ctypes.c_int),
                ("dot11AuthAlgorithm", ctypes.c_uint),
                ("dot11CipherAlgorithm", ctypes.c_uint)]


class _WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("isState", ctypes.c_uint), ("wlanConnectionMode", ctypes.c_uint),
                ("strProfileName", ctypes.c_wchar * 256),
                ("wlanAssociationAttributes", _WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", _WLAN_SECURITY_ATTRIBUTES)]


class _WLAN_RATE_SET(ctypes.Structure):
    """`WLAN_RATE_SET`：4 字节长度 + 126 个 `USHORT`（= 256 字节）。

    🔴 不能省成 `c_ulong * 1`：它后面紧跟 `ulIeOffset` / `ulIeSize`，
    少 252 字节会让**每一条 BSS 的 IE 尺寸都读错**，进而步长走偏、
    后续条目全是垃圾数据（而不是报错）。
    """

    _fields_ = [("uRateSetLength", ctypes.c_ulong),
                ("usRateSet", ctypes.c_ushort * 126)]


class _WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", _DOT11_SSID), ("uPhyId", ctypes.c_ulong),
                ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11BssType", ctypes.c_uint),
                ("dot11PhyType", ctypes.c_uint), ("uDot11PhyIndex", ctypes.c_ulong),
                ("wlanSignalQuality", ctypes.c_ulong),
                ("ulRxRate", ctypes.c_ulong), ("ulTxRate", ctypes.c_ulong),
                ("uBeaconPeriod", ctypes.c_ulong),
                ("ulChCenterFrequency", ctypes.c_ulonglong),
                ("wlanRateSet", _WLAN_RATE_SET),
                ("ulIeOffset", ctypes.c_ulong), ("ulIeSize", ctypes.c_ulong)]


class _WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", ctypes.c_ulong), ("dwNumberOfItems", ctypes.c_ulong),
                ("wlanBssEntries", _WLAN_BSS_ENTRY * 1)]


def _mac_text(raw) -> str:
    return ":".join("%02x" % b for b in raw)


#: 802.11 PHY 类型 → 名字（`DOT11_PHY_TYPE`）。
_PHY_TYPES = {
    0: "", 1: "FHSS", 2: "DSSS", 3: "IR", 4: "802.11a", 5: "802.11b",
    6: "802.11g", 7: "802.11n", 8: "802.11ac", 9: "802.11ad",
    10: "802.11ax", 11: "802.11be",
}


class _WlanApi:
    """`wlanapi.dll` 的薄封装 —— **注入点**。

    所有 ctypes 调用都收在这个类里，测试传一个替身就能覆盖"主路径"，
    不必真的有一块无线网卡（CI 上没有）。这与 `ports.reset_async_engine_state()`
    是同一个思路：跨进程/跨机器的能力，必须能脱离真实硬件测。
    """

    def __init__(self, dll=None):
        if dll is None:
            dll = ctypes.WinDLL("wlanapi.dll")       # 非 Windows 会抛 OSError
        self._dll = dll

    # ── 会话 ──
    def open(self):
        """`WlanOpenHandle` → 句柄；失败抛 `OSError(errno)` 供调用方分类。"""
        negotiated = ctypes.c_ulong()
        handle = ctypes.c_void_p()
        rc = self._dll.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                                      ctypes.byref(handle))
        if rc != 0:
            raise OSError(rc, "WlanOpenHandle failed")
        return handle

    def close(self, handle) -> None:
        try:
            self._dll.WlanCloseHandle(handle, None)
        except OSError as e:                    # pragma: no cover - 只在收尾失败
            _log.debug("WlanCloseHandle 失败: %s", e)

    # ── 枚举 ──
    def interfaces(self, handle) -> List[Dict[str, Any]]:
        ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
        rc = self._dll.WlanEnumInterfaces(handle, None, ctypes.byref(ptr))
        if rc != 0:
            raise OSError(rc, "WlanEnumInterfaces failed")
        try:
            head = ptr.contents
            count = int(head.dwNumberOfItems)
            base = ctypes.addressof(head) + _WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
            stride = ctypes.sizeof(_WLAN_INTERFACE_INFO)
            out = []
            for i in range(count):
                info = _WLAN_INTERFACE_INFO.from_address(base + i * stride)
                out.append({"guid": info.InterfaceGuid,
                            "guid_text": str(info.InterfaceGuid),
                            "description": info.strInterfaceDescription,
                            "state": _INTERFACE_STATE_NAMES.get(int(info.isState),
                                                                STATE_UNKNOWN)})
            return out
        finally:
            self._dll.WlanFreeMemory(ptr)

    # ── 查询 ──
    def _query(self, handle, guid, opcode):
        size = ctypes.c_ulong()
        data = ctypes.c_void_p()
        opcode_type = ctypes.c_uint()
        rc = self._dll.WlanQueryInterface(handle, ctypes.byref(guid), opcode, None,
                                          ctypes.byref(size), ctypes.byref(data),
                                          ctypes.byref(opcode_type))
        if rc != 0:
            raise OSError(rc, "WlanQueryInterface(%d) failed" % opcode)
        return data, size

    def current_connection(self, handle, guid) -> Optional[Dict[str, Any]]:
        data, _size = self._query(handle, guid, _OPCODE_CURRENT_CONNECTION)
        try:
            attrs = ctypes.cast(data, ctypes.POINTER(_WLAN_CONNECTION_ATTRIBUTES)).contents
            assoc = attrs.wlanAssociationAttributes
            return {
                "state": _INTERFACE_STATE_NAMES.get(int(attrs.isState), STATE_UNKNOWN),
                "ssid": assoc.dot11Ssid.text(),
                "bssid": _mac_text(assoc.dot11Bssid),
                "radio_type": _PHY_TYPES.get(int(assoc.dot11PhyType), ""),
                "signal_percent": int(assoc.wlanSignalQuality),
                "rx_mbps": int(assoc.ulRxRate) // 1000,
                "tx_mbps": int(assoc.ulTxRate) // 1000,
                "profile": attrs.strProfileName,
            }
        finally:
            self._dll.WlanFreeMemory(data)

    def channel_number(self, handle, guid) -> Optional[int]:
        data, _size = self._query(handle, guid, _OPCODE_CHANNEL_NUMBER)
        try:
            return int(ctypes.cast(data, ctypes.POINTER(ctypes.c_ulong)).contents.value)
        finally:
            self._dll.WlanFreeMemory(data)

    def bss_list(self, handle, guid) -> List[Dict[str, Any]]:
        """`WlanGetNetworkBssList` → 每个可见射频的 SSID/BSSID/信号/中心频率。

        🔴 条目是**变长**的（尾部挂着 IE 字节）：步长必须按
        `sizeof(entry) + ulIeSize` 走。按固定 `sizeof(entry)` 递增会在第二个
        条目开始读串行 —— 而读串行的表现是"数据看起来合理但全错"，比崩溃难查。
        """
        ptr = ctypes.POINTER(_WLAN_BSS_LIST)()
        rc = self._dll.WlanGetNetworkBssList(handle, ctypes.byref(guid), None,
                                             _BSS_TYPE_ANY, False, None,
                                             ctypes.byref(ptr))
        if rc != 0:
            raise OSError(rc, "WlanGetNetworkBssList failed")
        try:
            head = ptr.contents
            count = int(head.dwNumberOfItems)
            base = ctypes.addressof(head) + _WLAN_BSS_LIST.wlanBssEntries.offset
            stride = ctypes.sizeof(_WLAN_BSS_ENTRY)
            out = []
            offset = 0
            for _ in range(count):
                entry = _WLAN_BSS_ENTRY.from_address(base + offset)
                out.append({
                    "ssid": entry.dot11Ssid.text(),
                    "bssid": _mac_text(entry.dot11Bssid),
                    "signal_percent": int(entry.wlanSignalQuality),
                    "freq_khz": int(entry.ulChCenterFrequency),
                    "radio_type": _PHY_TYPES.get(int(entry.dot11PhyType), ""),
                })
                offset += stride + max(0, int(entry.ulIeSize))
            return out
        finally:
            self._dll.WlanFreeMemory(ptr)

    def scan(self, handle, guid) -> None:
        """`WlanScan` —— **主动让无线电扫一圈**（只由 `refresh=True` 调用）。"""
        rc = self._dll.WlanScan(handle, ctypes.byref(guid), None, None, None)
        if rc != 0:
            raise OSError(rc, "WlanScan failed")


_WLANAPI_CACHE: Dict[str, Any] = {}


def reset_wlanapi_cache() -> None:
    """丢掉缓存的 `_WlanApi`（测试隔离用；与 `reset_throttle()` 同口径）。"""
    _WLANAPI_CACHE.clear()


def _load_wlanapi() -> Optional[_WlanApi]:
    """惰性加载 wlanapi；不可用返回 `None`（**不抛**）。"""
    if "api" not in _WLANAPI_CACHE:
        api = None
        if _IS_WINDOWS:
            try:
                api = _WlanApi()
            except OSError as e:               # 没有 wlanapi.dll（精简系统）
                _log.debug("wlanapi.dll 不可用: %s", e)
            except AttributeError as e:        # 老系统缺导出函数
                _log.debug("wlanapi.dll 缺导出函数: %s", e)
        _WLANAPI_CACHE["api"] = api
    return _WLANAPI_CACHE["api"]


def capability(api: Optional[_WlanApi] = None) -> WifiCapability:
    """本机能不能做无线切片；不能时 `reason` 说明为什么（**不抛**）。"""
    if not _IS_WINDOWS:
        return WifiCapability(False, REASON_NOT_WINDOWS,
                              "wlanapi 是 Windows 独占 API（本项不做跨平台等价）")
    api = api if api is not None else _load_wlanapi()
    if api is None:
        return WifiCapability(False, REASON_NO_WLANAPI, "找不到 wlanapi.dll")
    try:
        handle = api.open()
    except OSError as e:
        if int(getattr(e, "errno", 0) or 0) == _ERROR_SERVICE_NOT_RUNNING:
            return WifiCapability(False, REASON_SERVICE_STOPPED, "WlanSvc 未运行")
        return WifiCapability(False, REASON_QUERY_FAILED, str(e))
    try:
        if not api.interfaces(handle):
            return WifiCapability(False, REASON_NO_ADAPTER, "没有无线网卡")
    except OSError as e:
        return WifiCapability(False, REASON_QUERY_FAILED, str(e))
    finally:
        api.close(handle)
    return WifiCapability(True, REASON_OK)


# ── 取数（主路径 → 降级 → 诚实失败） ─────────────────────────────────────

def query_interface(api: Optional[_WlanApi] = None, *, netsh_text: Optional[str] = None
                    ) -> Tuple[Optional[WifiInterface], str]:
    """当前关联的无线网卡 → `(接口, 来源)`。

    `source` ∈ `wlanapi` / `netsh` / `none`：**调用方必须据它决定文案**
    （"来自结构化 API" 与 "来自文本降级" 的可信度不同，尤其换语言的机器上）。

    🔴 `netsh_text` 是**硬覆盖**（给了就只走文本路径，与 `scan_networks` 同口径）：
    否则在真机（wlanapi 可用）上永远测不到降级分支 —— 而"降级分支能不能用"
    恰恰是最需要测的那条。
    """
    api = api if api is not None else _load_wlanapi()
    if api is not None and netsh_text is None:
        try:
            handle = api.open()
        except OSError as e:
            _log.debug("WlanOpenHandle 失败，改走 netsh: %s", e)
            handle = None
        if handle is not None:
            try:
                ifaces = api.interfaces(handle)
                if ifaces:
                    first = ifaces[0]
                    # ⚠️ wlanapi 只给 `strInterfaceDescription`（"Intel(R) Wi-Fi 6
                    # AX201 160MHz"），**给不出** netsh 那个连接名（"WLAN"）——
                    # 所以 `name` 留空，别拿描述冒充名字（`display_name` 负责回退）。
                    iface = WifiInterface(
                        name="",
                        description=first.get("description", ""),
                        guid=str(first.get("guid_text", "")),
                        state=first.get("state", STATE_UNKNOWN),
                        source=SOURCE_WLANAPI)
                    if iface.state == STATE_CONNECTED:
                        _fill_from_connection(api, handle, first["guid"], iface)
                    return iface, SOURCE_WLANAPI
            except OSError as e:
                _log.debug("wlanapi 取数失败，改走 netsh: %s", e)
            finally:
                api.close(handle)
    text = netsh_text if netsh_text is not None else _run(
        ["netsh", "wlan", "show", "interfaces"])
    parsed = parse_interfaces(text)
    if not parsed:
        return None, SOURCE_NONE
    parsed[0].source = SOURCE_NETSH
    return parsed[0], SOURCE_NETSH


def _fill_from_connection(api: _WlanApi, handle, guid, iface: WifiInterface) -> None:
    """把「当前连接」属性填进接口对象（失败就留空，**不抛**）。"""
    try:
        conn = api.current_connection(handle, guid)
    except OSError as e:
        _log.debug("WlanQueryInterface(current_connection) 失败: %s", e)
        return
    if not conn:
        return
    iface.ssid = conn.get("ssid", "")
    iface.bssid = conn.get("bssid", "")
    iface.radio_type = conn.get("radio_type", "")
    iface.signal_percent = conn.get("signal_percent")
    iface.rx_mbps = conn.get("rx_mbps")
    iface.tx_mbps = conn.get("tx_mbps")
    iface.profile = conn.get("profile", "")
    try:
        ch = api.channel_number(handle, guid)
    except OSError as e:
        _log.debug("WlanQueryInterface(channel_number) 失败: %s", e)
        ch = None
    iface.channel = ch
    if ch is not None:
        iface.band = _band_for_channel(ch)


def _band_for_channel(channel: int) -> str:
    """信道号 → 波段（`channel_for_frequency_khz` 的逆推，用于只有信道号的场合）。"""
    if 1 <= channel <= 14:
        return BAND_24
    if 32 <= channel <= 177:
        return BAND_5
    if channel >= 181:
        return BAND_6
    return BAND_UNKNOWN


def scan_networks(api: Optional[_WlanApi] = None, *, refresh: bool = False,
                  netsh_text: Optional[str] = None, wait_seconds: float = 1.5
                  ) -> Tuple[List[WifiBss], str]:
    """可见 BSS 列表 → `(列表, 来源)`。

    🔴 `refresh=True` 才会调 `WlanScan`（**让无线电真的扫一圈**）：默认只读
    系统缓存 —— 与 mDNS `listen_only`、LLMNR「默认不发包」同口径。
    扫完要等一会儿缓存才有新结果，所以 `refresh` 时 `sleep(wait_seconds)`。
    """
    api = api if api is not None else _load_wlanapi()
    if api is not None and netsh_text is None:
        try:
            handle = api.open()
        except OSError as e:
            _log.debug("WlanOpenHandle 失败，改走 netsh: %s", e)
            handle = None
        if handle is not None:
            try:
                ifaces = api.interfaces(handle)
                if ifaces:
                    if refresh:
                        try:
                            api.scan(handle, ifaces[0]["guid"])
                            _sleep(wait_seconds)
                        except OSError as e:
                            _log.debug("WlanScan 失败（继续读缓存）: %s", e)
                    entries = api.bss_list(handle, ifaces[0]["guid"])
                    out = [_bss_from_entry(e) for e in entries]
                    out = [b for b in out if b.bssid]
                    if out:
                        return out, SOURCE_WLANAPI
            except OSError as e:
                _log.debug("wlanapi 取 BSS 列表失败，改走 netsh: %s", e)
            finally:
                api.close(handle)
    text = netsh_text if netsh_text is not None else _run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"])
    parsed = parse_networks(text)
    for b in parsed:
        b.source = SOURCE_NETSH
    return parsed, (SOURCE_NETSH if parsed else SOURCE_NONE)


def _bss_from_entry(entry: Dict[str, Any]) -> WifiBss:
    freq = int(entry.get("freq_khz") or 0)
    return WifiBss(
        ssid=entry.get("ssid", ""),
        ssid_known=bool(entry.get("ssid", "")),
        bssid=str(entry.get("bssid", "")).lower(),
        band=band_for_frequency_khz(freq) if freq else BAND_UNKNOWN,
        channel=channel_for_frequency_khz(freq) if freq else None,
        signal_percent=entry.get("signal_percent"),
        radio_type=entry.get("radio_type", ""),
        source=SOURCE_WLANAPI,
    )


def _sleep(seconds: float) -> None:
    """可注入的等待（测试里被换掉，避免真等）。"""
    import time
    time.sleep(seconds)


# ── 漫游时间线（事件日志） ───────────────────────────────────────────────

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.S)
_EVENT_ID_RE = re.compile(r"<EventID>(\d+)</EventID>")
_TIME_RE = re.compile(r"<TimeCreated\s+SystemTime='([^']+)'")
_DATA_RE = re.compile(r"<Data\s+Name='([^']+)'>([^<]*)</Data>")


def parse_roaming_xml(xml: Any) -> List[RoamEvent]:
    """`WLAN-AutoConfig` 事件的 XML → 关联/断开/失败时间线（**只取 8000–8003**）。

    ⚠️ 本机实测：AutoConfig 的这几条事件**不带 BSSID**（只有 SSID/Profile），
    所以时间线是 **SSID 粒度**的 —— 想标成"漫游到某个 AP"会说过头。
    这里如实只记 `ssid`，BSSID 留给"当前关联"那一项。

    `11000`/`11004` 之类的内部事件（AutoConfig 自身的状态机）一律跳过：
    它们没有 SSID，混进时间线只会让"什么时候断的"更难读。
    """
    text = _as_text(xml)
    out: List[RoamEvent] = []
    for block in _EVENT_RE.findall(text):
        m_id = _EVENT_ID_RE.search(block)
        if m_id is None:
            continue
        event_id = m_id.group(1)
        kind = _ROAM_EVENT_IDS.get(event_id)
        if kind is None:
            continue
        data = {k: v for k, v in _DATA_RE.findall(block)}
        m_time = _TIME_RE.search(block)
        out.append(RoamEvent(
            timestamp=_parse_system_time(m_time.group(1) if m_time else ""),
            kind=kind,
            ssid=data.get("SSID", ""),
            reason_code=data.get("ReasonCode", ""),
            reason_text=data.get("Reason", "") or data.get("FailureReason", ""),
            event_id=event_id,
        ))
    out.sort(key=lambda e: (e.timestamp is None, e.timestamp or datetime.min))
    return out


def _parse_system_time(value: str) -> Optional[datetime]:
    """事件日志的 `2026-10-13T06:37:30.1875366Z` → UTC aware datetime。

    小数位是 **7 位**（100ns 精度），Python 3.10 的 `fromisoformat` 只认 3/6 位 ——
    与 `cve_snapshot.parse_timestamp` 同一个坑，这里同样手工规整。
    """
    s = (value or "").strip()
    if not s:
        return None
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(.*)\.(\d+)([+-]\d{2}:\d{2})?$", s)
    if m and len(m.group(2)) not in (3, 6):
        s = "%s.%s%s" % (m.group(1), (m.group(2) + "000000")[:6],
                         m.group(3) or "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        _log.debug("无法解析事件时间戳: %r", value)
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def roaming_events(limit: int = MAX_ROAM_EVENTS, *, xml_text: Optional[str] = None
                   ) -> Tuple[List[RoamEvent], str]:
    """读事件日志 → `(事件, 来源)`。读不到返回 `([], SOURCE_NONE)`（**不抛**）。

    只读、不写、不改日志设置；`wevtutil` 需要读取 Operational 日志的权限，
    普通用户通常有 —— 没有时如实返回空并 `debug` 留痕。
    """
    if xml_text is None:
        if not _IS_WINDOWS:
            return [], SOURCE_NONE
        xml_text = _run(["wevtutil", "qe", ROAM_CHANNEL, "/c:%d" % max(1, limit),
                         "/rd:true", "/f:xml"], timeout=20)
    events = parse_roaming_xml(xml_text)
    if not events:
        return [], SOURCE_NONE
    return events[-limit:], SOURCE_WEVTUTIL


# ── SSID ↔ BSSID ↔ 子网 ─────────────────────────────────────────────────

#: 无线适配器在 `ipconfig` 里的名字通常带这些词（中英文都列上）。
_WIFI_ADAPTER_HINTS = ("wi-fi", "wifi", "wlan", "wireless", "802.11", "无线")

# `MATCH_BY_NAME` / `MATCH_BY_KEYWORD` / `MATCH_BY_NONE` 在文件顶部「规范值」区定义
# （`WifiSnapshot` 的字段默认值要在类体求值，必须早于 dataclass）。

#: `ipconfig` 的适配器标题行（**顶格**、以冒号结尾），例如
#: `无线局域网适配器 WLAN:` / `Wireless LAN adapter WLAN:`。
_IPCONFIG_HEAD_RE = re.compile(r"^(?P<name>\S.*?)\s*[:：]\s*$")
#: IPv4 地址 / 子网掩码（中英双语）。
#: ⚠️ 与 `scanner/ping.py` 的同名正则是**故意重复**的 —— 那个模块 `import socket`，
#: 本模块不能依赖它。两份实现的一致性由测试对同一份文本**交叉对拍**守住
#: （`tests/test_wifi.py::AdapterSubnetParseTest`）。
_IPCONFIG_IP_RE = re.compile(r"IPv4\s*(?:地址|Address)[^\d]*(\d+\.\d+\.\d+\.\d+)", re.I)
_IPCONFIG_MASK_RE = re.compile(
    r"(?:子网掩码|Subnet\s*Mask)[^\d]*(\d+\.\d+\.\d+\.\d+)", re.I)


def parse_adapter_subnets(text: Any) -> List[Tuple[str, str]]:
    """`ipconfig` 文本 → `[(适配器名, CIDR), ...]`（**带适配器名**）。

    `scanner.ping.windows_ipconfig_subnets()` 只给 `(ip, 掩码)`，没有适配器名 ——
    而"这个网段是不是无线网卡的"只能靠名字判（见 `link_subnets` 的两条规则）。
    所以这里按**标题行**分段：顶格、以冒号结尾的行开一个新适配器，段内的
    IP/掩码配对挂到它名下。

    配对规则与 `parse_windows_ipconfig` 一致：**先 IP 后掩码**才成对（避免多网卡
    场景错位）；只有地址没有掩码的条目丢弃。CIDR 由 `ip_network(strict=False)` 算，
    与扫描器口径相同。
    """
    out: List[Tuple[str, str]] = []
    name = ""
    cur_ip: Optional[str] = None
    for raw in _as_text(text).splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():                 # 顶格 → 适配器标题
            head = _IPCONFIG_HEAD_RE.match(line)
            name = head.group("name").strip() if head else ""
            cur_ip = None
            continue
        m = _IPCONFIG_IP_RE.search(line)
        if m:
            cur_ip = m.group(1)
            continue
        sm = _IPCONFIG_MASK_RE.search(line)
        if sm and cur_ip:
            try:
                cidr = str(ipaddress.ip_network("%s/%s" % (cur_ip, sm.group(1)),
                                                strict=False))
            except ValueError as e:
                # 掩码不是合法掩码（如 0.0.0.0）→ 丢掉这一对，别猜一个网段
                _log.debug("ipconfig 掩码无法解析 %s/%s: %s",
                           cur_ip, sm.group(1), e)
                cur_ip = None
                continue
            out.append((name, cidr))
            cur_ip = None
    return out


def local_adapter_subnets() -> List[Tuple[str, str]]:
    """跑一次 `ipconfig` 并解析出 `[(适配器名, CIDR), ...]`；失败返回 `[]`。

    `ipconfig` 是**本机命令**（不发 IP 包），与 `netsh` / `wevtutil` 同一类；
    非 Windows 直接返回空（Windows 独占项）。
    """
    if not _IS_WINDOWS:
        return []
    return parse_adapter_subnets(_run(["ipconfig"], timeout=10))


def link_subnets(iface: Optional[WifiInterface],
                 adapter_subnets: Optional[Sequence[Tuple[str, str]]] = None
                 ) -> Dict[str, Any]:
    """把当前关联的 SSID/BSSID 与网段挂起来 → `{matched, all, matched_by}`。

    🔴 网段**解析**刻意不复用 `scanner/ping.py`：那个模块 `import socket`，本模块
    一旦依赖它就再也**证明不了"不出网"**。所以本模块自带
    `parse_adapter_subnets()`（见那里的注释），本函数则仍是**纯投影**：
    入参不动、不跑命令。

    `adapter_subnets` 是 `[(适配器名, CIDR), ...]`。关联规则：
    ① 适配器名里**包含**网卡名（`WLAN` 命中「无线局域网适配器 WLAN」）；
    ② 否则按"无线适配器特征词"命中；
    ③ 都不中 → `matched_by="none"`、`matched` 为空 —— **如实说关联不上**，
    不把"本机所有网段"冒充成"无线网段"。
    """
    pairs = [(str(n), str(c)) for n, c in (adapter_subnets or [])]
    all_cidrs = sorted({c for _n, c in pairs})
    if iface is None or not pairs:
        return {"matched": [], "all": all_cidrs, "matched_by": MATCH_BY_NONE}

    keys = [k.strip() for k in (iface.name, iface.description) if k and k.strip()]
    for name, cidr in pairs:
        low = name.lower()
        if any(k.lower() in low for k in keys):
            return {"matched": sorted({c for n, c in pairs if n == name}),
                    "all": all_cidrs, "matched_by": MATCH_BY_NAME}
    for name, cidr in pairs:
        low = name.lower()
        if any(h in low for h in _WIFI_ADAPTER_HINTS):
            return {"matched": sorted({c for n, c in pairs if n == name}),
                    "all": all_cidrs, "matched_by": MATCH_BY_KEYWORD}
    return {"matched": [], "all": all_cidrs, "matched_by": MATCH_BY_NONE}


def snapshot(api: Optional[_WlanApi] = None, *, refresh: bool = False,
             netsh_interfaces: Optional[str] = None,
             netsh_networks: Optional[str] = None,
             roaming_xml: Optional[str] = None,
             adapter_subnets: Optional[Sequence[Tuple[str, str]]] = None,
             include_roaming: bool = True) -> WifiSnapshot:
    """一次性取全（GUI 只调这一个函数）。

    每一项都**独立降级**：拿不到 BSS 列表不影响当前关联，读不到事件日志不影响
    前两项 —— 这也是 `notes` 存在的意义：把"哪一项没拿到、为什么"如实带回界面。

    `adapter_subnets` 不给时**自动跑一次 `ipconfig`**（`local_adapter_subnets()`）；
    显式传 `[]` 表示"就是不想关联"。关联失败不影响其它三项，只会多一条 `notes`。
    """
    cap = capability(api)
    snap = WifiSnapshot(capability=cap)
    if not cap.supported:
        snap.notes.append(cap.reason)
        return snap

    if adapter_subnets is None:
        adapter_subnets = local_adapter_subnets()

    iface, iface_src = query_interface(api, netsh_text=netsh_interfaces)
    snap.interface, snap.interface_source = iface, iface_src
    if iface is None:
        snap.notes.append(NOTE_NO_INTERFACE)
    elif iface.state == STATE_DISCONNECTED:
        snap.notes.append(NOTE_DISCONNECTED)

    bss, bss_src = scan_networks(api, refresh=refresh, netsh_text=netsh_networks)
    snap.bss_list, snap.bss_source = bss, bss_src
    if not bss:
        snap.notes.append(NOTE_NO_BSS)

    if include_roaming:
        events, roam_src = roaming_events(xml_text=roaming_xml)
        snap.roam_events, snap.roam_source = events, roam_src
        if not events:
            snap.notes.append(NOTE_NO_ROAMING_LOG)

    link = link_subnets(iface, adapter_subnets)
    snap.subnets = link["matched"]
    snap.all_subnets = link["all"]
    snap.subnet_match = link["matched_by"]
    if iface is not None and iface.connected and not snap.subnets:
        snap.notes.append(NOTE_NO_SUBNET)
    return snap
