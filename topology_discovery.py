# -*- coding: utf-8 -*-
"""网络拓扑发现：LLDP / CDP 邻居 + BRIDGE-MIB 转发表 → 真实链路。

三条互补的发现路径，按代价从低到高逐级升级
--------------------------------------------

1. **LLDP**（IEEE 802.1AB，`lldpRemTable` = 1.0.8802.1.1.2.1.4.1.1）
   多数厂商支持：HP/Aruba、Juniper、Dell、H3C、华为、锐捷、Extreme…
2. **CDP**（Cisco 专有，`cdpCacheTable` = 1.3.6.1.4.1.9.9.23.1.2.1.1）
   只有 Cisco 系支持；`cdpCacheCapabilities` 还能直接告诉我们对端是
   交换机还是路由器。
3. **BRIDGE-MIB 转发表**（`dot1dTpFdbTable`，复用 `switch_mapper`）
   交换机没开 LLDP/CDP 时的兜底。转发表是**交换机自己学到的**事实数据：
   「这个 MAC 是从我第几个口学到的」——足以还原接入层拓扑，还能识别交换机
   之间的上联口（某口上学到的 MAC 正好是另一台交换机的 MAC）。

历史缺陷（V1.7.4，用户反馈「拓扑视图无法识别交换机/路由器」）
------------------------------------------------------------

* `_discover_lldp_neighbors` 走的是 `lldpRemLocalPortNum` —— 那是 lldpRemTable
  的**第 2 列**，值只是一个 INTEGER；chassisId / portId / sysName 全在**别的列**
  里。于是每个邻居都成了空壳（remote_id 为空串），`discover_topology` 再把所有
  空壳折叠成**同一个** `ext:` 节点 —— 图上多出一个无名节点，一条真链路都没有。
* CDP 解析用 `parts[:-1]` 剥索引，而 cdpCacheTable 的索引是**两段**
  （cdpCacheIfIndex.cdpCacheDeviceIndex），列号永远匹配不上，整条路径等于没写。
* `_find_switches` 只认 `snmp_sys_descr` / `"SNMP" in services`。而 SNMP 识别
  必须先勾选「SNMP 协议」才会执行 —— 没勾选时**一台交换机都找不到**，直接返回
  空链路，界面回退成网关星型，用户看到的永远不是真实拓扑。
* 同一端口挂多个邻居（remIndex>1）、chassisId 是 networkAddress 子类型
  （值里第 1 字节是地址族）都未处理。

本模块**不依赖 PyQt**：布局 `layout_real_topology` 是纯函数，可单测。
"""
import ipaddress
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app_logging import get_logger
from bounded_pool import run_bounded
from i18n import tr
from scanner.constants import SVC_SNMP, service_code
from scanner.snmp import (
    _CDP_CACHE_BASE,
    _LLDP_REM_BASE,
    snmp_get_system,
    snmp_walk,
)
from scanner.snmp_v3 import ERR_NO_RESPONSE, snmp_v3_get_system, snmp_v3_walk

_log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  OID 常量
# ══════════════════════════════════════════════════════════════════════
#
# 基址从 scanner.snmp 取（那里是唯一来源），列号在这里按 MIB 定义展开 —— 列号
# 写错是这块历史上最贵的 bug，所以 tests/test_topology_discovery.py 会拿真实的
# LLDP-MIB / CISCO-CDP-MIB 实例 OID 逐列断言。

# lldpRemEntry；实例 OID = entry . 列号 . lldpRemTimeMark . lldpRemLocalPortNum . lldpRemIndex
_LLDP_REM_ENTRY = _LLDP_REM_BASE
_LLDP_COL_CHASSIS_ID_SUBTYPE = 4
_LLDP_COL_CHASSIS_ID = 5
_LLDP_COL_PORT_ID_SUBTYPE = 6
_LLDP_COL_PORT_ID = 7
_LLDP_COL_PORT_DESC = 8
_LLDP_COL_SYS_NAME = 9
_LLDP_COL_SYS_DESC = 10

# chassisIdSubtype / portIdSubtype 里唯二的"二进制"取值，其余都是文本
_LLDP_ID_MAC_ADDRESS = 3
_LLDP_ID_NETWORK_ADDRESS = 4

# cdpCacheEntry；实例 OID = entry . 列号 . cdpCacheIfIndex . cdpCacheDeviceIndex
_CDP_CACHE_ENTRY = _CDP_CACHE_BASE
_CDP_COL_ADDRESS = 4
_CDP_COL_DEVICE_ID = 6
_CDP_COL_DEVICE_PORT = 7
_CDP_COL_PLATFORM = 8
_CDP_COL_CAPABILITIES = 9

# cdpCacheCapabilities 位含义（CISCO-CDP-MIB）
_CDP_CAP_ROUTER = 0x01
_CDP_CAP_SWITCH = 0x08

# IF-MIB：ifIndex → 端口名（LLDP 的 localPortNum 主流实现直接复用 ifIndex）
_OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
_OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"


# ══════════════════════════════════════════════════════════════════════
#  数据模型
# ══════════════════════════════════════════════════════════════════════

#: 节点种类。空串按 host 处理（向后兼容：旧调用方只设 is_switch）。
KIND_HOST = "host"
KIND_SWITCH = "switch"
KIND_ROUTER = "router"
KIND_GATEWAY = "gateway"
KIND_SUBNET = "subnet"

#: 会被画成"网络设备方块"的种类
INFRA_KINDS = (KIND_SWITCH, KIND_ROUTER, KIND_GATEWAY, KIND_SUBNET)


@dataclass
class TopoNode:
    """拓扑节点：交换机 / 路由器 / 终端设备 / 网段。"""
    id: str                          # 唯一标识 (IP、MAC 或合成 id)
    label: str                       # 显示名
    ip: str = ""
    mac: str = ""
    is_switch: bool = False
    vendor: str = ""
    model: str = ""
    kind: str = ""                   # 见 KIND_*；空串 = host
    device_class: str = ""           # 规范值（展示时走 device_class_label）
    online: bool = True
    is_gateway: bool = False
    #: 接入端口名（终端的"挂在哪个口"来自转发表；交换机的上联口来自 LLDP/CDP）。
    #: 画在图上会互相压字，所以走悬停提示。
    port: str = ""

    @property
    def is_infra(self) -> bool:
        """是否按"网络设备"绘制（交换机/路由器/网关/网段）。"""
        return self.is_switch or self.kind in INFRA_KINDS


@dataclass
class TopoLink:
    """拓扑链路：两个节点间的连接。"""
    source_id: str
    target_id: str
    source_port: str = ""            # 源端口名
    target_port: str = ""            # 目标端口名
    protocol: str = ""               # "LLDP" / "CDP" / "FDB" / "subnet"


@dataclass
class Topology:
    """完整拓扑。"""
    nodes: List[TopoNode] = field(default_factory=list)
    links: List[TopoLink] = field(default_factory=list)
    #: 图例尾部的一句补充：为什么长这样 / 有多少东西没画出来
    note: str = ""
    #: 识别到的可管理网络设备（交换机/路由器）台数
    infra_count: int = 0
    #: 转发表里学到了 MAC、但不在本次扫描范围内的设备数
    unplaced: int = 0


# ══════════════════════════════════════════════════════════════════════
#  SNMP 访问层（v2c / v3 统一）
# ══════════════════════════════════════════════════════════════════════

def _default_communities() -> List[str]:
    """返回默认 SNMP community 尝试列表。"""
    return ["public", "private", ""]


class _SnmpClient:
    """一台设备的 SNMP 访问入口：v3 优先、v2c 兜底，并记住哪个团体字通了。

    与 `scanner.engine._identify_snmp` 同一口径：**只有目标根本不回话**
    （ERR_NO_RESPONSE）才回退 v2c；凭据类错误直接记日志，否则「密码写错了」
    会被伪装成「这台设备不支持 SNMP」。
    """

    def __init__(self, ip: str, communities=None, timeout: float = 1.0,
                 snmp_v3_user=None, port: int = 161):
        self.ip = ip
        self.communities = list(communities) if communities else _default_communities()
        self.timeout = timeout
        self.user = snmp_v3_user
        self.port = port
        #: 本次会话中确认可用的团体字（供 switch_mapper 这类外部调用复用）
        self.working_community = ""

    def get_system(self) -> dict:
        """返回 {'sys_descr','sys_name','sys_objectid'}；取不到返回 {}。"""
        if self.user is not None:
            res = snmp_v3_get_system(self.ip, self.user, timeout=self.timeout,
                                     port=self.port)
            if "error" not in res:
                return res
            if res.get("error_kind") != ERR_NO_RESPONSE:
                # 凭据/配置错：不再用明文团体字去撞，避免把配置问题糊过去
                _log.warning("SNMPv3 识别失败 %s: %s", self.ip, res.get("error", ""))
                return {}
        for community in self.communities:
            info = snmp_get_system(self.ip, communities=[community],
                                   timeout=self.timeout, port=self.port)
            if info:
                self.working_community = self.working_community or community
                return info
        return {}

    def walk(self, base_oid: str, max_iterations: int = 2000) -> dict:
        """遍历子树；v3 优先，v2c 兜底。返回 {oid: (bytes, tag)}。"""
        if self.user is not None:
            entries = snmp_v3_walk(self.ip, self.user, base_oid,
                                   timeout=self.timeout, port=self.port,
                                   max_iterations=max_iterations)
            if entries:
                return entries
        for community in self.communities:
            entries = snmp_walk(self.ip, base_oid, community=community,
                                timeout=self.timeout, port=self.port,
                                max_iterations=max_iterations)
            if entries:
                self.working_community = self.working_community or community
                return entries
        return {}


# ══════════════════════════════════════════════════════════════════════
#  BER 取值小工具
# ══════════════════════════════════════════════════════════════════════

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_IPADDRESS = 0x40


def _as_int(vbytes, vtag) -> Optional[int]:
    """INTEGER / 位串 → int。取不到返回 None。"""
    if vtag not in (_TAG_INTEGER, _TAG_OCTET_STRING) or not vbytes:
        return None
    try:
        return int.from_bytes(vbytes, "big")
    except (TypeError, ValueError):
        return None


def _as_text(vbytes, vtag) -> str:
    """OCTET STRING → 文本；IPv4 地址类型 → 点分十进制；其余 → hex。"""
    if vtag == _TAG_IPADDRESS:
        return _bytes_to_ip(vbytes)
    if vtag == _TAG_INTEGER:
        n = _as_int(vbytes, vtag)
        return "" if n is None else str(n)
    if vtag != _TAG_OCTET_STRING:
        return _bytes_to_hex(vbytes)
    # 有些设备把定长 OCTET STRING 用 \x00 补齐，留着会在界面上显示成一串空格
    return vbytes.decode("utf-8", "replace").replace("\x00", "").strip()


def _bytes_to_ip(vbytes) -> str:
    """4 字节 → 点分十进制；其余返回 hex（不猜）。"""
    if len(vbytes) == 4:
        return ".".join(str(b) for b in vbytes)
    return _bytes_to_hex(vbytes)


def _bytes_to_hex(vbytes) -> str:
    """SNMP value bytes → hex:xx:xx 格式。"""
    return ":".join(f"{b:02x}" for b in vbytes)


def _bytes_to_mac(vbytes) -> str:
    """6 字节 → aa:bb:cc:dd:ee:ff（小写，便于跨厂商比对）。"""
    return ":".join(f"{b:02x}" for b in vbytes)


def _bytes_to_str(vbytes, vtag) -> str:
    """旧名保留（历史调用方/文档引用），等价于 `_as_text`。"""
    return _as_text(vbytes, vtag)


def _decode_lldp_identifier(subtype: Optional[int], vbytes, vtag) -> str:
    """按 subtype 解码 LLDP 的 chassisId / portId。

    只对"二进制"子类型特殊处理（3=macAddress、4=networkAddress）；其余
    （1=chassisComponent、5=interfaceName、6/7=locallyAssigned…）本来就是文本。

    subtype 缺失（对端没送那一列，或权限不足只 walk 到部分列）时按长度兜底：
    6 字节就是 MAC —— 否则 MAC 会被 UTF-8 解成乱码，再拿它去匹配扫描结果的
    MAC 必然失配，最后在图上多出一个 id 是乱码的"外部设备"。
    """
    if subtype == _LLDP_ID_MAC_ADDRESS and len(vbytes) == 6 and vtag in (
            _TAG_OCTET_STRING, _TAG_IPADDRESS):
        return _bytes_to_mac(vbytes)
    if subtype == _LLDP_ID_NETWORK_ADDRESS:
        return _decode_network_address(vbytes)
    if subtype is None and vtag == _TAG_OCTET_STRING:
        if len(vbytes) == 6:
            return _bytes_to_mac(vbytes)
        text = _as_text(vbytes, vtag)
        return text if _looks_like_text(text) else _bytes_to_hex(vbytes)
    return _as_text(vbytes, vtag)


def _looks_like_text(value: str) -> bool:
    """是否是可打印文本（区别于被误当 UTF-8 解的二进制）。

    `\ufffd`（U+FFFD REPLACEMENT CHARACTER）必须一起挡掉：`bytes.decode(errors=
    "replace")` 会把非法字节换成它，而它本身 `isprintable()` 为真 —— 只看
    isprintable 的话，`\\xff\\xfe\\x80` 会被"成功"解成三个替换符。
    """
    return bool(value) and "\ufffd" not in value and all(
        ch.isprintable() for ch in value)


def _decode_network_address(vbytes) -> str:
    """networkAddress：第 1 字节是地址族（1=IPv4，2=IPv6），其后是地址本体。"""
    if not vbytes:
        return ""
    family, body = vbytes[0], vbytes[1:]
    if family == 1 and len(body) == 4:
        return ".".join(str(b) for b in body)
    if family == 2 and len(body) == 16:
        # 长度已卡死 16 字节，`IPv6Address` 的 packed 形式不会抛
        return str(ipaddress.IPv6Address(body))
    return _bytes_to_hex(vbytes)


# ══════════════════════════════════════════════════════════════════════
#  表遍历结果拆解
# ══════════════════════════════════════════════════════════════════════

def _iter_instances(entries, entry_oid: str):
    """把 walk 结果拆成 `(列号, 索引字符串列表, (值, tag))`，**按 OID 升序**。

    升序很要紧：chassisId 的解码依赖同一行里**先读到的** subtype 列
    （列 4 < 列 5），而 `snmp_walk` 的插入顺序虽然事实上也是升序，但那是实现
    细节，不该被解析器依赖。OID 前导点在这里统一剥掉（零成本的防御）。
    """
    prefix = entry_oid.rstrip(".") + "."
    items = []
    for oid, value in entries.items():
        flat = oid.lstrip(".")
        if not flat.startswith(prefix):
            continue
        rest = flat[len(prefix):].split(".")
        if len(rest) < 2:
            continue
        items.append((_oid_sort_key(rest), rest[0], rest[1:], value))
    for _key, column, indexes, value in sorted(items, key=lambda x: x[0]):
        yield column, indexes, value


def _oid_sort_key(parts) -> Tuple[int, ...]:
    """OID 段按**数值**排序（字符串排序会把列 10 排到列 9 前面）。"""
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            out.append(1 << 30)
    return tuple(out)


def _column_entries(entries, column_oid: str):
    """遍历**单列**表（基址本身就是列 OID，例如 ifDescr / ifName）。

    与 `_iter_instances` 的区别：那里基址是"表项"、后面还有列号；这里的基址
    就是列，`rest` 只剩索引本身。搞混会让 `len(rest) >= 2` 的守卫把所有条目
    全部丢弃、端口名永远解析不出来。

    返回 `(索引后缀, (值, tag))`，按 OID 升序。
    """
    prefix = column_oid.rstrip(".") + "."
    items = []
    for oid, value in entries.items():
        flat = oid.lstrip(".")
        if not flat.startswith(prefix):
            continue
        suffix = flat[len(prefix):]
        if suffix:
            items.append((_oid_sort_key(suffix.split(".")), suffix, value))
    for _key, suffix, value in sorted(items, key=lambda x: x[0]):
        yield suffix, value


# ══════════════════════════════════════════════════════════════════════
#  LLDP
# ══════════════════════════════════════════════════════════════════════

def _parse_lldp_entries(entries) -> List[dict]:
    """解析 lldpRemTable walk 结果为邻居列表。

    索引是三段 `lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex`。同一个物理口
    上挂多台邻居（remIndex>1 —— 典型是口下面接了一台小交换机或 AP）必须按
    `(localPortNum, remIndex)` 分组；只按口分组会互相覆盖，直接丢设备。
    """
    if not entries:
        return []

    rows: Dict[Tuple[str, str], dict] = {}
    for column, indexes, (vbytes, vtag) in _iter_instances(entries, _LLDP_REM_ENTRY):
        if len(indexes) < 3:
            continue
        local_port, rem_index = indexes[-2], indexes[-1]
        row = rows.setdefault((local_port, rem_index),
                              {"local_port": local_port, "rem_index": rem_index})
        col = str(_to_int(column))
        if col == str(_LLDP_COL_CHASSIS_ID_SUBTYPE):
            row["chassis_subtype"] = _as_int(vbytes, vtag)
        elif col == str(_LLDP_COL_CHASSIS_ID):
            row["chassis_id"] = _decode_lldp_identifier(
                row.get("chassis_subtype"), vbytes, vtag)
        elif col == str(_LLDP_COL_PORT_ID_SUBTYPE):
            row["port_subtype"] = _as_int(vbytes, vtag)
        elif col == str(_LLDP_COL_PORT_ID):
            row["remote_port"] = _decode_lldp_identifier(
                row.get("port_subtype"), vbytes, vtag)
        elif col == str(_LLDP_COL_PORT_DESC):
            row["remote_port_desc"] = _as_text(vbytes, vtag)
        elif col == str(_LLDP_COL_SYS_NAME):
            row["sys_name"] = _as_text(vbytes, vtag)
        elif col == str(_LLDP_COL_SYS_DESC):
            row["sys_desc"] = _as_text(vbytes, vtag)

    out = []
    for key in _sorted_index_pairs(rows):
        row = rows[key]
        sys_name = row.get("sys_name", "")
        # sysDesc 常带多行版本号，只留首行当"平台"用
        sys_desc = _first_line(row.get("sys_desc"))
        local_port = row["local_port"]
        out.append({
            "local_port": local_port,
            "local_port_name": "",           # 由调用方用 ifName/ifDescr 补
            "local_port_desc": f"Port {local_port}",
            "remote_id": row.get("chassis_id", ""),
            "remote_port": row.get("remote_port", ""),
            "remote_port_desc": row.get("remote_port_desc", ""),
            "remote_name": sys_name,
            "remote_ip": row.get("chassis_id", "")
            if row.get("chassis_subtype") == _LLDP_ID_NETWORK_ADDRESS else "",
            "remote_platform": sys_desc,
            "remote_role": _role_from_text(sys_desc) or _role_from_text(sys_name),
            "protocol": "LLDP",
        })
    return out


def _to_int(text: str) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return -1


def _first_line(text) -> str:
    """取首行并去空白。`str.splitlines()` 对空串返回 `[]`，不能直接取 [0]。"""
    if not text:
        return ""
    return str(text).splitlines()[0].strip() if str(text).splitlines() else ""


def _sorted_index_pairs(rows: Dict[Tuple[str, str], dict]):
    """按数值顺序排索引对（保证邻居输出顺序稳定，便于复现与测试）。"""
    return sorted(rows, key=lambda k: (_to_int(k[0]), _to_int(k[1])))


def _discover_lldp_neighbors(switch_ip: str, communities=None,
                             timeout: float = 1.0, snmp_v3_user=None,
                             client: Optional["_SnmpClient"] = None,
                             port: int = 161) -> List[dict]:
    """对一台交换机执行 LLDP 邻居发现。

    ⚠️ 必须从 `lldpRemEntry` 起遍历**整张表**：只走某一列（历史 bug 走的是
    `lldpRemLocalPortNum`）永远拿不到 chassisId / portId / sysName。
    """
    client = client or _SnmpClient(switch_ip, communities, timeout,
                                   snmp_v3_user, port)
    neighbors = _parse_lldp_entries(client.walk(_LLDP_REM_ENTRY))
    if not neighbors:
        return []
    _attach_local_port_names(neighbors, client)
    return neighbors


def _attach_local_port_names(neighbors: List[dict], client: "_SnmpClient") -> None:
    """把 LLDP 的 localPortNum（= ifIndex）解析成可读端口名。

    `lldpRemLocalPortNum` 指向 `lldpLocPortTable`，而主流实现都直接复用 ifIndex，
    因此用 ifName/ifDescr 反查即可；查不到就保留 "Port N"。
    """
    names = _if_index_names(client)
    if not names:
        return
    for nb in neighbors:
        name = names.get(str(nb.get("local_port", "")))
        if name:
            nb["local_port_name"] = name
            nb["local_port_desc"] = name


def _if_index_names(client: "_SnmpClient") -> Dict[str, str]:
    """ifIndex → 端口名（先 ifDescr 兜底，再被 ifName 覆盖成短名）。"""
    names: Dict[str, str] = {}
    for base_oid in (_OID_IF_DESCR, _OID_IF_NAME):
        for suffix, (vbytes, vtag) in _column_entries(client.walk(base_oid), base_oid):
            name = _as_text(vbytes, vtag)
            if name:
                names[suffix] = name
    return names


# ══════════════════════════════════════════════════════════════════════
#  CDP
# ══════════════════════════════════════════════════════════════════════

def _parse_cdp_entries(entries) -> List[dict]:
    """解析 cdpCacheTable walk 结果为邻居列表。

    索引是**两段** `cdpCacheIfIndex.cdpCacheDeviceIndex` —— 历史实现按一段剥，
    列号永远匹配不上，整条 CDP 路径等于没写。
    """
    if not entries:
        return []

    rows: Dict[Tuple[str, str], dict] = {}
    for column, indexes, (vbytes, vtag) in _iter_instances(entries, _CDP_CACHE_ENTRY):
        if len(indexes) < 2:
            continue
        if_index, device_index = indexes[-2], indexes[-1]
        row = rows.setdefault((if_index, device_index),
                              {"local_port": if_index, "rem_index": device_index})
        col = str(_to_int(column))
        if col == str(_CDP_COL_ADDRESS):
            is_ip = vtag == _TAG_IPADDRESS or (
                vtag == _TAG_OCTET_STRING and len(vbytes) == 4)
            row["remote_ip"] = _bytes_to_ip(vbytes) if is_ip else _bytes_to_hex(vbytes)
        elif col == str(_CDP_COL_DEVICE_ID):
            row["remote_name"] = _as_text(vbytes, vtag)
        elif col == str(_CDP_COL_DEVICE_PORT):
            row["remote_port"] = _as_text(vbytes, vtag)
        elif col == str(_CDP_COL_PLATFORM):
            row["platform"] = _as_text(vbytes, vtag)
        elif col == str(_CDP_COL_CAPABILITIES):
            row["capabilities"] = _as_int(vbytes, vtag)

    out = []
    for key in _sorted_index_pairs(rows):
        row = rows[key]
        platform = row.get("platform", "")
        local_port = row.get("local_port", key[0])
        out.append({
            "local_port": local_port,
            "local_port_name": "",
            "local_port_desc": f"ifIndex {local_port}",
            "remote_id": row.get("remote_ip", "") or row.get("remote_name", ""),
            "remote_port": row.get("remote_port", ""),
            "remote_port_desc": "",
            "remote_name": row.get("remote_name", ""),
            "remote_ip": row.get("remote_ip", ""),
            "remote_platform": platform,
            "remote_role": _role_from_capabilities(row.get("capabilities"))
            or _role_from_text(platform),
            "protocol": "CDP",
        })
    return out


def _discover_cdp_neighbors(switch_ip: str, communities=None,
                            timeout: float = 1.0, snmp_v3_user=None,
                            client: Optional["_SnmpClient"] = None,
                            port: int = 161) -> List[dict]:
    """对一台 Cisco 设备执行 CDP 邻居发现（遍历整张 cdpCacheTable）。"""
    client = client or _SnmpClient(switch_ip, communities, timeout,
                                   snmp_v3_user, port)
    neighbors = _parse_cdp_entries(client.walk(_CDP_CACHE_ENTRY))
    if not neighbors:
        return []
    _attach_local_port_names(neighbors, client)
    return neighbors


# ══════════════════════════════════════════════════════════════════════
#  设备角色判定
# ══════════════════════════════════════════════════════════════════════

#: sysDescr / 主机名 / CDP platform 里出现即视为网络基础设施的关键词。
#: 这是**匹配**用的表，绝不能包 tr()（否则英文界面下匹配不到中文串）。
#: `ios software` 一并收进来：Cisco 的 sysDescr 长这样既可能是交换机也可能是
#: 路由器，但**一定**是网络设备 —— 画成方块而不是终端圆点才是重点。
_INFRA_TEXT_KEYWORDS = (
    "switch", "router", "routing", "gateway", "firewall", "ios software",
    "ios-xe", "ios xe", "nx-os", "nxos", "junos", "routeros", "comware",
    "procurve", "arubaos", "vyos", "fortigate", "fortios", "screenos",
    "pan-os", "edgeos", "wireless controller", "access point", "accesspoint",
    "wlc", "layer 3", "l3 switch", "catalyst", "nexus", "omada", "unifi",
)

#: 只可能出现在**路由器/防火墙**上的关键词（判定时排在交换机前面）。
_ROUTER_TEXT_KEYWORDS = (
    "router", "routeros", "gateway", "firewall", "fortigate", "fortios",
    "junos", "vyos", "pan-os", "screenos", "edgeos",
)

#: 厂商关键词：OUI 命中这些厂商时，即使没有任何 SNMP 痕迹也值得去试一次。
_INFRA_VENDOR_KEYWORDS = (
    "cisco", "aruba", "hp ", "hewlett", "procurve", "juniper", "h3c", "huawei",
    "ruijie", "mikrotik", "ubiquiti", "fortinet", "netgear", "tp-link", "tplink",
    "d-link", "dlink", "extreme", "zyxel", "ruckus", "meraki", "edgecore",
    "tenda", "mercury", "sophos", "palo alto", "checkpoint", "watchguard",
    "brocade", "foundry", "alcatel", "nortel", "avaya", "allied telesis",
    "锐捷", "华为", "中兴", "zte", "新华三", "迈普", "神码", "飞鱼星", "艾泰",
)

#: 设备类别（规范值）里属于"网络基础设施"的
_INFRA_CLASSES = ("交换机", "路由器", "网络设备", "AP", "防火墙")

_KIND_BY_ROLE = {"switch": KIND_SWITCH, "router": KIND_ROUTER}


def _role_from_text(text: str) -> str:
    """从自由文本里猜角色：返回 "switch" / "router" / ""。

    先看"只可能是路由器/防火墙"的关键词，再看泛化的网络设备关键词 ——
    后者命中时按交换机处理（`Cisco IOS Software, C2960` 这类无法区分型号的
    sysDescr 归到这一类：画成网络设备方块是对的，圆点则明显错）。
    """
    low = (text or "").lower()
    if not low:
        return ""
    if any(k in low for k in _ROUTER_TEXT_KEYWORDS):
        return "router"
    if any(k in low for k in _INFRA_TEXT_KEYWORDS):
        return "switch"
    return ""


def _role_from_capabilities(caps: Optional[int]) -> str:
    """CDP capabilities 位图 → 角色。交换机位优先（三层交换机两个位都置）。"""
    if not caps:
        return ""
    if caps & _CDP_CAP_SWITCH:
        return "switch"
    if caps & _CDP_CAP_ROUTER:
        return "router"
    return ""


def has_snmp_service(result) -> bool:
    """扫描结果里是否有 SNMP 服务标记（按规范代码比较，不认翻译后的文本）。"""
    for svc in getattr(result, "services", None) or []:
        if service_code(svc).upper() == SVC_SNMP:
            return True
    return False


def looks_like_infrastructure(result) -> bool:
    """这台设备是否"值得用 SNMP 探一次"。

    纯被动、零网络开销的判据，宁可宽松 —— 多探一台只是多发一个 UDP 包，
    漏探一台交换机则会让整张拓扑退化成一个星型。
    """
    if getattr(result, "device_class", "") in _INFRA_CLASSES:
        return True
    if has_snmp_service(result):
        return True
    if getattr(result, "snmp_sys_descr", "") or getattr(result, "snmp_sys_name", ""):
        return True
    # TCP 161 极少开放，但开放就是强信号（旧实现里唯一的端口判据）
    if 161 in (getattr(result, "open_ports", None) or []):
        return True
    text = " ".join(filter(None, (
        getattr(result, "snmp_sys_descr", ""),
        getattr(result, "hostname", ""),
        getattr(result, "upnp_model", ""),
    ))).lower()
    if any(k in text for k in _INFRA_TEXT_KEYWORDS):
        return True
    vendor = (getattr(result, "vendor", "") or "").lower()
    return any(k in vendor for k in _INFRA_VENDOR_KEYWORDS)


def _is_gateway(result, gateway_ip: str) -> bool:
    return bool(gateway_ip) and getattr(result, "ip", "") == gateway_ip


def _online_results(results) -> List:
    return [r for r in results if getattr(r, "status", "") == "online"]


def _select_candidates(results, gateway_ip: str) -> List:
    """挑出要试 SNMP 的候选设备：网关 + 一切"像网络设备"的在线主机。

    网关排在最前面：它是唯一"几乎肯定在转发 IP 包"的设备，而且候选列表会被
    `max_switches` 截断 —— 排在后面就可能被截掉，那是最不该漏的一台。
    """
    ordered, others, seen = [], [], set()
    for r in results:
        if getattr(r, "status", "") != "online":
            continue
        ip = getattr(r, "ip", "")
        if not ip or ip in seen:
            continue
        if _is_gateway(r, gateway_ip):
            seen.add(ip)
            ordered.append(r)
        elif looks_like_infrastructure(r):
            seen.add(ip)
            others.append(r)
    return ordered + others


# ══════════════════════════════════════════════════════════════════════
#  主流程
# ══════════════════════════════════════════════════════════════════════

def _progress(cb, phase, current, total, message):
    if cb:
        try:
            cb(phase, current, total, message)
        except Exception as e:      # noqa: BLE001 - 进度回调失败不能拖垮发现
            _log.debug("拓扑进度回调失败: %s", e)


def _probe_snmp(targets, communities, timeout, snmp_v3_user, enable_probe,
                workers, progress_callback, phase_total) -> Dict[str, tuple]:
    """并发对每台设备做一次 SNMP GET sysDescr，返回 {ip: (descr, name, client)}。

    **不修改扫描结果对象** —— 发现过程跑在后台线程里，而去改主线程正在显示的
    `ScanResult` 是跨线程写共享状态；这里把探测结果留在本地字典里。
    """
    snapshots: Dict[str, tuple] = {}
    if not targets:
        return snapshots
    total = len(targets)
    done = 0

    def _probe(result):
        client = _SnmpClient(result.ip, communities, timeout, snmp_v3_user)
        info = client.get_system() if enable_probe else {}
        # 扫描阶段已经取到过 sysDescr 的直接复用，不再重复发请求
        sys_descr = info.get("sys_descr") or getattr(result, "snmp_sys_descr", "") or ""
        sys_name = info.get("sys_name") or getattr(result, "snmp_sys_name", "") or ""
        return sys_descr, sys_name, client

    def _on_probe(result, payload, exc):
        nonlocal done
        done += 1
        if exc is not None:
            _log.debug("SNMP 探测失败 %s: %s", getattr(result, "ip", ""), exc)
        elif payload:
            snapshots[result.ip] = payload
        _progress(progress_callback, "discover", done, phase_total,
                  tr("网络设备识别: {ip}/{total}").format(
                      ip=getattr(result, "ip", ""), total=total))

    run_bounded(targets, _probe, max_workers=workers, on_result=_on_probe)
    return snapshots


def _classify_infra(candidates, snapshots: Dict[str, tuple],
                    node_map: Dict[str, TopoNode]):
    """把"有 SNMP 响应 + 角色像网络设备"的候选定性成拓扑里的网络设备节点。

    返回 `[(ScanResult, _SnmpClient), ...]`（可管理 = 能继续做 LLDP/CDP/FDB）。
    同一 IP 只取一次（候选批次与"其余在线设备"批次可能重叠）。
    """
    infra = []
    done = set()
    for r in candidates:
        ip = getattr(r, "ip", "")
        if ip in done:
            continue
        done.add(ip)
        payload = snapshots.get(ip)
        if not payload:
            continue
        sys_descr, sys_name, client = payload
        # ① 没有 SNMP 响应就不是"可管理设备"：既不该被标成交换机（那会让用户
        #    以为识别到了却看不到任何链路），也走不了 LLDP/CDP/FDB。
        if not (sys_descr or sys_name):
            continue
        role = (_role_from_text(sys_descr) or _role_from_text(sys_name)
                or _role_from_text(getattr(r, "hostname", "")))
        if not role:
            # 有 SNMP 响应、且确实像网络设备 → 至少按交换机处理，否则整张拓扑
            # 会退化成星型（用户看到的就是"识别不出交换机/路由器"）。
            role = "switch"
        node = node_map.get(ip)
        if node is None:
            continue
        node.kind = KIND_GATEWAY if node.is_gateway else _KIND_BY_ROLE.get(
            role, KIND_SWITCH)
        node.is_switch = True
        if sys_descr:
            node.model = node.model or sys_descr.splitlines()[0].strip()[:60]
        if sys_name and node.label == ip:
            node.label = sys_name
        infra.append((r, client))
    return infra


def discover_topology(results, progress_callback=None, *,
                      gateway_ip: str = "", communities=None,
                      timeout: float = 1.0, snmp_v3_user=None,
                      enable_snmp_probe: bool = True,
                      enable_fdb: bool = True,
                      max_switches: int = 64,
                      max_fdb_switches: int = 16,
                      max_probe_all: int = 512,
                      probe_workers: int = 24) -> Topology:
    """从扫描结果中发现网络拓扑。

    Args:
        results: ScanResult 列表（**不会被就地修改**）。
        progress_callback(phase, current, total, message): 可选进度回调。
        gateway_ip: 本机网关 IP。网关是天然的路由器候选，也是分层布局的根。
        communities: SNMP v2c 团体字候选列表；None = public/private/空。
        timeout: 单次 SNMP 请求超时（秒）。
        snmp_v3_user: SnmpV3User 或 None。传入时 **v3 优先**，只在目标对 v3
            完全无响应时回退 v2c（与扫描引擎同一口径）。
        enable_snmp_probe: 是否主动发 SNMP GET 去确认候选设备。
            未勾选「SNMP 协议」的扫描不会填 `snmp_sys_descr`，此开关是
            「扫描没开 SNMP 也能识别交换机」的关键。
        enable_fdb: LLDP/CDP 无果时改用 BRIDGE-MIB 转发表兜底。
        max_switches: 最多对多少台设备做 LLDP/CDP 邻居发现。
        max_fdb_switches: 最多对多少台设备做转发表兜底（每台 5 次 walk，较贵）。
        max_probe_all: 候选全军覆没时，最多再对多少台在线设备做一次 SNMP GET。
        probe_workers: SNMP 探测并发度。

    Returns:
        Topology 对象，含 nodes / links / note。
    """
    topo = Topology()
    node_map: Dict[str, TopoNode] = {}

    # ── 1) 全部扫描结果先成为节点 ──
    for r in results:
        node = TopoNode(
            id=r.ip,
            label=r.hostname or r.ip,
            ip=r.ip,
            mac=r.mac or "",
            vendor=r.vendor or "",
            model=getattr(r, "device_model", "") or "",
            device_class=getattr(r, "device_class", "") or "",
            kind=KIND_HOST,
            online=getattr(r, "status", "") == "online",
            is_gateway=_is_gateway(r, gateway_ip),
        )
        topo.nodes.append(node)
        node_map[r.ip] = node

    # ── 2) SNMP 探测：先探"像网络设备"的，全军覆没再扩到全部在线设备 ──
    candidates = _select_candidates(results, gateway_ip)[:max_switches]
    _progress(progress_callback, "discover", 0, max(len(candidates), 1),
              tr("正在识别网络设备（SNMP）..."))
    snapshots = _probe_snmp(candidates, communities, timeout, snmp_v3_user,
                            enable_snmp_probe, probe_workers, progress_callback,
                            max(len(candidates), 1))

    if enable_snmp_probe and not _has_snmp_response(snapshots):
        probed = {getattr(r, "ip", "") for r in candidates}
        rest = [r for r in _online_results(results)
                if getattr(r, "ip", "") not in probed][:max_probe_all]
        if rest:
            _progress(progress_callback, "discover", 0, len(rest),
                      tr("候选设备均无 SNMP 响应，改为逐台探测..."))
            # 这一轮只是"再找找有没有人应 SNMP"，不是取数据，所以把单次超时收紧：
            # 上千台都不回话时，1 秒超时 × 3 个团体字会把总耗时拖到分钟级。
            snapshots.update(_probe_snmp(
                rest, communities, min(timeout, 0.5), snmp_v3_user,
                enable_snmp_probe, probe_workers, progress_callback, len(rest)))

    # ── 3) 定性：谁是可管理的交换机/路由器 ──
    candidate_ips = {getattr(r, "ip", "") for r in candidates}
    extra = [r for r in _online_results(results)
             if getattr(r, "ip", "") not in candidate_ips]
    infra = _classify_infra(candidates + extra, snapshots, node_map)

    topo.infra_count = len(infra)
    _progress(progress_callback, "discover", len(candidates), max(len(candidates), 1),
              tr("识别到 {n} 台可管理的网络设备").format(n=len(infra)))

    # ── 4) LLDP → CDP 邻居发现 ──
    raw_links: List[TopoLink] = []
    for idx, (r, client) in enumerate(infra):
        _progress(progress_callback, "lldp", idx, len(infra),
                  tr("LLDP/CDP 发现: {ip}").format(ip=r.ip))
        neighbors = _discover_lldp_neighbors(r.ip, client=client)
        if not neighbors:
            neighbors = _discover_cdp_neighbors(r.ip, client=client)
        for nb in neighbors:
            link = _neighbor_to_link(r.ip, nb, results, node_map, topo)
            if link is not None:
                raw_links.append(link)

    links = _dedup_links(raw_links)

    # ── 5) 转发表兜底 / 补全 ──
    #
    # LLDP/CDP 只告诉我们"交换机之间"怎么连 —— 服务器、PC、打印机都不说 LLDP，
    # 它们挂在哪个交换机的哪个口只有**交换机自己的转发表**知道。所以两者是
    # 互补而非二选一：只要还有扫描到的终端没落位，就跑一遍转发表。
    scanned_ids = {getattr(r, "ip", "") for r in results}
    connected = {link.source_id for link in links} | {link.target_id for link in links}
    unlocalized = [n for n in topo.nodes
                   if not n.is_infra and n.id in scanned_ids and n.id not in connected]
    if enable_fdb and infra and unlocalized:
        fdb_links, unplaced = _discover_fdb_links(
            infra, results, node_map, topo,
            progress_callback=progress_callback, max_switches=max_fdb_switches)
        # 交换机之间被 LLDP 和转发表同时发现的链路交给 `_dedup_links` 合并，
        # 它按"端口信息更全 / 协议更可信"保留一条
        links = _dedup_links(links + fdb_links)
        topo.unplaced = unplaced

    # ── 6) 仍无链路 → 按 /24 网段做层次结构（真实数据，不编造链路） ──
    subnet_links: List[TopoLink] = []
    if not links:
        subnet_links = _build_subnet_layer(topo, node_map, gateway_ip)
        links = _dedup_links(subnet_links)

    topo.links = links
    # 接入端口落到节点上：几十条链路的端口名直接画在图上会糊成一片，
    # 放在悬停提示里才是可用的（"这台 PC 挂在 access-sw-1 的 GE1/0/7"）。
    for link in links:
        if not link.source_port:
            continue
        target = node_map.get(link.target_id)
        if target is not None and not target.is_infra and not target.port:
            target.port = link.source_port
    linked_ids = {link.source_id for link in links} | {
        link.target_id for link in links}
    orphans = [n for n in topo.nodes
               if not n.is_infra and n.id in scanned_ids and n.id not in linked_ids]
    topo.note = _build_note(topo, links, subnet_links, len(orphans))
    _progress(progress_callback, "done", len(infra), len(infra),
              tr("拓扑发现完成: {nodes} 节点, {links} 链路")
              .format(nodes=len(topo.nodes), links=len(topo.links)))
    return topo


def collect_switch_port_maps(results, *, communities=None, timeout: float = 1.0,
                             snmp_v3_user=None, max_switches: int = 16,
                             probe_workers: int = 24,
                             progress_callback=None) -> List[dict]:
    """读取各交换机的转发表，返回 `history_store.save_port_map()` 能吃的 dict 列表。

    用途：给「定位查询」（`history_store.locate_device`）留一份
    (MAC → 交换机端口) 的数据。**不建图、不算链路** —— 那是 `discover_topology`
    的活；这里只回答「谁挂在哪个口」。

    与拓扑发现共用同一套候选筛选（`_select_candidates`）和 SNMP 探测
    （`_probe_snmp`），所以「扫描没勾 SNMP 也能识别交换机」这条性质在这里同样成立。

    **失败也如实返回**：读不到转发表的交换机会带 `error` 返回（而不是被丢掉），
    这样落库后 `locate_device()` 才能区分「从未采集」与「采集了但失败」——
    延续本项目的诚实降级原则。

    代价：每台交换机 5 次 SNMP walk，因此调用方**必须显式开启**（见扫描选项
    「读取交换机转发表」），不能默认跑；且**必须在后台线程调用**，
    否则会冻住界面。

    Args:
        results:  ScanResult 列表（不会被就地修改）。
        communities: SNMP v2c 团体字候选；None = 与拓扑发现同一默认。
        timeout:  单次 SNMP 请求超时（秒）。
        snmp_v3_user: SnmpV3User 或 None，口径与扫描引擎一致（v3 优先、v2c 兜底）。
        max_switches: 最多对多少台候选设备读转发表（每台 5 次 walk，故有上限）。
        probe_workers: SNMP 探测并发度。
        progress_callback(phase, current, total, message): 可选进度回调。

    Returns:
        `[{"switch_ip", "switch_name", "error", "mappings": [...]}, ...]`
    """
    from switch_mapper import SwitchInfo, map_switch_ports, switch_info_to_dict

    candidates = _select_candidates(results, "")[:max_switches]
    if not candidates:
        return []

    _progress(progress_callback, "switch_map", 0, len(candidates),
              tr("正在识别可管理的交换机（SNMP）..."))
    snapshots = _probe_snmp(candidates, communities, timeout, snmp_v3_user,
                            True, probe_workers, progress_callback,
                            max(len(candidates), 1))

    # 只有真回了 SNMP 系统信息的才算可管理设备：读转发表靠的就是 SNMP，
    # 连 sysDescr 都取不到的目标再试也是白等。
    targets = []
    for r in candidates:
        payload = snapshots.get(getattr(r, "ip", ""))
        if not payload:
            continue
        sys_descr, sys_name, client = payload
        if not (sys_descr or sys_name):
            continue
        targets.append((r, client))

    if not targets:
        _progress(progress_callback, "switch_map", 0, 1,
                  tr("没有设备响应 SNMP，跳过转发表读取"))
        return []

    infos: List[SwitchInfo] = []
    done = 0

    def _fetch(item):
        r, client = item
        return map_switch_ports(
            r.ip,
            community=client.working_community or "public",
            timeout=max(client.timeout, 1.5),
            snmp_v3_user=client.user,
        )

    def _on_result(item, info, exc):
        nonlocal done
        done += 1
        r, _client = item
        if exc is not None:
            _log.warning("读取 %s 的转发表失败: %s", r.ip, exc)
            # 异常也要落成一条带 error 的记录，否则这台交换机在库里"不存在"，
            # locate 会把「读取失败」误报成「从未采集过」
            info = SwitchInfo(ip=r.ip, error=tr("读取转发表异常: {err}").format(err=exc))
        _progress(progress_callback, "switch_map", done, len(targets),
                  tr("读取转发表: {ip}").format(ip=r.ip))
        if info is not None:
            infos.append(info)

    # 并发度单独收窄：每台交换机是 5 次串行 walk，不像单次 GET 那么轻
    run_bounded(targets, _fetch, max_workers=min(probe_workers, 8),
                on_result=_on_result)
    return [switch_info_to_dict(i) for i in infos]


def _has_snmp_response(snapshots: Dict[str, tuple]) -> bool:
    """探测结果里是否至少有一台设备真的回了 SNMP 系统信息。"""
    return any((payload[0] or payload[1]) for payload in snapshots.values())


def _promote_to_infra(node: Optional[TopoNode], role: str, platform: str = "") -> None:
    """LLDP/CDP 说对端是交换机/路由器时，把已经扫到的那台设备也升级成网络设备。

    必要性：SNMP 可能只在核心交换机上开着。核心通过 LLDP 看到了接入交换机，
    但接入交换机自己没回 SNMP，于是它在扫描结果里只是个"未知设备"。若不升级，
    图上会把它画成终端圆点 —— 明明拿到了权威的邻居信息却不用。
    """
    if node is None or not role or node.is_gateway or node.is_infra:
        return
    node.kind = _KIND_BY_ROLE.get(role, KIND_SWITCH)
    node.is_switch = True
    if not node.model and platform:
        node.model = platform.splitlines()[0].strip()[:60]


def _neighbor_to_link(switch_ip: str, nb: dict, results, node_map: dict,
                      topo: "Topology") -> Optional[TopoLink]:
    """把一个 LLDP/CDP 邻居转成链路；对端不在扫描结果里就建"外部节点"。"""
    remote_id = nb.get("remote_id") or nb.get("remote_ip") or ""
    remote_name = nb.get("remote_name") or ""
    source_port = nb.get("local_port_name") or nb.get("local_port_desc") or ""

    # 完全没有身份信息的邻居**必须丢弃**：否则所有空壳会挤在同一个 "ext:" 节点
    # 上 —— 图上多出一个无名节点，看起来像"发现了东西"，实际一条真链路都没有。
    if not (remote_id or remote_name):
        return None

    target_ip = _match_neighbor(remote_id, remote_name, nb, results, node_map)
    if target_ip:
        _promote_to_infra(node_map.get(target_ip), nb.get("remote_role", ""),
                          nb.get("remote_platform", ""))
    if not target_ip:
        ext_id = f"ext:{remote_id or remote_name}"
        node = node_map.get(ext_id)
        if node is None:
            role = nb.get("remote_role", "")
            platform = nb.get("remote_platform", "") or ""
            label = remote_name or remote_id
            if platform and platform.lower() not in label.lower():
                label = f"{label} ({platform[:40]})"
            node = TopoNode(
                id=ext_id,
                label=label or remote_id,
                ip=nb.get("remote_ip", ""),
                is_switch=role in ("switch", "router"),
                kind=_KIND_BY_ROLE.get(role, KIND_HOST),
                model=platform[:60],
                online=True,
            )
            topo.nodes.append(node)
            node_map[ext_id] = node
        target_ip = ext_id

    if target_ip == switch_ip:
        return None
    return TopoLink(
        source_id=switch_ip,
        target_id=target_ip,
        source_port=source_port,
        target_port=nb.get("remote_port", ""),
        protocol=nb.get("protocol", ""),
    )


def _dedup_links(links: List[TopoLink]) -> List[TopoLink]:
    """去重：同一对节点之间只留一条（双向 LLDP 会各报一次）。

    交换机之间的链路按**无序节点对**去重，保留端口信息最全的那条；这样同一对
    设备上的链路聚合（多条并行线）不会在图上叠成一堆重合的线。
    """
    best: Dict[Tuple[str, str], TopoLink] = {}
    order: List[Tuple[str, str]] = []

    def _score(link: TopoLink) -> int:
        return (bool(link.source_port) + bool(link.target_port) +
                (link.protocol in ("LLDP", "CDP")))

    for link in links:
        if not link.source_id or not link.target_id:
            continue
        if link.source_id == link.target_id:
            continue
        key = tuple(sorted((link.source_id, link.target_id)))
        if key not in best:
            best[key] = link
            order.append(key)
        elif _score(link) > _score(best[key]):
            best[key] = link
    return [best[k] for k in order]


def _match_neighbor(remote_id: str, remote_name: str, nb: dict, results,
                    node_map: dict) -> Optional[str]:
    """尝试把 LLDP/CDP 邻居匹配到扫描结果中的 IP。"""
    # 方法1: CDP 直接给了 IP
    remote_ip = nb.get("remote_ip", "")
    if remote_ip and remote_ip in node_map:
        return remote_ip

    # 方法2: 用 chassis id (通常是 MAC) 匹配
    clean_id = _normalize_mac(remote_id)
    if clean_id:
        for r in results:
            clean_mac = _normalize_mac(getattr(r, "mac", "") or "")
            if not clean_mac:
                continue
            if clean_mac == clean_id:
                return r.ip
            # 有些厂商只给后 6 字节，或给的是带前缀的 EUI-64
            if len(clean_id) >= 12 and len(clean_mac) >= 12:
                if clean_mac[-12:] == clean_id[-12:]:
                    return r.ip

    # 方法3: 用邻居系统名匹配（大小写无关，允许带域名后缀）
    name = (remote_name or "").strip().lower()
    if name:
        short = name.split(".")[0]
        for r in results:
            hn = (getattr(r, "hostname", "") or "").strip().lower()
            if hn and (hn == name or hn.split(".")[0] == short):
                return r.ip

    return None


def _normalize_mac(value: str) -> str:
    """把 MAC 文本归一成纯小写 hex；含非 hex 字符（主机名等）时返回空串。"""
    if not value:
        return ""
    raw = value.replace(":", "").replace("-", "").replace(".", "").strip().lower()
    if len(raw) != 12 or any(c not in "0123456789abcdef" for c in raw):
        return ""
    return raw


# ══════════════════════════════════════════════════════════════════════
#  BRIDGE-MIB 转发表兜底
# ══════════════════════════════════════════════════════════════════════

def _discover_fdb_links(infra, results, node_map: dict, topo: "Topology",
                        progress_callback=None, max_switches: int = 16,
                        workers: int = 4):
    """用 `switch_mapper` 的转发表映射推断接入关系。

    返回 `(links, unplaced)`：

    * 学到了 MAC、且能在扫描结果里找到对应 IP 的 → 一条 `FDB` 链路，
      端口名就是交换机自己报的 ifName/ifDescr；
    * 某端口上学到的是**另一台交换机的 MAC** → 那是上联口。凡是"从该上联口
      学到的终端"都不再连到本交换机上（那些设备真正接入的是下游那台），
      否则一台核心交换机会把全网设备都吸到自己身上。
    * 学到了 MAC 但不在扫描范围内 → 计入 `unplaced`（按**唯一 MAC** 计数，
      同一台设备被多台交换机学到不会重复计），只报数不画点。

    读一台交换机的转发表要 5 次 walk，是整条发现链里最贵的一步，所以这里
    用有界并发（`run_bounded`）而不是逐台串行：单台超时不再线性累加。
    """
    from switch_mapper import map_switch_ports

    mac_to_ip: Dict[str, str] = {}
    switch_macs: Dict[str, str] = {}          # 归一 MAC → 交换机 IP
    for r in results:
        mac = _normalize_mac(getattr(r, "mac", "") or "")
        if mac:
            mac_to_ip[mac] = r.ip
        node = node_map.get(r.ip)
        if mac and node is not None and node.is_switch:
            switch_macs[mac] = r.ip

    links: List[TopoLink] = []
    unplaced_macs = set()
    targets = list(infra[:max_switches])
    if not targets:
        return links, 0

    def _fetch(item):
        r, client = item
        return map_switch_ports(
            r.ip,
            community=client.working_community or "public",
            timeout=max(client.timeout, 1.5),
            snmp_v3_user=client.user,
        )

    def _on_result(item, info, exc):
        # run_bounded 在**调用方线程**里回调，因此这里的读写无需加锁
        r, _client = item
        if exc is not None:
            _log.warning("读取 %s 的转发表失败: %s", r.ip, exc)
            return
        if info is None or info.error:
            # 转发表不可用属常见情形（设备不支持 BRIDGE-MIB / 团体字权限不足），
            # 只记 info，不打扰用户
            if info is not None and info.error:
                _log.info("交换机 %s 转发表不可用: %s",
                          r.ip, info.error.splitlines()[0])
            return
        node = node_map.get(r.ip)
        if info.sys_name and node is not None and node.label == r.ip:
            node.label = info.sys_name

        # 先找出上联口：学到的是另一台交换机的 MAC
        uplink_ports = set()
        for m in info.mappings:
            peer_switch = switch_macs.get(_normalize_mac(m.mac))
            if peer_switch and peer_switch != r.ip:
                uplink_ports.add(m.port_name)
                links.append(TopoLink(source_id=r.ip, target_id=peer_switch,
                                      source_port=m.port_name, protocol="FDB"))

        for m in info.mappings:
            mac = _normalize_mac(m.mac)
            if not mac or mac in switch_macs:
                continue                       # 交换机之间的链路已在上面处理
            if m.port_name in uplink_ports:
                continue                       # 上联口学到的是"下游的设备"，不算接入
            peer_ip = mac_to_ip.get(mac)
            if not peer_ip:
                unplaced_macs.add(mac)
                continue
            if peer_ip == r.ip:
                continue
            links.append(TopoLink(source_id=r.ip, target_id=peer_ip,
                                  source_port=m.port_name, protocol="FDB"))

    # 进度用"已完成台数"驱动：run_bounded 的回调按完成顺序触发，正好
    done = 0

    def _on_result_with_progress(item, info, exc):
        nonlocal done
        done += 1
        _progress(progress_callback, "fdb", done, len(targets),
                  tr("读取转发表: {ip}").format(ip=item[0].ip))
        _on_result(item, info, exc)

    run_bounded(targets, _fetch, max_workers=workers,
                on_result=_on_result_with_progress)
    return links, len(unplaced_macs)


# ══════════════════════════════════════════════════════════════════════
#  无 SNMP 时的层次兜底：按 /24 网段分层
# ══════════════════════════════════════════════════════════════════════

def _subnet_of(ip: str) -> str:
    """"10.0.0.7" → "10.0.0.0/24"；非法 IP 返回空串。"""
    try:
        return str(ipaddress.ip_network(str(ip) + "/24", strict=False))
    except (ValueError, TypeError):
        return ""


def _build_subnet_layer(topo: "Topology", node_map: dict,
                        gateway_ip: str) -> List[TopoLink]:
    """多网段扫描时的层次结构：网关 → 各 /24 网段 → 网段内设备。

    这是**从真实数据推导**的结构（设备所属网段 + 网关归属），不是假链路。
    单网段时退化成星型、没有额外价值，故返回空，让界面走原有的星型视图。
    """
    hosts = [n for n in topo.nodes if not n.is_infra and n.ip and not n.is_gateway]
    subnets: Dict[str, List[TopoNode]] = {}
    for node in hosts:
        sn = _subnet_of(node.ip)
        if sn:
            subnets.setdefault(sn, []).append(node)
    if len(subnets) < 2:
        return []

    gw_node = node_map.get(gateway_ip) if gateway_ip else None
    if gw_node is None:
        if not gateway_ip:
            return []
        # 网关不在扫描范围内也值得画出来 —— 它是所有跨网段流量的必经点
        gw_node = TopoNode(id=gateway_ip, label=tr("网关"), ip=gateway_ip,
                           kind=KIND_GATEWAY, is_switch=True, is_gateway=True)
        topo.nodes.append(gw_node)
        node_map[gateway_ip] = gw_node
    else:
        gw_node.kind = KIND_GATEWAY
        gw_node.is_switch = True
        gw_node.is_gateway = True

    gw_subnet = _subnet_of(gateway_ip)
    links: List[TopoLink] = []
    for sn in sorted(subnets):
        members = subnets[sn]
        # 网关自己不再挂到自己网段的中继节点下（它是根，画出来会和
        # "网关→网段"连成环）
        if sn == gw_subnet:
            members = [n for n in members if n.id != gw_node.id]
        hub_id = f"subnet:{sn}"
        hub = node_map.get(hub_id)
        if hub is None:
            hub = TopoNode(id=hub_id, label=f"{sn} ({len(members)})",
                           kind=KIND_SUBNET, is_switch=True)
            topo.nodes.append(hub)
            node_map[hub_id] = hub
        links.append(TopoLink(source_id=gw_node.id, target_id=hub_id,
                              protocol="subnet"))
        for node in members:
            links.append(TopoLink(source_id=hub_id, target_id=node.id,
                                  protocol="subnet"))
    return links


# ══════════════════════════════════════════════════════════════════════
#  说明文案
# ══════════════════════════════════════════════════════════════════════

def _build_note(topo: "Topology", links: List[TopoLink],
                subnet_links: List[TopoLink], orphan_count: int = 0) -> str:
    """图例尾部的补充说明：为什么长这样、有多少东西没画出来。"""
    if subnet_links:
        return tr("未发现可管理的交换机/路由器（需在其上开启 SNMP），"
                  "已按 /24 网段分层展示")
    if not links:
        # 区分两种"没有链路"，因为要用户做的事完全不同：
        #   ① SNMP 根本没通 → 先解决 SNMP；
        #   ② SNMP 通了、但设备没说 LLDP/CDP、转发表也读不到 → 去设备上开 LLDP/CDP。
        if topo.infra_count:
            return tr("已通过 SNMP 识别到 {n} 台网络设备，但它们没有上报 "
                      "LLDP/CDP 邻居、转发表也不可用，因此无法还原实际连接"
                      ).format(n=topo.infra_count)
        return tr("未发现真实链路：请在交换机/路由器上开启 SNMP"
                  "（v2c 团体字或 SNMPv3 用户）并启用 LLDP/CDP，"
                  "拓扑才能按实际连接绘制")
    parts = []
    # 数"图上画出来的网络设备"，而不是"可管理的网络设备"：用户看到的方块有几个，
    # 这里就该写几个（含 LLDP 发现但对端没开 SNMP 的那几台）。
    drawn_infra = [n for n in topo.nodes if n.is_infra and n.kind != KIND_SUBNET]
    if drawn_infra:
        parts.append(tr("识别到 {n} 台网络设备").format(n=len(drawn_infra)))
    if orphan_count:
        parts.append(tr("另有 {n} 台设备接入位置未知（已排在画布底部）")
                     .format(n=orphan_count))
    if topo.unplaced:
        parts.append(tr("另有 {n} 个 MAC 未匹配到扫描结果").format(n=topo.unplaced))
    return "；".join(parts)


# ══════════════════════════════════════════════════════════════════════
#  布局（纯函数，不依赖 PyQt，便于单测）
# ══════════════════════════════════════════════════════════════════════

#: 布局刻度（px）
_X_UNIT = 150.0        # 一个网络设备的横向最小占位
_HOST_COL = 74.0       # 终端节点网格的列距
_HOST_ROW = 80.0       # 终端节点网格的行距
_INFRA_STEP = 190.0    # 相邻两层网络设备的基准垂直间距

# ── 过宽折行（v1.9 #9）──
_WRAP_MAX_ASPECT = 3.0  # 整体宽高比超过此值才折行（建议书 §6.2 验收阈值）
_WRAP_MAX_EDGE = 4000.0  # 像素预算：最长边 ≤ 4000（建议书 §6.2，1000 台以内）
_WRAP_MIN_EDGE = 600.0   # 像素预算：最短边 ≥ 600（别压成一条线）
_WRAP_GAP_X = 60.0      # 折行后并列子树之间的横向间隙
_WRAP_GAP_Y = 40.0      # 折行后并列子树之间的纵向间隙


def layout_real_topology(topo: "Topology",
                         gateway_ip: str = "") -> Dict[str, Tuple[float, float]]:
    """给真实拓扑算坐标，返回 `{node_id: (x, y)}`。

    思路（两层）：

    1. **骨干层**：把网络设备（交换机/路由器/网关/网段）之间的链路当成一棵树，
       从网关（或度数最高的网络设备）做 BFS 分层，再用经典 tidy-tree 口径按
       子树宽度分配横向位置 —— 网关在最上面，越往下离核心越远。
    2. **接入层**：每台网络设备直连的终端排成**紧凑网格**，居中放在该设备正下方
       （列数取 `ceil(sqrt(n))`，接近正方形）。几百台终端因此既不会把画布横向
       撑爆，也不会糊成一条线。

    为什么不用旧实现那种"交换机排一行、主机围成半圆"：那套布局里 `unassigned`
    存的是节点对象、比较用的却是 id 字符串，永远匹配不上，最后
    `node_pos[node]` 对不可哈希的 dataclass 直接抛 TypeError —— 只要有一台设备
    没挂在交换机上，整个真实拓扑视图就崩。
    """
    nodes = {n.id: n for n in topo.nodes}
    if not nodes:
        return {}

    adjacency: Dict[str, List[str]] = {nid: [] for nid in nodes}
    for link in topo.links:
        a, b = link.source_id, link.target_id
        if a in nodes and b in nodes and a != b:
            adjacency[a].append(b)
            adjacency[b].append(a)

    # ── BFS 生成树（环只影响画线，不影响坐标，因此不会死循环） ──
    roots = _pick_roots(topo, nodes, adjacency, gateway_ip)
    parent: Dict[str, Optional[str]] = {}
    forest_roots: List[str] = []
    for root in roots:
        if root in parent:
            continue
        parent[root] = None
        forest_roots.append(root)
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for nxt in adjacency[cur]:
                if nxt in parent:
                    continue
                parent[nxt] = cur
                queue.append(nxt)

    def _nearest_infra(nid: str) -> Optional[str]:
        cur: Optional[str] = nid
        seen = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            if nodes[cur].is_infra:
                return cur
            cur = parent.get(cur)
        return None

    infra_ids = [nid for nid in nodes if nodes[nid].is_infra]
    primary = next((r for r in forest_roots if nodes[r].is_infra),
                   forest_roots[0] if forest_roots else None)

    # 一条链路都没有的终端单独排在画布**底部**：它们"接在哪"是未知的。
    # 混进根节点的接入网格会让人误以为直接挂在网关上，而且那一格正好压在
    # "网关 → 第一台交换机"的竖线上（一条竖线 + 一个居中网格 = 必然重叠）。
    orphans = [nid for nid in sorted(nodes)
               if not nodes[nid].is_infra and not adjacency[nid]]

    # ── 终端归位：挂在最近的网络设备下；没有任何归属的丢给主根 ──
    blocks: Dict[str, List[str]] = {nid: [] for nid in infra_ids}
    if primary is not None:
        blocks.setdefault(primary, [])
    orphan_set = set(orphans)
    for nid in sorted(nodes):
        if nodes[nid].is_infra or nid in orphan_set:
            continue
        owner = _nearest_infra(nid) or primary
        if owner is None:
            continue
        blocks.setdefault(owner, []).append(nid)

    # ── 骨干树的"压缩"父子关系（跳过中间的非网络设备） ──
    infra_children: Dict[str, List[str]] = {nid: [] for nid in infra_ids}
    for nid in infra_ids:
        cur = parent.get(nid)
        while cur is not None:
            if nodes[cur].is_infra:
                infra_children[cur].append(nid)
                break
            cur = parent.get(cur)

    cols_of = {nid: _grid_columns(len(blocks.get(nid, ()))) for nid in infra_ids}

    def _own_units(nid: str) -> float:
        """本节点自身（含其终端网格）需要的横向单位数。"""
        cols = cols_of[nid]
        return max(1.0, cols * _HOST_COL / _X_UNIT) if cols else 1.0

    infra_roots = [nid for nid in infra_ids if parent.get(nid) is None]
    if not infra_roots:
        # 理论上不会发生（有链路就一定有网络设备端点），但布局是纯函数、
        # 会被直接单测，退化时给一个"全部铺成网格"的兜底比返回空字典好。
        return _grid_fallback(sorted(nodes))

    widths: Dict[str, float] = {}
    order: List[str] = []
    stack = list(infra_roots)
    while stack:
        nid = stack.pop()
        order.append(nid)
        stack.extend(infra_children[nid])
    for nid in reversed(order):
        kids = infra_children[nid]
        widths[nid] = max(_own_units(nid), sum(widths[k] for k in kids) if kids else 0.0)

    # ── 每个网络设备的层号（压缩树上），以及各层高度 ──
    depth: Dict[str, int] = {}
    for root in infra_roots:
        depth[root] = 0
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for kid in infra_children[cur]:
                depth[kid] = depth[cur] + 1
                queue.append(kid)

    rows_of = {nid: (math.ceil(len(blocks.get(nid, ())) / cols_of[nid])
                     if cols_of[nid] else 0) for nid in infra_ids}
    band_rows: Dict[int, int] = {}
    for nid, d in depth.items():
        band_rows[d] = max(band_rows.get(d, 0), rows_of[nid])
    layer_y: Dict[int, float] = {}
    cur_y = 0.0
    for d in range(max(band_rows) + 1 if band_rows else 1):
        layer_y[d] = cur_y
        cur_y += _INFRA_STEP + band_rows.get(d, 0) * _HOST_ROW

    # ── 骨干层坐标：tidy tree ──
    positions: Dict[str, Tuple[float, float]] = {}
    cursor = 0.0
    for root in infra_roots:
        width = widths[root]
        stack = [(root, cursor)]
        while stack:
            nid, left = stack.pop()
            positions[nid] = ((left + widths[nid] / 2.0) * _X_UNIT, layer_y[depth[nid]])
            child_left = left + (widths[nid] - sum(widths[k] for k in infra_children[nid])) / 2.0
            for kid in infra_children[nid]:
                stack.append((kid, child_left))
                child_left += widths[kid]
        cursor += width

    # ── 过宽折行（v1.9 #9）：骨干并列子树按行装箱 ──
    # 仅在「不折行时整体宽高比会超 3:1」才动手，本就达标的窄拓扑（≤4 台交换机）
    # 维持原样，避免修坏回归守卫。折行 = 把「一排交换机」变成「一片」：
    # 每个子树内部坐标（tidy tree）保持不变，只整体平移进各自的格子。
    _xs = [p[0] for p in positions.values()]
    _ys = [p[1] for p in positions.values()]
    _aspect_now = ((max(_xs) - min(_xs)) / (max(_ys) - min(_ys))
                   if _ys and max(_ys) != min(_ys) else 0.0)
    if _aspect_now > _WRAP_MAX_ASPECT:
        def _subtree_infra(nid):
            out = [nid]
            stack = list(infra_children.get(nid, ()))
            while stack:
                x = stack.pop()
                out.append(x)
                stack.extend(infra_children.get(x, ()))
            return out

        for _root in infra_roots:
            _kids = infra_children[_root]
            if len(_kids) < 2:
                continue
            # 每个子树的占位尺寸（含其接入网格的预留跨度）
            _kid_w = {k: max(1.0, widths[k]) * _X_UNIT for k in _kids}
            _kid_h = {k: (_INFRA_STEP * 0.42 + rows_of[k] * _HOST_ROW)
                      for k in _kids}
            _cell_w = max(_kid_w.values()) + _WRAP_GAP_X
            _cell_h = max(_kid_h.values()) + _WRAP_GAP_Y
            # 选列数：在「尽量少换行」与「宽高比 ≤ 3:1」之间取平衡，
            # 取能达标的最大列数（= 尽量保留成一行）；同时尽量别撑爆画布
            # （最长边 ≤ 4000、最短边 ≥ 600，与建议书 §6.2 像素预算一致）。
            # 设备过多时像素预算无法满足，则退而只保宽高比。
            _n = len(_kids)
            _cols = _n
            _ok = None
            while _cols >= 1:
                _rows = math.ceil(_n / _cols)
                _tw, _th = _cols * _cell_w, _rows * _cell_h
                if ((_tw / _th) <= _WRAP_MAX_ASPECT
                        and max(_tw, _th) <= _WRAP_MAX_EDGE
                        and min(_tw, _th) >= _WRAP_MIN_EDGE):
                    _ok = _cols
                    break
                _cols -= 1
            if _ok is None:  # 像素预算无法满足（节点过多），只保宽高比
                _cols = _n
                while _cols > 1:
                    _rows = math.ceil(_n / _cols)
                    if (_cols * _cell_w) / (_rows * _cell_h) <= _WRAP_MAX_ASPECT:
                        break
                    _cols -= 1
            else:
                _cols = _ok
            _grid_w = _cols * _cell_w
            _base_x = positions[_root][0] - _grid_w / 2.0
            _base_y = positions[_root][1] + _INFRA_STEP
            for _i, _k in enumerate(sorted(_kids)):
                _r = _i // _cols
                _c = _i % _cols
                # 平移该子树的整棵 infra 子树（含其下级交换机），保持内部相对坐标
                _dx = (_base_x + _c * _cell_w) - (positions[_k][0] - _kid_w[_k] / 2.0)
                _dy = (_base_y + _r * _cell_h) - positions[_k][1]
                for _d in _subtree_infra(_k):
                    _ox, _oy = positions[_d]
                    positions[_d] = (_ox + _dx, _oy + _dy)

    # ── 接入层坐标：每个网络设备正下方的紧凑网格 ──
    for nid, hosts in blocks.items():
        if not hosts or nid not in positions:
            continue
        ox, oy = positions[nid]
        cols = cols_of[nid]
        for i, hid in enumerate(hosts):
            col, row = i % cols, i // cols
            positions[hid] = (ox + (col - (cols - 1) / 2.0) * _HOST_COL,
                              oy + _INFRA_STEP * 0.42 + row * _HOST_ROW)

    # ── 接入位置未知的终端：画布底部另起一块，居中于整张图 ──
    if orphans:
        placed = list(positions.values())
        xs = [x for x, _ in placed] or [0.0]
        cx = (min(xs) + max(xs)) / 2.0
        top = max((y for _, y in placed), default=0.0) + _INFRA_STEP * 0.7
        cols = _grid_columns(len(orphans))
        for i, nid in enumerate(orphans):
            col, row = i % cols, i // cols
            positions[nid] = (cx + (col - (cols - 1) / 2.0) * _HOST_COL,
                              top + row * _HOST_ROW)
    return positions


# ── 拓扑文本导出（v1.9 #9 可读性包：树形 / Markdown / ASCII）──

TOPO_TEXT_FORMATS = ("tree", "markdown", "ascii")


def _topo_forest(topo, gateway_ip=""):
    """从 links 抽一棵树（森林），供文本导出用。

    根选择 / BFS 与 `layout_real_topology` 同一套 `_pick_roots` —— 文本和图形
    讲同一个故事。返回 ``(nodes, parent, children, roots)``：
    `parent[nid]` 是该节点的父（根 = None），`children[nid]` 是子列表，
    `roots` 是所有森林根（含没有任何链路、被 `_pick_roots` 兜底成根的孤立节点）。
    """
    nodes = {n.id: n for n in topo.nodes}
    if not nodes:
        return nodes, {}, {}, []
    adjacency = {nid: [] for nid in nodes}
    for link in topo.links:
        a, b = link.source_id, link.target_id
        if a in nodes and b in nodes and a != b:
            adjacency[a].append(b)
            adjacency[b].append(a)
    roots = _pick_roots(topo, nodes, adjacency, gateway_ip)
    parent = {}
    children = {nid: [] for nid in nodes}
    # 「真正的森林根」= BFS 实际用到的起点。`_pick_roots` 把所有节点都列为候选根，
    # 但 BFS 一旦从更早的根到达某节点，该节点就不再是根（parent 已设）。
    # 下面只收「没被更早的根覆盖」的候选，渲染时按这个顺序画，避免同一台设备
    # 既挂在上游下面、又被当成顶层再画一遍（重复节点）。
    used_roots = []
    for root in roots:
        if root in parent:
            continue
        parent[root] = None
        used_roots.append(root)
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for nxt in adjacency[cur]:
                if nxt in parent:
                    continue
                parent[nxt] = cur
                children[cur].append(nxt)
                queue.append(nxt)
    return nodes, parent, children, used_roots


def _topo_link_by_child(topo):
    """``child_id -> 连接它的那条链路``（仅取第一条，纯展示用）。"""
    by_child = {}
    for link in topo.links:
        a, b = link.source_id, link.target_id
        if a and b and a != b:
            by_child.setdefault(a, link)
            by_child.setdefault(b, link)
    return by_child


def _topo_node_fields(node):
    """节点的「类型 / 状态 / 厂商型号」展示片段（规范值，语言无关）。"""
    kind = node.kind or (KIND_SWITCH if node.is_switch else KIND_HOST)
    state = "up" if node.online else "down"
    vm = ("%s %s" % (node.vendor, node.model)).strip()
    return kind, state, vm


def _topo_uplink(node, nid, pid, nodes, link_by_child):
    """对某个子节点，拼出「上联：父设备:父端口 → 本端端口 (协议)」。"""
    if pid is None:
        return ""
    link = link_by_child.get(nid)
    if link is None:
        return ""
    if link.source_id == pid:
        uport, dport = link.source_port, link.target_port
    elif link.target_id == pid:
        uport, dport = link.target_port, link.source_port
    else:
        return ""
    proto = link.protocol or "-"
    pname = nodes[pid].label or pid
    if dport:
        return "  ← %s:%s → %s (%s)" % (pname, uport, dport, proto)
    return "  ← %s:%s (%s)" % (pname, uport, proto)


def render_topology_tree(topo, gateway_ip=""):
    """树形缩进文本：每个节点一行，子节点缩进并带树形连接符。

    含端口与协议（见 `_topo_uplink`）。语言无关（kind/state 用 up/down 规范值，
    device_class 用库里的规范串）。
    """
    nodes, parent, children, roots = _topo_forest(topo, gateway_ip)
    if not nodes:
        return ""
    link_by_child = _topo_link_by_child(topo)

    def _kids(nid):
        return sorted(children[nid],
                      key=lambda k: (0 if nodes[k].is_infra else 1,
                                     nodes[k].label))

    def _summary(nid):
        node = nodes[nid]
        kind, state, vm = _topo_node_fields(node)
        base = "%s (%s)" % (node.label or nid, node.ip or nid)
        extra = " [%s/%s]" % (kind, state)
        if node.device_class:
            extra += " " + node.device_class
        if vm:
            extra += " " + vm
        extra += _topo_uplink(node, nid, parent.get(nid), nodes, link_by_child)
        return base + extra

    lines = []

    def _walk(nid, prefix, is_last):
        lines.append(prefix + ("└── " if is_last else "├── ") + _summary(nid))
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, kid in enumerate(_kids(nid)):
            _walk(kid, child_prefix, i == len(children[kid]) - 1)

    for root in roots:
        lines.append(_summary(root))
        for i, kid in enumerate(_kids(root)):
            _walk(kid, "", i == len(children[kid]) - 1)
    if topo.note:
        lines.append("")
        lines.append("# " + topo.note)
    return "\n".join(lines)


def render_topology_markdown(topo, gateway_ip=""):
    """Markdown 表格：一列一个节点，含上联端口/协议。"""
    nodes, parent, children, roots = _topo_forest(topo, gateway_ip)
    if not nodes:
        return ""
    link_by_child = _topo_link_by_child(topo)
    header = ["节点", "IP", "类型", "状态", "设备类", "厂商/型号",
              "上联设备", "上联端口", "本端端口", "协议"]

    def _kids(nid):
        return sorted(children[nid],
                      key=lambda k: (0 if nodes[k].is_infra else 1,
                                     nodes[k].label))

    def _order():
        out = []
        for root in roots:
            stack = [root]
            while stack:
                nid = stack.pop(0)
                if nid in out:
                    continue
                out.append(nid)
                stack.extend(_kids(nid))
        return out

    def _row(nid):
        node = nodes[nid]
        kind, state, vm = _topo_node_fields(node)
        pid = parent.get(nid)
        uplink_dev = uport = dport = proto = "-"
        if pid is not None:
            link = link_by_child.get(nid)
            if link is not None:
                if link.source_id == pid:
                    uport, dport = link.source_port, link.target_port
                elif link.target_id == pid:
                    uport, dport = link.target_port, link.source_port
                proto = link.protocol or "-"
                uplink_dev = nodes[pid].label or pid
        return [node.label or nid, node.ip or "-", kind, state,
                node.device_class or "-", vm or "-", uplink_dev,
                uport or "-", dport or "-", proto]

    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join(["---"] * len(header)) + " |"]
    for nid in _order():
        lines.append("| " + " | ".join(_row(nid)) + " |")
    if topo.note:
        lines.append("")
        lines.append("> " + topo.note)
    return "\n".join(lines)


def render_topology_ascii(topo, gateway_ip=""):
    """等宽 ASCII 表：节点名按树深度缩进，列对齐，含上联端口/协议。"""
    nodes, parent, children, roots = _topo_forest(topo, gateway_ip)
    if not nodes:
        return ""
    link_by_child = _topo_link_by_child(topo)

    depth = {}
    for root in roots:
        depth[root] = 0
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for kid in children[cur]:
                depth[kid] = depth[cur] + 1
                queue.append(kid)

    def _kids(nid):
        return sorted(children[nid],
                      key=lambda k: (0 if nodes[k].is_infra else 1,
                                     nodes[k].label))

    def _order():
        out = []
        for root in roots:
            stack = [root]
            while stack:
                nid = stack.pop(0)
                if nid in out:
                    continue
                out.append(nid)
                stack.extend(_kids(nid))
        return out

    def _uplink_str(nid):
        pid = parent.get(nid)
        if pid is None:
            return "-"
        link = link_by_child.get(nid)
        if link is None:
            return "-"
        if link.source_id == pid:
            uport, dport = link.source_port, link.target_port
        elif link.target_id == pid:
            uport, dport = link.target_port, link.source_port
        else:
            return "-"
        proto = link.protocol or "-"
        pname = nodes[pid].label or pid
        if dport:
            return "%s:%s→%s(%s)" % (pname, uport, dport, proto)
        return "%s:%s(%s)" % (pname, uport, proto)

    cols = []
    for nid in _order():
        node = nodes[nid]
        kind, state, vm = _topo_node_fields(node)
        name = "%s%s (%s)" % ("  " * depth[nid], node.label or nid,
                              node.ip or "-")
        cols.append((name, kind, state, node.device_class or "-",
                     vm or "-", _uplink_str(nid)))

    heads = ["NODE", "TYPE", "STATE", "CLASS", "VENDOR/MODEL", "UPLINK"]
    w = [len(h) for h in heads]
    for name, kind, state, dev, vm, up in cols:
        w[0] = max(w[0], len(name))
        w[1] = max(w[1], len(kind))
        w[2] = max(w[2], len(state))
        w[3] = max(w[3], len(dev))
        w[4] = max(w[4], len(vm))
        w[5] = max(w[5], len(up))

    def _fmt(row):
        return "  ".join(c.ljust(w[i]) for i, c in enumerate(row))

    lines = [_fmt(heads), _fmt(["-" * w[i] for i in range(6)])]
    for name, kind, state, dev, vm, up in cols:
        lines.append(_fmt([name, kind, state, dev, vm, up]))
    if topo.note:
        lines.append("")
        lines.append("# " + topo.note)
    return "\n".join(lines)


def render_topology_text(topo, fmt, gateway_ip=""):
    """把 Topology 渲染成可读文本。

    fmt ∈ ``TOPO_TEXT_FORMATS``（``tree`` / ``markdown`` / ``ascii``）。
    三种格式都会遍历**整张**拓扑树（不依赖坐标），因此不会出现「因为
    图形折行/分栏而丢节点」的情况 —— 每台交换机和它的每个下游节点都在。
    """
    if fmt not in TOPO_TEXT_FORMATS:
        raise ValueError("未知拓扑文本格式: %r（应为 %s）"
                         % (fmt, "/".join(TOPO_TEXT_FORMATS)))
    if fmt == "markdown":
        return render_topology_markdown(topo, gateway_ip)
    if fmt == "ascii":
        return render_topology_ascii(topo, gateway_ip)
    return render_topology_tree(topo, gateway_ip)


def _grid_columns(count: int) -> int:
    """终端网格列数：取 `ceil(sqrt(n))`，让块接近正方形。"""
    if count <= 0:
        return 0
    return max(1, int(math.ceil(math.sqrt(count))))


def _grid_fallback(ids: List[str]) -> Dict[str, Tuple[float, float]]:
    """没有任何网络设备端点时的兜底：所有节点铺成一个方阵。

    只在"调用方绕过了 discover_topology、手工拼了一个畸形 Topology"时才会
    走到；但布局是公开的纯函数，宁可画一个方阵也不要返回空字典让界面白屏。
    """
    if not ids:
        return {}
    cols = _grid_columns(len(ids))
    return {nid: ((i % cols) * _HOST_COL, (i // cols) * _HOST_ROW)
            for i, nid in enumerate(ids)}


def _pick_roots(topo, nodes, adjacency, gateway_ip) -> List[str]:
    """根的选择顺序：网关 → 网络设备（按链路数降序） → 其余节点。

    根决定分层：网关在最上面，越往下离网关越远 —— 与"物理上离核心多远"
    基本一致，比把所有交换机排成一行可读得多。
    """
    roots: List[str] = []
    gw = None
    if gateway_ip:
        gw = next((n.id for n in topo.nodes
                   if n.is_gateway or (n.ip and n.ip == gateway_ip)), None)
    if gw and gw in nodes:
        roots.append(gw)
    infra = [n.id for n in topo.nodes
             if n.is_infra and n.id in nodes and n.id not in roots]
    infra.sort(key=lambda nid: (-len(adjacency[nid]), nid))
    roots.extend(infra)
    for nid in sorted(nodes):
        if nid not in roots:
            roots.append(nid)
    return roots
