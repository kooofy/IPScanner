# -*- coding: utf-8 -*-
"""拓扑手工校正：节点钉住 / 隐藏链路或节点 / 节点备注。

为什么需要它
------------
自动发现（`topology_discovery`）只能还原**协议说得清**的那部分连接：

* 设备没开 LLDP/CDP、转发表也读不到 → 图上就没有那条真链路；
* 一台哑交换机/AP/集线器被当成普通终端 → 它"吸"走的设备全挂在它下面，
  看起来像直连核心；
* 自动分层为了可读性会把并列子树折行，个别节点落在用户觉得"反直觉"的位置。

这些都是**协议层面无法自证的事实**，只有人知道。所以给一份手工校正层：
把它叠在自动结果之上，**不修改扫描数据**，只影响"怎么看"。

设计取舍
--------
**与扫描结果解耦。** 校正文件按**稳定身份键**匹配节点，绝不存索引或坐标对象。
扫描结果每次都可能不同（IP 变了、设备下线了），但 MAC 不变、主机名大体不变。
于是"钉住 + 隐藏 + 备注"在下一轮扫描后依然生效，而不是一次性摆设。

**零第三方依赖、零 PyQt。** 与 `notifier.py` 同一口径：纯标准库 + `json`，
放在 `app_paths.data_dir()`。这样 CLI（无头）与 GUI 共用同一份实现，
且本模块可被纯单元测试直接覆盖（沙箱无 PyQt5 也能跑）。

**容忍空文件 / 损坏文件。** 校正文件是用户在编辑器里手改的对象，
写坏一个逗号不该让整个拓扑视图崩掉或白屏 —— 与 `notifier.load_config`
同一条原则：读失败只意味着"这次没有校正"，而不是失败。

**节点身份键**（`identity_key`）的取值优先级：

1. 显式 ``mac``（归一成小写 hex）—— 最稳定，跨网段/换 IP 都不变；
2. ``ip`` —— 次稳定，同网段内基本不变；
3. ``name``（主机名 / 显示名）—— 兜底，用户手写的场景。

匹配时**从高到低**逐个尝试：MAC 优先于 IP 优先于名字。同一优先级里
MAC 命中即返回，避免"IP 复用给了另一台设备"时把校正错套到新设备上。
"""
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app_logging import get_logger

_log = get_logger(__name__)

#: 校正文件默认文件名（位于 `app_paths.data_dir()`）
DEFAULT_FILENAME = "topology_overrides.json"

#: 校正文件格式版本。将来结构不兼容时递增，旧文件按"尽力读取"处理。
SCHEMA_VERSION = 1

_MAC_CLEAN_RE = re.compile(r"[^0-9a-f]")


def default_path() -> str:
    """校正文件路径：数据目录下的 ``topology_overrides.json``。

    与 `notify.json` / `scan_history.db` 一致 —— 便携版与用户目录版各自
    持有自己的校正文件，换台机器不串味。
    """
    import app_paths
    return os.path.join(app_paths.data_dir(), DEFAULT_FILENAME)


# ══════════════════════════════════════════════════════════════════════
#  归一化工具
# ══════════════════════════════════════════════════════════════════════

def normalize_mac(value) -> str:
    """MAC → 纯小写 hex（去分隔符）；不像 MAC 时返回空串。

    与 `topology_discovery._normalize_mac` 同一口径 —— 但这里**刻意复制**
    （而非 import）：本模块要保持"零 PyQt、可独立被 CLI 加载"的性质，
    而 `topology_discovery` 顶层会拉起 `scanner.snmp` 那一坨。两处口径不一致
    会导致"校正匹配不上"，所以有测试 (`test_topology_overrides.py`)
    钉住两者对同一批样本的输出完全一致。
    """
    if not value:
        return ""
    raw = _MAC_CLEAN_RE.sub("", str(value).strip().lower())
    if len(raw) != 12:
        return ""
    return raw


def _clean_str(value) -> str:
    return str(value).strip() if value is not None else ""


@dataclass
class NodeOverride:
    """针对**单个节点**的手工校正。

    ``pin`` 是 ``(x, y)`` 或 ``None``；``hidden`` 为真时该节点连同其链路都不画；
    ``note`` 是一段自由文本（用户自己加的解释），会并进节点、出现在文本导出里。
    """
    #: 用户可读的标识（写回文件用；匹配靠下面的键）
    key: str = ""
    mac: str = ""
    ip: str = ""
    name: str = ""
    pin: Optional[tuple] = None
    hidden: bool = False
    note: str = ""

    @property
    def stable_key(self) -> str:
        """最高优先级的匹配键（有 mac 用 mac，否则 ip，否则 name）。"""
        return self.mac or self.ip or self.name

    def to_dict(self) -> dict:
        out: dict = {"key": self.key or self.stable_key}
        if self.mac:
            out["mac"] = self.mac
        if self.ip:
            out["ip"] = self.ip
        if self.name:
            out["name"] = self.name
        if self.pin is not None:
            out["pin"] = [float(self.pin[0]), float(self.pin[1])]
        if self.hidden:
            out["hidden"] = True
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class LinkOverride:
    """针对**一条链路**的手工校正（按两端身份键的无序集合匹配）。"""
    source: str = ""
    target: str = ""
    hidden: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        out = {"source": self.source, "target": self.target}
        if self.hidden:
            out["hidden"] = True
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class TopologyOverrides:
    """一份手工校正集合。空实例 = "没有任何校正"，行为与不做校正完全一致。"""
    nodes: List[NodeOverride] = field(default_factory=list)
    links: List[LinkOverride] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.nodes and not self.links

    def to_dict(self) -> dict:
        return {
            "version": SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
        }


# ══════════════════════════════════════════════════════════════════════
#  解析 / 序列化
# ══════════════════════════════════════════════════════════════════════

def _parse_node(raw) -> Optional[NodeOverride]:
    """一条节点的 JSON → NodeOverride；无法识别时返回 None（跳过，不炸）。"""
    if not isinstance(raw, dict):
        return None
    mac = normalize_mac(raw.get("mac", ""))
    ip = _clean_str(raw.get("ip"))
    name = _clean_str(raw.get("name"))
    key = _clean_str(raw.get("key"))
    # 三者全空 → 这条校正永远匹配不上任何东西，留着只会误导，直接丢
    if not (mac or ip or name or key):
        return None
    pin = None
    raw_pin = raw.get("pin")
    if isinstance(raw_pin, (list, tuple)) and len(raw_pin) == 2:
        try:
            pin = (float(raw_pin[0]), float(raw_pin[1]))
        except (TypeError, ValueError):
            pin = None
    return NodeOverride(
        key=key, mac=mac, ip=ip, name=name, pin=pin,
        hidden=bool(raw.get("hidden", False)),
        note=_clean_str(raw.get("note")),
    )


def _parse_link(raw) -> Optional[LinkOverride]:
    """一条链路的 JSON → LinkOverride；缺端点则丢弃。"""
    if not isinstance(raw, dict):
        return None
    src = normalize_mac(raw.get("source", "")) or _clean_str(raw.get("source"))
    dst = normalize_mac(raw.get("target", "")) or _clean_str(raw.get("target"))
    if not src or not dst:
        return None
    return LinkOverride(
        source=src, target=dst,
        hidden=bool(raw.get("hidden", False)),
        note=_clean_str(raw.get("note")),
    )


def parse(data) -> TopologyOverrides:
    """把已解析的 JSON 对象规整成 `TopologyOverrides`（纯函数，容错）。

    对每一层都做类型守卫：``nodes`` 不是列表就当空，单条坏数据就跳过它。
    用户在编辑器里手改这份文件，局部写错不该让整份校正失效 —— 能用的部分
    照常生效，坏的那几条静默丢弃并留一条 debug 日志。
    """
    if not isinstance(data, dict):
        return TopologyOverrides()
    nodes = []
    for raw in data.get("nodes") or []:
        node = _parse_node(raw)
        if node is None:
            _log.debug("跳过无法识别的节点校正: %r", raw)
        else:
            nodes.append(node)
    links = []
    for raw in data.get("links") or []:
        link = _parse_link(raw)
        if link is None:
            _log.debug("跳过无法识别的链路校正: %r", raw)
        else:
            links.append(link)
    return TopologyOverrides(nodes=nodes, links=links)


def load(path: str = None) -> TopologyOverrides:
    """读取校正文件。不存在 / 损坏时返回空校正（不抛异常）。

    刻意不抛：校正文件是**可选**的增强层。它读不出来只应代表"这次没有校正"，
    而绝不该让拓扑视图或 CLI 导出整体失败。
    """
    p = path or default_path()
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return TopologyOverrides()
    except Exception as e:  # noqa: BLE001
        _log.warning("拓扑校正文件读取失败 %s: %s", p, e)
        return TopologyOverrides()
    return parse(data)


def save(overrides: TopologyOverrides, path: str = None):
    """写入校正文件。返回 ``(是否成功, 错误信息)``（与 `notifier.save_config` 一致）。"""
    p = path or default_path()
    try:
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump((overrides or TopologyOverrides()).to_dict(),
                      f, ensure_ascii=False, indent=2)
        return True, ""
    except Exception as e:  # noqa: BLE001
        _log.warning("拓扑校正文件写入失败 %s: %s", p, e)
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════
#  应用（纯投影）
# ══════════════════════════════════════════════════════════════════════

def node_identity_keys(node) -> List[str]:
    """一个拓扑节点的候选身份键，**按匹配优先级降序**。

    顺序即语义：MAC 最稳（换网段、换 IP 都不变），其次 IP，最后名字。
    校正匹配时按这个顺序逐个比，第一个命中即采用。
    """
    keys: List[str] = []
    mac = normalize_mac(getattr(node, "mac", "") or "")
    if mac:
        keys.append("mac:" + mac)
    ip = _clean_str(getattr(node, "ip", ""))
    if ip:
        keys.append("ip:" + ip)
    # `ext:` / `subnet:` 这类合成节点的 id 本身没有 IP/MAC，用 id 兜底最稳
    nid = _clean_str(getattr(node, "id", ""))
    if nid and nid not in (ip,):
        keys.append("id:" + nid)
    name = _clean_str(getattr(node, "label", ""))
    if name:
        keys.append("name:" + name)
    return keys


def _override_keys(ov: NodeOverride) -> List[str]:
    """一个校正条目的候选键，顺序与 `node_identity_keys` 一致。"""
    keys: List[str] = []
    if ov.mac:
        keys.append("mac:" + ov.mac)
    if ov.ip:
        keys.append("ip:" + ov.ip)
    # `key` 字段是用户手写的兜底标识，按 id/name 两种都可能匹配，
    # 显式写 ip: 前缀时归一成 ip 键（见下）
    if ov.key:
        if ov.key.startswith(("mac:", "ip:", "id:", "name:")):
            keys.append(ov.key)
        elif normalize_mac(ov.key):
            keys.append("mac:" + normalize_mac(ov.key))
        else:
            keys.append("name:" + ov.key)
            keys.append("id:" + ov.key)
    if ov.name:
        keys.append("name:" + ov.name)
    return keys


def _resolve_link_end(raw: str, key_to_id: Dict[str, str],
                      node_by_id: Dict[str, object]) -> Optional[str]:
    """把链路校正里写的一端（MAC / IP / 节点 id / 名字）解析成节点 id。

    与节点校正同一优先级口径（mac → ip → id → name）；解析不到返回 None，
    调用方据此跳过整条链路校正 —— **宁可这条校正不生效，也不要乱配一对**。
    """
    text = _clean_str(raw)
    if not text:
        return None
    mac = normalize_mac(text)
    if mac:
        hit = key_to_id.get("mac:" + mac)
        if hit is not None:
            return hit
    if text in node_by_id:
        return text
    for prefix in ("ip:", "id:", "name:"):
        hit = key_to_id.get(prefix + text)
        if hit is not None:
            return hit
    return None


def apply_overrides(topo, overrides: TopologyOverrides):
    """把手工校正**投影**到一个新拓扑上；**不修改入参**。

    处理顺序（每一步都只影响"怎么看"，不动原始数据）：

    1. **隐藏节点**：被隐藏的节点整条移除，且**以它为端点的链路一并移除**
       （否则会留下悬空线段）。
    2. **隐藏链路**：按两端身份键的**无序**组合移除（方向不重要 ——
       用户不会关心谁写的 source）。
    3. **备注**：节点备注并进 `TopoNode` 的备注字段（通过 ``setattr`` 挂一个
       ``manual_note``，不改 dataclass 定义，避免波及 `discover_topology`
       的构造与既有测试）；链路备注同理。
    4. **钉住坐标**：把 ``(x, y)`` 按节点身份键收进返回的 ``pinned`` 字典，
       交给布局层覆盖自动坐标。

    Returns:
        ``(new_topo, pinned)``。``new_topo`` 是过滤/标注后的拓扑副本
        （``nodes`` / ``links`` 是新列表，但节点对象本身是**浅拷贝**）；
        ``pinned`` 是 ``{node_id: (x, y)}``。
    """
    import copy

    from topology_discovery import Topology

    if overrides is None or overrides.is_empty():
        return topo, {}

    # ── 建"校正键 → 节点 id"的映射（一次性，O(节点数 × 键数)）──
    key_to_id: Dict[str, str] = {}
    node_by_id = {n.id: n for n in topo.nodes}
    for node in topo.nodes:
        for key in node_identity_keys(node):
            key_to_id.setdefault(key, node.id)

    node_ovs: Dict[str, NodeOverride] = {}
    for ov in overrides.nodes:
        target = None
        for key in _override_keys(ov):
            target = key_to_id.get(key)
            if target is not None:
                break
        if target is not None:
            node_ovs[target] = ov

    hidden_nodes = {nid for nid, ov in node_ovs.items() if ov.hidden}

    # ── 链路校正：按无序身份对归一 ──
    def _link_key(a: str, b: str) -> frozenset:
        return frozenset((a, b))

    hidden_links = set()
    link_notes: Dict[frozenset, str] = {}
    for lov in overrides.links:
        ends = []
        for raw in (lov.source, lov.target):
            nid = _resolve_link_end(raw, key_to_id, node_by_id)
            if nid is None:
                break
            ends.append(nid)
        if len(ends) != 2 or ends[0] == ends[1]:
            continue
        lk = _link_key(ends[0], ends[1])
        if lov.hidden:
            hidden_links.add(lk)
        elif lov.note:
            link_notes[lk] = lov.note

    # ── 生成新拓扑（浅拷贝节点，过滤链路）──
    kept_nodes = []
    for node in topo.nodes:
        if node.id in hidden_nodes:
            continue
        ov = node_ovs.get(node.id)
        if ov is not None and (ov.note or ov.pin is not None):
            node = copy.copy(node)
            if ov.note:
                node.manual_note = ov.note
        kept_nodes.append(node)

    kept_links = []
    for link in topo.links:
        if link.source_id in hidden_nodes or link.target_id in hidden_nodes:
            continue
        lk = _link_key(link.source_id, link.target_id)
        if lk in hidden_links:
            continue
        note = link_notes.get(lk)
        if note:
            link = copy.copy(link)
            link.manual_note = note
        kept_links.append(link)

    new_topo = Topology(
        nodes=kept_nodes,
        links=kept_links,
        note=topo.note,
        infra_count=sum(1 for n in kept_nodes if n.is_infra),
        unplaced=topo.unplaced,
    )

    pinned = {nid: ov.pin for nid, ov in node_ovs.items()
              if ov.pin is not None and nid not in hidden_nodes}
    return new_topo, pinned
