# -*- coding: utf-8 -*-
"""暴露面启发式：banner → 粗粒度 CPE → 候选 CVE（v2.1 §2.3）。

**这个模块回答什么问题**：`这台机器上跑的东西，在本地 CVE 快照里有没有已知条目`。
它**不**回答「这台机器有漏洞」—— 见下面「措辞硬约束」。

为什么只做产品级匹配（不做版本区间）
------------------------------------
完整 CPE 版本区间匹配需要 NVD 全量 CPE 字典（数百 MB，随版本膨胀），而且
`vulnerable: true` 的语义随 CVE 逐个解释，极易错。本工具的定位是**内网资产
可见性**：给出「`Apache httpd` 这类产品出现在这台机器上，而本地快照里该产品
有已知 CVE」这个**信号**，已经足够让管理员去人工确认。粗粒度匹配不会漏报
（同产品的新旧版本都在同一 key 下），代价是可能多报 —— 多报由人工收窄，
漏报则永远看不到（模型文档 §4「粗粒度 CPE」注）。

三件必须说清的事（`docs/CVE_SNAPSHOT_MODEL.md` §1 原则 3 / §5）
---------------------------------------------------------------
1. **措辞硬约束**：结论一律写「**匹配到**候选 CVE」，**绝不**写
   「已验证 / 可利用 / 存在漏洞」。命中 KEV 的事实可以呈现（那是 CISA 的
   公开标注），但不能升级成「这台机器正在被利用」。
2. **无数据 ≠ 无漏洞**：`ExposureReport.verdict` 把「快照不可用」
   （`no-data`）、「查了、没有匹配」（`none`）、「有匹配」（`matched`）
   分成**三个**可区分的状态。扫描结果里没有候选时，返回 `none`
   而不是空列表让调用方自己猜。
3. **匹配是启发式**：同一产品在快照里的 CPE 由 `cve_snapshot.coarsen_cpe()`
   收敛，版本信息**刻意被丢弃**（见上）。因此 `ExposureHit` 带
   `evidence`（这个产品名是从哪里看出来的）与 `version`（看到的版本号，
   仅供人工判断，**不参与匹配**）。

零依赖：零 PyQt / 零第三方 / **零网络**（只读本地快照 + 内存计算）。
"""
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app_logging import get_logger

from . import cve_snapshot as snap
from .cve_snapshot import CveEntry, CveSnapshot

_log = get_logger(__name__)

# ── 判定规范值（调用方据此出文案，**不要**把文案写进这里） ──────────────
VERDICT_MATCHED = "matched"      # 有候选 CVE
VERDICT_NONE = "none"            # 查了，没有匹配
VERDICT_NO_DATA = "no-data"      # 快照不可用（缺失/损坏/过期/0 条）→ 无结论

#: 产品名的来源（规范值）。`banner` = 服务 banner 指纹库解析出的「产品 版本」。
EVIDENCE_BANNER = "banner"
EVIDENCE_SNMP = "snmp"
EVIDENCE_HTTP = "http"

#: 产品名（小写）→ 粗粒度 CPE（vendor:product）。
#: 只收**指纹库真能输出**的产品名（`service_fingerprints.json` 的 33 个
#: 产品）+ 网络设备 sysDescr 里常见厂商 —— 凭空往里加映射只会让用户
#: 看到一堆永远匹配不上的产品。
#: ⚠ 这是**提示表**不是权威字典：快照里没有的 CPE 自然匹配不上，
#:    不会产生「假阳性」；漏了的条目只会少报（由人工补）。
_PRODUCT_CPE: Dict[str, str] = {
    # ── Web / 应用服务（part = a） ──────────────────────────────────
    "apache httpd": "a:apache:http_server",
    "apache tomcat": "a:apache:tomcat",
    "tomcat": "a:apache:tomcat",
    "nginx": "a:nginx:nginx",
    "lighttpd": "a:lighttpd:lighttpd",
    "jetty": "a:eclipse:jetty",
    "werkzeug": "a:palletsprojects:werkzeug",
    "gunicorn": "a:gunicorn:gunicorn",
    "uvicorn": "a:encode:uvicorn",
    "openssh": "a:openbsd:openssh",
    "dropbear": "a:dropbear:dropbear",
    "vsftpd": "a:vsftpd:vsftpd",
    "proftpd": "a:proftpd:proftpd",
    "pure-ftpd": "a:pureftpd:pure-ftpd",
    "filezilla server": "a:filezilla-project:filezilla_server",
    "exim": "a:exim:exim",
    "sendmail": "a:sendmail:sendmail",
    "postfix": "a:postfix:postfix",
    "dovecot": "a:dovecot:dovecot",
    "haraka": "a:haraka:haraka",
    "microsoft iis": "a:microsoft:internet_information_server",
    "mysql": "a:oracle:mysql",
    "mariadb": "a:mariadb:mariadb",
    "postgresql": "a:postgresql:postgresql",
    "mongodb": "a:mongodb:mongodb",
    "redis": "a:redis:redis",
    "log4j": "a:apache:log4j",
    # ── 网络设备（part = o） ───────────────────────────────────────
    "cisco ios": "o:cisco:ios",
    "ios": "o:cisco:ios",
    "huawei vrp": "o:huawei:vrp",
    "vrp": "o:huawei:vrp",
    "h3c comware": "o:h3c:comware",
    "comware": "o:h3c:comware",
    "ruijie": "o:ruijie:rgos",
    "juniper junos": "o:juniper:junos",
    "junos": "o:juniper:junos",
    "mikrotik routeros": "o:mikrotik:routeros",
    "routeros": "o:mikrotik:routeros",
    "fortios": "o:fortinet:fortios",
    "cisco ios xe": "o:cisco:ios_xe",
    "ios xe": "o:cisco:ios_xe",
    "ios-xe": "o:cisco:ios_xe",
    # ── 边界设备 / 中间件（内置种子要能真的匹配上，见 `cve_snapshot.json`） ──
    "openssl": "a:openssl:openssl",
    "spring framework": "a:vmware:spring_framework",
    "vcenter server": "a:vmware:vcenter_server",
    "vcenter": "a:vmware:vcenter_server",
    "citrix adc": "a:citrix:application_delivery_controller",
    "netscaler": "a:citrix:netscaler_application_delivery_controller",
    "big-ip": "a:f5:big-ip_traffic_management_user_interface",
    "big ip": "a:f5:big-ip_traffic_management_user_interface",
    "pan-os": "a:paloaltonetworks:pan-os",
    "pan os": "a:paloaltonetworks:pan-os",
}

#: 匹配时按**长度降序**扫，保证 "apache tomcat" 先于 "tomcat" 命中
#: （"tomcat" 是 "apache tomcat" 的子串）。
_ALIASES_BY_LEN: Tuple[str, ...] = tuple(
    sorted(_PRODUCT_CPE, key=len, reverse=True))


#: banner 尾部的版本号形状（`Apache httpd 2.4.41` → `Apache httpd`）。
_VERSION_TAIL_RE = re.compile(r"[\s_-]+v?[0-9][0-9A-Za-z._\-]*$")

#: 版本 token：粗粒度匹配不看版本，但**要**把它呈现给用户看。
_VERSION_TOKEN_RE = re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+)*")

#: sysDescr 里的版本标注：``Version 12.2(55)SE`` / ``Version 5.20``。
_SNMP_VERSION_RE = re.compile(r"\bversion\s+([0-9][0-9A-Za-z.()_\-]*)", re.I)


def cpe_for_hint(hint: str) -> str:
    """``"a:apache:http_server"`` → 粗粒度 CPE 串（`part:vendor:product` → CPE）。"""
    parts = hint.split(":", 2)
    if len(parts) != 3:
        return ""
    part, vendor, product = parts
    if part not in ("a", "o", "h"):
        return ""
    return "cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*" % (part, vendor, product)


# ── 数据结构 ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProductHit:
    """从一台设备的一处证据里认出来的一个产品。

    `source_text` 原样保留证据片段（截断过）—— 匹配是启发式，用户必须能
    回看「这个产品名是从哪看出来的」，否则没法判断要不要信。
    """

    product: str
    cpe: str
    version: str = ""
    evidence: str = EVIDENCE_BANNER
    source_text: str = ""


@dataclass(frozen=True)
class ExposureHit:
    """一台设备上的**一个产品**命中的候选 CVE 集合。"""

    ip: str
    product: str
    cpe: str
    version: str = ""
    mac: str = ""
    evidence: str = EVIDENCE_BANNER
    source_text: str = ""
    candidates: Tuple[CveEntry, ...] = ()

    @property
    def top(self) -> Optional[CveEntry]:
        """排在最前的候选（KEV 优先、EPSS 最高）。"""
        return self.candidates[0] if self.candidates else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "evidence": self.evidence,
            "source_text": self.source_text,
            "candidates": [c.to_dict() for c in self.candidates],
        }


@dataclass(frozen=True)
class ExposureReport:
    """一次暴露面匹配的结果 + 快照健康状况。

    🔴 `verdict` 三态是调用方**唯一**可以依据的出口：
    `no-data`（快照不可用，**无结论**）/ `none`（查了、没有匹配）/
    `matched`（有候选）。不要把「空 hits」当成「none」—— 快照坏的时候
    hits 也是空的，但那件事必须说成「无数据可查」。
    """

    snapshot_state: str = snap.STATE_MISSING
    snapshot_source: str = snap.SOURCE_NONE
    age_days: Optional[int] = None
    entry_count: int = 0
    hits: Tuple[ExposureHit, ...] = ()

    @property
    def verdict(self) -> str:
        if self.snapshot_state in (snap.STATE_MISSING, snap.STATE_CORRUPT,
                                   snap.STATE_EMPTY):
            return VERDICT_NO_DATA
        # STATE_OK / STATE_STALE / STATE_UNKNOWN_AGE：数据在，可以给结论
        # （过期/未知新鲜度由调用方额外提示，但不影响「查了没有」这个事实）。
        return VERDICT_MATCHED if self.hits else VERDICT_NONE

    @property
    def matched_hosts(self) -> Tuple[str, ...]:
        """命中的主机（去重、保持首次出现顺序）。"""
        seen: List[str] = []
        for h in self.hits:
            if h.ip and h.ip not in seen:
                seen.append(h.ip)
        return tuple(seen)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "snapshot": {
                "state": self.snapshot_state,
                "source": self.snapshot_source,
                "age_days": self.age_days,
                "entry_count": self.entry_count,
            },
            "matched_hosts": list(self.matched_hosts),
            "hits": [h.to_dict() for h in self.hits],
        }


# ── 产品识别 ────────────────────────────────────────────────────────────

def _split_product_version(text: str) -> Tuple[str, str]:
    """``"Apache httpd 2.4.41"`` → ``("Apache httpd", "2.4.41")``。

    `service_details[].banner` 存的是指纹库的**展示串**（``产品 版本``，
    见 `scanner/engine._probe_services` 的 ``fp.display``），所以这里按
    「尾部版本号」切；切不出来就整串当产品名、版本留空。
    """
    s = (text or "").strip()
    if not s:
        return "", ""
    m = _VERSION_TAIL_RE.search(s)
    if m and m.start() > 0:
        return s[:m.start()].strip(), s[m.start():].strip()
    return s, ""


def _alias_hit(alias: str, low_text: str) -> bool:
    """别名是否作为**完整词**出现在 `low_text` 里。

    🔴 必须带词边界：否则 `"ios"` 会命中 `"radios"`、`"vrp"` 会命中
    `"srvproxy"` —— 短别名 + 裸子串 = 稳定的假阳性来源。
    """
    return re.search(r"(?<![0-9a-z])" + re.escape(alias) + r"(?![0-9a-z])",
                     low_text) is not None


def _hint_of(name_low: str) -> Optional[str]:
    """产品名 → 提示表里的**别名**（命中的 key；别名同时也是展示名）。"""
    if name_low in _PRODUCT_CPE:
        return name_low
    for alias in _ALIASES_BY_LEN:
        if _alias_hit(alias, name_low):
            return alias
    return None


def _cpe_of(name_low: str) -> Optional[str]:
    """产品名 → 粗粒度 CPE（先精确、再长别名优先的子串命中）。"""
    alias = _hint_of(name_low)
    if not alias:
        return None
    return cpe_for_hint(_PRODUCT_CPE[alias]) or None


def _truncate(text: str, limit: int = 80) -> str:
    s = " ".join(str(text or "").split())
    return s[:limit]


def cpe_for_product(text: str, version: str = "") -> Optional[Tuple[str, str, str]]:
    """产品名（可带版本）→ ``(展示名, 粗粒度 CPE, 版本)``；认不出来返回 `None`。

    供 `ipscanner cve --product "Apache httpd 2.4.41"` 这类**手工查询**复用
    与扫描完全相同的识别口径：同一条 `_split_product_version` → `_hint_of`
    → `cpe_for_hint` 链，命令行查得到的产品，扫描里就一定认得出（反之亦然），
    不存在第二套规则。
    """
    s = str(text or "").strip()
    if not s:
        return None
    if version:
        name, ver = s, str(version).strip()
    else:
        name, ver = _split_product_version(s)
    alias = _hint_of(name.lower())
    if not alias:
        return None
    cpe = cpe_for_hint(_PRODUCT_CPE[alias]) or ""
    if not cpe:
        return None
    # 与 `products_from_result()` 同一取舍：精确命中保留原文大小写，
    # 别名命中用别名当展示名（原文往往是一整串 sysDescr）。
    return (name if name.lower() == alias else alias), cpe, ver


def products_from_result(result) -> List[ProductHit]:
    """从一台扫描结果里挑出**认识的**产品（列表稳定去重）。

    证据来源（规范值 `EVIDENCE_*`）：
    * `banner`：`service_details[].banner`（指纹库解析出的「产品 版本」）；
    * `snmp`：`snmp_sys_descr`（交换机 / AP 的 Cisco IOS、H3C Comware 等）。

    认不出来的产品**静默跳过**（只记 debug）—— 本模块只做「认识的」，
    不猜。空列表 ≠ 这台设备没软件，只等于「没有可用的粗粒度线索」。
    """
    out: List[ProductHit] = []
    seen_cpe = set()

    def _add(text: str, evidence: str, version: str = "") -> None:
        name, tail_version = _split_product_version(text) if not version \
            else (str(text or "").strip(), version)
        if not name:
            return
        alias = _hint_of(name.lower())
        if not alias:
            return                      # 不认识的产品：不猜，跳过
        cpe = cpe_for_hint(_PRODUCT_CPE[alias]) or ""
        if not cpe or cpe in seen_cpe:
            return
        seen_cpe.add(cpe)
        out.append(ProductHit(
            # 走别名命中时用别名当展示名（`Cisco IOS Software, C2960 ...` 太长）；
            # 精确命中时用原文（保留 "Apache httpd" 的原大小写）。
            product=(name if name.lower() == alias else alias),
            cpe=cpe,
            version=version or tail_version,
            evidence=evidence,
            source_text=_truncate(text),
        ))

    details = getattr(result, "service_details", None) or []
    for sd in details:
        if not isinstance(sd, dict):
            continue
        banner = str(sd.get("banner") or "").strip()
        if banner:
            _add(banner, EVIDENCE_BANNER)

    sys_descr = str(getattr(result, "snmp_sys_descr", "") or "").strip()
    if sys_descr:
        m = _SNMP_VERSION_RE.search(sys_descr)
        _add(sys_descr, EVIDENCE_SNMP, version=m.group(1) if m else "")

    for ph in out:
        _log.debug("识别到产品 %s（%s，来自 %s）", ph.product, ph.cpe,
                   ph.evidence)
    return out


# ── 匹配入口 ────────────────────────────────────────────────────────────

def match_result(result, snapshot: CveSnapshot) -> List[ExposureHit]:
    """单台结果 → 该设备上每个产品的候选 CVE（已排序）。"""
    hits: List[ExposureHit] = []
    ip = str(getattr(result, "ip", "") or "")
    mac = str(getattr(result, "mac", "") or "")
    for ph in products_from_result(result):
        candidates = tuple(snap.find_candidates(snapshot, ph.cpe))
        if not candidates:
            continue
        hits.append(ExposureHit(
            ip=ip,
            product=ph.product,
            cpe=ph.cpe,
            version=ph.version,
            mac=mac,
            evidence=ph.evidence,
            source_text=ph.source_text,
            candidates=candidates,
        ))
    return hits


def match_results(results: Iterable, snapshot: Optional[CveSnapshot] = None
                  ) -> ExposureReport:
    """一批扫描结果 → `ExposureReport`。

    `snapshot=None` 时现场 `load_snapshot()`（CLI 的默认行为）。
    🔴 快照不可用时**不匹配**：返回 `verdict == no-data` 的空报告，
    而不是一堆空 hits —— 后者会被误读成「查过了，没问题」。
    """
    snap_obj = snapshot if snapshot is not None else snap.load_snapshot()
    if not snap_obj.usable:
        _log.debug("CVE 快照不可用（%s），本次不给暴露面结论", snap_obj.state)
        return ExposureReport(
            snapshot_state=snap_obj.state,
            snapshot_source=snap_obj.source,
            age_days=snap_obj.age_days,
            entry_count=0,
            hits=(),
        )
    hits: List[ExposureHit] = []
    for result in results or ():
        hits.extend(match_result(result, snap_obj))
    # 命中的排序：按「最严重的那条候选」走同一套 KEV 优先 / EPSS 降序，
    # 于是一眼先看到最该看的。同分按 IP，保证输出可复现。
    hits.sort(key=lambda h: (h.top.sort_key if h.top else (2, 1, 0.0, ""),
                             h.ip, h.product))
    return ExposureReport(
        snapshot_state=snap_obj.state,
        snapshot_source=snap_obj.source,
        age_days=snap_obj.age_days,
        entry_count=len(snap_obj.entries),
        hits=tuple(hits),
    )


def exposure_for_results(results: Iterable) -> ExposureReport:
    """`match_results()` 的语法糖：自己加载快照。"""
    return match_results(results)
