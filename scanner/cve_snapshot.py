# -*- coding: utf-8 -*-
"""离线 CVE 快照：加载 / 校验 / 新鲜度判定（v2.1 §2.3）。

**这份模块是什么**：`docs/CVE_SNAPSHOT_MODEL.md`（§2.3 的「第 0 步」产物）
裁定出来的**消费端**。快照是一份**只读数据文件**（纯 JSON，不含任何可执行逻辑），
由上游聚合方生成、本项目只消费；运行期**零网络、零第三方、零 PyQt**。

三条铁律（直接抄自模型文档 §1，实现逐条对应）
------------------------------------------------
1. **数据不出网**：本模块不 import `urllib` / `requests` / `socket`，不发任何请求。
   更新快照 = 用户**手动**把新文件放进 `data_dir()`（同 `oui.db` 的更新方式）。
   下载能力在调用方（GUI/CLI）那一侧单独实现，本模块只负责**读本地文件**。
2. **声明式扩展，不执行代码**：只做「JSON → 数据结构」映射，没有 `eval`、
   没有动态 import；本模块用到的正则**只用于校验 / 清洗输入**（CVE 号形状、
   CPE 字符集、剥 summary 的 HTML 标签），**绝不**把快照里的字符串当正则编译。
   快照里的 `summary` 会进 GUI tooltip，因此 **strip 标签 + 截断** 在解析时
   就地做掉（外部内容 = 注入面）。
3. **诚实降级**：快照**缺失 / 过期 / 损坏** 与「查了、没有匹配」在 `state`
   上**可区分**（见 `STATE_*`）。宁可报「数据过期」，也绝不拿旧快照给用户
   一个过期的安心感。

新鲜度（§3.1）
--------------
快照自带 `generated_at` + `max_age_days`（生成方声明，建议默认 30 天）：

* `age ≤ max_age_days` → `STATE_OK`，可正常使用；
* `age > max_age_days` → `STATE_STALE`，仍可用（用户自己选的），但调用方
  **必须**显式提示「快照已过期 N 天，结论可能滞后」；
* `generated_at` **缺失或不可解析** → `STATE_UNKNOWN_AGE`（未知新鲜度），
  与「过期」同级告警 —— **不假设它新鲜**。

完整性（§3.4）
--------------
`cve_snapshot.json` 旁边可放 `cve_snapshot.sha256`（格式同发布流程的
`SHA256SUMS.txt`：``<hex>␠␠<文件名>``）：

* 一致 → 正常加载，`checksum_verified=True`；
* 不一致 → **拒绝加载**（`STATE_CORRUPT`，可能是下载损坏/半截文件）；
* 清单缺失 → **不阻断**，按原样加载并 `checksum_verified=None`，
  记一条 warning（「未校验」是可感知的，见 §3.4 尾注的理由）。

搜索路径（§3.2）
----------------
沿用 `oui.db` / `service_fingerprints.json` 的同一套约定：
``data_dir()/cve_snapshot.json``（用户更新版）优先 → 回退
``resource_dir()/cve_snapshot.json``（内置种子）。便携模式下 `data_dir()`
落在 exe 同级，于是「U 盘带着快照走」自动成立。

i18n 约定
---------
`state` / `source` / `kev` / `cve_id` 等都是**语言无关的规范值**；显示文案
由调用方走 `tr()`。本模块**不 import i18n**（`scanner/` 的既有约定：领域层
不放显示文本，避免 import 期冻结与规范值污染）。
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app_logging import get_logger
from app_paths import data_dir, resource_dir

_log = get_logger(__name__)

#: 快照格式版本（§4）。解析器只认**本版本**；遇到更高版本 → warning 后按 v1 尽力解析。
SCHEMA = "ipscanner.cve_snapshot/1"

DATA_FILENAME = "cve_snapshot.json"
SUMS_FILENAME = "cve_snapshot.sha256"

#: 生成方**没有**声明 `max_age_days` 时的兜底值（§3.1：建议默认 30）。
DEFAULT_MAX_AGE_DAYS = 30

#: `summary` 落 UI 前的截断长度（§9.2）。快照来自外网内容，超长 tooltip
#: 既难读又是注入面。
SUMMARY_MAX_CHARS = 200

#: 在线快照的默认地址（§9.4）。
#: 🔴 **占位常量**：用户建好公开数据仓后**只改这一处**。
#: 刻意不用本仓库 Release —— 仓库是私有的，匿名访问资产直接 404，
#: 而且不该为下载一个 JSON 让桌面应用持有 GitHub token（模型文档 §9.4 否决理由）。
DEFAULT_SNAPSHOT_URL = ("https://raw.githubusercontent.com/CHANGE-ME/"
                        "ipscanner-cve-data/main/cve_snapshot.json")

# ── 状态规范值（调用方据此决定文案，**不要**把文案写进这里） ──────────────
STATE_OK = "ok"                  # 加载成功且新鲜
STATE_STALE = "stale"            # 加载成功但已过期（用户自己选的，仍可用）
STATE_UNKNOWN_AGE = "unknown-age"  # generated_at 缺失/不可解析 → 新鲜度未知
STATE_EMPTY = "empty"            # 解析成功但 0 条（查了也没得查）
STATE_MISSING = "missing"        # 两个搜索路径都没有文件
STATE_CORRUPT = "corrupt"        # 文件在读不出来 / 结构不符 / 摘要不匹配

# ── 来源规范值（§9.4 要求 UI 显示「快照来源」） ─────────────────────────
SOURCE_DATA = "data-dir"         # data_dir() 里的用户更新版
SOURCE_SEED = "seed"             # resource_dir() 里的内置种子
SOURCE_NONE = "none"             # 没有快照
#: 在线下载（v2.2 §3.1）。🔴 本模块**仍然零网络**：这个值只表示「data_dir()
#: 里那份是怎么来的」，落盘由 `cve_updater.py` 完成。加载器**不感知**下载，
#: 靠同目录下一份 `cve_snapshot.online` 标记文件来区分（见 `_read_source_mark`）。
SOURCE_ONLINE = "online-download"

#: 在线更新成功后在快照旁边留下的**来源标记**文件名。内容无关紧要（空文件即可），
#: 存在即表示「这份是程序自己下回来的」。
#: 🔴 为什么要单独一个文件、而不是在 JSON 里加字段：快照 JSON 是**上游聚合方**
#: 生成、经过 SHA256 清单校验的**只读数据**，往里写本地状态会当场把摘要校验搞坏。
#: 标记文件不参与校验，是"本地对来源的判断"，与数据本身分开。
ONLINE_MARK_FILENAME = "cve_snapshot.online"

#: CPE 2.3 的「粗粒度」模板：只保留厂商 + 产品，其余全通配。
_COARSE_CPE = "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*"

#: 允许出现在 CPE 里的字符（厂商/产品段）。
_CPE_PART_RE = re.compile(r"^[a-z0-9._\-]{1,64}$")

#: CVE 编号形状。放宽到 4 位起（CVE-2021-44228），年份段 4 位。
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

#: HTML 标签（外网 `summary` 可能带富文本 / 链接）。
_TAG_RE = re.compile(r"<[^<>]{0,200}>")

_EPSS_MIN, _EPSS_MAX = 0.0, 1.0


# ── 数据结构 ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CveEntry:
    """快照里的一条 CVE 记录（粗粒度产品级，§4）。

    * `kev=None` / `epss=None` 表示「**无该信号**」—— 与「查了、KEV 为 false」
      在类型上**可区分**，排序时置后（§4：不是「分值 0」的强断言）。
    * `summary` 已 strip 标签 + 截断到 `SUMMARY_MAX_CHARS`。
    """

    cve_id: str
    cpe: Tuple[str, ...] = ()
    kev: Optional[bool] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """语言无关的字典形态（CLI JSON / 报告序列化用，键固定英文）。"""
        return {
            "cve_id": self.cve_id,
            "cpe": list(self.cpe),
            "kev": self.kev,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "summary": self.summary,
        }

    @property
    def sort_key(self) -> Tuple:
        """排序键：KEV 命中优先 → 组内有 EPSS 的排在无 EPSS 前 → EPSS 降序。

        🔴 刻意**不**把 `epss=None` 当 0：那会把「FIRST 没给分」的事实改成
        「利用概率为 0」的强断言（§4 注）。None 只表示排序置后。
        """
        return (
            0 if self.kev else 1,
            0 if self.epss is not None else 1,
            -(self.epss or 0.0),
            self.cve_id,
        )


@dataclass
class CveSnapshot:
    """一份已加载的快照 + 它的「健康状况」。

    `state` 是**唯一**的降级信号源（见 `STATE_*`）；`checksum_verified` 三态：
    `True` 校验通过 / `False` 不匹配（已拒绝加载，不会到这里） /
    `None` 没有摘要清单、未校验。调用方据此决定文案，**不要**自己猜。
    """

    entries: List[CveEntry] = field(default_factory=list)
    state: str = STATE_MISSING
    source: str = SOURCE_NONE
    schema: str = ""
    generated_at: Optional[datetime] = None
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    sources: Dict[str, str] = field(default_factory=dict)
    checksum_verified: Optional[bool] = None
    age_days: Optional[int] = None
    path: str = ""
    skipped: int = 0

    # ── 便捷判据 ───────────────────────────────────────────────────────
    @property
    def usable(self) -> bool:
        """能不能拿它查 CVE。

        过期（`stale`）/ 新鲜度未知（`unknown-age`）都算**能查**：数据在，
        只是可能旧 —— 调用方必须按 `state` 给降级提示，但结论本身有效。
        🔴 `missing` / `corrupt` / `empty` **不算**：那不是「查了、没有匹配」，
        而是「无数据可查」，两件事的文案与退出码都必须不同（模型文档 §1 原则 3）。
        """
        return (self.state in (STATE_OK, STATE_STALE, STATE_UNKNOWN_AGE)
                and bool(self.entries))

    @property
    def fresh(self) -> bool:
        """数据是否新鲜（`can_consult` 的子集，仅供 UI 徽标用）。"""
        return self.state == STATE_OK and bool(self.entries)

    def stats(self) -> Dict[str, Any]:
        """诊断用统计（语言无关；CLI `cve --status` 直接输出）。"""
        kev = sum(1 for e in self.entries if e.kev)
        scored = sum(1 for e in self.entries if e.epss is not None)
        return {
            "state": self.state,
            "source": self.source,
            "schema": self.schema,
            "path": self.path,
            "generated_at": (self.generated_at.isoformat()
                             if self.generated_at else None),
            "max_age_days": self.max_age_days,
            "age_days": self.age_days,
            "entry_count": len(self.entries),
            "kev_count": kev,
            "epss_scored_count": scored,
            "checksum_verified": self.checksum_verified,
            "skipped_records": self.skipped,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.stats()
        out["sources"] = dict(self.sources)
        return out


# ── 解析助手（全部纯函数，可独立单测） ─────────────────────────────────

def parse_timestamp(value: Any) -> Optional[datetime]:
    """解析 ISO 8601 UTC 时间戳，失败返回 ``None``（绝不抛）。

    上游源 / 快照里的时间戳形如 ``2022-10-27T04:37:47.1583133Z``：小数位
    1~7 位都有，``Z`` 后缀在 Python 3.10 的 `fromisoformat` 里还不认
    （3.11 才认）。这里**手工归一化**到 UTC aware 再解析，兼容 3.10。
    """
    if isinstance(value, (int, float)):      # 允许 epoch 秒（快照可能来自脚本）
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value or "").strip()
    if not s:
        return None
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    # 小数位规整到 6 位（微秒）。3.10 的 fromisoformat 只接受 3 或 6 位。
    m = re.match(r"^(.*)\.(\d+)([+-]\d{2}:\d{2})?$", s)
    if m and len(m.group(2)) not in (3, 6):
        frac = (m.group(2) + "000000")[:6]
        s = "{}.{}{}".format(m.group(1), frac, m.group(3) or "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        _log.debug("无法解析时间戳: %r", value)
        return None
    if dt.tzinfo is None:                     # 没有时区信息 → 按 UTC 解释（§4）
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def coarsen_cpe(raw: Any) -> Optional[str]:
    """把任意写法的 CPE 收敛成**粗粒度产品级**串（``cpe:2.3:a:vendor:product:*…``）。

    接受：
    * CPE 2.3 格式化串：``cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*``
    * CPE 2.2 URI 串：``cpe:/a:apache:log4j:2.14.1``
    * 已经是粗粒度的串（原样校验后返回）

    返回 ``None`` 表示这条 CPE **不可用**（形状不对 / 缺厂商或产品）——
    调用方据此跳过该条，**不抛**（§3.3：单条坏记录只跳过错的那条）。
    """
    s = str(raw or "").strip().lower()
    if not s:
        return None
    parts: List[str] = []
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")
    elif s.startswith("cpe:/"):
        # CPE 2.2 URI 形式（`cpe:/a:apache:log4j:2.14.1`）—— 老 NVD 1.1 feed
        # 里还有。剥掉 `cpe:/` 后自己补上 2.3 的部分号。
        parts = ["cpe", "2.3"] + s[len("cpe:/"):].split(":")
    else:
        return None
    if len(parts) < 6:
        return None
    part, vendor, product = parts[2], parts[3], parts[4]
    if part not in ("a", "o", "h"):
        return None
    if not (_CPE_PART_RE.match(vendor) and _CPE_PART_RE.match(product)):
        return None
    # 保留 part（a=应用 / o=操作系统 / h=硬件）：把 OS 的 CPE 降级成
    # `a:` 会让「Cisco IOS 的 CVE」永远匹配不上，而那类 CVE 恰好是
    # 网络设备最常见的已知漏洞来源。
    return "cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*" % (part, vendor, product)


def sanitize_summary(raw: Any) -> str:
    """`summary` 的清洗：剥标签 + 去控制字符 + 截断（§9.2）。

    快照是**外网内容**，`summary` 会进 GUI tooltip：不 strip 就是一条注入面。
    """
    s = _TAG_RE.sub("", str(raw or ""))
    s = "".join(ch if ch.isprintable() else " " for ch in s)
    s = " ".join(s.split())
    return s[:SUMMARY_MAX_CHARS]


def _as_float(raw: Any, lo: float, hi: float) -> Optional[float]:
    """把 ``raw`` 收成 [lo, hi] 内的 float；不行就 ``None``。"""
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    if val != val or val < lo or val > hi:     # NaN / 越界
        return None
    return val


# ── 条目解析（单条坏只跳过错的那条，§3.3） ─────────────────────────────

def _parse_entry(raw: Any) -> Optional[CveEntry]:
    """把 JSON 里的一条 dict 转成 `CveEntry`；不可用则 ``None``。"""
    if not isinstance(raw, dict):
        return None
    cve_id = str(raw.get("cve_id") or "").strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        return None
    raw_cpe = raw.get("cpe")
    if isinstance(raw_cpe, str):
        raw_cpe = [raw_cpe]
    if not isinstance(raw_cpe, (list, tuple)):
        raw_cpe = []
    cpes: List[str] = []
    for item in raw_cpe:
        coarse = coarsen_cpe(item)
        if coarse and coarse not in cpes:
            cpes.append(coarse)
    kev_raw = raw.get("kev")
    kev: Optional[bool]
    if isinstance(kev_raw, bool):
        kev = kev_raw
    elif kev_raw in (0, 1, "0", "1", "true", "false", "True", "False"):
        kev = str(kev_raw).lower() == "true" or kev_raw == 1
    else:
        kev = None                        # 缺失 / 无法解释 → 「无该信号」
    epss = _as_float(raw.get("epss"), _EPSS_MIN, _EPSS_MAX)
    epss_pct = _as_float(raw.get("epss_percentile"), _EPSS_MIN, _EPSS_MAX)
    if not cpes:
        # 一条 CPE 都收敛不出来的记录**匹配不上任何东西**，留着只是噪声
        # （生成端同样会跳过它，见 `tools/build_cve_snapshot.py`）。
        return None
    return CveEntry(
        cve_id=cve_id,
        cpe=tuple(cpes),
        kev=kev,
        epss=epss,
        epss_percentile=epss_pct,
        summary=sanitize_summary(raw.get("summary")),
    )


def parse_entries(raw: Any) -> Tuple[List[CveEntry], int]:
    """解析 ``cves`` 数组 → (entries, 跳过的条数)。

    🔴 单条字段缺失 / 类型错（`cve_id` 不像 CVE、`cpe` 是数字、`epss` 是
    "高"）→ **跳过该条并计数**，其余照常生效。整段坏（不是数组）→ 空列表。
    """
    if not isinstance(raw, (list, tuple)):
        return [], 0
    out: List[CveEntry] = []
    seen = set()
    skipped = 0
    for item in raw:
        entry = _parse_entry(item)
        if entry is None:
            skipped += 1
            continue
        if entry.cve_id in seen:            # 重复 cve_id 保留首条（稳定）
            skipped += 1
            continue
        seen.add(entry.cve_id)
        out.append(entry)
    return out, skipped


# ── 搜索路径 / 验签 ───────────────────────────────────────────────────

def data_path() -> str:
    """快照 JSON 的**实际使用**路径（用户版优先，种子兜底）。

    与 `service_fingerprints.data_path()` 同口径：**存在的第一个**。
    两个都不存在时返回空串（调用方据此报 `STATE_MISSING`）。
    """
    user_path = os.path.join(data_dir(), DATA_FILENAME)
    if os.path.isfile(user_path):
        return user_path
    seed_path = os.path.join(resource_dir(), DATA_FILENAME)
    if os.path.isfile(seed_path):
        return seed_path
    return ""


def sums_path_for(json_path: str) -> str:
    """与 `json_path` 同目录的摘要清单路径（清单放在数据旁边，不由代码生成）。"""
    return os.path.join(os.path.dirname(os.path.abspath(json_path)),
                        SUMS_FILENAME)


def online_mark_path_for(json_path: str) -> str:
    """与 `json_path` 同目录的「在线下载来源标记」路径（v2.2 §3.1）。"""
    return os.path.join(os.path.dirname(os.path.abspath(json_path)),
                        ONLINE_MARK_FILENAME)


def _read_source_mark(json_path: str) -> bool:
    """快照旁边有没有「在线下载」标记文件。

    **只读存在性、不读内容**：标记文件是本地状态，内容无关紧要。
    读不到的（权限/竞态）按"没有标记"处理 —— 来源显示退化成 `data-dir`，
    不会因为一个标记文件的读取失败而影响加载本身。
    """
    try:
        return os.path.isfile(online_mark_path_for(json_path))
    except OSError:                       # 极罕见：路径非法 / 权限
        return False


def find_sums_path(json_path: str) -> str:
    """摘要清单的实际位置：先认 `cve_snapshot.sha256`，再认发布口径的 `SHA256SUMS`。

    用户从 release 里下载时拿到的往往是后者（发布流程的既有命名），
    两个名字内容同构，都该认。
    """
    primary = sums_path_for(json_path)
    if os.path.isfile(primary):
        return primary
    alt = os.path.join(os.path.dirname(primary), "SHA256SUMS")
    if os.path.isfile(alt):
        return alt
    return ""


def sha256_of(path: str, chunk: int = 1 << 16) -> Optional[str]:
    """算文件 SHA256；读不了返回 ``None``（调用方按「无法校验」处理）。"""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                digest.update(block)
    except OSError as e:
        _log.debug("计算 %s 摘要失败: %s", path, e)
        return None
    return digest.hexdigest()


def read_sums(path: str) -> Dict[str, str]:
    """读 ``<hex>␠␠<文件名>`` 清单 → ``{文件名: hex}``。

    容忍：空行、``#`` 注释行、单空格分隔、绝对/相对路径混写、行尾 ``*``
    （`sha256sum -b` 的二进制标记）。格式错的行**跳过**并 debug 留痕 ——
    清单本身是给人看的，不该因为它脏就拒绝校验。
    """
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                hexdigest = parts[0].lower()
                name = parts[-1].lstrip("*")
                if len(hexdigest) != 64 or any(c not in "0123456789abcdef"
                                               for c in hexdigest):
                    continue
                out[os.path.basename(name)] = hexdigest
    except OSError as e:
        _log.debug("读摘要清单 %s 失败: %s", path, e)
    return out


def verify_checksum(json_path: str) -> Optional[bool]:
    """校验快照完整性，返回三态：``True`` 通过 / ``False`` 不匹配 / ``None`` 未校验。

    * 清单文件不存在 → ``None``（**不阻断**，§3.4：有则校验、无则告警）；
    * 清单里没有本文件名 → 若清单**只有一条**，按单条目比对（常见于用户
      手工裁剪过的清单）；否则 ``None``；
    * 真的读不了快照本身 → ``None``（调用方随后会按损坏处理）。
    """
    sums_path = find_sums_path(json_path)
    if not sums_path:
        return None
    sums = read_sums(sums_path)
    if not sums:
        return None
    name = os.path.basename(json_path)
    expected = sums.get(name)
    if expected is None:
        if len(sums) == 1:
            expected = next(iter(sums.values()))
        else:
            _log.warning("摘要清单 %s 里没有 %s，本次不做完整性校验",
                         sums_path, name)
            return None
    actual = sha256_of(json_path)
    if actual is None:
        return None
    if actual != expected:
        _log.warning("快照 %s 的 SHA256 与清单不一致（可能下载损坏/被改动），"
                     "已拒绝加载", json_path)
        return False
    return True


# ── 主入口 ────────────────────────────────────────────────────────────

def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_snapshot(path: Optional[str] = None, *,
                  now: Optional[datetime] = None) -> CveSnapshot:
    """加载快照。**任何情况都不抛**（§3.3），失败一律降级 + 留痕。

    Args:
        path: 显式指定快照文件（测试 / CLI 调试用）。``None`` → 走 `data_path()`。
        now: 「当前时间」注入点（测试用假时钟；默认 `datetime.now(utc)`）。

    Returns:
        `CveSnapshot`。**没有可查数据**时 `state` 是 `missing` / `corrupt` /
        `empty` 之一 —— 调用方必须把这三种与「查了、没有匹配」区分开。
    """
    target = path if path else data_path()
    if not target:
        _log.warning("未找到 CVE 快照（%s / %s 均不存在），本次不产出暴露面",
                     os.path.join(data_dir(), DATA_FILENAME),
                     os.path.join(resource_dir(), DATA_FILENAME))
        return CveSnapshot(state=STATE_MISSING, source=SOURCE_NONE)
    if not os.path.isfile(target):
        # 显式给了路径却不存在的文件也是「没有数据」，不是「数据坏了」——
        # 两者的处置动作完全不同（前者去下载，后者去重下）。
        _log.warning("CVE 快照文件不存在：%s", target)
        return CveSnapshot(state=STATE_MISSING, source=SOURCE_NONE,
                           path=target)

    snap = CveSnapshot(path=target)
    # 来源判定：**只有**解析到 resource_dir() 里那份、且 data_dir() 里没有
    # 同名文件时才算「内置种子」。开发模式下两个目录相同（都在源码根），
    # 同一条路径同时是用户可覆盖的那份 —— 那就如实报 data-dir，
    # 不假装它是只读种子（否则 dev 模式永远显示"种子"，与事实不符）。
    _seed_real = os.path.realpath(os.path.join(resource_dir(), DATA_FILENAME))
    _user_real = os.path.realpath(os.path.join(data_dir(), DATA_FILENAME))
    # v2.2 §3.1：优先认「在线下载」标记（同目录一份 cve_snapshot.online）。
    # 标记只可能由 `cve_updater.py` 在**校验通过后**的原子落盘里一并写出，
    # 所以「有标记」= 这份是我们自己下回来的，比"在哪个目录"更精确。
    if _read_source_mark(target):
        snap.source = SOURCE_ONLINE
    else:
        snap.source = (SOURCE_SEED
                       if (os.path.realpath(target) == _seed_real
                           and _seed_real != _user_real)
                       else SOURCE_DATA)

    verified = verify_checksum(target)
    snap.checksum_verified = verified
    if verified is False:
        snap.state = STATE_CORRUPT
        return snap
    if verified is None and find_sums_path(target):
        _log.warning("快照 %s 没有可用的摘要清单，按原样加载（未校验）", target)

    try:
        doc = json.loads(_read_text(target))
    except (OSError, ValueError) as e:
        _log.warning("CVE 快照 %s 读取/解析失败，本次不产出暴露面: %s", target, e)
        snap.state = STATE_CORRUPT
        return snap

    if not isinstance(doc, dict):
        _log.warning("CVE 快照 %s 顶层不是对象，已拒绝", target)
        snap.state = STATE_CORRUPT
        return snap

    schema = str(doc.get("schema") or "")
    snap.schema = schema
    if schema != SCHEMA:
        # 未知 schema：不拒绝，按 v1 尽力解析（§4：向前兼容）+ 留痕。
        _log.warning("CVE 快照 schema 为 %r（期望 %r），按 v1 尽力解析",
                     schema or "(缺失)", SCHEMA)

    snap.generated_at = parse_timestamp(doc.get("generated_at"))
    max_age_raw = doc.get("max_age_days")
    if isinstance(max_age_raw, bool) or not isinstance(max_age_raw, (int, float)):
        snap.max_age_days = DEFAULT_MAX_AGE_DAYS
    else:
        snap.max_age_days = max(1, int(max_age_raw))
    srcs = doc.get("sources")
    if isinstance(srcs, dict):
        snap.sources = {str(k): str(v) for k, v in srcs.items()}

    snap.entries, snap.skipped = parse_entries(doc.get("cves"))
    if snap.skipped:
        _log.warning("CVE 快照有 %d 条记录不可用，已跳过", snap.skipped)

    # ── 新鲜度判定（§3.1）──────────────────────────────────────────
    ref = now or datetime.now(timezone.utc)
    if snap.generated_at is None:
        snap.state = STATE_UNKNOWN_AGE
        snap.age_days = None
        _log.warning("CVE 快照没有 generated_at，新鲜度未知（按过期同级告警）")
    else:
        age = ref - snap.generated_at
        snap.age_days = max(0, age.days)
        if age > timedelta(days=snap.max_age_days):
            snap.state = STATE_STALE
            _log.warning("CVE 快照已过期：%d 天 > 上限 %d 天（生成于 %s）",
                         snap.age_days, snap.max_age_days,
                         snap.generated_at.date().isoformat())
        else:
            snap.state = STATE_OK
    if not snap.entries and snap.state in (STATE_OK, STATE_STALE,
                                           STATE_UNKNOWN_AGE):
        snap.state = STATE_EMPTY
        _log.warning("CVE 快照解析成功但没有任何条目")
    return snap


# ── 查询（KEV 优先、组内 EPSS 降序） ─────────────────────────────────

def sort_candidates(entries) -> List[CveEntry]:
    """按 `CveEntry.sort_key` 排序：**KEV 命中优先 → 组内 EPSS 降序**。

    同分兜底按 `cve_id` 字典序，保证**可复现**（同样的输入永远同一输出）。
    """
    return sorted(entries, key=lambda e: e.sort_key)


def find_candidates(snapshot: CveSnapshot, cpe: str) -> List[CveEntry]:
    """找出**匹配到这个粗粒度 CPE** 的候选 CVE，已排序。

    `snapshot.usable == False`（无数据 / 损坏）→ 空列表 + debug；
    此时调用方**必须**用 `snapshot.state` 报「无数据可查」，而不是
    「查了、没有匹配」—— 这两件事在 UI 上不是一回事（§1 原则 3）。
    """
    if snapshot is None or not snapshot.usable:
        return []
    want = coarsen_cpe(cpe)
    if not want:
        return []
    hits = [e for e in snapshot.entries if want in e.cpe]
    return sort_candidates(hits)


def stats_for(snapshot: CveSnapshot) -> Dict[str, Any]:
    """`CveSnapshot.stats()` 的函数式别名（供 CLI / 报告统一取数）。"""
    return snapshot.stats()
