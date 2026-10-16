"""资产生命周期字段的**纯计算**部分（零 DB、零 PyQt、零 i18n、零第三方）。

为什么单独开一个模块
--------------------
`history_store.py` 负责「生命周期字段怎么存、怎么读」，本模块负责
「怎么判定、怎么归一」。拆法与 `trend_store.py` 一致：

- **可测**：输入是字符串 / 字典，输出是字典 —— 不建库、不需要 Qt、
  不需要 `ensure_qt_app()`，测试是纯函数级的（毫秒级）。
- **可复用**：CLI（`assets --warranty-days`）与 GUI（详情面板）拿**同一份**
  判定代码 —— 「已过期」在两处必须同时成立或同时不成立，否则用户会
  在两个界面看到互相矛盾的结论。

🔴 本模块**不 import `i18n`**、**不 import PyQt5**、**不碰 SQLite**。
   产出的状态一律是**语言无关的英文规范值**（`unset`/`expired`/`expiring`/`ok`），
   显示文字由调用方翻译。

🔴 `custom_json` 的**键名绝不翻译**（`docs/ROADMAP_V2.3.md` §3.4 验收 2）：
   用户写的键是拿来**比较**的（"哪些机器有 `rack` 字段"），一旦存进去的是
   `tr()` 的结果，切一次界面语言键就变了 —— 与 v2.2 §3.3「审计事件名不能是
   中文」是同一条教训（判据：拿比较还是显示）。
"""

import datetime
import json
import re

# ── 生命周期字段（`assets` 表的 v7 新列）───────────────────────────────
#
# 🔴 这 6 列**不进** `history_store._ASSET_COLS`：那一组是「随观测刷新的展示
#    属性」，扫描 UPSERT 用「最近一次非空才覆盖」的规则去刷它们。生命周期字段
#    是**人工填写的台账**，扫描（它根本不知道采购日期）绝不能覆盖 ——
#    一次扫描把 `owner` 抹成空串，那是**静默丢数据**。
LIFECYCLE_COLUMNS = (
    "purchase_date",
    "warranty_end",
    "owner",
    "serial",
    "location_tree",
    "custom_json",
)

# ── 保修状态（🔴 语言无关的规范值，绝不 tr()）─────────────────────────
#
# `unset` 必须与 `expired` **分开**：未填保修日期 ≠ 已过期
# （`docs/ROADMAP_V2.3.md` §3.4 验收 4）。把"没填"混进"已过期"会让
# `--warranty-days` 满屏假告警 —— 用户从此不信这个功能。
WARRANTY_UNSET = "unset"
WARRANTY_EXPIRED = "expired"
WARRANTY_EXPIRING = "expiring"
WARRANTY_OK = "ok"

#: 全部保修状态（顺序即文档顺序：从"最该处理"到"最没事"）。
WARRANTY_STATUSES = (
    WARRANTY_UNSET,
    WARRANTY_EXPIRED,
    WARRANTY_EXPIRING,
    WARRANTY_OK,
)

#: 默认提前多少天提醒。30 天 —— 够走一次采购/续保流程，又不至于天天响。
DEFAULT_WARRANTY_WARN_DAYS = 30

# ── 日期解析 ─────────────────────────────────────────────────────────
#
# 接受几种写法（中文用户实际会怎么填就收哪种）：
#   `2026-05-01` / `2026/5/1` / `2026.05.01` / `20260501` / `2026年5月1日`
# ⚠ 但**不**接受「2026-5」这种缺字段的写法：缺字段只能靠猜（补 1 号还是月末？），
#   猜错就是错日期 —— 台账里的错日期比空着危险得多。
_DATE_RE = re.compile(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$")
_DATE_COMPACT_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})$")
_DATE_CN_RE = re.compile(r"^(\d{4})年(\d{1,2})月(\d{1,2})日?$")


def parse_date(value):
    """把用户填的日期串解析成 `datetime.date`；**无法解析时返回 None**。

    接受 `2026-05-01` / `2026/5/1` / `2026.05.01` / `20260501` / `2026年5月1日`，
    也直接接受 `date` / `datetime` 实例（内部调用与测试方便）。

    ⚠ 与 `parse_date_strict()` 的分工：

    * **读**库里的值用本函数 —— 脏值不能让整个资产列表打不开，返回 `None` 即可；
    * **写**用户输入用 `parse_date_strict()` —— 非法输入必须当场报错，
      不能静默存成空串（那等于悄悄丢了用户刚填的东西）。
    """
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    m = (_DATE_RE.match(s) or _DATE_COMPACT_RE.match(s)
         or _DATE_CN_RE.match(s))
    if m is None:
        return None
    year, month, day = (int(g) for g in m.groups())
    try:
        return datetime.date(year, month, day)
    except ValueError:
        # `datetime.date()` 自己会挡住 2026-13-45 / 2026-02-30 这类"格式对、
        # 日期错"的输入 —— 不自己写闰年与月份天数表，那种表只会写错。
        return None


def parse_date_strict(value, field="日期"):
    """同 `parse_date()`，但**非法输入直接抛 `ValueError`**（给写入路径用）。

    `None` 与空串视为「清空这个字段」→ 返回 `None`，不报错。
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    parsed = parse_date(value)
    if parsed is None:
        raise ValueError("%s格式无效：%r（应为 YYYY-MM-DD）" % (field, value))
    return parsed


def _as_local_date(now=None):
    """把 `now` 归一成**本地时区**的 `date`；`None` → 今天（本地）。

    🔴 保修到期**按本地时区**推导（`docs/ROADMAP_V2.3.md` §3.4 验收 3）：
       用户说"5 月 1 日到期"，指的是**他所在时区**的 5 月 1 日。所以数字
       时间戳一律用 `datetime.fromtimestamp()`（**本地时区**）解释，绝不用
       `utcfromtimestamp()` —— 后者在东八区会把到期日整体挪早 8 小时，
       边界那天（今天到期）会提前一天报"已过期"。
       ⚠ 测试断言必须跟着**同时区**推导，否则在 UTC 的 CI 上会差一天。
    """
    if now is None:
        return datetime.date.today()
    if isinstance(now, datetime.datetime):
        if now.tzinfo is not None:
            now = now.astimezone()  # aware → 本地时区
        return now.date()
    if isinstance(now, datetime.date):
        return now
    return datetime.datetime.fromtimestamp(float(now)).date()


def warranty_state(warranty_end, now=None,
                   warn_days=DEFAULT_WARRANTY_WARN_DAYS):
    """保修状态 → dict。**语言无关的规范值**，调用方负责翻译。

    返回 ``{"status", "end", "days_left", "warn_days"}``：

    * ``status``：`unset` / `expired` / `expiring` / `ok`（见模块顶部常量）；
    * ``end``：归一后的 `YYYY-MM-DD`；未填或无法解析时 `None`；
    * ``days_left``：距到期还有几天（**负数 = 已过期**，`0` = 今天到期）；
      未填时 `None`；
    * ``warn_days``：本次判定用的提前量（已夹到 ≥ 0）。

    🔴 未填日期返回 `unset` **而不是** `expired`（§3.4 验收 4）。
    🔴 「今天到期」算 `expiring` 不算 `expired`：今天还没过完。
    """
    try:
        warn = int(warn_days)
    except (TypeError, ValueError):
        warn = DEFAULT_WARRANTY_WARN_DAYS
    warn = max(0, warn)
    end = parse_date(warranty_end)
    if end is None:
        return {"status": WARRANTY_UNSET, "end": None,
                "days_left": None, "warn_days": warn}
    days = (end - _as_local_date(now)).days
    if days < 0:
        status = WARRANTY_EXPIRED
    elif days <= warn:
        status = WARRANTY_EXPIRING
    else:
        status = WARRANTY_OK
    return {"status": status, "end": end.isoformat(),
            "days_left": days, "warn_days": warn}


def is_warranty_alerting(state) -> bool:
    """该状态是否属于「需要提醒」（已过期 / N 天内到期）。

    `unset` **不算**提醒项 —— 它是"没填"，不是"到期"。
    """
    if not isinstance(state, dict):
        return False
    return state.get("status") in (WARRANTY_EXPIRED, WARRANTY_EXPIRING)


def filter_by_warranty(rows, days=DEFAULT_WARRANTY_WARN_DAYS, now=None):
    """挑出「已过期 或 `days` 天内到期」的资产行。

    返回 ``(matched, skipped_unset)``：

    * ``matched``：**新字典**列表（不改原行），每行多三个键
      `warranty_status` / `warranty_days_left` / `warranty_end`；
      排序为「**最该处理的排最前**」（过期最久的在前，其次最快到期的）；
    * ``skipped_unset``：**未填保修日期**而被跳过的台数。

    ⚠️ `skipped_unset` 必须报给用户（"另有 N 台没填保修日期，没算进来"）：
       不报的话，用户看到 12 台的结果会以为**其余全部保修正常** ——
       而其中可能有一半根本没填。

    ⚠️ 未填日期的行**不进** `matched`：把它当"已过期"报出来是假告警。
    """
    matched = []
    skipped = 0
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        state = warranty_state(row.get("warranty_end"), now=now, warn_days=days)
        if state["status"] == WARRANTY_UNSET:
            skipped += 1
            continue
        if not is_warranty_alerting(state):
            continue
        item = dict(row)
        item["warranty_status"] = state["status"]
        item["warranty_days_left"] = state["days_left"]
        item["warranty_end"] = state["end"]
        matched.append(item)
    # 天数升序 = 最该处理的排最前；再按身份键兜底，保证顺序**完全确定**
    # （翻页 / 快照对比可复现，不依赖 dict 的隐式顺序）。
    matched.sort(key=lambda r: (r["warranty_days_left"], r.get("identity_key", "")))
    return matched, skipped


# ── 自定义字段（custom_json）──────────────────────────────────────────

def normalize_custom_json(value):
    """自定义字段 → **稳定序列化**的 JSON 文本（键名**原样**保留）。

    接受 `dict` / JSON 文本 / `None`：

    * `None` 或空串 → `""`（= 清空该字段）；
    * 非法 JSON，或解析出来不是**对象**（数组 / 数字 / 字符串）→ 抛 `ValueError`。

    🔴 键名与键值**一个字符都不改**（不翻译、不转大小写、不 trim 键名）——
       用户写的键是拿来比较的（§3.4 验收 2）。

    `sort_keys=True` 只影响**存储顺序**，不影响任何键的存在与拼写；换来的是
    「同样的字段集序列化结果逐字节相同」—— 否则 `{"a":1,"b":2}` 与
    `{"b":2,"a":1}` 会存成两行不同的文本，快照比对时全是假变更。
    """
    if value is None:
        return ""
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return ""
        try:
            value = json.loads(s)
        except (TypeError, ValueError) as exc:
            raise ValueError("自定义字段不是合法 JSON：%r" % s) from exc
    if not isinstance(value, dict):
        raise ValueError("自定义字段必须是 JSON 对象（键值对），而不是 %s"
                         % type(value).__name__)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("自定义字段无法序列化：%s" % exc) from exc


def parse_custom_json(text):
    """读回自定义字段 → `dict`。**任何异常都返回空字典**（不抛）。

    读取路径必须容忍脏值：库里可能有人手工改过，或旧版本写坏过 ——
    一个坏 JSON 不该让整个资产列表打不开。
    """
    if not text:
        return {}
    if isinstance(text, dict):
        return text
    try:
        obj = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}
