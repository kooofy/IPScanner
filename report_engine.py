# -*- coding: utf-8 -*-
"""报表引擎：把资产数据渲染成**版式可编辑**的 HTML 报告（v2.0 §2.2）。

为什么要有这个模块
------------------
v1.9 的 1.2（互操作导出）让资产表**给机器**用；报表让资产表**给人**用。
在此之前唯一的"给人看"出口是 `excel_handler.export_html()` —— 它的版式
**硬编码在内联 f-string 里**（表头、行着色、`<td>` 拼接全是字面量），
改一个颜色/列序都要动代码、发一次版。本模块把版式**抽成数据文件**。

设计铁律（见 `docs/ROADMAP_V2.0.md` §3 2.2）
--------------------------------------------
- **模板是数据，不是代码**：`assets/report_templates/*.html` 里只有**受限占位符**
  （`{{rows}}` / `{{summary}}` / `{{generated_at}}`），**不执行代码**、
  **不引入 Jinja2**（第三方依赖，违反本项目「零新依赖」身份）。
- **语言无关（i18n 铁律）**：报表里的**值**一律是规范值
  （`status` → `online`/`offline`、`device_class` → 中文源串、时间 → ISO），
  **绝不落 `tr()` 之后的展示串**。模板文案由模板文件本身承载，不进语言包 ——
  与 `interop_export.py` 同口径。
- **加载策略与 `oui.db` / `service_fingerprints.json` 一致**：
  优先 `data_dir()`（用户可改）→ 回退 `resource_dir()`（内置）。
- **稳健性**：模板缺失/损坏/占位符写错都**不能**让"报表坏了"升级成
  "程序崩了"。缺失内置模板时回退到模块内的最小兜底模板。

模板语法（刻意极简，够用即可）
------------------------------
- `{{key}}` —— 替换为装配好的值；
- `{{rows}}` —— 替换为该模板的**主表行**（已渲染好的 `<tr>` 片段）；
- 其余文本原样保留。
- 值输出时做 **HTML 转义**（`& < > " '`）—— 设备主机名/厂商里带 `<` 是真实存在的，
  不转义会让报表被注入坏标签（甚至脚本）。**转义发生在渲染层，模板作者不用操心。**
"""
from __future__ import annotations

import datetime
import html
import os

from app_logging import get_logger
from app_paths import data_dir, resource_dir

_log = get_logger(__name__)

__all__ = [
    "REPORT_TEMPLATES",
    "template_path",
    "load_template",
    "available_templates",
    "build_report",
    "render_report",
    "REPORT_KINDS",
]

#: 内置模板名（也是 `assets/report_templates/<名>.html` 的文件名主体）。
#: ``assets``  资产清单（一行一台设备）
#: ``changes`` 变更摘要（两份快照之间发生了什么）
#: ``exposure`` 暴露面摘要（按开放端口聚合，看"谁开了什么"）
REPORT_TEMPLATES = ("assets", "changes", "exposure")

#: 三种报表的"种类"（= 需要装配哪份数据）。当前与模板名一一对应，
#: 但单独列出来是为了让"模板文件叫什么"与"要装配什么数据"解耦 ——
#: 用户可以把 `exposure` 模板复制成 `my_exposure.html` 而无需改代码。
REPORT_KINDS = REPORT_TEMPLATES

#: 模板目录（相对资源根）。
_TEMPLATE_SUBDIR = ("assets", "report_templates")

#: 数据文件缺失时的最小兜底模板（只求"能出张表"，不求好看）。
#: 刻意用规范值直出 —— 兜底模板也不撒谎。
_FALLBACK_TEMPLATES = {
    "assets": (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>Assets</title></head><body>"
        "<h1>Assets</h1><p>{{summary}}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th>"
        "<th>Vendor</th><th>Device class</th><th>Location</th><th>User</th>"
        "</tr></thead><tbody>{{rows}}</tbody></table>"
        "<p>Generated at {{generated_at}}</p></body></html>"
    ),
    "changes": (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>Changes</title></head><body>"
        "<h1>Changes</h1><p>{{summary}}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<thead><tr><th>Severity</th><th>Type</th><th>IP</th><th>MAC</th>"
        "<th>Hostname</th><th>Old</th><th>New</th><th>Description</th>"
        "</tr></thead><tbody>{{rows}}</tbody></table>"
        "<p>Generated at {{generated_at}}</p></body></html>"
    ),
    "exposure": (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<title>Exposure</title></head><body>"
        "<h1>Exposure</h1><p>{{summary}}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<thead><tr><th>Port</th><th>Service</th><th>Device count</th>"
        "<th>Devices</th></tr></thead><tbody>{{rows}}</tbody></table>"
        "<p>Generated at {{generated_at}}</p></body></html>"
    ),
}


# ────────────────────────── 模板加载 ──────────────────────────

def _load_text(path: str) -> str:
    """读一个文本文件；失败返回空串（调用方决定回退）。"""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except OSError as e:
        _log.warning("报表模板读取失败（%s）：%s", path, e)
        return ""


def template_path(name: str) -> str:
    """返回实际使用的模板路径（用户可改版优先，回退内置）。

    与 `service_fingerprints.data_path()` 同一套策略：`data_dir()` 优先，
    这样用户把模板复制到数据目录改一份就能生效，不必碰安装目录。
    """
    filename = "%s.html" % name
    user_path = os.path.join(data_dir(), *_TEMPLATE_SUBDIR, filename)
    if os.path.exists(user_path):
        return user_path
    return os.path.join(resource_dir(), *_TEMPLATE_SUBDIR, filename)


def load_template(name: str) -> str:
    """读取模板文本；文件缺失/损坏时回退到内置兜底模板。

    找不到**任何**来源（连兜底名都没有）时返回空串 —— 调用方（`build_report`）
    会把它当成不支持的模板报错，而不是静默产出空文档。
    """
    if name not in REPORT_TEMPLATES:
        return ""
    text = _load_text(template_path(name))
    if text.strip():
        return text
    _log.warning("报表模板 %s 不可用，改用内置兜底模板", name)
    return _FALLBACK_TEMPLATES.get(name, "")


def available_templates() -> list:
    """列出可用模板名（内置三项；用户新增的同名文件不会改变这份清单）。

    刻意**不**扫描目录：清单固定 = 可预测 = 测试稳定。用户自建模板走
    `--template-file` 直接给路径，不进这份清单。
    """
    return list(REPORT_TEMPLATES)


# ────────────────────────── 数据装配 ──────────────────────────

#: 资产清单表头（规范值语义的英文键 → 中文表头由模板文件决定，这里只出值）。
#: 刻意用**语言无关**的列键：报表值不落 `tr()`。
_ASSET_ROW_COLUMNS = (
    "ip", "status", "hostname", "mac", "vendor", "device_class",
    "location", "user",
)


def _esc(value) -> str:
    """HTML 转义一个值。None → 空串。"""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _norm_status(value) -> str:
    """把状态规范成 online/offline。

    ``status`` 的**规范值就是英文** `online` / `offline`（见 `scanner/engine.py`；
    中文的「在线/离线」只是 `tr()` 出来的展示串，**从不入库**）。
    所以这里只认英文及其常见等价写法。

    ⚠ **认不出时原样返回**，不返回空串：把认不出的值悄悄抹成空单元格，
    会让报表"看起来正常但少了一个状态"，比让那个值显眼地留在表里更难查。
    报表的职责是**如实呈现**，不是替上游擦屁股。
    """
    s = ("" if value is None else str(value)).strip().lower()
    if s in ("online", "up", "1", "true"):
        return "online"
    if s in ("offline", "down", "0", "false"):
        return "offline"
    return "" if not s else str(value).strip()


def _norm_row(row: dict) -> dict:
    """把一行资产规范成报表要用的字段（值语言无关）。"""
    out = {k: _esc(row.get(k, "")) for k in _ASSET_ROW_COLUMNS}
    out["status"] = _norm_status(row.get("status"))
    return out


def _td(value, style: str = "") -> str:
    if style:
        return '<td style="%s">%s</td>' % (style, value)
    return "<td>%s</td>" % value


def _render_asset_rows(rows) -> str:
    """把资产行渲染成 `<tr>` 片段。在线/离线行着色（沿用旧 export_html 的语义色，
    但这里写**字面量**：报表是独立产物，不该依赖 GUI 主题令牌）。"""
    out = []
    for row in rows:
        d = _norm_row(row)
        online = d["status"] == "online"
        bg = "#e6f9ed" if online else "#fdecec"
        color = "#16713a" if online else "#b3261e"
        tds = [
            _td(d["ip"]),
            _td(d["status"], "color:%s;font-weight:600;text-align:center" % color),
            _td(d["hostname"]),
            _td(d["mac"]),
            _td(d["vendor"]),
            _td(d["device_class"]),
            _td(d["location"]),
            _td(d["user"]),
        ]
        out.append('<tr style="background:%s">%s</tr>' % (bg, "".join(tds)))
    return "".join(out)


def _asset_summary(rows) -> str:
    total = len(rows)
    online = sum(1 for r in rows if _norm_status(r.get("status")) == "online")
    return "%d assets, %d online, %d offline" % (total, online, total - online)


# ── 变更摘要 ──

_CHANGE_ROW_COLUMNS = ("severity", "change_type", "ip", "mac", "hostname",
                       "old_value", "new_value")


def _change_to_dict(c) -> dict:
    """把 `change_detector.Change` 或 dict 规范成报表行（值语言无关）。"""
    if isinstance(c, dict):
        get = c.get
    else:
        get = lambda k, default="": getattr(c, k, default)  # noqa: E731
    return {
        "severity": _esc(get("severity", "")),
        "change_type": _esc(get("change_type", "")),
        "ip": _esc(get("ip", "")),
        "mac": _esc(get("mac", "")),
        "hostname": _esc(get("hostname", "")),
        "old_value": _esc(get("old_value", "")),
        "new_value": _esc(get("new_value", "")),
    }


def _render_change_rows(changes) -> str:
    out = []
    for c in changes:
        d = _change_to_dict(c)
        sev = d["severity"]
        color = {"high": "#b3261e", "warning": "#b26a00", "info": "#16713a"}.get(
            sev, "#333333")
        tds = [
            _td(d["severity"], "color:%s;font-weight:600" % color),
            _td(d["change_type"]),
            _td(d["ip"]), _td(d["mac"]), _td(d["hostname"]),
            _td(d["old_value"]), _td(d["new_value"]),
        ]
        out.append("<tr>%s</tr>" % "".join(tds))
    return "".join(out)


def _changes_summary(changes) -> str:
    from collections import Counter
    counts = Counter((_change_to_dict(c)["severity"] or "unknown") for c in changes)
    total = len(changes)
    if not total:
        return "0 changes"
    parts = ["%d changes" % total]
    for sev in ("high", "warning", "info"):
        if counts.get(sev):
            parts.append("%d %s" % (counts[sev], sev))
    return ", ".join(parts)


# ── 暴露面摘要 ──

def _exposure_rows(rows) -> list:
    """按「开放端口 + 服务」聚合：哪些端口被多少台设备开着。

    端口从 `open_ports` 取（分号/逗号分隔的字符串，或 list）。
    服务名从 `services` 取**规范值**（ASCII 服务码，如 `http`/`smb`）。

    返回 ``[(port:int, service:str, devices:[(ip, hostname)])]``，按端口升序。
    """
    bucket = {}  # (port, service) -> [(ip, hostname)]
    for r in rows:
        ports = _split_ports(r.get("open_ports"))
        svc_by_port = _services_by_port(r.get("services"))
        for p in ports:
            key = (p, svc_by_port.get(p, ""))
            bucket.setdefault(key, []).append(
                (str(r.get("ip", "")), str(r.get("hostname", ""))))
    return [(p, s, v) for (p, s), v in sorted(bucket.items())]


def _split_ports(value) -> list:
    """把 `open_ports` 解析成端口整数列表（容忍 str / list / 空）。"""
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        text = str(value).replace(";", ",")
        items = [x for x in text.split(",")]
    out = []
    for x in items:
        x = str(x).strip()
        if not x:
            continue
        # 容忍 "80/tcp" 这种写法
        head = x.split("/", 1)[0].strip()
        if head.isdigit():
            out.append(int(head))
    return out


def _services_by_port(value) -> dict:
    """把 `services` 解析成 ``{port: service}``。

    `services` 的历史形态可能是： ``"80=http;443=https"`` / ``"80,443"`` /
    JSON 字符串 / list。**只在能明确对上端口时才填服务名**，否则空
    （诚实：编一个服务名比留空更糟）。
    """
    out = {}
    if not value:
        return out
    raw = value
    if isinstance(raw, str):
        text = raw.strip()
        # 先试 JSON（interop 侧就是这么存的）
        if text[:1] in ("[", "{"):
            import json
            try:
                raw = json.loads(text)
            except (ValueError, TypeError):
                return out
        else:
            raw = [chunk for chunk in text.replace(";", ",").split(",")]
    if isinstance(raw, dict):
        for k, v in raw.items():
            if str(k).isdigit():
                out[int(k)] = str(v)
        return out
    if isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, dict):
                # `item` 是外部数据（可能是 JSON 反序列化来的），键/值都可能是
                # 任意类型 → 一律先 `str()` 再判，绝不假设它就是 int。
                port = str(item.get("port") or "")
                if port.isdigit():
                    out[int(port)] = str(item.get("service") or item.get("name") or "")
                continue
            s = str(item)
            if "=" in s:
                p, _, name = s.partition("=")
                if p.strip().isdigit():
                    out[int(p.strip())] = name.strip()
            elif s.split("/", 1)[0].strip().isdigit():
                out[int(s.split("/", 1)[0].strip())] = ""
    return out


def _render_exposure_rows(rows) -> str:
    out = []
    for port, service, devices in _exposure_rows(rows):
        names = ", ".join(
            _esc(h or ip) for ip, h in devices[:20])
        if len(devices) > 20:
            names += ", … (+%d)" % (len(devices) - 20)
        tds = [
            _td(str(port)), _td(_esc(service)), _td(str(len(devices))),
            _td(names),
        ]
        out.append("<tr>%s</tr>" % "".join(tds))
    return "".join(out)


def _exposure_summary(rows) -> str:
    pairs = _exposure_rows(rows)
    devices = len({ip for _p, _s, ds in pairs for ip, _h in ds if ip})
    return "%d open port/service pairs across %d devices" % (len(pairs), devices)


# ────────────────────────── 渲染 ──────────────────────────

def build_report(kind, rows, summary, generated_at, template_text) -> str:
    """把数据与模板合成最终 HTML（**纯函数**，便于 golden 断言）。

    Args:
        kind:          模板种类（`assets`/`changes`/`exposure`），决定 `{{rows}}`
                       用哪个行渲染器。
        rows:          原始行（资产行 / 变更行；`exposure` 用资产行再聚合）。
        summary:       概要串（**调用方给的规范值文本**，不在此处翻译）。
        generated_at:  生成时间（ISO 字符串）。
        template_text: 模板正文（已读好的字符串）。

    Returns:
        渲染后的 HTML 字符串。`template_text` 为空时返回空串（调用方报错）。
    """
    if not template_text:
        return ""
    if kind == "changes":
        rows_html = _render_change_rows(rows)
    elif kind == "exposure":
        rows_html = _render_exposure_rows(rows)
    else:
        rows_html = _render_asset_rows(rows)

    out = template_text
    out = out.replace("{{rows}}", rows_html)
    out = out.replace("{{summary}}", _esc(summary))
    out = out.replace("{{generated_at}}", _esc(generated_at))
    # 允许模板里出现 `{{template_name}}` 之类的小占位符（无害，便于自述）
    out = out.replace("{{template_name}}", _esc(kind))
    return out


def _assemble(kind, rows, changes, generated_at) -> tuple:
    """按 kind 装配 (行, 概要)。变更类需要 change_detector 的概要口径但**不**进 i18n。"""
    if kind == "changes":
        return rows, _changes_summary(rows)
    if kind == "exposure":
        return rows, _exposure_summary(rows)
    return rows, _asset_summary(rows)


def render_report(kind: str, *, assets=None, changes=None, template_text=None,
                  generated_at=None, template_name=None) -> str:
    """高层入口：装配数据 + 渲染。

    Args:
        kind:          报表种类（`assets`/`changes`/`exposure`）。
        assets:        资产行（`list_assets` 的输出）；`assets`/`exposure` 用。
        changes:       变更行（`change_detector.Change` 列表）；`changes` 用。
        template_text: 模板正文；不传则按 `kind` 从磁盘加载。
        generated_at:  生成时间（ISO）；不传则用当前本地时间。
        template_name: 模板文件名主体（与 `kind` 解耦；不传 = `kind`）。

    Returns:
        渲染后的 HTML。`kind` 不支持时抛 `ValueError`（**不静默出空文档**）。
    """
    if kind not in REPORT_KINDS:
        raise ValueError("不支持的报表种类: %r（可选：%s）"
                         % (kind, ", ".join(REPORT_KINDS)))
    if template_text is None:
        template_text = load_template(template_name or kind)
    if not template_text:
        raise ValueError("报表模板不可用: %s" % (template_name or kind))

    if generated_at is None:
        generated_at = datetime.datetime.now().isoformat(timespec="seconds")

    rows = changes if kind == "changes" else (assets or [])
    rows, summary = _assemble(kind, rows, changes, generated_at)
    return build_report(kind, rows, summary, generated_at, template_text)
