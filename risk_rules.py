# -*- coding: utf-8 -*-
"""风险评分（UI_REVIEW.md P3-4「风险列/评分」）。

只回答一个问题：**这台机器的服务暴露面有多大。**

刻意**不**掺入"是否纳入资产台账""是不是陌生设备"这类**归属**问题 —— 那属于
资产视角（已有「资产」列预设与地址库）。混进来会让每一台未登记的设备都带分，
用户一旦还没导入台账，整列就全是同一个数字，这一列立刻变成噪声。

评分只用**已有信号**，不新增任何网络探测：

- `open_ports`：明文 / 无认证的服务端口（Telnet、FTP、TFTP、VNC、SNMP v2c…）；
- `conflict_detector` 的冲突结果（分值直接取冲突的**严重级别**，不另立一套
  判断 —— 严重级别是那一边的单一事实来源）。

刻度是 0–100 的加法制，封顶 100。**每一分都必须能说出理由**（`reasons` 带分值），
tooltip 会把分数拆开给用户看：说不出理由的风险分没人会信。

标定参考（改造前的真实端口组合，用来确认这一列不会"什么都报"）：

    普通 Windows 主机 (135/139/445/3389)          -> 0    「—」
    打印机 (80/161/9100)                          -> 25   「低」
    路由器 (23/80/161)                            -> 55   「中」
    群晖 NAS (80/445/5000)                        -> 10   「低」
    网络摄像头 (23/80/554)                        -> 40   「中」
    老设备 (21/23) + MAC 冲突                     -> 90   「高」
"""
from conflict_detector import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_WARNING
from i18n import tr

# ── 等级 ───────────────────────────────────────────────────────────────

RISK_LEVEL_NONE = "none"
RISK_LEVEL_LOW = "low"
RISK_LEVEL_MEDIUM = "medium"
RISK_LEVEL_HIGH = "high"

#: 风险列在结果表格里的**列索引**（对应 `main_window.COLUMN_LABELS`）。
#: 放在这里而不是 `main_window_tree`：后者是被 `main_window` 导入的，反向
#: import 会成环。漂移由 `tests/test_risk_rules.py` 断言
#: `COLUMN_LABELS[RISK_COLUMN] == "风险"` 兜住。
RISK_COLUMN = 13

#: 等级 → 下界阈值。**降序**，`risk_level()` 顺序命中即返回。
RISK_THRESHOLDS = (
    (60, RISK_LEVEL_HIGH),
    (30, RISK_LEVEL_MEDIUM),
    (1, RISK_LEVEL_LOW),
)

#: 分数上限。多项叠加（如 Telnet + FTP + 冲突）很容易超过 100，封顶后仍能保持
#: "高 / 中 / 低"的相对次序不变。
RISK_MAX = 100

#: 等级 → 语义色令牌名（`theme_tokens`）。四个等级都有颜色 —— `none` 也要设成
#: `muted` 而不是留默认色：默认色在深色主题下几乎看不见。
#: 用令牌名而不是 `QColor`：存 `QColor` 会把浅色值冻死在 import 期。
RISK_LEVEL_TOKEN = {
    RISK_LEVEL_HIGH: "danger",
    RISK_LEVEL_MEDIUM: "warn",
    RISK_LEVEL_LOW: "fg_strong",
    RISK_LEVEL_NONE: "muted",
}

#: 等级 → 显示名。字面量（不能在这里调 `tr()`，会被冻成导入期语言），
#: 且已登记进 `tests/test_i18n_lazy.py::TableDrivenLabelCoverageTest`。
_RISK_LEVEL_TEXT = {
    RISK_LEVEL_HIGH: "高",
    RISK_LEVEL_MEDIUM: "中",
    RISK_LEVEL_LOW: "低",
    RISK_LEVEL_NONE: "—",
}


# ── 端口规则 ───────────────────────────────────────────────────────────

#: (理由代码, 端口, 分值)。分值按"被人利用的难易 × 后果"粗排：
#: Telnet/VNC 直接给交互式 shell 或桌面，最重；SNMP v2c 只泄露信息，最轻。
_PORT_RULES = (
    ("cleartext_telnet", 23, 30),
    ("unauthenticated_vnc", 5900, 25),
    ("cleartext_ftp", 21, 20),
    ("cleartext_tftp", 69, 20),
    ("cleartext_snmp", 161, 15),
)

_REASON_CLEARTEXT_HTTP = "cleartext_http"
_HTTP_ONLY_POINTS = 10

#: 冲突严重级别 → 分值。**复用冲突检测的判定**，不另立一套。
_SEVERITY_POINTS = {
    SEVERITY_HIGH: 40,
    SEVERITY_WARNING: 20,
    SEVERITY_INFO: 5,
}
_DEFAULT_CONFLICT_POINTS = 5

#: 理由代码 → 显示名（同上：字面量表，已登记进 i18n 覆盖测试）。
_REASON_TEXT = {
    "cleartext_telnet": "Telnet 明文管理",
    "unauthenticated_vnc": "VNC 远程桌面（常无认证）",
    "cleartext_ftp": "FTP 明文凭据",
    "cleartext_tftp": "TFTP 无认证文件传输",
    "cleartext_snmp": "SNMP v2c 团体字明文",
    _REASON_CLEARTEXT_HTTP: "HTTP 明文管理面",
    "duplicate_mac": "MAC 地址冲突",
    "duplicate_hostname": "主机名冲突",
    "unknown_device": "不在地址库中的设备",
}


# ── 惰性翻译 ───────────────────────────────────────────────────────────

def risk_level_label(value: str) -> str:
    """风险等级代码 → 当前语言的显示名（惰性翻译）。"""
    text = _RISK_LEVEL_TEXT.get(value)
    return tr(text) if text else str(value)


def reason_label(code: str) -> str:
    """风险理由代码 → 当前语言的显示名（惰性翻译）。"""
    text = _REASON_TEXT.get(code)
    return tr(text) if text else str(code)


# ── 评分 ───────────────────────────────────────────────────────────────

def risk_level(score) -> str:
    """分数 → 等级。"""
    try:
        value = int(score)
    except (TypeError, ValueError):
        value = 0
    for threshold, level in RISK_THRESHOLDS:
        if value >= threshold:
            return level
    return RISK_LEVEL_NONE


def score_risk(result, conflicts=()) -> dict:
    """给一台设备打分。

    `conflicts` 是**属于这台设备**的冲突对象（任何带 `.severity` /
    `.conflict_type` 的对象都行）。`result` 为 None 时返回零分。

    返回 `{"score": int, "level": str, "reasons": [(代码, 分值), ...]}`。
    `reasons` 保序（先端口后冲突）且**带分值**，这样 tooltip 能把分数拆开给
    用户看 —— 一个说不出理由的风险分没人会信。
    """
    score = 0
    reasons = []
    ports = set(getattr(result, "open_ports", None) or [])
    for code, port, points in _PORT_RULES:
        if port in ports:
            score += points
            reasons.append((code, points))
    # 明文 HTTP 只在**没有** HTTPS 时才计分：同机开了 443 说明有加密替代，
    # 这时候再报"HTTP 明文"就是噪声。
    if 80 in ports and 443 not in ports:
        score += _HTTP_ONLY_POINTS
        reasons.append((_REASON_CLEARTEXT_HTTP, _HTTP_ONLY_POINTS))
    for conflict in (conflicts or ()):
        severity = getattr(conflict, "severity", "")
        points = _SEVERITY_POINTS.get(severity, _DEFAULT_CONFLICT_POINTS)
        code = getattr(conflict, "conflict_type", "") or "unknown_device"
        score += points
        reasons.append((code, points))
    return {"score": min(score, RISK_MAX),
            "level": risk_level(score),
            "reasons": reasons}


# ── 显示 ───────────────────────────────────────────────────────────────

def format_risk(risk) -> str:
    """单元格文本：`高 65` / `—`。

    用 `%` 而不是 f-string：`tests/` 里有一道"用户可见文案不许用裸 f-string"
    的网（f-string 拼串天然躲过语言包完整性检查），虽然这里只有数字拼接，
    也没必要去踩线。
    """
    if not risk or risk.get("level") == RISK_LEVEL_NONE:
        return "—"
    return "%s %d" % (risk_level_label(risk["level"]), risk["score"])


def format_risk_tooltip(risk) -> str:
    """tooltip：把分数拆成"哪几项各加了多少分"。"""
    if not risk or not risk.get("reasons"):
        return tr("未发现明显的服务暴露风险")
    lines = [tr("风险评分 {n}/100").format(n=risk["score"])]
    for code, points in risk["reasons"]:
        lines.append("· %s +%d" % (reason_label(code), points))
    return "\n".join(lines)
