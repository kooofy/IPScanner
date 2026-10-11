# -*- coding: utf-8 -*-
"""风险评分（docs/reviews/UI_REVIEW.md P3-4「风险列/评分」）。

只回答一个问题：**这台机器的服务暴露面有多大。**

刻意**不**掺入"是否纳入资产台账""是不是陌生设备"这类**归属**问题 —— 那属于
资产视角（已有「资产」列预设与地址库）。混进来会让每一台未登记的设备都带分，
用户一旦还没导入台账，整列就全是同一个数字，这一列立刻变成噪声。

评分只用**已有信号**，不新增任何网络探测：

- `open_ports`：明文 / 无认证的服务端口（Telnet、FTP、TFTP、VNC、SNMP v2c…）。
  这一族**聚合成一条结论**「弱协议暴露面」，明细放在 tooltip 的子行里 ——
  理由见 `_REASON_WEAK_PROTOCOLS`；
- `conflict_detector` 的冲突结果（分值直接取冲突的**严重级别**，不另立一套
  判断 —— 严重级别是那一边的单一事实来源）；
- `tls_cert`：TLS 证书事实（到期 / 自签名 / 弱算法，v1.9 #3「零利用安全体检」）。
  ⚠ 它**不是新探测** —— 证书是从**已有的** HTTPS 握手里顺带取的（见
  `scanner/http.read_https`），所以"评分不增加网络开销"这条依然成立。
  ⚠ 也刻意**不引入任何利用行为**：只读证书、不试凭据、不发畸形报文。
- `name_responder`：LLMNR / NBNS 响应器事实（"有主机应答了不存在的主机名"，
  v1.9 #3 第二刀）。同样是**零利用**的 —— 只编一个不可能存在的名字查一次，
  谁给肯定应答就报谁；不注册名字、不应答别人的查询、**绝不投毒**。
  ⚠ 它**是**新探测（会往网络里发组播 / 广播包），所以由显式开关控制、
  默认关（GUI 勾选框 / CLI `--name-responder`）—— "评分不增加网络开销"
  这条对它**不**成立，这是它与 `tls_cert` 的关键区别。

刻度是 0–100 的加法制，封顶 100。**每一分都必须能说出理由**（`reasons` 带分值），
tooltip 会把分数拆开给用户看：说不出理由的风险分没人会信。

标定参考（改造前的真实端口组合，用来确认这一列不会"什么都报"）：

    普通 Windows 主机 (135/139/445/3389)          -> 0    「—」
    打印机 (80/161/9100)                          -> 25   「低」
    路由器 (23/80/161)                            -> 55   「中」
    群晖 NAS (80/445/5000)                        -> 10   「低」
    网络摄像头 (23/80/554)                        -> 40   「中」
    老设备 (21/23) + MAC 冲突                     -> 90   「高」

TLS 那几项的标定：自签名**只给 5 分** —— 局域网设备管理面几乎全是自签名证书，
给高分会让整列又变成同一个数字（正是本文开头要避免的噪声）。真正的信号是
**到期**（功能已经坏 / 马上会坏）与**弱算法**（已被实证可攻破）。

名字响应器给 30 分（与 Telnet 明文同级）：这个发现本身是**歧义的** —— 应答
不存在名字的既可能是欺骗响应器（攻击），也可能是安全扫描工具 / 蜜罐（防护）。
分数只表示"值得看一眼"，不替用户断定对方恶意；30 分够它冒头，又不至于单独
一条就把设备拉满。

明文 / 无认证的那一族端口**聚合成一条理由**（`_REASON_WEAK_PROTOCOLS`）：
一台老路由器 (23/80/161) 会同时命中三条规则，各占一行说的是同一件事，把
tooltip 撑成一面墙。聚合成一条 + 一行明细，结论先出来、明细按需看。
⚠ **总分不变**（各端口分值照旧相加），上面那张标定表因此依然成立。
"""
from conflict_detector import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_WARNING
from i18n import tr
from scanner.x509 import days_until, is_weak_key, is_weak_signature

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

#: 上面这一族（明文 / 无认证服务）在 tooltip 里**聚合成一条**理由的代码。
#:
#: 为什么聚合：一台老路由器 (23/80/161) 会同时命中三条规则，tooltip 里就出现
#: 「Telnet 明文管理 / HTTP 明文管理面 / SNMP v2c 团体字明文」三行 —— 它们说的是
#: **同一件事**（这台设备的管理面是明文或没有认证），却把 tooltip 撑成一面墙，
#: 用户看完还是不知道"到底多危险"。聚合成一条 + 一行明细，结论先出来、明细按需看。
#:
#: ⚠ **总分不变**：各端口的分值照旧相加，只是不再各占一行。这是刻意的 ——
#: 本文档顶部那张标定表（打印机 25 / 路由器 55 / 摄像头 40 …）是这一列的
#: 可信度来源，聚合若顺手改了分数，等于把标定推翻。
_REASON_WEAK_PROTOCOLS = "weak_protocols"

# ── 零利用安全体检：TLS 证书（v1.9 #3 第一刀）─────────────────────────
#
# 判定所需的**事实**来自 `ScanResult.tls_cert`（见 `scanner/x509.py`）。
# 扫描器只报事实，结论与阈值只写在这一处 —— 阈值两处写迟早会不一致。
_REASON_TLS_EXPIRED = "tls_expired"
_REASON_TLS_EXPIRING = "tls_expiring_soon"
_REASON_TLS_SELF_SIGNED = "tls_self_signed"
_REASON_TLS_WEAK_SIG = "tls_weak_signature"
_REASON_TLS_WEAK_KEY = "tls_weak_key"

#: 剩余天数 ≤ 它就算"即将过期"。30 天是运维能安排一次更换的常见窗口。
TLS_EXPIRING_DAYS = 30

#: 理由 → 分值。按严重度递减排列（`tls_reasons()` 也按这个顺序产出，
#: tooltip 因此天然是"最要紧的排在最上面"）。
_TLS_POINTS = (
    (_REASON_TLS_EXPIRED, 40),        # 已过期：客户端直接拒绝，功能其实已经坏了
    (_REASON_TLS_WEAK_SIG, 25),       # MD5/SHA-1 签名：碰撞攻击已被实证
    (_REASON_TLS_WEAK_KEY, 20),       # 密钥过短：可被离线爆破
    (_REASON_TLS_EXPIRING, 15),       # 即将过期：还没坏，但马上会
    (_REASON_TLS_SELF_SIGNED, 5),     # 自签名：无法验证身份（局域网常态，故低分）
)
_TLS_POINT_OF = dict(_TLS_POINTS)

# ── 零利用安全体检：LLMNR / NBNS 响应器（v1.9 #3 第二刀）───────────────
#
# 事实来自 `ScanResult.name_responder`（见 `scanner/llmnr_nbns.py`）。
#
# **只给一个理由代码**，不分 llmnr / nbns：同一台主机对两个协议都给肯定应答
# 是**同一个发现**（"它在应答自己不拥有的名字"），拆成两条会让风险栏里出现
# 两条近义理由，分数还翻倍。协议明细留在事实层（`security_findings` 里的
# `llmnr_responder` / `nbns_responder`）—— 这正是"事实与结论分开"的用法。
_REASON_NAME_RESPONDER = "name_responder"

#: 30 分：与 Telnet 明文同级。
#:
#: 之所以不给更高分：这个发现**本身是歧义的** —— 应答不存在名字的既可能是
#: 欺骗响应器（攻击），也可能是安全扫描工具 / 蜜罐（防护）。分数要反映
#: "值得看一眼"，而不是替用户断定对方是恶意的。30 分能把它推进"中危"、
#: 在风险栏里冒头，又不至于单独一条就把设备拉满。
_NAME_RESPONDER_POINTS = 30

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
    _REASON_TLS_EXPIRED: "TLS 证书已过期",
    _REASON_TLS_EXPIRING: "TLS 证书即将过期",
    _REASON_TLS_SELF_SIGNED: "TLS 证书自签名",
    _REASON_TLS_WEAK_SIG: "TLS 证书签名算法过时",
    _REASON_TLS_WEAK_KEY: "TLS 证书密钥过短",
    _REASON_NAME_RESPONDER: "应答了不存在的主机名（疑似欺骗响应器）",
    _REASON_WEAK_PROTOCOLS: "弱协议暴露面",
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


def weak_protocol_reasons(ports) -> tuple:
    """把「明文 / 无认证服务」这一族端口聚成**一条**理由。

    返回 `(总分, [命中的理由代码, ...])`；一个都没命中时是 `(0, [])`。
    代码按 `_PORT_RULES` 的严重度顺序排（HTTP 明文在最后，它分值最低），
    于是 tooltip 的明细行天然是"最要紧的排在最前面"。

    独立成函数与 `tls_reasons()` 同一个理由：**纯函数式单测**，不用去连任何端口。

    ⚠ 明文 HTTP **只在没有 HTTPS 时**才计分：同机开了 443 说明有加密替代，
    这时候再报"HTTP 明文"就是噪声（这条规则原来就在 `score_risk()` 里，
    聚合时原样搬过来）。
    """
    ports = set(ports or ())
    total = 0
    hit = []
    for code, port, points in _PORT_RULES:
        if port in ports:
            total += points
            hit.append(code)
    if 80 in ports and 443 not in ports:
        total += _HTTP_ONLY_POINTS
        hit.append(_REASON_CLEARTEXT_HTTP)
    return total, hit


def tls_reasons(cert, now=None) -> list:
    """从 TLS 证书事实推出风险理由，返回 `[(理由代码, 分值), ...]`。

    `cert` 是 `ScanResult.tls_cert`（见 `scanner/x509.parse_certificate`），
    为空 dict 时返回 `[]`。`now` 可注入，测试用来固定"今天"。

    独立成函数是为了能**纯函数式**单测：不用真去连一台 HTTPS 服务，
    也能覆盖"过期 / 即将过期 / 自签名 / 弱签名 / 弱密钥"全部分支。
    """
    if not cert:
        return []
    out = []
    remaining = days_until(cert.get("not_after", ""), now=now)
    if remaining is not None:
        if remaining < 0:
            out.append((_REASON_TLS_EXPIRED, _TLS_POINT_OF[_REASON_TLS_EXPIRED]))
        elif remaining <= TLS_EXPIRING_DAYS:
            out.append((_REASON_TLS_EXPIRING, _TLS_POINT_OF[_REASON_TLS_EXPIRING]))
    if is_weak_signature(cert.get("sig_alg", "")):
        out.append((_REASON_TLS_WEAK_SIG, _TLS_POINT_OF[_REASON_TLS_WEAK_SIG]))
    if is_weak_key(cert.get("key_alg", ""), cert.get("key_bits") or 0):
        out.append((_REASON_TLS_WEAK_KEY, _TLS_POINT_OF[_REASON_TLS_WEAK_KEY]))
    if cert.get("self_signed"):
        out.append((_REASON_TLS_SELF_SIGNED, _TLS_POINT_OF[_REASON_TLS_SELF_SIGNED]))
    # 按 `_TLS_POINTS` 的严重度顺序排（上面的追加顺序与它一致），
    # 这样 tooltip 里最要紧的理由永远在最上面。
    order = {code: i for i, (code, _p) in enumerate(_TLS_POINTS)}
    return sorted(out, key=lambda item: order.get(item[0], len(order)))


def responder_reasons(responder) -> list:
    """从名字响应器事实推出风险理由，返回 `[(理由代码, 分值), ...]`。

    `responder` 是 `ScanResult.name_responder`（`{协议: 探测名}`），空 dict
    时返回 `[]`。与 `tls_reasons()` 一样独立成函数，方便纯函数式单测。

    协议**不**进理由代码（见 `_REASON_NAME_RESPONDER` 处的说明）：无论应答
    的是 LLMNR 还是 NBNS，结论都是同一条，只算一次分。
    """
    if not responder:
        return []
    return [(_REASON_NAME_RESPONDER, _NAME_RESPONDER_POINTS)]


def score_risk(result, conflicts=(), now=None) -> dict:
    """给一台设备打分。

    `conflicts` 是**属于这台设备**的冲突对象（任何带 `.severity` /
    `.conflict_type` 的对象都行）。`result` 为 None 时返回零分。
    `now` 可注入（测试固定"今天"，用于 TLS 证书剩余天数）。

    返回 `{"score": int, "level": str, "reasons": [(代码, 分值), ...],
    "weak_protocols": [代码, ...]}`。
    `reasons` 保序（先弱协议、再 TLS、再名字响应器、后冲突）且**带分值**，
    这样 tooltip 能把分数拆开给用户看 —— 一个说不出理由的风险分没人会信。

    排序按**类别**而不是全局按分值：类别内部已按严重度排好（见 `_TLS_POINTS`），
    跨类别再排一次会让"哪来的分"变得难以对照代码。

    `weak_protocols` 是聚合理由的**明细**（命中的端口规则代码，语言无关），
    tooltip 用它渲染子行；不在 `reasons` 里展开是刻意的（见
    `_REASON_WEAK_PROTOCOLS`）。键**恒定存在**（没命中时是空列表），
    消费方不用判断有没有。
    """
    score = 0
    reasons = []
    ports = set(getattr(result, "open_ports", None) or [])
    # 明文 / 无认证服务聚成一条 —— 它们说的是同一件事（见 _REASON_WEAK_PROTOCOLS）。
    weak_points, weak_hits = weak_protocol_reasons(ports)
    if weak_points:
        score += weak_points
        reasons.append((_REASON_WEAK_PROTOCOLS, weak_points))
    for code, points in tls_reasons(getattr(result, "tls_cert", None), now=now):
        score += points
        reasons.append((code, points))
    for code, points in responder_reasons(getattr(result, "name_responder", None)):
        score += points
        reasons.append((code, points))
    for conflict in (conflicts or ()):
        severity = getattr(conflict, "severity", "")
        points = _SEVERITY_POINTS.get(severity, _DEFAULT_CONFLICT_POINTS)
        code = getattr(conflict, "conflict_type", "") or "unknown_device"
        score += points
        reasons.append((code, points))
    return {"score": min(score, RISK_MAX),
            "level": risk_level(score),
            "reasons": reasons,
            "weak_protocols": weak_hits}


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
    """tooltip：把分数拆成"哪几项各加了多少分"。

    弱协议那一条会多一行缩进的**明细**（命中的具体服务），见
    `_REASON_WEAK_PROTOCOLS` —— 结论一行先出来，明细按需往下看。

    ⚠ 各项之和**可能大于** `score`（`RISK_MAX` 封顶）。这时末尾补一行说明 ——
    否则用户看到"100/100"底下几项加起来 120，会以为算错了。**不**去把某项
    截断到 0：那会凭空丢掉一条真实发现（"MAC 地址冲突 +0" 或干脆不显示），
    比多一行说明糟得多。

    ⚠ 明细用 `", ".join()` 拼（与 `main_window_tree` 拼服务名同一手法），
    不再单独做一个"分隔符"词条：语言包里的分隔符只会多一处可能漏翻的地方。
    """
    if not risk or not risk.get("reasons"):
        return tr("未发现明显的服务暴露风险")
    lines = [tr("风险评分 {n}/100").format(n=risk["score"])]
    for code, points in risk["reasons"]:
        lines.append("· %s +%d" % (reason_label(code), points))
        if code == _REASON_WEAK_PROTOCOLS:
            detail = ", ".join(reason_label(c)
                               for c in risk.get("weak_protocols") or ())
            if detail:
                lines.append("    " + detail)
    raw = sum(points for _code, points in risk["reasons"])
    if raw > risk["score"]:
        lines.append(tr("已达评分上限（各项合计 {n}）").format(n=raw))
    return "\n".join(lines)
