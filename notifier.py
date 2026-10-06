# -*- coding: utf-8 -*-
"""变更告警通知渠道（仅标准库）。

设计取舍
--------
**零第三方依赖。** 用 ``urllib.request`` + ``smtplib`` 就足够覆盖
webhook / 企业微信 / 钉钉 / 邮件四类渠道。本项目连 SNMPv3 的 AES 都是自研的
（见 ``scanner/aes.py``），为了发个告警引入 requests/dingtalk-sdk 并不划算。

**敏感值不落盘。** webhook URL 里带着机器人 token，安全等级等同于口令。
因此配置中的敏感字段支持 ``env:VAR_NAME`` 间接引用，实际值从环境变量读取。
这与 CLI 侧 SNMPv3 口令"只走环境变量、绝不进 argv"的既有约定是同一条原则。

**失败隔离。** 多个渠道中任意一个挂掉都不影响其余；逐渠道回传结果，
由调用方决定如何呈现。告警系统的价值在于"总有一条能到"，而不是全或无。

**业务错误也算失败。** 企业微信/钉钉即使业务失败也返回 HTTP 200，
错误藏在 body 的 ``errcode`` 里。只看 HTTP 状态码会把"机器人被禁用"
"token 失效"当成发送成功 —— 告警静默丢失比告警发不出去更危险。
"""
import base64
import hashlib
import hmac
import json
import os
import smtplib
import ssl
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Dict, List, Tuple

from app_logging import get_logger
from i18n import tr

_log = get_logger(__name__)

_DEFAULT_TIMEOUT = 10


def resolve_secret(value: str) -> str:
    """解析配置中的敏感字段。

    支持 ``env:VAR_NAME`` 形式：实际值从环境变量读取，配置文件里不出现明文。
    这与 README「SNMPv3 口令只从环境变量读取」一节是同一条原则 ——
    配置文件常被复制、备份、误提交，明文口令放进去等于泄露。
    """
    if not value:
        return ""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:].strip(), "")
    return value


# ── 底层 HTTP ────────────────────────────────────────────────────────

def _raise_if_business_error(raw: bytes):
    """企业微信 / 钉钉用 HTTP 200 + body 里的 errcode 表示业务失败。"""
    if not raw:
        return
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        # 不是 JSON（自建 webhook 常见）→ 无法判断，按成功处理
        return
    if not isinstance(obj, dict):
        return
    code = obj.get("errcode", obj.get("code"))
    if code in (0, None, "0"):
        return
    msg = obj.get("errmsg") or obj.get("message") or ""
    raise RuntimeError(f"渠道返回业务错误 errcode={code}: {msg}")


def post_json(url: str, payload: dict, timeout: float = _DEFAULT_TIMEOUT) -> bytes:
    """POST 一段 JSON，返回响应体。失败抛异常（由 send_all 捕获）。"""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(8192)
    _raise_if_business_error(raw)
    return raw


# ── 渠道 ─────────────────────────────────────────────────────────────

class Notifier:
    """通知渠道基类。``send()`` 失败时抛异常，由 send_all 逐渠道捕获。"""

    name = "notifier"

    def send(self, subject: str, body: str) -> None:
        raise NotImplementedError


class WebhookNotifier(Notifier):
    """通用 Webhook：POST 一段 JSON（字段含 subject / body / text）。"""

    def __init__(self, url: str, timeout: float = _DEFAULT_TIMEOUT,
                 extra_fields: dict = None):
        self.url = resolve_secret(url)
        self.timeout = timeout
        self.extra_fields = dict(extra_fields or {})

    @property
    def name(self):
        return "webhook"

    def payload(self, subject: str, body: str) -> dict:
        data = {"subject": subject, "body": body, "text": f"{subject}\n{body}"}
        data.update(self.extra_fields)
        return data

    def _target_url(self) -> str:
        return self.url

    def send(self, subject: str, body: str) -> None:
        if not self.url:
            raise ValueError(tr("Webhook 地址为空（若用 env: 引用，请确认环境变量已设置）"))
        post_json(self._target_url(), self.payload(subject, body), self.timeout)


class WeComNotifier(WebhookNotifier):
    """企业微信群机器人。"""

    @property
    def name(self):
        return "企业微信"

    def payload(self, subject: str, body: str) -> dict:
        return {
            "msgtype": "markdown",
            "markdown": {"content": f"**{subject}**\n{body}"},
        }


class DingTalkNotifier(WebhookNotifier):
    """钉钉群机器人（支持加签，secret 可选）。"""

    def __init__(self, url: str, secret: str = "",
                 timeout: float = _DEFAULT_TIMEOUT):
        super().__init__(url, timeout)
        self.secret = resolve_secret(secret)

    @property
    def name(self):
        return "钉钉"

    def _target_url(self) -> str:
        """加签：timestamp + HMAC-SHA256(secret, "ts\\nsecret")，URL 编码后拼上。"""
        if not self.secret:
            return self.url
        ts = str(round(time.time() * 1000))
        string_to_sign = f"{ts}\n{self.secret}"
        digest = hmac.new(self.secret.encode("utf-8"),
                          string_to_sign.encode("utf-8"),
                          hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest))
        sep = "&" if "?" in self.url else "?"
        return f"{self.url}{sep}timestamp={ts}&sign={sign}"

    def payload(self, subject: str, body: str) -> dict:
        return {
            "msgtype": "markdown",
            "markdown": {"title": subject, "text": f"### {subject}\n\n{body}"},
        }


class EmailNotifier(Notifier):
    """SMTP 邮件。use_ssl=True 走隐式 TLS(465)，False 走 STARTTLS(587)。"""

    def __init__(self, host: str, port: int = 0, user: str = "",
                 password: str = "", recipients: List[str] = None,
                 use_ssl: bool = True, timeout: float = _DEFAULT_TIMEOUT):
        self.host = host
        self.use_ssl = use_ssl
        self.port = int(port or (465 if use_ssl else 587))
        self.user = user
        self.password = resolve_secret(password)
        self.recipients = [r for r in (recipients or []) if r]
        self.timeout = timeout

    @property
    def name(self):
        return "邮件"

    def send(self, subject: str, body: str) -> None:
        if not self.host:
            raise ValueError(tr("SMTP 服务器未配置"))
        if not self.recipients:
            raise ValueError(tr("收件人列表为空"))

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.user or f"ipscanner@{self.host}"
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(body)

        if self.use_ssl:
            with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout,
                                  context=ssl.create_default_context()) as s:
                if self.user:
                    s.login(self.user, self.password)
                s.send_message(msg)
            return

        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            s.ehlo()
            try:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            except smtplib.SMTPException as e:
                # 服务器不支持 STARTTLS：继续发送，但必须留痕 ——
                # 静默降级会让用户以为邮件是加密发出去的
                _log.warning("SMTP 服务器不支持 STARTTLS，将明文发送: %s", e)
            if self.user:
                s.login(self.user, self.password)
            s.send_message(msg)


# ── 组装与发送 ───────────────────────────────────────────────────────

_CHANNEL_ALIASES = {
    "webhook": "webhook",
    "wecom": "wecom",
    "wechat_work": "wecom",
    "qywx": "wecom",
    "dingtalk": "dingtalk",
    "ding": "dingtalk",
    "email": "email",
    "smtp": "email",
    "mail": "email",
}


def default_config_path() -> str:
    """通知配置文件路径：数据目录下的 notify.json。

    放在数据目录（而不是源码目录）是为了让打包后的便携版/用户目录版
    各自持有自己的配置，与 scan_history.db / audit_log.db 保持一致。
    """
    import app_paths
    return os.path.join(app_paths.data_dir(), "notify.json")


def load_config(path: str = None) -> Dict:
    """读取通知配置。文件不存在或损坏时返回空配置（不抛异常）。

    刻意不抛：告警配置缺失只应导致"没有渠道可用"这一条明确告警，
    而不该让整个定时扫描任务失败 —— 扫描本身才是主任务。
    """
    p = path or default_config_path()
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001
        _log.warning("通知配置读取失败 %s: %s", p, e)
        return {}
    return data if isinstance(data, dict) else {}


def save_config(config: Dict, path: str = None) -> Tuple[bool, str]:
    """写入通知配置。返回 ``(是否成功, 错误信息)``。"""
    p = path or default_config_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(config or {}, f, ensure_ascii=False, indent=2)
        return True, ""
    except Exception as e:  # noqa: BLE001
        _log.warning("通知配置写入失败 %s: %s", p, e)
        return False, str(e)


def build_notifiers(config: Dict) -> List[Notifier]:
    """按配置构造渠道列表。

    配置形如::

        {"channels": [
            {"type": "wecom", "url": "env:IPSCANNER_WECOM_URL"},
            {"type": "dingtalk", "url": "env:DING_URL", "secret": "env:DING_SECRET"},
            {"type": "email", "host": "smtp.example.com", "user": "a@b.c",
             "password": "env:SMTP_PASS", "recipients": ["ops@example.com"]}
        ]}

    未启用（``enabled: false``）、类型未知或构造失败的渠道会被跳过并留痕，
    不影响其余渠道 —— 配错一个渠道不该让整套告警失效。
    """
    out: List[Notifier] = []
    for item in (config or {}).get("channels", []) or []:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        raw_kind = str(item.get("type") or "").strip().lower()
        kind = _CHANNEL_ALIASES.get(raw_kind, raw_kind)
        try:
            if kind == "webhook":
                out.append(WebhookNotifier(
                    item.get("url", ""),
                    extra_fields=item.get("fields") or {},
                ))
            elif kind == "wecom":
                out.append(WeComNotifier(item.get("url", "")))
            elif kind == "dingtalk":
                out.append(DingTalkNotifier(item.get("url", ""),
                                            item.get("secret", "")))
            elif kind == "email":
                out.append(EmailNotifier(
                    item.get("host", ""),
                    port=item.get("port", 0),
                    user=item.get("user", ""),
                    password=item.get("password", ""),
                    recipients=item.get("recipients") or [],
                    use_ssl=item.get("use_ssl", True),
                ))
            else:
                _log.warning("未知的通知渠道类型 %r，已跳过", raw_kind)
        except Exception as e:  # noqa: BLE001
            # 单个渠道配置写错不该让整份配置作废
            _log.warning("通知渠道 %r 构造失败，已跳过: %s", raw_kind, e)
    return out


def send_all(notifiers: List[Notifier], subject: str,
             body: str) -> List[Tuple[str, bool, str]]:
    """逐渠道发送，失败隔离。

    Returns:
        ``[(渠道名, 是否成功, 错误信息)]``，顺序与入参一致。
    """
    results: List[Tuple[str, bool, str]] = []
    for n in notifiers:
        try:
            n.send(subject, body)
        except Exception as e:  # noqa: BLE001
            results.append((n.name, False, str(e)))
            _log.warning("告警发送失败 [%s]: %s", n.name, e)
        else:
            results.append((n.name, True, ""))
            _log.info("告警已发送 [%s]", n.name)
    return results


# ── 消息渲染（纯函数，便于单测）───────────────────────────────────────

def format_change_message(changes, summary: str, label: str = "",
                          max_items: int = 20) -> Tuple[str, str]:
    """把变更列表渲染成 ``(标题, 正文)``。

    截断到 ``max_items`` 条：企业微信/钉钉单条消息有长度上限，超长会被
    整条拒收（而不是截断），结果是告警全丢。宁可少列几条也要保证能送达。
    """
    label = label or tr("资产变更")
    subject = f"[IPScanner] {label}：{summary}"
    if not changes:
        return subject, tr("本次未检测到变更。")

    lines = [f"{tr('对比基线')}: {label}", f"{tr('摘要')}: {summary}", ""]
    for c in changes[:max_items]:
        line = f"- [{c.severity_label}] {c.type_label} {c.ip}".rstrip()
        if c.hostname:
            line += f" ({c.hostname})"
        if c.description:
            line += f" — {c.description}"
        lines.append(line)
    if len(changes) > max_items:
        lines.append(tr("… 其余 {n} 条已省略").format(n=len(changes) - max_items))
    return subject, "\n".join(lines)
