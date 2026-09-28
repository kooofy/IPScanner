# -*- coding: utf-8 -*-
"""WMI / SNMPv3 凭据存储。

- 运行期凭据保存在内存，供本次会话多次识别复用。
- 持久化：使用 Windows DPAPI（CryptProtectData / CryptUnprotectData）将密码加密后
  存入 QSettings（ipscanner.ini）。解密只能由同一用户在同一台机器完成，明文不落盘。
- 非 Windows 环境无 DPAPI，自动退化为"仅内存、不持久化"，save_to 静默跳过。
- SNMPv3 的认证/加密口令与 WMI 密码同等敏感，走同一套 DPAPI 策略。
"""
import base64
from app_logging import get_logger
from i18n import tr
from .wmi import TRANSPORT_AUTO, TRANSPORTS
from .snmp_v3 import (AUTH_NONE, AUTH_PROTOS, PRIV_NONE, PRIV_PROTOS,
                      SnmpV3User)

_log = get_logger(__name__)

try:
    import ctypes
    from ctypes import wintypes
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _HAS_DPAPI = True
except AttributeError:
    _HAS_DPAPI = False


if _HAS_DPAPI:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    def _protect(plaintext: str) -> bytes:
        data = plaintext.encode("utf-16-le")
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = _DATA_BLOB()
        if not _crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(blob_out.pbData)

    def _unprotect(blob: bytes) -> str:
        buf = ctypes.create_string_buffer(blob, len(blob))
        blob_in = _DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = _DATA_BLOB()
        if not _crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            raise ctypes.WinError()
        try:
            size = blob_out.cbData
            arr = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_byte * size))[0]
            return bytes(arr).decode("utf-16-le")
        finally:
            _kernel32.LocalFree(blob_out.pbData)
else:
    def _protect(plaintext: str) -> bytes:
        raise RuntimeError(tr("当前平台不支持 DPAPI 加密"))

    def _unprotect(blob: bytes) -> str:
        raise RuntimeError(tr("当前平台不支持 DPAPI 解密"))


class WmiCredentialStore:
    """WMI 凭据：内存态 + 可选的 DPAPI 加密持久化。"""

    def __init__(self):
        self.username: str = ""
        self.password: str = ""
        self.domain: str = ""
        # 传输偏好：auto / dcom / winrm（语言无关的规范值，见 scanner.wmi）
        self.transport: str = TRANSPORT_AUTO
        self.saved: bool = False

    def has_creds(self) -> bool:
        return bool(self.username) and bool(self.password)

    def set(self, username: str, password: str, domain: str = "",
            transport: str = None):
        self.username = username or ""
        self.password = password or ""
        self.domain = domain or ""
        if transport is not None:
            # 非法值一律回落到 auto，避免持久化里出现无法识别的字符串
            self.transport = transport if transport in TRANSPORTS else TRANSPORT_AUTO

    def save_to(self, settings):
        """加密持久化到 QSettings。非 Windows 环境静默跳过。"""
        try:
            settings.setValue("wmi/username", self.username)
            settings.setValue("wmi/domain", self.domain)
            settings.setValue("wmi/transport", self.transport)
            if self.password and _HAS_DPAPI:
                blob = _protect(self.password)
                settings.setValue("wmi/password_enc", base64.b64encode(blob).decode("ascii"))
                self.saved = True
        except Exception as e:  # noqa: BLE001
            # 保存失败不影响本次会话使用（凭据仍在内存里），但用户会误以为
            # "勾了记住密码"，所以必须留痕
            _log.warning(tr("WMI 凭据加密保存失败，本次会话仍可用但不会记住: %s"), e)

    def load_from(self, settings):
        """从 QSettings 解密载入。解密失败则清空密码，不影响启动。"""
        self.username = settings.value("wmi/username", "") or ""
        self.domain = settings.value("wmi/domain", "") or ""
        _t = settings.value("wmi/transport", TRANSPORT_AUTO) or TRANSPORT_AUTO
        self.transport = _t if _t in TRANSPORTS else TRANSPORT_AUTO
        enc = settings.value("wmi/password_enc", "") or ""
        self.password = ""
        self.saved = False
        if enc and _HAS_DPAPI:
            try:
                self.password = _unprotect(base64.b64decode(enc))
                self.saved = True
            except Exception as e:  # noqa: BLE001
                _log.warning(tr("WMI 凭据解密失败，已清空保存的密码: %s"), e)
                self.password = ""


class SnmpV3CredentialStore:
    """SNMPv3 USM 用户配置：内存态 + 可选的 DPAPI 加密持久化。

    只有用户名 + 认证/加密协议是"非敏感配置"，可以明文落盘；
    两个口令一律经 DPAPI 加密，与 WMI 密码同一策略。
    """

    def __init__(self):
        self.username: str = ""
        self.auth_proto: str = AUTH_NONE
        self.auth_key: str = ""
        self.priv_proto: str = PRIV_NONE
        self.priv_key: str = ""
        self.saved: bool = False

    def has_creds(self) -> bool:
        return bool(self.username)

    def to_user(self) -> SnmpV3User:
        """转成协议层用的不可变参数对象。"""
        return SnmpV3User(
            username=self.username, auth_proto=self.auth_proto,
            auth_key=self.auth_key, priv_proto=self.priv_proto,
            priv_key=self.priv_key,
        )

    def set(self, username: str, auth_proto: str = AUTH_NONE, auth_key: str = "",
            priv_proto: str = PRIV_NONE, priv_key: str = ""):
        """写入配置。非法协议值一律回落成"不启用"，避免脏值进入持久化。"""
        self.username = username or ""
        self.auth_proto = auth_proto if auth_proto in AUTH_PROTOS else AUTH_NONE
        self.auth_key = auth_key or ""
        self.priv_proto = priv_proto if priv_proto in PRIV_PROTOS else PRIV_NONE
        self.priv_key = priv_key or ""
        # 没启用认证就不该留下加密（RFC 3414：priv 必须建立在 auth 之上）
        if self.auth_proto == AUTH_NONE:
            self.priv_proto = PRIV_NONE
            self.priv_key = ""

    def save_to(self, settings):
        """加密持久化到 QSettings。非 Windows 环境静默跳过。"""
        try:
            settings.setValue("snmpv3/username", self.username)
            settings.setValue("snmpv3/auth_proto", self.auth_proto)
            settings.setValue("snmpv3/priv_proto", self.priv_proto)
            if not _HAS_DPAPI:
                return
            for key, value in (("snmpv3/auth_key_enc", self.auth_key),
                               ("snmpv3/priv_key_enc", self.priv_key)):
                if value:
                    blob = _protect(value)
                    settings.setValue(
                        key, base64.b64encode(blob).decode("ascii"))
            self.saved = True
        except Exception as e:  # noqa: BLE001
            # 保存失败不影响本次会话使用（口令仍在内存里），但用户会误以为
            # "勾了记住密码"，所以必须留痕
            _log.warning(tr("SNMPv3 凭据加密保存失败，本次会话仍可用但不会记住: %s"), e)

    def load_from(self, settings):
        """从 QSettings 解密载入。解密失败则清空口令，不影响启动。"""
        self.username = settings.value("snmpv3/username", "") or ""
        _a = settings.value("snmpv3/auth_proto", AUTH_NONE) or AUTH_NONE
        self.auth_proto = _a if _a in AUTH_PROTOS else AUTH_NONE
        _p = settings.value("snmpv3/priv_proto", PRIV_NONE) or PRIV_NONE
        self.priv_proto = _p if _p in PRIV_PROTOS else PRIV_NONE
        self.auth_key = ""
        self.priv_key = ""
        self.saved = False
        if not _HAS_DPAPI:
            return
        for key, attr in (("snmpv3/auth_key_enc", "auth_key"),
                          ("snmpv3/priv_key_enc", "priv_key")):
            enc = settings.value(key, "") or ""
            if not enc:
                continue
            try:
                setattr(self, attr, _unprotect(base64.b64decode(enc)))
                self.saved = True
            except Exception as e:  # noqa: BLE001
                _log.warning(tr("SNMPv3 凭据解密失败，已清空保存的口令: %s"), e)
                setattr(self, attr, "")
