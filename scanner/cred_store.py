# -*- coding: utf-8 -*-
"""WMI 管理员凭据存储。

- 运行期凭据保存在内存，供本次会话多次 WMI 识别复用。
- 持久化：使用 Windows DPAPI（CryptProtectData / CryptUnprotectData）将密码加密后
  存入 QSettings（ipscanner.ini）。解密只能由同一用户在同一台机器完成，明文不落盘。
- 非 Windows 环境无 DPAPI，自动退化为"仅内存、不持久化"，save_to 静默跳过。
"""
import base64

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
        raise RuntimeError("当前平台不支持 DPAPI 加密")

    def _unprotect(blob: bytes) -> str:
        raise RuntimeError("当前平台不支持 DPAPI 解密")


class WmiCredentialStore:
    """WMI 凭据：内存态 + 可选的 DPAPI 加密持久化。"""

    def __init__(self):
        self.username: str = ""
        self.password: str = ""
        self.domain: str = ""
        self.saved: bool = False

    def has_creds(self) -> bool:
        return bool(self.username) and bool(self.password)

    def set(self, username: str, password: str, domain: str = ""):
        self.username = username or ""
        self.password = password or ""
        self.domain = domain or ""

    def save_to(self, settings):
        """加密持久化到 QSettings。非 Windows 环境静默跳过。"""
        try:
            settings.setValue("wmi/username", self.username)
            settings.setValue("wmi/domain", self.domain)
            if self.password and _HAS_DPAPI:
                blob = _protect(self.password)
                settings.setValue("wmi/password_enc", base64.b64encode(blob).decode("ascii"))
                self.saved = True
        except Exception as e:  # noqa: BLE001
            print("WMI 凭据加密保存失败（已忽略）:", e)

    def load_from(self, settings):
        """从 QSettings 解密载入。解密失败则清空密码，不影响启动。"""
        self.username = settings.value("wmi/username", "") or ""
        self.domain = settings.value("wmi/domain", "") or ""
        enc = settings.value("wmi/password_enc", "") or ""
        self.password = ""
        self.saved = False
        if enc and _HAS_DPAPI:
            try:
                self.password = _unprotect(base64.b64decode(enc))
                self.saved = True
            except Exception as e:  # noqa: BLE001
                print("WMI 凭据解密失败（已忽略）:", e)
                self.password = ""
