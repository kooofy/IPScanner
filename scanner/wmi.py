# -*- coding: utf-8 -*-
"""WMI/WinRM 远程设备识别（需目标为 Windows 且提供管理员凭据）。

通过 PowerShell 的 CIM cmdlet 查询远程主机的硬件与系统信息，作为对纯被动指纹
之外的"权威"设备识别手段。典型适用场景：规范管理的公司域环境。

**传输层**（P2 功能批新增 WinRM 回退）
--------------------------------------
CIM 有两条独立通路，二者的防火墙要求差别很大：

- **DCOM**（`New-CimSessionOption -Protocol Dcom`）：需要 135 端口 + 一段动态
  RPC 端口。跨网段/跨防火墙时极易被拦，是"扫描不到"的最常见原因。
- **WinRM**（`-Protocol Wsman`）：只需 5985（HTTP）或 5986（HTTPS）**单个**端口，
  是微软主推的现代通路。本模块使用 WinRM 默认的 HTTP/5985，不涉及证书校验
  （故不需要 `-SkipCACheck` 之类的开关，见脚本内注释）。
  ⚠️ 工作组环境（非域）下 WinRM 客户端默认不信任任何目标，需先把目标加入
  `TrustedHosts` —— 这是**客户端安全配置**，本模块只在报错里给出提示，
  **绝不**替用户静默修改。

旧实现只走 DCOM，于是"目标已启用 WinRM、但 DCOM 被防火墙拦掉"的环境完全识别不了。
现在 `transport="auto"`（默认）会先试 DCOM、失败再试 WinRM；也可强制单通路。

**自动回退的时间预算**：`timeout` 是**单次尝试**的超时。auto 模式下总耗时上限为
`2 × timeout`，且只在"首次尝试是**快速失败**（协议/权限被拒，而非卡住）"时才换通路 ——
因为"卡住"意味着目标整体不可达，换通路一样会卡，白等一个 timeout。

实现要点：
- 零额外依赖：PowerShell 为 Windows 自带，无需 pywin32 / impacket。
- 凭据安全：密码只通过子进程环境变量传入，不出现在进程命令行 / 脚本中。
- 仅查询只读硬件/系统类（Win32_ComputerSystem/BIOS/OperatingSystem/Processor），
  不会改动目标任何状态。
- WinRM 的 `TrustedHosts` 属于**客户端安全配置**，本模块只识别并给出提示，
  **绝不**替用户静默修改系统配置。
"""
import os
import re
import time
import json
import base64
import subprocess
from i18n import tr

# 单次尝试超时（秒）。WMI/DCOM 在防火墙拦截或权限不足时可能长时间挂起，
# 统一用 subprocess timeout 兜底，避免界面线程被拖死。
_WMI_TIMEOUT = 8.0

# ── 传输方式（语言无关的规范值；显示时经 transport_label() 翻译）──
TRANSPORT_AUTO = "auto"
TRANSPORT_DCOM = "dcom"
TRANSPORT_WINRM = "winrm"
TRANSPORTS = (TRANSPORT_AUTO, TRANSPORT_DCOM, TRANSPORT_WINRM)

# auto 模式下"是否值得换通路"的判据：
#   首次尝试耗时 > timeout × 该比例  → 判定为"卡住"，不换通路
#   剩余预算 < _AUTO_MIN_REMAINING   → 时间不够，不换通路
_AUTO_RETRY_ELAPSED_RATIO = 0.7
_AUTO_MIN_REMAINING = 2.0

# 规范值 → 中文源串（显示文本，惰性翻译，见 transport_label()）
_TRANSPORT_LABEL_TEXT = {
    TRANSPORT_AUTO: "自动（先 DCOM，失败再试 WinRM）",
    TRANSPORT_DCOM: "DCOM",
    TRANSPORT_WINRM: "WinRM",
}

# PowerShell 脚本模板：按类分别查询，单类失败不影响其余；最终合并为 JSON。
# 凭证由环境变量注入，脚本本身不含任何凭据明文。
# `__PROTO__` 会被替换成 'Dcom' / 'Wsman'（见下方预编译），避免运行时再分支。
_POWERSHELL_TEMPLATE = """
$ErrorActionPreference = 'Stop'
# 统一输出编码为 UTF-8。PowerShell 在 stdout/stderr 被重定向时默认使用**控制台 OEM
# 代码页**（简体中文 Windows 是 GBK），而调用方按 UTF-8 解码 —— 不显式设置的话，
# 只要返回内容含中文（例如 OS Caption 里的"专业版"）就会解码失败，
# 连失败原因一起丢掉，表现为只看到"PowerShell 退出码 N"。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host_ = $env:IPSC_WMI_HOST
$user_ = $env:IPSC_WMI_USER
$proto = '__PROTO__'
$sec_ = ConvertTo-SecureString $env:IPSC_WMI_PASS -AsPlainText -Force
$cred_ = New-Object System.Management.Automation.PSCredential ($user_, $sec_)
$sess = $null
$cs = $null; $bios = $null; $os = $null; $cpu = $null
try {
    $opt = New-CimSessionOption -Protocol $proto
    # 注意：这里**不要**给 $opt 赋"跳过证书校验"的属性。
    # SkipCACheck / SkipCNCheck 是 New-CimSessionOption 的**开关参数**，
    # 不是返回对象上的属性（WSManSessionOptions 的真实属性名是
    # CertCACheck / CertCNCheck）；把开关当属性赋值会抛"找不到属性"，
    # 而它写在 try 里 → 整次 WinRM 尝试直接废掉。
    # 另外 WinRM 默认走 HTTP/5985，全程不涉及证书校验，本就不需要这两个开关。
    # 整个查询共用一个 CIM 会话（旧实现每次 Get-CimInstance -ComputerName
    # 都会隐式建一次会话，4 个类就是 4 次握手）。
    $sess = New-CimSession -ComputerName $host_ -Credential $cred_ -SessionOption $opt -ErrorAction Stop
    try { $cs   = Get-CimInstance -CimSession $sess -ClassName Win32_ComputerSystem  -ErrorAction Stop | Select-Object Manufacturer,Model,Domain,UserName,Name,TotalPhysicalMemory } catch {}
    try { $bios = Get-CimInstance -CimSession $sess -ClassName Win32_BIOS            -ErrorAction Stop | Select-Object SerialNumber,SMBIOSBIOSVersion } catch {}
    try { $os   = Get-CimInstance -CimSession $sess -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption,Version,OSArchitecture,BuildNumber,LastBootUpTime } catch {}
    try { $cpu  = Get-CimInstance -CimSession $sess -ClassName Win32_Processor       -ErrorAction Stop | Select-Object Name,NumberOfCores } catch {}
}
catch {
    # 建会话就失败（防火墙 / 凭据 / 未启用）。错误**走 stdout 的 JSON**，不写 stderr：
    # stderr 在重定向时会被 PowerShell 包成 CLIXML（既难读又容易踩编码坑），
    # 而 stdout 是同一个已被强制为 UTF-8、且调用方本来就在解析的通道。
    [PSCustomObject]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 0
}
finally {
    if ($sess) { Remove-CimSession $sess -ErrorAction SilentlyContinue }
}
[PSCustomObject]@{
    ok = $true
    ComputerSystem = $cs
    BIOS = $bios
    OS = $os
    CPU = $cpu
} | ConvertTo-Json -Compress -Depth 4
"""


def _encode_script(protocol: str) -> str:
    """把脚本编码为 UTF-16LE Base64，作为 -EncodedCommand 传入（免引号转义）。"""
    text = _POWERSHELL_TEMPLATE.replace("__PROTO__", protocol)
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


# 协议名（CIM 口径）→ 预编译脚本
_PROTOCOL_SCRIPTS = {proto: _encode_script(proto) for proto in ("Dcom", "Wsman")}

# 传输规范值 → CIM 协议名
_PROTOCOL_BY_TRANSPORT = {
    TRANSPORT_DCOM: "Dcom",
    TRANSPORT_WINRM: "Wsman",
}


def transport_label(value: str) -> str:
    """传输方式/偏好值 → 当前语言的显示名（惰性翻译）。

    规范值（auto/dcom/winrm）会落库、会进日志，**只在显示时**经此函数翻译。
    """
    return tr(_TRANSPORT_LABEL_TEXT.get(value, value))


def _attempts_for(transport: str):
    """把传输偏好展开成 [(CIM 协议名, 传输规范值), ...] 尝试序列。"""
    if transport == TRANSPORT_DCOM:
        return [(_PROTOCOL_BY_TRANSPORT[TRANSPORT_DCOM], TRANSPORT_DCOM)]
    if transport == TRANSPORT_WINRM:
        return [(_PROTOCOL_BY_TRANSPORT[TRANSPORT_WINRM], TRANSPORT_WINRM)]
    # auto：先 DCOM（兼容既有环境，且不要求目标启用 WinRM），失败再试 WinRM。
    return [
        (_PROTOCOL_BY_TRANSPORT[TRANSPORT_DCOM], TRANSPORT_DCOM),
        (_PROTOCOL_BY_TRANSPORT[TRANSPORT_WINRM], TRANSPORT_WINRM),
    ]


def _classify_error(text: str) -> str:
    """把 PowerShell 的原始报错归类成一句**可操作**的中文提示。

    WinRM/DCOM 的报错原文（多为英文 + HRESULT）对用户毫无指导意义，
    这里只做关键词归类；识别不出就返回空串，不硬凑。
    """
    t = (text or "").lower()
    if not t:
        return ""
    if "trustedhosts" in t or "0x80090311" in t:
        return tr("WinRM 客户端未信任该目标：工作组环境需把目标加入 TrustedHosts，或改用域账号")
    if "access is denied" in t or "0x80070005" in t or "拒绝访问" in t:
        return tr("凭据被拒绝：用户名/密码错误，或该账号在目标上无管理员权限")
    if ("rpc server is unavailable" in t or "0x800706ba" in t
            or "rpc 服务器不可用" in t):
        return tr("DCOM/RPC 不可达：135 端口或动态 RPC 端口被防火墙拦截")
    if ("ws-management" in t or "0x80338012" in t or "winrm" in t
            or "cannot process the request" in t):
        return tr("WinRM 不可用：目标未启用 WinRM，或 5985/5986 端口被拦截")
    if ("cannot find the computer" in t or "network path" in t
            or "找不到网络路径" in t or "找不到网络名" in t):
        return tr("目标主机不可达：主机名/地址无法解析或网络不通")
    return ""


# PowerShell 在"错误流被重定向"时会把错误序列化成 CLIXML（形如
# `#< CLIXML\r\n<Objs ...><S S="Error">文本_x000D__x000A_</S>...`）。
_CLIXML_HEADER = "#< CLIXML"
_CLIXML_ITEM_RE = re.compile(r'<S S="(?:Error|Warning)">(.*?)</S>', re.S)
_CLIXML_ESCAPE_RE = re.compile(r"_x[0-9A-Fa-f]{4}_")


def _clean_stderr(text: str) -> str:
    """把 CLIXML 包装还原成可读文本。

    正常失败路径走 stdout 的 JSON（见脚本 catch 块），用不到这里；只有
    "脚本本身没跑起来"（语法错误 / PowerShell 版本过旧）才会落到 stderr，
    而那种情况 PowerShell 会输出 CLIXML —— 原样展示给用户完全不可读。
    """
    if not text:
        return ""
    if not text.startswith(_CLIXML_HEADER):
        return text
    parts = [p.strip() for p in _CLIXML_ITEM_RE.findall(text) if p.strip()]
    if not parts:
        return ""
    joined = _CLIXML_ESCAPE_RE.sub(" ", " ".join(parts))
    return re.sub(r"\s{2,}", " ", joined).strip()


def _total_memory_gb(value):
    """WMI 的 `TotalPhysicalMemory`（字符串/整数/浮点）→ GB（保留 1 位）。

    缺失 / 非数值 / 负数返回 `None`（调用方保持默认 0.0）。

    🔴 **刻意不用 try/except**：WMI 缺字段是常态，抛了再 `pass` 既是慢路径，
    又会被 `tests/test_logging_policy.py` 的静默吞异常棘轮记一笔。这里改成
    显式的类型判断 —— 控制流一眼可见，且"不是数值"与"是 0"能区分开
    （0 字节内存是不存在的，`None` 才是"没拿到"）。
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text.lstrip("+-").isdigit():
            return None
        value = int(text)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None          # NaN / inf：`int()` 会抛，直接判掉
        value = int(value)
    elif not isinstance(value, int):
        return None
    if value <= 0:
        return None
    return round(value / (1024 ** 3), 1)


def _flatten(raw: dict) -> dict:
    """把 PowerShell 返回的嵌套对象拍平为统一字段。"""
    out = {
        "wmi_manufacturer": "",
        "wmi_model": "",
        "wmi_serial": "",
        "wmi_bios": "",
        "wmi_os": "",
        "wmi_os_version": "",
        "wmi_os_arch": "",
        "wmi_domain": "",
        "wmi_user": "",
        "wmi_cpu": "",
        "wmi_ram_gb": 0.0,
        "wmi_last_boot": "",
        "wmi_hostname": "",
        "wmi_transport": "",
        "wmi_error": "",
    }
    cs = raw.get("ComputerSystem") or {}
    bios = raw.get("BIOS") or {}
    os_ = raw.get("OS") or {}
    cpu = raw.get("CPU") or {}

    # Win32_ComputerSystem 在某些版本返回的是单行对象（dict），但 PowerShell
    # Select-Object 在单结果时仍是对象；ConvertTo-Json 默认对单元素数组会拆成对象，
    # 多结果才是列表。这里统一当 dict 处理（WMI 单类查询恒为单行）。
    if isinstance(cs, list):
        cs = cs[0] if cs else {}
    if isinstance(bios, list):
        bios = bios[0] if bios else {}
    if isinstance(os_, list):
        os_ = os_[0] if os_ else {}
    if isinstance(cpu, list):
        cpu = cpu[0] if cpu else {}

    out["wmi_manufacturer"] = (cs.get("Manufacturer") or "").strip()
    out["wmi_model"] = (cs.get("Model") or "").strip()
    out["wmi_domain"] = (cs.get("Domain") or "").strip()
    out["wmi_user"] = (cs.get("UserName") or "").strip()
    out["wmi_hostname"] = (cs.get("Name") or "").strip()
    mem_gb = _total_memory_gb(cs.get("TotalPhysicalMemory"))
    if mem_gb is not None:
        out["wmi_ram_gb"] = mem_gb

    out["wmi_serial"] = (bios.get("SerialNumber") or "").strip()
    out["wmi_bios"] = (bios.get("SMBIOSBIOSVersion") or "").strip()

    out["wmi_os"] = (os_.get("Caption") or "").strip()
    out["wmi_os_version"] = (os_.get("Version") or "").strip()
    out["wmi_os_arch"] = (os_.get("OSArchitecture") or "").strip()
    # LastBootUpTime 是 CIM datetime (YYYYMMDDHHMMSS.mmmmmmsUUU)，转可读
    lbt = os_.get("LastBootUpTime")
    if lbt:
        try:
            out["wmi_last_boot"] = _cim_datetime_to_str(lbt)
        except Exception:
            out["wmi_last_boot"] = str(lbt)

    out["wmi_cpu"] = (cpu.get("Name") or "").strip()

    # 任一关键字段缺失即视为基本失败（多半是权限/防火墙导致返回空对象）
    if not (out["wmi_manufacturer"] or out["wmi_model"] or out["wmi_os"]):
        out["wmi_error"] = tr("目标未返回任何设备信息（权限不足、WMI 被防火墙拦截，或目标非 Windows）")
    return out


def _cim_datetime_to_str(val: str) -> str:
    """把 CIM datetime 字符串转 'YYYY-MM-DD HH:MM:SS'。"""
    s = str(val)
    if len(s) >= 14 and s[:14].isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
    return s


def _full_username(username: str, domain: str) -> str:
    """凭证用户名：已带域分隔符则用原值，否则拼 domain\\\\user。"""
    if "\\" in username:
        return username
    if domain:
        return f"{domain}\\{username}"
    return username


def _run_powershell(protocol: str, ip: str, user_full: str, password: str,
                    timeout: float):
    """执行一次单传输的 PowerShell CIM 查询。

    Returns:
        (raw, error)：成功时 raw 为解析出的 dict（`ok` 为 True）且 error 为空；
        失败时 raw 为 None，error 为人类可读原因。

    错误来源有两个通道：脚本内 `catch` 会输出 `{ok:false, error:...}` 到 **stdout**
    （主通道，已强制 UTF-8）；只有脚本自身没跑起来时才会落到 stderr，
    那种情况下 PowerShell 会输出 CLIXML，由 `_clean_stderr()` 还原。
    """
    env = dict(os.environ)
    env["IPSC_WMI_HOST"] = ip
    env["IPSC_WMI_USER"] = user_full
    env["IPSC_WMI_PASS"] = password

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", _PROTOCOL_SCRIPTS[protocol]],
            env=env, capture_output=True, timeout=timeout,
            # 固定按 UTF-8 解码（脚本里已把 [Console]::OutputEncoding 设为 UTF-8）。
            # errors="replace" 是最后一道保险：解码失败会让 subprocess 的读取线程
            # 抛 UnicodeDecodeError、**整个输出连同失败原因一起丢失**（只剩"退出码 N"），
            # 那比看到几个乱码严重得多。
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return None, f"查询超时（{timeout:.0f}s），目标可能被防火墙拦截或不可达"
    except FileNotFoundError:
        return None, tr("未找到 powershell，WMI 识别仅支持 Windows 宿主")
    except Exception as e:  # noqa: BLE001
        return None, f"启动 PowerShell 失败: {e}"

    out_text = (proc.stdout or "").strip()
    err_text = _clean_stderr((proc.stderr or "").strip())
    if not out_text:
        msg = err_text or (f"PowerShell 退出码 {proc.returncode}"
                           if proc.returncode else tr("无输出"))
        return None, msg

    try:
        raw = json.loads(out_text)
    except json.JSONDecodeError:
        return None, f"返回无法解析: {out_text[:200]}"

    if raw.get("ok") is not True:
        return None, raw.get("error") or tr("查询失败")
    return raw, ""


# 单条原始报错的展示上限。PowerShell 的 WinRM 报错动辄 300+ 字符（还带配置指引），
# 直接塞进 tooltip 完全没法看；关键信息已在 _classify_error() 归类的提示里，
# 这里只保留原文开头供排障。
_MAX_ERR_CHARS = 160


def _truncate(text: str, limit: int = _MAX_ERR_CHARS) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _format_failure(errors) -> str:
    """把各通路的失败原因合成一条可操作的消息。"""
    if not errors:
        return tr("WMI 查询失败")
    text = " | ".join(
        f"{transport_label(tv)}: {_truncate(msg)}" for tv, msg in errors
    )
    hint = ""
    for _tv, msg in errors:
        # 归类用**完整**原文（截断只影响展示）
        hint = _classify_error(msg)
        if hint:
            break
    return f"{text}；{hint}" if hint else text


def wmi_query(ip: str, username: str, password: str, domain: str = "",
              timeout: float = None, transport: str = TRANSPORT_AUTO) -> dict:
    """
    对单台 Windows 主机执行 WMI/CIM 识别。

    Args:
        ip: 目标 IP
        username: 管理员用户名（不含域；若 username 已含 '\\\\' 则忽略 domain）
        password: 管理员密码
        domain: 域（可选）。当 username 不含 '\\\\' 时，凭证拼为 'DOMAIN\\\\user'
        timeout: **单次尝试**的超时（秒），默认 _WMI_TIMEOUT。
                 auto 模式下总耗时上限为 2 × timeout（且只在快速失败时才换通路）。
        transport: TRANSPORT_AUTO（默认，先 DCOM 失败再 WinRM）/
                   TRANSPORT_DCOM（仅 DCOM）/ TRANSPORT_WINRM（仅 WinRM）

    Returns:
        dict，含统一字段 wmi_manufacturer / wmi_model / wmi_serial / wmi_os /
        wmi_domain / wmi_user / wmi_cpu / wmi_ram_gb / wmi_last_boot /
        wmi_transport（实际成功的通路，失败时为空）/ wmi_error 等。
        失败时 wmi_error 非空，并尽量附带可操作提示。
    """
    if timeout is None:
        timeout = _WMI_TIMEOUT

    if not ip or not username or not password:
        return _error_dict(tr("缺少目标 IP 或凭据（用户名/密码不能为空）"))

    if transport not in TRANSPORTS:
        transport = TRANSPORT_AUTO

    user_full = _full_username(username, domain)
    attempts = _attempts_for(transport)
    started = time.monotonic()
    errors = []                      # [(传输规范值, 失败原因)]

    for idx, (protocol, transport_value) in enumerate(attempts):
        attempt_timeout = timeout
        if idx > 0:
            elapsed = time.monotonic() - started
            if elapsed > timeout * _AUTO_RETRY_ELAPSED_RATIO:
                # 首次尝试"卡住"了：目标整体不可达，换通路一样会卡
                errors.append((transport_value, tr("跳过：前一次尝试已耗尽时间预算")))
                break
            remaining = timeout - elapsed
            if remaining < _AUTO_MIN_REMAINING:
                errors.append((transport_value, tr("跳过：剩余时间不足以完成一次查询")))
                break
            attempt_timeout = remaining

        raw, err = _run_powershell(
            protocol, ip, user_full, password, attempt_timeout
        )
        if raw is not None:
            result = _flatten(raw)
            if not result["wmi_error"]:
                result["wmi_transport"] = transport_value
                return result
            # 会话建起来了但字段全空 —— 视为本次通路失败，交给下一种
            err = result["wmi_error"]
        errors.append((transport_value, err))

    return _error_dict(_format_failure(errors))


def _error_dict(msg: str, transport: str = "") -> dict:
    return {
        "wmi_manufacturer": "", "wmi_model": "", "wmi_serial": "",
        "wmi_bios": "", "wmi_os": "", "wmi_os_version": "", "wmi_os_arch": "",
        "wmi_domain": "", "wmi_user": "", "wmi_cpu": "", "wmi_ram_gb": 0.0,
        "wmi_last_boot": "", "wmi_hostname": "",
        "wmi_transport": transport,
        "wmi_error": msg,
    }


def wmi_device_class(manufacturer: str, model: str) -> str:
    """根据 WMI 厂商/型号粗略归类设备类别（仅在原指纹未判定时补充）。

    返回**语言无关的规范值**（与 scanner/classify.py 保持一致），
    显示时才翻译；该值会落库到 scan_history.db。
    """
    text = f"{manufacturer} {model}".lower()
    server_kw = ("poweredge", "proliant", "system x", "server", "r720", "r730",
                 "r740", "dl360", "dl380", "tower server")
    if any(k in text for k in server_kw):
        return "服务器"
    # 注意：这里的中文厂商名是**匹配关键词**（WMI 可能返回中文厂商名），
    # 不能包 tr()，否则英文模式下会变成英文词而匹配不到。
    pc_vendors = ("dell", "hp", "hewlett", "lenovo", "thinkcentre", "thinkpad",
                  "asus", "acer", "msi", "micro-star", "apple", "gigabyte",
                  "神舟", "清华同方", "华为", "hasee")
    if any(v in text for v in pc_vendors):
        return "电脑"
    return ""


def merge_wmi(result, wmi_dict: dict):
    """把 WMI 查询结果合并进 ScanResult，并用权威信息补全设备指纹。

    纯函数（不依赖 PyQt），便于单元测试。修改传入的 result 对象。
    """
    result.wmi_manufacturer = wmi_dict.get("wmi_manufacturer", "") or ""
    result.wmi_model = wmi_dict.get("wmi_model", "") or ""
    result.wmi_serial = wmi_dict.get("wmi_serial", "") or ""
    result.wmi_bios = wmi_dict.get("wmi_bios", "") or ""
    result.wmi_os = wmi_dict.get("wmi_os", "") or ""
    result.wmi_os_version = wmi_dict.get("wmi_os_version", "") or ""
    result.wmi_os_arch = wmi_dict.get("wmi_os_arch", "") or ""
    result.wmi_domain = wmi_dict.get("wmi_domain", "") or ""
    result.wmi_user = wmi_dict.get("wmi_user", "") or ""
    result.wmi_cpu = wmi_dict.get("wmi_cpu", "") or ""
    # 实际生效的传输通路（语言无关的规范值 dcom/winrm），仅供展示与排障
    result.wmi_transport = wmi_dict.get("wmi_transport", "") or ""
    try:
        result.wmi_ram_gb = float(wmi_dict.get("wmi_ram_gb", 0) or 0)
    except (TypeError, ValueError):
        result.wmi_ram_gb = 0.0
    result.wmi_last_boot = wmi_dict.get("wmi_last_boot", "") or ""
    result.wmi_error = wmi_dict.get("wmi_error", "") or ""

    if result.wmi_error:
        result.wmi_identified = False
        return
    result.wmi_identified = True

    # 用权威硬件信息补全设备指纹
    if result.wmi_model and not result.device_model:
        result.device_model = result.wmi_model
    if not result.device_class:
        result.device_class = wmi_device_class(
            result.wmi_manufacturer, result.wmi_model
        )
