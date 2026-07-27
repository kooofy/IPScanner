# -*- coding: utf-8 -*-
"""WMI/WinRM 远程设备识别（需目标为 Windows 且提供管理员凭据）。

通过 PowerShell 的 Get-CimInstance（WMI/CIM over DCOM）查询远程主机的
硬件与系统信息，作为对纯被动指纹之外的"权威"设备识别手段。
典型适用场景：规范管理的公司域环境（域管理员凭据可访问域内 Windows 终端）。

实现要点：
- 零额外依赖：PowerShell 为 Windows 自带，无需安装 pywin32 / impacket。
- 凭据安全：密码只通过子进程环境变量传入，不出现在进程命令行 / 脚本中，
  避免被本地进程查看工具捕获。
- 仅查询只读硬件/系统类（Win32_ComputerSystem/BIOS/OperatingSystem/Processor），
  不会改动目标任何状态。
"""
import os
import sys
import json
import base64
import subprocess
from i18n import tr

# 单次查询超时（秒）。WMI/DCOM 在防火墙拦截或权限不足时可能长时间挂起，
# 统一用 subprocess timeout 兜底，避免界面线程被拖死。
_WMI_TIMEOUT = 8.0

# PowerShell 脚本模板：按类分别查询，单类失败不影响其余；最终合并为 JSON。
# 凭证由环境变量注入，脚本本身不含任何凭据明文。
_POWERSHELL_SCRIPT = """
$ErrorActionPreference = 'Stop'
$host_ = $env:IPSC_WMI_HOST
$user_ = $env:IPSC_WMI_USER
$sec_ = ConvertTo-SecureString $env:IPSC_WMI_PASS -AsPlainText -Force
$cred_ = New-Object System.Management.Automation.PSCredential ($user_, $sec_)
$cs = $null; $bios = $null; $os = $null; $cpu = $null
try { $cs = Get-CimInstance -ComputerName $host_ -Credential $cred_ -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object Manufacturer,Model,Domain,UserName,Name,TotalPhysicalMemory } catch {}
try { $bios = Get-CimInstance -ComputerName $host_ -Credential $cred_ -ClassName Win32_BIOS -ErrorAction Stop | Select-Object SerialNumber,SMBIOSBIOSVersion } catch {}
try { $os = Get-CimInstance -ComputerName $host_ -Credential $cred_ -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption,Version,OSArchitecture,BuildNumber,LastBootUpTime } catch {}
try { $cpu = Get-CimInstance -ComputerName $host_ -Credential $cred_ -ClassName Win32_Processor -ErrorAction Stop | Select-Object Name,NumberOfCores } catch {}
[PSCustomObject]@{
    ok = $true
    ComputerSystem = $cs
    BIOS = $bios
    OS = $os
    CPU = $cpu
} | ConvertTo-Json -Compress -Depth 4
"""

# 将脚本编码为 UTF-16LE Base64，作为 -EncodedCommand 传入（避免引号转义问题）
_SCRIPT_B64 = base64.b64encode(
    _POWERSHELL_SCRIPT.encode("utf-16-le")
).decode("ascii")


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
        "wmi_error": "",
    }
    cs = raw.get("ComputerSystem") or {}
    bios = raw.get("BIOS") or {}
    os_ = raw.get("OS") or {}
    cpu = raw.get(tr("CPU")) or {}

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
    try:
        mem = cs.get("TotalPhysicalMemory")
        if mem:
            out["wmi_ram_gb"] = round(int(mem) / (1024 ** 3), 1)
    except (TypeError, ValueError):
        pass

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
        out["wmi_error"] = tr("目标未返回任何设备信息（权限不足、WMI/DCOM 被防火墙拦截，或目标非 Windows）")
    return out


def _cim_datetime_to_str(val: str) -> str:
    """把 CIM datetime 字符串转 'YYYY-MM-DD HH:MM:SS'。"""
    s = str(val)
    if len(s) >= 14 and s[:14].isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
    return s


def wmi_query(ip: str, username: str, password: str, domain: str = "",
              timeout: float = None) -> dict:
    """
    对单台 Windows 主机执行 WMI 识别。

    Args:
        ip: 目标 IP
        username: 管理员用户名（不含域；若 username 已含 '\\' 则忽略 domain）
        password: 管理员密码
        domain: 域（可选）。当 username 不含 '\\' 时，凭证拼为 'DOMAIN\\user'
        timeout: 单次查询超时（秒），默认 _WMI_TIMEOUT

    Returns:
        dict，含统一字段 wmi_manufacturer / wmi_model / wmi_serial / wmi_os /
        wmi_domain / wmi_user / wmi_cpu / wmi_ram_gb / wmi_last_boot / wmi_error 等。
        失败时 wmi_error 非空。
    """
    if timeout is None:
        timeout = _WMI_TIMEOUT

    if not ip or not username or not password:
        return {
            "wmi_manufacturer": "", "wmi_model": "", "wmi_serial": "",
            "wmi_bios": "", "wmi_os": "", "wmi_os_version": "", "wmi_os_arch": "",
            "wmi_domain": "", "wmi_user": "", "wmi_cpu": "", "wmi_ram_gb": 0.0,
            "wmi_last_boot": "", "wmi_hostname": "",
            "wmi_error": tr("缺少目标 IP 或凭据（用户名/密码不能为空）"),
        }

    # 凭证用户名：已带域分隔符则用原值，否则拼 domain\\user
    if "\\" in username:
        user_full = username
    elif domain:
        user_full = f"{domain}\\{username}"
    else:
        user_full = username

    env = dict(os.environ)
    env["IPSC_WMI_HOST"] = ip
    env["IPSC_WMI_USER"] = user_full
    env["IPSC_WMI_PASS"] = password

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", _SCRIPT_B64],
            env=env, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return _error_dict(f"WMI 查询超时（{timeout:.0f}s），目标可能防火墙拦截或不可达")
    except FileNotFoundError:
        return _error_dict(tr("未找到 powershell，WMI 识别仅支持 Windows 宿主"))
    except Exception as e:  # noqa: BLE001
        return _error_dict(f"启动 PowerShell 失败: {e}")

    out_text = (proc.stdout or "").strip()
    err_text = (proc.stderr or "").strip()
    if not out_text:
        msg = err_text or (f"PowerShell 退出码 {proc.returncode}" if proc.returncode else tr("无输出"))
        return _error_dict(f"WMI 查询无输出: {msg}")

    try:
        raw = json.loads(out_text)
    except json.JSONDecodeError:
        return _error_dict(f"WMI 返回无法解析: {out_text[:200]}")

    if raw.get("ok") is not True:
        return _error_dict(raw.get("error") or tr("WMI 查询失败"))

    result = _flatten(raw)
    # 若 flatten 判定为空（授权失败但 PowerShell 没抛错），补充 stderr 线索
    if result["wmi_error"] and err_text:
        result["wmi_error"] = f"{result['wmi_error']} | {err_text[:160]}"
    return result


def _error_dict(msg: str) -> dict:
    return {
        "wmi_manufacturer": "", "wmi_model": "", "wmi_serial": "",
        "wmi_bios": "", "wmi_os": "", "wmi_os_version": "", "wmi_os_arch": "",
        "wmi_domain": "", "wmi_user": "", "wmi_cpu": "", "wmi_ram_gb": 0.0,
        "wmi_last_boot": "", "wmi_hostname": "",
        "wmi_error": msg,
    }


def wmi_device_class(manufacturer: str, model: str) -> str:
    """根据 WMI 厂商/型号粗略归类设备类别（仅在原指纹未判定时补充）。"""
    text = f"{manufacturer} {model}".lower()
    server_kw = ("poweredge", "proliant", "system x", "server", "r720", "r730",
                 "r740", "dl360", "dl380", "tower server")
    if any(k in text for k in server_kw):
        return tr("服务器")
    pc_vendors = ("dell", "hp", "hewlett", "lenovo", "thinkcentre", "thinkpad",
                  "asus", "acer", "msi", "micro-star", "apple", "gigabyte",
                  tr("神舟"), tr("清华同方"), tr("华为"), "hasee")
    if any(v in text for v in pc_vendors):
        return tr("电脑")
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
