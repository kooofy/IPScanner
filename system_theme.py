# -*- coding: utf-8 -*-
"""读取操作系统的「浅色/深色」偏好（对应 docs/reviews/UI_REVIEW.md 的 P3-3）。

为什么需要这个模块
------------------
旧版只有两个主题开关：`theme/dark`（当前是否深色）与 `theme/auto_time`
（18:00 之后自动转深色）。这有两个问题：

1. **与系统脱节** —— Windows 10/11 的「个性化 → 颜色 → 选择默认应用模式」
   是用户表达偏好的标准入口，本工具视而不见；用户白天把系统切到深色，
   打开本工具仍是刺眼的浅色。
2. **按时间猜偏好很不可靠** —— 18:00 这个边界是拍脑袋定的，做夜间运维的人
   反而希望白天也是深色。

所以把「跟随系统」提升为默认行为，把「按时间」降级为可选项。

实现要点
--------
本模块**不依赖 PyQt**，可被测试与 CLI 无成本导入。

Windows 侧读注册表
`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize`
的 `AppsUseLightTheme`（DWORD）：`0` = 深色，`1` = 浅色。这是「应用模式」
而非「Windows 模式」—— 任务栏那套是 `SystemUsesLightTheme`，与本工具无关。

读不到时一律返回 `None`（"未知"），而不是猜一个 False。调用方拿到 `None`
应当**保持当前主题不动**：在信息不足时贸然翻转主题，比不跟随更让人困惑。

模式解析（`resolve_dark`）也放在这里，且是**纯函数**：MainWindow 只做
"取当前状态 → 调它 → 应用结果"三步。这样"四种模式各自该出什么颜色"
可以脱离 Qt 完整单测 —— 而 MainWindow 因为要读配置、起线程，在测试里
构造代价很高，历史上从没有测试构造过它。
"""

import sys
from datetime import datetime

import app_logging

#: 主题模式常量（规范 key，与界面语言无关）
MODE_SYSTEM = "system"
MODE_LIGHT = "light"
MODE_DARK = "dark"
MODE_TIME = "time"

#: 合法模式；顺序即菜单顺序（跟随系统优先，它是新装默认）
VALID_MODES = (MODE_SYSTEM, MODE_LIGHT, MODE_DARK, MODE_TIME)

#: 新装 / 配置损坏时的默认模式
DEFAULT_MODE = MODE_SYSTEM

#: 「按时间」模式的深色时段：[18:00, 次日 06:00)
TIME_DARK_START = 18
TIME_DARK_END = 6

#: Windows 注册表路径与键名（应用模式，不是系统模式）
_WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
_WIN_VALUE = "AppsUseLightTheme"

_LOG = app_logging.get_logger("theme")


def platform() -> str:
    """返回当前平台标识（独立成函数，便于测试覆盖）。"""
    return sys.platform


def _windows_prefers_dark():
    """读 Windows「应用模式」注册表项。返回 True/False/None。"""
    try:
        import winreg
    except ImportError:  # 非 Windows 平台
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, _WIN_VALUE)
    except OSError:
        # 键或值不存在（老版本 Windows / 未设置过）—— 视为未知
        return None
    # AppsUseLightTheme: 0 = 深色, 1 = 浅色
    return not bool(value)


def _macos_prefers_dark():
    """读 macOS 全局偏好 AppleInterfaceStyle。返回 True/False/None。"""
    import subprocess

    try:
        out = subprocess.run(
            ["defaults", "read", "-g", "AppleInterfaceStyle"],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        # 未设置该项 = 浅色模式（macOS 只在深色下写这个键）
        return False
    return out.stdout.strip().lower() == "dark"


def _linux_prefers_dark():
    """读 GNOME 的 color-scheme 设置。返回 True/False/None。"""
    import subprocess

    try:
        out = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    _val = out.stdout.strip().strip("'\"").lower()
    if _val in ("prefer-dark", "dark"):
        return True
    if _val in ("prefer-light", "light", "default"):
        return False
    return None


def system_prefers_dark():
    """返回操作系统是否偏好深色主题。

    Returns:
        True  系统为深色模式
        False 系统为浅色模式
        None  无法判定（非 Windows / 读不到 / 命令失败）
    """
    _plat = platform()
    try:
        if _plat.startswith("win"):
            return _windows_prefers_dark()
        if _plat == "darwin":
            return _macos_prefers_dark()
        if _plat.startswith("linux"):
            return _linux_prefers_dark()
    except Exception as exc:
        # 平台探测属"锦上添花"，任何意外都不应打断启动；但必须留下痕迹，
        # 否则"跟随系统没生效"这类反馈将无从定位。
        _LOG.debug("读取系统主题偏好失败（%s）: %s", _plat, exc)
        return None
    return None


def is_time_dark(hour: int) -> bool:
    """「按时间」模式：给定小时是否落在深色时段（18:00–次日 06:00）。"""
    return hour >= TIME_DARK_START or hour < TIME_DARK_END


#: 「未传入」哨兵。必须与 `None` 区分开 —— `None` 表示"系统偏好未知"，
#: 而"没传这个参数"表示"请你自己去探测"。用 None 兼任两者会让
#: `resolve_dark(..., system=None, current=True)` 意外地去读真实注册表，
#: 从而丢掉 `current`（保持现状）这条语义。
_UNSET = object()


def resolve_dark(mode, current=False, system=_UNSET, hour=None) -> bool:
    """把主题模式解析成"现在到底是不是深色"。

    Args:
        mode:    VALID_MODES 之一；非法值退化为跟随系统。
        current: 当前实际明暗。仅用于 system 模式读不到系统偏好时**保持不变**。
        system:  系统偏好（True/False/None）。不传 = 自行探测；显式传 None
                 = 已知探测不到，此时必须回落到 `current`。
        hour:    「按时间」模式使用的小时（0–23）。None 表示取当前时间。

    Returns:
        该模式对应的深色开关。

    为什么 system 读不到时要返回 current 而不是 False：用户并没有要求
    "变成浅色"，只是要求"跟系统走"；系统偏好未知时维持现状，是唯一不会
    突然刺眼的选择。
    """
    if mode == MODE_LIGHT:
        return False
    if mode == MODE_DARK:
        return True
    if mode == MODE_TIME:
        _h = datetime.now().hour if hour is None else hour
        return is_time_dark(_h)
    # system（含非法/未知取值）
    _sys = system_prefers_dark() if system is _UNSET else system
    if _sys is None:
        return bool(current)
    return bool(_sys)


def migrate_mode(stored_mode, has_legacy_dark, legacy_dark, legacy_auto) -> str:
    """把配置里的主题设置迁移为合法的 `theme_mode`。

    老配置只有两个键：`theme/dark`（当时是否深色）与 `theme/auto_time`
    （是否按时间自动切）。迁移原则是**外观不变** —— 老用户升级后看到的
    明暗应与升级前一致，不能因为引入了新模式就把人家的深色悄悄改掉：

    - 有合法的 `theme/mode` → 直接用；
    - `auto_time` 为真 → `time`（这正是旧版当时的实际行为）；
    - 写过 `theme/dark` → 固化当时的明暗（`dark` / `light`）；
    - 两个键都没有 → 全新安装，用默认值（跟随系统）。

    Args:
        stored_mode:     配置里的 `theme/mode`，可能为空或非法。
        has_legacy_dark: 配置里是否存在 `theme/dark` 键。
        legacy_dark:     `theme/dark` 的值（仅当 has_legacy_dark 时有意义）。
        legacy_auto:     `theme/auto_time` 的值。
    """
    if stored_mode in VALID_MODES:
        return stored_mode
    if legacy_auto:
        return MODE_TIME
    if has_legacy_dark:
        return MODE_DARK if legacy_dark else MODE_LIGHT
    return DEFAULT_MODE
