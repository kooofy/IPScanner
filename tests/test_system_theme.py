# -*- coding: utf-8 -*-
"""P3-3 回归测试：主题模式与「跟随系统」。

历史缺陷
--------
旧版主题只有两个开关：`theme/dark`（当前明暗）与 `theme/auto_time`
（18:00 后自动转深色）。用户既无法显式指定明暗，也无法跟随 Windows 的
「应用模式」—— 只能在某天 18:00 被突然变脸。

本次改动把「跟随系统」升为默认，并按平台读系统偏好。这里的测试覆盖三件事：

1. 纯逻辑 `is_time_dark` / `resolve_dark` 在四种模式下的输出；
2. Windows 注册表读取的**语义**（`AppsUseLightTheme: 0` = 深色，
   这是最容易写反的一处）；
3. 读不到系统偏好时**必须保持现状**，不能擅自翻成浅色。
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import system_theme


class TimeDarkTest(unittest.TestCase):
    """「按时间」模式的时段判定。"""

    def test_evening_hours_are_dark(self):
        for h in (18, 19, 21, 23):
            self.assertTrue(system_theme.is_time_dark(h), f"{h} 点应为深色")

    def test_early_morning_is_dark(self):
        for h in (0, 1, 3, 5):
            self.assertTrue(system_theme.is_time_dark(h), f"{h} 点应为深色")

    def test_daytime_is_light(self):
        for h in (6, 9, 12, 15, 17):
            self.assertFalse(system_theme.is_time_dark(h), f"{h} 点应为浅色")

    def test_boundaries_are_half_open(self):
        """[18:00, 次日 06:00) —— 18 点入、6 点出。"""
        self.assertTrue(system_theme.is_time_dark(system_theme.TIME_DARK_START))
        self.assertFalse(system_theme.is_time_dark(system_theme.TIME_DARK_END))


class ResolveDarkTest(unittest.TestCase):
    """四种模式 → 实际明暗。"""

    def test_light_and_dark_ignore_everything_else(self):
        for sys_pref in (True, False, None):
            self.assertFalse(
                system_theme.resolve_dark(
                    system_theme.MODE_LIGHT, current=True, system=sys_pref, hour=23
                ),
                "浅色模式应恒为浅色，不受系统偏好或时间影响",
            )
            self.assertTrue(
                system_theme.resolve_dark(
                    system_theme.MODE_DARK, current=False, system=sys_pref, hour=12
                ),
                "深色模式应恒为深色，不受系统偏好或时间影响",
            )

    def test_time_mode_follows_hour(self):
        self.assertTrue(
            system_theme.resolve_dark(system_theme.MODE_TIME, hour=20))
        self.assertFalse(
            system_theme.resolve_dark(system_theme.MODE_TIME, hour=10))

    def test_system_mode_follows_system_preference(self):
        self.assertTrue(
            system_theme.resolve_dark(system_theme.MODE_SYSTEM, system=True))
        self.assertFalse(
            system_theme.resolve_dark(system_theme.MODE_SYSTEM, system=False))

    def test_system_mode_keeps_current_when_unknown(self):
        """读不到系统偏好时保持现状 —— 这是本模块最关键的一条约束。

        若这里返回 False，那么每次在非 Windows 平台或注册表缺失时，
        用户显式选过的深色都会被悄悄翻成浅色。
        """
        self.assertTrue(
            system_theme.resolve_dark(
                system_theme.MODE_SYSTEM, current=True, system=None))
        self.assertFalse(
            system_theme.resolve_dark(
                system_theme.MODE_SYSTEM, current=False, system=None))

    def test_explicit_none_does_not_probe_platform(self):
        """显式传 system=None 表示"已知读不到"，不得再去探测。

        这里刻意把探测器换成"会返回 True"的替身：若实现把 None 当成
        "没传参"，结果就会变成 True，与"保持现状"矛盾。
        """
        original = system_theme.system_prefers_dark
        try:
            system_theme.system_prefers_dark = lambda: True
            self.assertFalse(
                system_theme.resolve_dark(
                    system_theme.MODE_SYSTEM, current=False, system=None),
                "显式传入的 None 被误当成'未传参'，从而绕过了保持现状的语义",
            )
        finally:
            system_theme.system_prefers_dark = original

    def test_unknown_mode_falls_back_to_system(self):
        self.assertTrue(
            system_theme.resolve_dark("bogus", current=False, system=True))
        self.assertTrue(
            system_theme.resolve_dark(None, current=True, system=None),
            "未知模式 + 系统偏好未知时应保持现状",
        )

    def test_system_none_probes_platform(self):
        """不传 system 时应自行探测（这里用替身拦截，避免依赖真机注册表）。"""
        original = system_theme.system_prefers_dark
        try:
            system_theme.system_prefers_dark = lambda: True
            self.assertTrue(
                system_theme.resolve_dark(system_theme.MODE_SYSTEM))
            system_theme.system_prefers_dark = lambda: None
            self.assertTrue(
                system_theme.resolve_dark(system_theme.MODE_SYSTEM, current=True))
        finally:
            system_theme.system_prefers_dark = original


class _FakeWinreg(types.ModuleType):
    """最小 winreg 替身：只需支持 OpenKey / QueryValueEx / HKEY_CURRENT_USER。"""

    HKEY_CURRENT_USER = object()

    def __init__(self, value=None, raises=None):
        super().__init__("winreg")
        self._value = value
        self._raises = raises
        self.opened_keys = []

    def OpenKey(self, hive, path):  # noqa: N802 —— 保持 winreg 的命名
        self.opened_keys.append((hive, path))
        if self._raises is not None:
            raise self._raises
        return _FakeKey()

    def QueryValueEx(self, key, name):  # noqa: N802
        return self._value, 4  # 4 = REG_DWORD


class _FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class WindowsRegistryTest(unittest.TestCase):
    """Windows「应用模式」注册表语义。"""

    def _with_fake_winreg(self, fake, fn):
        original = sys.modules.get("winreg")
        sys.modules["winreg"] = fake
        try:
            return fn()
        finally:
            if original is None:
                sys.modules.pop("winreg", None)
            else:
                sys.modules["winreg"] = original

    def test_zero_means_dark(self):
        """AppsUseLightTheme=0 → 深色。写反了会导致主题完全颠倒。"""
        fake = _FakeWinreg(value=0)
        self.assertTrue(self._with_fake_winreg(
            fake, system_theme._windows_prefers_dark))

    def test_one_means_light(self):
        fake = _FakeWinreg(value=1)
        self.assertFalse(self._with_fake_winreg(
            fake, system_theme._windows_prefers_dark))

    def test_reads_the_apps_mode_key_not_system_mode(self):
        """必须读 AppsUseLightTheme（应用模式），不是 SystemUsesLightTheme。

        后者是任务栏/开始菜单那套，与"应用窗口该不该深色"无关。
        """
        fake = _FakeWinreg(value=1)
        self._with_fake_winreg(fake, system_theme._windows_prefers_dark)
        self.assertTrue(fake.opened_keys, "应尝试打开注册表键")
        _hive, path = fake.opened_keys[0]
        self.assertIn("Themes", path)
        self.assertIn("Personalize", path)

    def test_missing_key_returns_none(self):
        """键/值不存在（老系统或用户从未设置）→ 未知，而不是猜 False。"""
        fake = _FakeWinreg(raises=OSError("not found"))
        self.assertIsNone(self._with_fake_winreg(
            fake, system_theme._windows_prefers_dark))


class PlatformDispatchTest(unittest.TestCase):
    """system_prefers_dark 的平台分发与失败兜底。"""

    def setUp(self):
        self._orig_platform = system_theme.platform
        self._orig_win = system_theme._windows_prefers_dark
        self._orig_mac = system_theme._macos_prefers_dark
        self._orig_lin = system_theme._linux_prefers_dark

    def tearDown(self):
        system_theme.platform = self._orig_platform
        system_theme._windows_prefers_dark = self._orig_win
        system_theme._macos_prefers_dark = self._orig_mac
        system_theme._linux_prefers_dark = self._orig_lin

    def test_windows_dispatches_to_registry_reader(self):
        system_theme.platform = lambda: "win32"
        system_theme._windows_prefers_dark = lambda: True
        self.assertTrue(system_theme.system_prefers_dark())

    def test_macos_dispatches_to_defaults_reader(self):
        system_theme.platform = lambda: "darwin"
        system_theme._macos_prefers_dark = lambda: True
        self.assertTrue(system_theme.system_prefers_dark())

    def test_linux_dispatches_to_gsettings_reader(self):
        system_theme.platform = lambda: "linux"
        system_theme._linux_prefers_dark = lambda: False
        self.assertFalse(system_theme.system_prefers_dark())

    def test_unsupported_platform_returns_none(self):
        system_theme.platform = lambda: "aix"
        self.assertIsNone(system_theme.system_prefers_dark())

    def test_reader_exception_does_not_propagate(self):
        """平台探测是"锦上添花"，任何意外都不能打断启动。"""
        def _boom():
            raise RuntimeError("注册表被锁")
        system_theme.platform = lambda: "win32"
        system_theme._windows_prefers_dark = _boom
        self.assertIsNone(system_theme.system_prefers_dark())


class MigrateModeTest(unittest.TestCase):
    """旧配置迁移：外观必须保持不变。"""

    def test_valid_stored_mode_wins(self):
        for mode in system_theme.VALID_MODES:
            self.assertEqual(
                system_theme.migrate_mode(
                    mode, has_legacy_dark=True, legacy_dark=True,
                    legacy_auto=True),
                mode,
                "已有合法的 theme/mode 时不应被旧键覆盖",
            )

    def test_legacy_auto_time_becomes_time_mode(self):
        """旧版开了"按时间自动切换"→ 新版的 time 模式（行为等价）。"""
        self.assertEqual(
            system_theme.migrate_mode(
                "", has_legacy_dark=True, legacy_dark=False, legacy_auto=True),
            system_theme.MODE_TIME,
        )

    def test_legacy_dark_is_frozen_not_reset(self):
        """老用户当时的深色/浅色必须固化，不能因为引入新模式被改掉。"""
        self.assertEqual(
            system_theme.migrate_mode(
                "", has_legacy_dark=True, legacy_dark=True, legacy_auto=False),
            system_theme.MODE_DARK,
        )
        self.assertEqual(
            system_theme.migrate_mode(
                "", has_legacy_dark=True, legacy_dark=False, legacy_auto=False),
            system_theme.MODE_LIGHT,
        )

    def test_fresh_install_defaults_to_system(self):
        self.assertEqual(
            system_theme.migrate_mode(
                "", has_legacy_dark=False, legacy_dark=False, legacy_auto=False),
            system_theme.MODE_SYSTEM,
        )

    def test_invalid_stored_mode_is_ignored(self):
        self.assertEqual(
            system_theme.migrate_mode(
                "neon", has_legacy_dark=True, legacy_dark=True,
                legacy_auto=False),
            system_theme.MODE_DARK,
        )


class ThemeModeTableTest(unittest.TestCase):
    """菜单表与解析模块的常量必须对齐。"""

    def test_menu_keys_match_valid_modes(self):
        from main_window import THEME_MODES
        keys = tuple(k for k, _lbl in THEME_MODES)
        self.assertEqual(keys, system_theme.VALID_MODES)

    def test_default_mode_is_system_and_present(self):
        from main_window import DEFAULT_THEME_MODE
        self.assertEqual(DEFAULT_THEME_MODE, system_theme.DEFAULT_MODE)
        self.assertEqual(DEFAULT_THEME_MODE, system_theme.MODE_SYSTEM)
        self.assertIn(DEFAULT_THEME_MODE, system_theme.VALID_MODES)


if __name__ == "__main__":
    unittest.main()
