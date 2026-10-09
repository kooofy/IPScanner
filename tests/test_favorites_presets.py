# -*- coding: utf-8 -*-
"""设备收藏与扫描预设的存储契约（docs/reviews/UI_REVIEW.md P1-3）。

这两块都是"写进 ipscanner.ini 再读回来"的功能，最容易出的问题是：
- 存进去的键和读回来判断用的键不是同一套 → 收藏了但下次打开不显示；
- 预设名里带 `/` 被 QSettings 当成层级分隔符 → 串层级、丢配置；
- 配置损坏时抛异常 → 整个程序起不来。

这里逐条覆盖。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt5.QtCore import QSettings

from favorites import FavoriteStore, favorite_key, MAC_PREFIX, IP_PREFIX
from scan_presets import (
    ScanPresetStore, PresetError, validate_name, MAX_NAME_LEN, MAX_PRESETS,
)
from scanner.models import ScanResult


class _TempSettings:
    """临时 ini 文件承载的 QSettings（用完即删）。"""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="ipscanner_cfg_")
        self.settings = QSettings(os.path.join(self.dir, "t.ini"),
                                  QSettings.IniFormat)
        return self.settings

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


class FavoriteKeyTest(unittest.TestCase):

    def test_prefers_mac_when_present(self):
        r = ScanResult(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(favorite_key(r), MAC_PREFIX + "AA:BB:CC:DD:EE:FF")

    def test_falls_back_to_ip_without_mac(self):
        r = ScanResult(ip="10.0.0.1", mac="")
        self.assertEqual(favorite_key(r), IP_PREFIX + "10.0.0.1")

    def test_mac_case_and_spaces_are_normalized(self):
        a = ScanResult(ip="10.0.0.1", mac=" aa:bb:cc:dd:ee:ff ")
        b = ScanResult(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:FF")
        self.assertEqual(favorite_key(a), favorite_key(b))


class FavoriteStoreTest(unittest.TestCase):

    def test_add_remove_toggle(self):
        with _TempSettings() as s:
            store = FavoriteStore(s)
            r = ScanResult(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
            self.assertFalse(store.is_favorite(r))
            self.assertTrue(store.toggle(r))
            self.assertTrue(store.is_favorite(r))
            self.assertFalse(store.toggle(r))
            self.assertFalse(store.is_favorite(r))

    def test_survives_reload(self):
        """核心回归：存进去的键必须能被重新构造的 store 认出来。"""
        with _TempSettings() as s:
            r = ScanResult(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
            FavoriteStore(s).add(r)
            again = FavoriteStore(QSettings(s.fileName(), QSettings.IniFormat))
            self.assertTrue(again.is_favorite(r))
            self.assertEqual(len(again), 1)

    def test_matches_device_after_ip_change(self):
        """以 MAC 收藏的设备换了 IP 仍应显示为已收藏。"""
        with _TempSettings() as s:
            store = FavoriteStore(s)
            store.add(ScanResult(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF"))
            moved = ScanResult(ip="10.0.0.99", mac="AA:BB:CC:DD:EE:FF")
            self.assertTrue(store.is_favorite(moved))

    def test_ip_only_favorite_does_not_leak_to_other_device(self):
        """仅按 IP 收藏的设备，其 IP 被别的设备占用时不应"继承"收藏。

        这正是"一台设备只存一个键"要避免的串号。
        """
        with _TempSettings() as s:
            store = FavoriteStore(s)
            store.add(ScanResult(ip="10.0.0.1", mac=""))
            other = ScanResult(ip="10.0.0.1", mac="11:22:33:44:55:66")
            self.assertFalse(store.is_favorite(other))

    def test_add_is_idempotent(self):
        with _TempSettings() as s:
            store = FavoriteStore(s)
            r = ScanResult(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
            self.assertTrue(store.add(r))
            self.assertFalse(store.add(r))
            self.assertEqual(len(store), 1)

    def test_corrupt_value_does_not_crash(self):
        with _TempSettings() as s:
            s.setValue("favorites/entries", "not-a-list-just-text")
            store = FavoriteStore(s)
            self.assertEqual(len(store), 0)


class ValidateNameTest(unittest.TestCase):

    def test_rejects_empty(self):
        with self.assertRaises(PresetError):
            validate_name("   ")

    def test_rejects_slash(self):
        """含 `/` 的名字会破坏 QSettings 的层级，必须拒绝。"""
        with self.assertRaises(PresetError):
            validate_name("office/lan")
        with self.assertRaises(PresetError):
            validate_name("office\\lan")

    def test_rejects_overlong(self):
        with self.assertRaises(PresetError):
            validate_name("x" * (MAX_NAME_LEN + 1))

    def test_strips_and_accepts(self):
        self.assertEqual(validate_name("  办公网日常  "), "办公网日常")


class ScanPresetStoreTest(unittest.TestCase):

    def _cfg(self, ranges=None):
        return {
            "ranges": ranges or ["192.168.1.0/24"],
            "level": "quick",
            "protocols": ["HTTP"],
            "tcp_mode": "connect",
            "port_scan": True,
            "mdns": True,
        }

    def test_put_get_delete(self):
        with _TempSettings() as s:
            store = ScanPresetStore(s)
            store.put("办公网", self._cfg())
            self.assertEqual(store.names(), ["办公网"])
            self.assertEqual(store.get("办公网")["ranges"], ["192.168.1.0/24"])
            self.assertTrue(store.delete("办公网"))
            self.assertEqual(store.names(), [])
            self.assertFalse(store.delete("办公网"))

    def test_put_overwrites_same_name(self):
        with _TempSettings() as s:
            store = ScanPresetStore(s)
            store.put("p", self._cfg(["10.0.0.0/24"]))
            store.put("p", self._cfg(["10.0.1.0/24"]))
            self.assertEqual(len(store), 1)
            self.assertEqual(store.get("p")["ranges"], ["10.0.1.0/24"])

    def test_survives_reload(self):
        with _TempSettings() as s:
            ScanPresetStore(s).put("机房全端口", self._cfg(["172.16.0.0/24"]))
            again = ScanPresetStore(QSettings(s.fileName(), QSettings.IniFormat))
            self.assertEqual(again.names(), ["机房全端口"])
            self.assertEqual(again.get("机房全端口")["ranges"], ["172.16.0.0/24"])

    def test_enforces_max_count(self):
        with _TempSettings() as s:
            store = ScanPresetStore(s)
            for i in range(MAX_PRESETS):
                store.put(f"p{i}", self._cfg())
            with self.assertRaises(PresetError):
                store.put("overflow", self._cfg())

    def test_corrupt_json_degrades_to_empty(self):
        with _TempSettings() as s:
            s.setValue("scan_presets/items", "{not json")
            self.assertEqual(len(ScanPresetStore(s)), 0)

    def test_non_list_json_degrades_to_empty(self):
        with _TempSettings() as s:
            s.setValue("scan_presets/items", json.dumps({"a": 1}))
            self.assertEqual(len(ScanPresetStore(s)), 0)

    def test_entries_without_name_or_config_are_skipped(self):
        with _TempSettings() as s:
            s.setValue("scan_presets/items", json.dumps([
                {"name": "ok", "config": {"ranges": []}},
                {"name": "", "config": {}},
                {"name": "no-config"},
                "garbage",
            ]))
            self.assertEqual(ScanPresetStore(s).names(), ["ok"])

    def test_name_is_validated_on_put(self):
        with _TempSettings() as s:
            store = ScanPresetStore(s)
            with self.assertRaises(PresetError):
                store.put("bad/name", self._cfg())

    def test_get_missing_returns_none(self):
        with _TempSettings() as s:
            self.assertIsNone(ScanPresetStore(s).get("nope"))


if __name__ == "__main__":
    unittest.main()
