# -*- coding: utf-8 -*-
"""设备收藏（对应 UI_REVIEW.md 的 P1-3）。

设计动机
--------
Advanced IP Scanner 最被称道的功能之一就是 Favorites —— 把常关注的设备钉住，
下次不用在一堆结果里翻。本项目有「MAC 地址库」，但那是**资产台账**（需要
导入 Excel、维护位置/使用者），不是"我常看这几台"的轻量标记。

收藏键的选取
------------
**一台设备只存一个键**：有 MAC 就存 `mac:`，否则退化成 `ip:`。

不把 MAC 与 IP 两个键都存下来，是因为那样会留下"陈旧键"：设备换了 IP 之后
旧 IP 键仍在集合里，而这个 IP 后来可能被**另一台设备**占用 —— 于是那台毫不
相干的设备会莫名其妙地显示为已收藏。单一键避免了这种串号。
"""
import json
import math

from PyQt5.QtGui import QIcon, QPainter, QPixmap, QBrush, QColor, QPen
from PyQt5.QtCore import Qt, QPointF

MAC_PREFIX = "mac:"
IP_PREFIX = "ip:"

_STAR_ICON = None


def _normalize_mac(mac) -> str:
    return (mac or "").strip().upper()


def _normalize_ip(ip) -> str:
    return (ip or "").strip()


def favorite_key(result) -> str:
    """返回该设备的收藏键。有 MAC 用 MAC（更稳定），否则用 IP。"""
    mac = _normalize_mac(getattr(result, "mac", ""))
    if mac:
        return MAC_PREFIX + mac
    return IP_PREFIX + _normalize_ip(getattr(result, "ip", ""))


class FavoriteStore:
    """收藏集合，持久化到 QSettings。"""

    def __init__(self, settings, section: str = "favorites/entries"):
        self._settings = settings
        self._section = section
        self._keys = set()
        self.load()

    # ── 持久化 ────────────────────────────────────────────

    def load(self):
        """读取收藏集合。

        存的是 JSON 数组，不是 QSettings 的原生列表 —— IniFormat 下原生列表
        的序列化形式（逗号分隔的单个字符串）在读写往返时并不总是还原成列表，
        一旦退化成字符串就会把整串当成"一个"收藏键。
        """
        raw = self._settings.value(self._section, "")
        self._keys = set()
        if not raw:
            return
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            # 配置损坏 → 退化为"没有收藏"，而不是让程序起不来
            return
        if not isinstance(data, list):
            return
        self._keys = {str(k).strip() for k in data if str(k).strip()}

    def save(self):
        self._settings.setValue(self._section, json.dumps(sorted(self._keys)))
        self._settings.sync()

    # ── 查询 / 修改 ───────────────────────────────────────

    def __len__(self):
        return len(self._keys)

    def keys(self) -> set:
        return set(self._keys)

    def is_favorite(self, result) -> bool:
        key = favorite_key(result)
        return bool(key) and key in self._keys

    def add(self, result) -> bool:
        """加入收藏。返回是否发生了变化。"""
        key = favorite_key(result)
        if not key or key in self._keys:
            return False
        self._keys.add(key)
        self.save()
        return True

    def remove(self, result) -> bool:
        """移出收藏。返回是否发生了变化。"""
        key = favorite_key(result)
        if key not in self._keys:
            return False
        self._keys.discard(key)
        self.save()
        return True

    def toggle(self, result) -> bool:
        """切换收藏状态，返回切换**后**是否为收藏。"""
        if self.is_favorite(result):
            self.remove(result)
            return False
        self.add(result)
        return True

    def clear(self):
        self._keys.clear()
        self.save()


def star_icon() -> QIcon:
    """收藏星标（矢量绘制，惰性构造并缓存）。

    画成图标而不是往 IP 文本里插 "★" 前缀：IP 列已经有冲突标记会加 "⚠ "
    前缀，两个前缀叠加会把文本搞得既难读又难解析。
    """
    global _STAR_ICON
    if _STAR_ICON is not None:
        return _STAR_ICON
    size = 14
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(QPen(QColor(217, 119, 6), 1.0))
    p.setBrush(QBrush(QColor(251, 191, 36)))
    cx, cy, outer, inner = size / 2.0, size / 2.0, size / 2.0 - 1.0, size / 5.0
    pts = []
    for i in range(10):
        r = outer if i % 2 == 0 else inner
        a = -math.pi / 2 + i * math.pi / 5
        pts.append(QPointF(cx + r * math.cos(a), cy + r * math.sin(a)))
    p.drawPolygon(*pts)
    p.end()
    _STAR_ICON = QIcon(pm)
    return _STAR_ICON
