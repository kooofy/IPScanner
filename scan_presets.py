# -*- coding: utf-8 -*-
"""扫描预设（对应 UI_REVIEW.md 的 P1-3）。

设计动机
--------
网段本来就会持久化（`scan/ip_ranges`），但只有**一份**：今天扫办公网、明天
扫机房，就得来回改。而"扫哪儿 + 扫多深"这件事是有固定组合的 ——
"办公网日常巡检"和"机房全端口排查"是两套完全不同的参数。

预设把 `网段 + 扫描级别 + 协议集 + 探测方式 + 端口扫描/mDNS 开关` 打包成
命名配置，工具栏一键切换。

存储
----
JSON 字符串存进 QSettings。**不用** QSettings 的数组/分组形式：那些形式在
IniFormat 下会产生带 `/` 的嵌套键，名字里一旦出现 `/` 就会串层级。
JSON 里名字是普通字符串，安全得多。
"""
import json

MAX_PRESETS = 30
MAX_NAME_LEN = 40


class PresetError(ValueError):
    """预设操作的用户可见错误。"""


class ScanPresetStore:
    """命名扫描预设集合，持久化到 QSettings。"""

    def __init__(self, settings, section: str = "scan_presets/items"):
        self._settings = settings
        self._section = section
        self._items = []      # [{"name": str, "config": {...}}, ...]
        self.load()

    # ── 持久化 ────────────────────────────────────────────

    def load(self):
        raw = self._settings.value(self._section, "")
        self._items = []
        if not raw:
            return
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            # 配置损坏时退化为"没有预设"，而不是让整个程序起不来
            return
        if not isinstance(data, list):
            return
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).strip()
            config = entry.get("config")
            if name and isinstance(config, dict):
                self._items.append({"name": name, "config": config})

    def save(self):
        self._settings.setValue(self._section, json.dumps(self._items, ensure_ascii=False))
        self._settings.sync()

    # ── 查询 / 修改 ───────────────────────────────────────

    def __len__(self):
        return len(self._items)

    def names(self) -> list:
        return [it["name"] for it in self._items]

    def items(self) -> list:
        return [dict(it) for it in self._items]

    def get(self, name: str):
        for it in self._items:
            if it["name"] == name:
                return dict(it["config"])
        return None

    def put(self, name: str, config: dict):
        """新增或覆盖同名预设。"""
        name = validate_name(name)
        if not isinstance(config, dict):
            raise PresetError("预设内容无效")
        for it in self._items:
            if it["name"] == name:
                it["config"] = dict(config)
                self.save()
                return
        if len(self._items) >= MAX_PRESETS:
            raise PresetError(f"预设数量已达上限（{MAX_PRESETS}）")
        self._items.append({"name": name, "config": dict(config)})
        self.save()

    def delete(self, name: str) -> bool:
        before = len(self._items)
        self._items = [it for it in self._items if it["name"] != name]
        if len(self._items) == before:
            return False
        self.save()
        return True


def validate_name(name: str) -> str:
    """校验并规整预设名。

    拒绝 `/` 与 `\\`：名字会被写进 QSettings 的 ini，且可能在日志/导出里
    被当成路径片段；拒绝空名与超长名。
    """
    text = (name or "").strip()
    if not text:
        raise PresetError("预设名称不能为空")
    if len(text) > MAX_NAME_LEN:
        raise PresetError(f"预设名称不能超过 {MAX_NAME_LEN} 个字符")
    if "/" in text or "\\" in text:
        raise PresetError("预设名称不能包含斜杠")
    return text
