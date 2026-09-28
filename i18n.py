# -*- coding: utf-8 -*-
"""轻量国际化模块。JSON 语言包 + 系统 locale 自动检测。"""
import json
import locale
import os
import sys

_translations: dict = {}
_current_lang: str = "zh-CN"
_reverse_cache: dict = None


def _lang_search_dirs():
    """返回语言包候选目录，按优先级排序。

    PyInstaller --onefile 会把 `i18n/` 打进归档并解压到 sys._MEIPASS，
    而不是 exe 所在目录；因此必须优先用 resource_dir()，否则打包后英文
    界面会静默退化成恒等翻译（显示中文原文）。
    依次尝试：用户数据目录（可覆盖）→ 打包资源目录 → exe/源码目录。
    """
    dirs = []
    try:
        from app_paths import data_dir, resource_dir
        dirs.append(data_dir())
        dirs.append(resource_dir())
    except Exception:
        # app_paths 不可用（例如被单独裁剪使用）→ 只用源码目录找语言包。
        # 此处刻意不记日志：i18n 是所有模块的 import 前置依赖，日志系统
        # （app_logging → app_paths）此时未必就绪，记了也可能丢。
        pass
    dirs.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    dirs.append(os.path.dirname(os.path.abspath(__file__)))
    out = []
    for d in dirs:
        if d and d not in out:
            out.append(d)
    return out


def init(lang: str = None):
    """加载语言包。lang=None 时自动检测系统语言。"""
    global _current_lang, _translations, _reverse_cache
    if lang is None:
        try:
            sys_lang = locale.getdefaultlocale()[0] or ""
        except Exception:
            sys_lang = ""
        lang = "zh-CN" if sys_lang.startswith("zh") else "en-US"
    _current_lang = lang
    _translations = {}
    _reverse_cache = None
    for base in _lang_search_dirs():
        path = os.path.join(base, "i18n", f"{lang}.json")
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    _translations = json.load(f)
            except Exception:
                _translations = {}
            if _translations:
                break


def tr(text: str) -> str:
    """翻译字符串。未找到翻译或翻译为空时返回原文。"""
    t = _translations.get(text)
    return t if t else text


def canonical(text: str) -> str:
    """把「翻译后的文本」还原为语言无关的源串。

    用途：跨语言比较。例如历史库里存的设备类别是规范源串「打印机」，
    而英文界面的筛选项是 "Printer"，直接比较会永远匹配不上。
    已经是源串的输入原样返回；未知文本也原样返回（不丢信息）。
    """
    if not text:
        return text
    t = str(text).strip()
    if not t:
        return t
    if t in _translations:          # 已是源串
        return t
    rev = _reverse()
    return rev.get(t, t)


def _reverse():
    """翻译值 -> 源串 的反查表（惰性构建并缓存，init() 时失效）。"""
    global _reverse_cache
    if _reverse_cache is None:
        _reverse_cache = {}
        for src, dst in _translations.items():
            if dst and dst not in _reverse_cache:
                _reverse_cache[dst] = src
    return _reverse_cache


def current_lang() -> str:
    """返回当前语言代码。"""
    return _current_lang
