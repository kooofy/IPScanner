# -*- coding: utf-8 -*-
"""轻量国际化模块。JSON 语言包 + 系统 locale 自动检测。"""
import json
import locale
import os
import sys

_translations: dict = {}
_current_lang: str = "zh-CN"


def _data_dir():
    """返回语言包所在目录（兼容 PyInstaller 打包）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.dirname(os.path.abspath(__file__))


def init(lang: str = None):
    """加载语言包。lang=None 时自动检测系统语言。"""
    global _current_lang, _translations
    if lang is None:
        try:
            sys_lang = locale.getdefaultlocale()[0] or ""
        except Exception:
            sys_lang = ""
        lang = "zh-CN" if sys_lang.startswith("zh") else "en-US"
    _current_lang = lang
    path = os.path.join(_data_dir(), "i18n", f"{lang}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            _translations = json.load(f)
    else:
        _translations = {}


def tr(text: str) -> str:
    """翻译字符串。未找到翻译或翻译为空时返回原文。"""
    t = _translations.get(text)
    return t if t else text


def current_lang() -> str:
    """返回当前语言代码。"""
    return _current_lang
