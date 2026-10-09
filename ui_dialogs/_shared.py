# -*- coding: utf-8 -*-
"""对话框公共助手：按字符截断、半透明色、按主题取语义色。

原 `ui_dialogs.py` 的模块级私有助手。拆分后集中在此，供各对话框子模块复用 ——
单独成文件是为了避免"共享助手 <-> 各子模块"之间形成环状依赖。
"""
from PyQt5.QtGui import QColor

from theme_tokens import token


def _ellipsize(text: str, limit: int) -> str:
    """按字符数截断并加省略号。

    自绘节点下方那行说明的横向空间是按最坏情况估的（终端网格列距 74px），
    直接 `text[:n]` 会在词中间硬切（"Cisco IOS Software, C456"），看起来像
    型号本身就叫这个 —— 加个省略号才不会被误读。
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:max(1, limit - 1)].rstrip() + "…"


def _faded(color: QColor, alpha: int) -> QColor:
    """返回同一个色相的半透明版本（用于"次要信息"的连线）。

    刻意不写进 `theme_tokens`：那里存的是语义色本体，透明度是**画法**而不是
    配色，跟着主题走会让两个概念纠缠在一起。
    """
    out = QColor(color)
    out.setAlpha(alpha)
    return out


def _theme_color(name: str, dark: bool) -> QColor:
    """按主题取语义色（`theme_tokens` 的 hex → `QColor`）。

    对话框里的**自绘图形**（拓扑画布）与**表格单元格着色**走这里 —— 这两类
    QSS 都覆盖不到，原先只能把同一套语义色硬编码在本文件里，深色主题下必然
    漏掉几处：摘要文字用的深灰在深色底上几乎不可见，严重级别用的红色在深色底
    上只有约 2.5:1 对比度（AA 要求 4.5:1）。

    统一从令牌取色后，"深色下这一处忘了改"这类问题从根上消失。
    `tests/test_ui_dialogs_colors.py` 会扫描本包，禁止再出现色值字面量。
    """
    return QColor(token(name, dark))
