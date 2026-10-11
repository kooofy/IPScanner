# -*- coding: utf-8 -*-
"""语义色令牌（对应 docs/reviews/UI_REVIEW.md 的 P2-1）。

为什么需要这个模块
------------------
QSS 能覆盖普通控件的配色，但**覆盖不到**这三类地方：

1. `QTreeWidgetItem.setForeground()` —— 树项的前景色只能从 Python 设；
2. 自绘图标（状态列的电脑图标、收藏星标）；
3. 内联 `setStyleSheet` 的标签。

于是这些颜色原先以字面量散落在 `main_window.py` / `main_window_tree.py` /
`ui_icons.py` 里，同一套语义色被硬编码了多次（在线绿出现过 `#16A34A` 与
`QColor(22,163,74)` 两种写法）。深色主题下要逐个改，漏一处就是"深色下某个
标签还是浅色文字"这类只能靠肉眼发现的问题。

这里把它们收敛成**唯一的色值来源**：QSS 管得着的走 QSS，管不着的从这里取。

色值刻意存 hex 字符串而非 QColor：本模块因此不依赖 PyQt，可被测试与 CLI
无成本导入；调用方按需自行包 `QColor(...)`。
"""

#: 语义名 → (浅色值, 深色值)
_TOKENS = {
    # 强调色（可点击文字、选中态）
    "accent": ("#0078D7", "#4DA6FF"),
    "link": ("#2563EB", "#4DA6FF"),
    # 文本层级
    "fg": ("#000000", "#FFFFFF"),
    "fg_strong": ("#333333", "#E0E0E0"),
    "muted": ("#64748B", "#969CA6"),
    "muted_label": ("#888888", "#9AA0A6"),
    "stats": ("#555555", "#C8C8C8"),
    # 工具栏自绘线条图标（`ui_icons._make_tool_icon` / `_make_pause_icon`）的描边色。
    # 浅色下用中灰 —— 纯黑在浅色按钮上过硬；深色下用近白。
    # 建按钮时与切主题时**两处**都要取它，同源才不会"切一次主题串一次色"。
    "tool_icon": ("#555555", "#FFFFFF"),
    # 分隔线
    "sep": ("#CCCCCC", "#3F3F46"),
    # 语义状态
    "online": ("#16A34A", "#4ADE80"),
    "offline": ("#DC2626", "#F87171"),
    "warn": ("#D97706", "#FBBF24"),
    "danger": ("#DC2626", "#F87171"),
    # 设备图标（状态列预渲染位图）
    "icon_online_edge": ("#16A34A", "#4ADE80"),
    "icon_online_screen": ("#DCFCE7", "#14532D"),
    "icon_offline_edge": ("#94A3B8", "#6B7280"),
    "icon_offline_screen": ("#F1F5F9", "#2D2D30"),
    # 在线图标屏幕上那两道"高亮线"。压在浅色屏(#DCFCE7)与深色屏(#14532D)上都
    # 看得见，因此浅深**刻意同值** —— 与下面 `topo_offline` / `gateway` / `cdp`
    # 是同一类"两底色通用色"，由 `tests/test_color_literals.py::SameInBothThemesTest` 守着。
    "icon_online_highlight": ("#86EFAC", "#86EFAC"),
    # 服务行地球图标（HTTP/HTTPS 的兜底图标）底色。
    # ⚠ 它是**一次构造后缓存**的位图（`main_window_tree._globe_icon_cache`），
    # 不随主题重绘 —— 所以这里也刻意同值：若配成两个不同的值，图标颜色就会取决于
    # "第一次渲染时恰好是哪个主题"，比固定一色更糟。
    "icon_globe": ("#3B82F6", "#3B82F6"),

    # ── 对话框（ui_dialogs/）用到的语义色 ──────────────────────
    #
    # 中性兜底：表格里"未知/提示"级别的文字。
    # 原来散落着 `#646464` 与 `#6B7280` 两种几乎一样的灰，合并为一个。
    "gray": ("#6B7280", "#9AA0A6"),
    # 次级表面（进度条槽底一类"比背景亮/暗一档"的填充）
    "surface_alt": ("#EEEEEE", "#333333"),
    # 拓扑画布：自绘 QGraphicsScene，QSS 与 QPalette 都覆盖不到，
    # 只能由 Python 按主题取色。
    "topo_bg": ("#F8F8F8", "#1E1E1E"),
    "topo_fg": ("#282828", "#E0E0E0"),
    "topo_muted": ("#AAAAAA", "#969CA6"),
    "topo_link": ("#0E639C", "#4DA6FF"),
    # 拓扑里的"离线"节点：浅深两色都取中灰 —— 它压在浅色画布(#F8F8F8)与
    # 深色画布(#1E1E1E)上都要看得见，偏任何一边都会糊掉。
    "topo_offline": ("#B4B4B4", "#B4B4B4"),
    "gateway": ("#E69500", "#E69500"),
    "cdp": ("#22C55E", "#22C55E"),
    # 转发表（BRIDGE-MIB）推断出来的接入链路。与 LLDP/CDP 用不同色相区分：
    # 前两者是交换机**主动通告**的邻居，后者是我们从 MAC 转发表**反推**的，
    # 可信度不同，画在图上就该一眼能分。
    "fdb": ("#7C3AED", "#A78BFA"),
    # 严重级别行底色。浅色下是淡彩底；深色下**另给一套深底** —— 深色主题若
    # 沿用淡彩底会整片刺眼，若干脆不铺底则"按级别着色"这条信息就丢了。
    "sev_bg_high": ("#FEE2E2", "#4A1D1D"),
    "sev_bg_warn": ("#FEF3C7", "#4A3413"),
    "sev_bg_info": ("#DBEAFE", "#1B3A5C"),
}


def token(name: str, dark: bool = False) -> str:
    """取语义色 hex 值。未知名字返回空串（调用方通常退化为默认前景色）。"""
    pair = _TOKENS.get(name)
    if pair is None:
        return ""
    return pair[1] if dark else pair[0]


#: 深色 `QPalette` 专色 —— 只服务于 `ui_icons._build_dark_palette()`。
#:
#: 为什么不并进上面的 `_TOKENS`：那张表里**每个名字都必须有"浅色 + 深色"两个值**
#: （浅色主题下也要用）。而深色 QPalette 只用于深色主题 —— 浅色主题直接沿用
#: `app.style().standardPalette()`，**根本不存在"浅色值"**。硬凑一个塞进 `_TOKENS`
#: 只会让"两套主题"这个不变量变成谎话。
#:
#: 键名与 `QPalette.ColorRole` 一一对应（下划线小写），便于对照 Qt 文档。
_DARK_PALETTE = {
    "window": "#2B2B2B",
    "window_text": "#E0E0E0",
    "base": "#1E1E1E",
    "alternate_base": "#2D2D30",
    "tooltip_base": "#2D2D30",
    "tooltip_text": "#E0E0E0",
    "text": "#E0E0E0",
    "button": "#3E3E42",
    "button_text": "#E0E0E0",
    "bright_text": "#FF5050",
    "link": "#4DA6FF",
    "link_visited": "#78B4FF",
    "highlight": "#0E639C",
    "highlighted_text": "#FFFFFF",
}


def dark_palette_color(role: str) -> str:
    """取深色 QPalette 某个角色（`_DARK_PALETTE` 的键）的色值。

    未知角色返回空串 —— 与 `token()` 一致。**拼错角色名不会报错**，只会让某个
    原生对话框控件变成无效色，因此由 `tests/test_color_literals.py` 守着。
    """
    return _DARK_PALETTE.get(role, "")


def all_dark_palette_colors() -> dict:
    """返回 {角色: 色值} 的副本，供测试校验完整性。"""
    return dict(_DARK_PALETTE)


def all_tokens() -> dict:
    """返回 {名字: (浅色, 深色)} 的副本，供测试校验完整性。"""
    return dict(_TOKENS)
