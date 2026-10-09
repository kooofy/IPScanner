# -*- coding: utf-8 -*-
"""语义色令牌（对应 UI_REVIEW.md 的 P2-1）。

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

    # ── 对话框（ui_dialogs）用到的语义色 ──────────────────────
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


def all_tokens() -> dict:
    """返回 {名字: (浅色, 深色)} 的副本，供测试校验完整性。"""
    return dict(_TOKENS)
