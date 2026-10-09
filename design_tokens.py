# -*- coding: utf-8 -*-
"""设计令牌：圆角 / 间距 / 行高的**唯一刻度**（UI_REVIEW.md 的 P2-1.1 与 P2-1.4）。

与 `theme_tokens` 的分工
------------------------
- `theme_tokens`：**语义色**，每个名字都要有浅/深两个值（随主题变）；
- `design_tokens`（本模块）：**尺寸**，与主题无关，两套主题共用同一刻度。

分开而不是合并：混在一起会让"取色"和"取尺寸"两种调用长得一模一样，容易误用；
分开之后 `token("link", dark)` 与 `SPACING_MD` 一眼可辨。

⚠️ QSS 不能 import Python，所以 `assets/styles/*.qss` 里的圆角与行高仍是**手写**的。
`tests/test_design_tokens.py` 会扫描两套 QSS，断言其中的 `border-radius` 取值全部
落在 `RADIUS_SCALE` 内 —— 否则"统一圆角"会被后续改动悄悄漂回去（改之前是
0/1/2/3/4px 五种值混用，其中 1px 有 7 处、2px 有 14 处）。

本模块**不依赖 PyQt**，可被测试与文档无成本引用。
"""
from i18n import tr

# ── 圆角（px）──────────────────────────────────────────────────────────

#: 直角。表格 / 菜单 / 滚动条这类"网格与系统件"刻意保持直角 ——
#: 数据网格加圆角会让相邻单元格的边框对不齐，反而更乱。
RADIUS_NONE = 0

#: 嵌在控件**内部**的小构件（列表项高亮、进度条填充）。
RADIUS_INNER = 2

#: 控件外壳统一档：按钮 / 输入框 / 下拉 / 分组框 / 进度条 / 卡片容器。
RADIUS_CONTROL = 4

#: 胶囊形（半径 ≈ 高度的一半）。目前只有筛选条的 chip 用。
RADIUS_PILL = 10

#: 允许出现在 QSS 里的全部圆角取值（由 `test_design_tokens` 强制）。
RADIUS_SCALE = (RADIUS_NONE, RADIUS_INNER, RADIUS_CONTROL, RADIUS_PILL)


# ── 间距（px）──────────────────────────────────────────────────────────

#: 4 的倍数阶梯。新增布局代码请从这里取值，不要再写字面量。
#: ⚠️ 存量代码里还有约 57 处 `setSpacing` / `setContentsMargins` 直接写了数字，
#: 本模块**不**做全量替换 —— 那是纯 churn、零用户可见收益，还会制造巨量 diff。
#: 从新代码开始接入即可（`scan_status.py` 是第一个接入方）。
SPACING_XS = 2
SPACING_SM = 4
SPACING_MD = 8
SPACING_LG = 12
SPACING_XL = 16

SPACING_SCALE = (SPACING_XS, SPACING_SM, SPACING_MD, SPACING_LG, SPACING_XL)


# ── 结果表格行高（px）──────────────────────────────────────────────────
#
# 行高两档（UI_REVIEW.md P2-1.2）。旧实现 `QTreeWidget::item { min-height: 26px }`
# 写死，扫 /24 出 254 行时一屏看不完也调不动。
#
# 规范值语言无关（`compact`/`comfortable`），显示名走 `density_label()` 惰性翻译。

DENSITY_COMPACT = "compact"
DENSITY_COMFORTABLE = "comfortable"
DENSITIES = (DENSITY_COMFORTABLE, DENSITY_COMPACT)
DEFAULT_DENSITY = DENSITY_COMFORTABLE

#: 档位 -> QSS `min-height`（px）。QSS 里必须用同样的数字，`test_design_tokens` 校验。
#:
#: ⚠️ 这是**内容盒**的最小高度，不是渲染出来的行高 —— Qt 的 QSS 盒模型还要再加上
#: 上下 padding。实测（Microsoft YaHei 默认字号、padding 4px）舒适档渲染 34px。
#: 更要紧的是：**min-height 压不过字号本身的行高**。实测把它从 26 降到 20，行高只
#: 从 34px 降到 29px。想让「紧凑」真的紧凑，必须**连 padding 一起收** —— 这就是
#: `ROW_PADDING_V` 存在的原因。
ROW_HEIGHT = {
    DENSITY_COMFORTABLE: 26,
    DENSITY_COMPACT: 20,
}

#: 档位 -> 单元格**上下** padding（px）。左右 padding 两档共用，写在 QSS 的基线规则
#: `QTreeWidget::item` 里（6px —— 不在 4 的阶梯上，因为它是改造前就有的值，且收放
#: 它会改变列宽的计算，属于另一件事）。
#: 舒适档沿用改造前的 4px（外观零变化）；紧凑档收到 2px，把行高真正降下来。
ROW_PADDING_V = {
    DENSITY_COMFORTABLE: SPACING_SM,
    DENSITY_COMPACT: SPACING_XS,
}

#: 行高档位的**显示名**。字面量（不能在这里调 `tr()`，会被冻成导入期语言），
#: 且已登记进 `tests/test_i18n_lazy.py::TableDrivenLabelCoverageTest`。
_DENSITY_TEXT = {
    DENSITY_COMFORTABLE: "舒适",
    DENSITY_COMPACT: "紧凑",
}


def density_label(value: str) -> str:
    """行高档位代码 -> 当前语言的显示名（惰性翻译）。"""
    text = _DENSITY_TEXT.get(value)
    return tr(text) if text else str(value)
