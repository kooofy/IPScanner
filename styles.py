# -*- coding: utf-8 -*-
"""样式表加载与预渲染字体常量。

本模块曾把 4 类东西混在一起（QSS 文本 / 图标绘制 / 字体常量 / IP 排序键），
791 行且改动理由互不相干。现已按"改动理由"拆分：

  - QSS 文本   → `assets/styles/{light,dark}.qss`（编辑器可高亮 / lint，改配色不必动 .py）
  - 图标绘制   → `ui_icons.py`（换图形，与换配色无关）
  - IP 排序键  → `ui_utils.py`（与样式无关的纯逻辑，和 `_is_valid_ip` 同处）
  - 字体常量   → 留在本模块（字体属于样式）

对外仍暴露 `STYLE_SHEET` / `DARK_STYLE_SHEET` 两个名字，调用方无需改动。
"""
import os

from PyQt5.QtGui import QFont

from app_paths import resource_dir

# 样式表在打包内的相对位置（GUI spec 的 datas 已包含整个 assets/ 目录，
# 因此新增 .qss 无需改 spec；CLI 不用样式，也就不需要这些文件）。
_QSS_SUBDIR = ("assets", "styles")


def _read_qss(filename: str) -> str:
    """读取 `assets/styles/<filename>`；缺失即报错，**不退化为"无样式"**。

    故意选择 fail-fast：样式表全部丢失时界面会静默变成默认灰白，用户看到的是
    "程序变丑了"这种无从下手的现象，排查成本极高；直接抛错能一眼定位到
    "打包漏了 assets/styles"。CI 里另有断言校验产物包含这些文件。
    """
    path = os.path.join(resource_dir(), *_QSS_SUBDIR, filename)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise RuntimeError(
            f"样式文件缺失或不可读：{path}（打包时需把 assets/styles 一并打进 exe）"
        ) from e


STYLE_SHEET = _read_qss("light.qss")
DARK_STYLE_SHEET = _read_qss("dark.qss")

# ── 预渲染字体常量 ─────────────────────────────────────
_FONT_CONSOLAS_10 = QFont("Consolas", 10)
_FONT_CONSOLAS_9 = QFont("Consolas", 9)
_FONT_YAHEI_BOLD_9 = QFont("Microsoft YaHei", 9, QFont.Bold)
