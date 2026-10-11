# -*- coding: utf-8 -*-
"""色值字面量禁令：UI 层不得绕过语义色令牌（建议书 §10 第 3 件）。

背景
----
`theme_tokens.py` 是"唯一的色值来源"，但这条规矩原先只有
`tests/test_ui_dialogs_colors.py::NoColorLiteralTest` 为 `ui_dialogs/` 包守着。
本轮把它扩到三个核心 UI 文件：

    `main_window.py` / `main_window_tree.py` / `ui_icons.py`

扩之前先按 `docs/reviews/PRODUCT_ADVISORY_REVIEW.md` §2/§3 把这三处处理掉 ——
`ui_icons.py` 的 14 处不透明 `QColor`（13 处是深色 `QPalette` 的裸字面量）、
`main_window.py` 写进 `tr()` 键的内联色。否则"顺手扩一下测试"实际是"先补一轮令牌"。
（原 `NoColorLiteralTest` 已由本文件接管，那个类删掉了 —— 同一件事只留一个口径。）

为什么判定改成 AST，而不是原来的源码正则
----------------------------------------
§3.1 实测过：对**原始源码**跑 `re.findall(r"#[0-9A-Fa-f]{3,8}\\b", src)` 会连
**注释与 docstring** 里的色值一起命中。`main_window.py` 的 9 处 hex 里有 3 处是
`_link_color()` 的说明文字（讲 WCAG 对比度时写了 `#2563EB` / `#252526` /
`#4DA6FF`），`main_window_tree.py` 的 2 处**全部**是 docstring 散文 —— 它们不是
"该换成令牌的配色"，是注释。

正则口径更坏的一面：它把"注释里提到颜色"变成**违规** —— 下一个想写
"旧值是 #2563EB，对比度不够才换掉"的人会被测试拦住，而他做的事是对的。
所以这里按 AST 只取**代码里的字符串字面量**，注释与 docstring 天然不在其中。

豁免
----
带 alpha 的 4 参数 `QColor(r, g, b, a)` 允许：那是半透明装饰（图标高光/描边），
压在浅深两种底色上都只是"淡一点的边"，与主题无关；令牌表刻意只存不透明色。
"""
import ast
import io
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from theme_tokens import all_dark_palette_colors, all_tokens, token

#: 需要守的三个核心 UI 文件（`ui_dialogs/` 包另算，见 `_targets()`）
CORE_FILES = ("main_window.py", "main_window_tree.py", "ui_icons.py")

_HEX = re.compile(r"#[0-9A-Fa-f]{3,8}\b")

#: 取色函数名 → 它取的是哪张表。`token` / `_theme_color` 走 `theme_tokens._TOKENS`，
#: `dark_palette_color` 走 `theme_tokens._DARK_PALETTE`。
_TOKEN_FUNCS = ("token", "_theme_color", "dark_palette_color")


def _targets():
    """扫描对象：三个核心文件 + `ui_dialogs/` 包内全部 `.py`。

    包内文件要逐个列出而不是只扫 `__init__.py`（门面）—— 否则子模块里的色值
    会**静默漏过**。
    """
    pkg = os.path.join(ROOT, "ui_dialogs")
    return list(CORE_FILES) + [
        os.path.join("ui_dialogs", fn)
        for fn in sorted(os.listdir(pkg)) if fn.endswith(".py")
    ]


def _parse(name):
    with io.open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return ast.parse(fh.read(), filename=name)


def _docstring_ids(tree):
    """模块 / 类 / 函数体**首条**字符串字面量的节点 id 集合。

    依赖"docstring 独占一行"这一事实（实测 0/1493 条 docstring 与代码同行）。
    若哪天出现 `'''说明''' ; x = 1` 这种同行写法，本函数会把同行代码一起放过 ——
    但那种写法在 PEP 8 / ruff 下本来就会红。
    """
    ids = set()
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", None) or []
        if not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            ids.add(id(first.value))
    return ids


def _code_strings(name):
    """返回 [(行号, 字符串)] —— 代码里的字符串字面量，**不含**注释与 docstring。

    f-string 的各段在 AST 里同样是 `ast.Constant`，所以
    `f"<p style='color:#94A3B8;'>"` 这类写法也抓得到。
    """
    tree = _parse(name)
    skip = _docstring_ids(tree)
    return [(n.lineno, n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in skip]


def _call_name(node):
    """`QColor(...)` / `token(...)` 这类调用的函数名；取不到就返回空串。"""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return getattr(func, "id", "")


def _opaque_qcolor_calls(name):
    """返回 [(行号, 源码)] —— `QColor(r, g, b)` 且三个实参**都是整数字面量**。

    只认恰好 3 个整数：`QColor(token(...))`（1 参）与 `QColor(r, g, b, a)`
    （4 参，半透明装饰）都不算。
    """
    out = []
    for node in ast.walk(_parse(name)):
        if not isinstance(node, ast.Call) or node.keywords:
            continue
        if _call_name(node) != "QColor" or len(node.args) != 3:
            continue
        if all(isinstance(a, ast.Constant) and isinstance(a.value, int)
               for a in node.args):
            out.append((node.lineno, ast.unparse(node)))
    return out


def _token_refs(name):
    """返回 {(取色函数名, 令牌名)} —— 代码里对令牌表的引用（AST，不含注释）。"""
    refs = set()
    for node in ast.walk(_parse(name)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        fname = _call_name(node)
        if fname not in _TOKEN_FUNCS:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            refs.add((fname, arg.value))
    return refs


class NoColorLiteralTest(unittest.TestCase):
    """核心 UI 文件与 `ui_dialogs/` 包都不得出现色值字面量。"""

    def test_no_hex_literal(self):
        found = []
        for name in _targets():
            for lineno, text in _code_strings(name):
                for hit in _HEX.findall(text):
                    found.append("%s:%d  %s" % (name, lineno, hit))
        self.assertEqual(
            found, [],
            "以下位置仍有 hex 色值字面量。自绘 / 单元格着色请用 "
            "theme_tokens.token()，普通控件请把配色收进 QSS：\n  "
            + "\n  ".join(found))

    def test_no_opaque_qcolor_literal(self):
        found = []
        for name in _targets():
            for lineno, src in _opaque_qcolor_calls(name):
                found.append("%s:%d  %s" % (name, lineno, src))
        self.assertEqual(
            found, [],
            "以下位置仍有不透明 QColor 字面量。核心文件请用 token()，"
            "深色 QPalette 请用 dark_palette_color()：\n  "
            + "\n  ".join(found))


class TokenReferenceTest(unittest.TestCase):
    """引用的令牌名 / 调色板角色名必须存在。

    拼错的名字会让 `token()` / `dark_palette_color()` **静默返回空串** ——
    颜色变成无效值，不报错，只表现为"某处颜色不对"。这类错靠肉眼极难定位。
    """

    def test_every_referenced_token_exists(self):
        known = all_tokens()
        unknown = sorted(
            "%s: %s(%r)" % (name, fname, value)
            for name in _targets()
            for fname, value in _token_refs(name)
            if fname in ("token", "_theme_color") and value not in known
        )
        self.assertEqual(unknown, [], "引用了未定义的令牌：\n  "
                         + "\n  ".join(unknown))

    def test_every_dark_palette_role_exists(self):
        known = all_dark_palette_colors()
        unknown = sorted(
            "%s: dark_palette_color(%r)" % (name, value)
            for name in _targets()
            for fname, value in _token_refs(name)
            if fname == "dark_palette_color" and value not in known
        )
        self.assertEqual(unknown, [], "引用了未定义的 QPalette 角色：\n  "
                         + "\n  ".join(unknown))

    def test_every_token_has_both_theme_values(self):
        for name in all_tokens():
            for dark in (False, True):
                self.assertTrue(token(name, dark),
                                "%s 在 dark=%s 下取不到色值" % (name, dark))


class DarkPaletteTableTest(unittest.TestCase):
    """深色 QPalette 的表与取用点必须一一对应。"""

    def test_table_and_call_sites_agree(self):
        """表里的角色与 `_build_dark_palette()` 真正取的角色必须**完全相同**。

        多一个 = 表里有没人用的死条目；少一个 = 某处 `dark_palette_color()`
        拼错了名字（会静默返回空串，那个控件在深色下变成无效色）。
        """
        used = {value for fname, value in _token_refs("ui_icons.py")
                if fname == "dark_palette_color"}
        declared = set(all_dark_palette_colors())
        self.assertEqual(sorted(declared - used), [],
                         "theme_tokens._DARK_PALETTE 里这些角色没人取")
        self.assertEqual(sorted(used - declared), [],
                         "这些角色不在 theme_tokens._DARK_PALETTE 里")


class SameInBothThemesTest(unittest.TestCase):
    """这些令牌**刻意浅深同值**，把它们钉住。

    两类，理由不同但结论一样 —— "同一个色在两套底色上都成立"：

    * **不随主题重绘的位图** —— `icon_globe`（`_globe_icon_cache` 一次构造后
      缓存）、`icon_online_highlight`（压在浅色屏 `#DCFCE7` 与深色屏 `#14532D`
      上都看得见）；
    * **拓扑画布上的中性色** —— `topo_offline` / `gateway` / `cdp`，浅深两套
      画布底色都要看得见，偏任何一边都会糊掉。

    若给前者配上不同的值，颜色就取决于"第一次渲染时恰好是哪个主题" —— 比固定
    一色更糟；给后者配上不同值，等于把"两底色通用"这个前提拆掉。后人若"顺手
    补齐浅色值"，这条测试会拦下并说明原因。
    """

    DELIBERATE = ("icon_globe", "icon_online_highlight",
                  "topo_offline", "gateway", "cdp")

    def test_they_really_are_the_same_in_both_themes(self):
        for name in self.DELIBERATE:
            with self.subTest(token=name):
                self.assertEqual(
                    token(name, False), token(name, True),
                    "%s 被改成了随主题变的值 —— 但它服务的位图/底色并不随主题变"
                    % name)


if __name__ == "__main__":
    unittest.main()
