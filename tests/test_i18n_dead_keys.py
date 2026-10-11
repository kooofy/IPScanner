# -*- coding: utf-8 -*-
"""语言包的**死键**与**漏翻**双向检查（建议书 §10 第 2 件）。

背景
----
`i18n/en-US.json` 里积了一批**没有任何代码引用**的键 —— 功能改写后留下的
化石。最典型的一批是 6 个「把颜色写进翻译键」的图例串：配色后来统一收进了
`theme_tokens.py`（图例改由令牌渲染），其中 5 个就此失去引用。留着它们的代价
不是体积，而是**误导**：下一个人看到 `i18n/*.json` 里躺着一堆色值，会以为
配色本来就该写在语言包里。

同类化石还有一批「旧措辞」：`Excel已匹配` / `FTP服务` / `全选并展开所有项` /
`复制 IP`（现在统一成 `tr("复制")`）/ `WMI 凭据加密保存失败（已忽略）:`
（文案已改写）…… 以及几条 **`\\n` 转义写法的重复键** —— 同一个句子既有一条
「真换行」的活键、又有一条「字面反斜杠 n」的死键，后者永远不会被命中。

判定口径
--------
一个键「可达」的定义是：**它的字符串在项目 .py 里作为字面量出现过**。

* 为什么不只看 `tr("…")` 的字面量？
  因为大量**规范值**走的是带变量的翻译 —— `device_class_label("打印机")`
  里的 `tr(text)` 收集不到，但 `"打印机"` 这个规范值本身就是代码里的字面量。
  只认 `tr()` 实参的话，「电脑」「打印机」「路由器」…… 几十个设备类别会被
  整体误报成死键（实测 100+ 条，全是不该删的）。
* 为什么是**字面量**而不是"任何地方出现过"？
  因为本项目有大量「以前这里写的是 tr(\"仅在线\")」这类**注释**在解释历史。
  注释不是字面量，所以那些键照样被正确地判为死键 —— 这正是化石键的典型特征。

维护提示
--------
真的误报（某个键确实可达，但测试说它死了）→ 把它加进 `_ALLOWLIST` 并写清
理由。**不要**为了让测试变绿去放宽判定口径 —— 那等于把这道网拆掉。
"""
import ast
import io
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

#: 扫描范围：项目自身的 .py。`.git/` 里是临时脚本（含大量中文注释），必须排除。
SKIP_DIRS = {"venv", ".venv", "env", "build", "dist", "dist_new", "__pycache__",
             ".git", ".github", ".workbuddy", ".workbuddy-ai", ".codeartsdoer",
             ".joycode", ".ruff_cache"}

#: 已知可达、但按上面的口径抓不到的键（误报豁免）。加条目必须写理由。
_ALLOWLIST = frozenset()


def _load(name):
    with io.open(os.path.join(ROOT, "i18n", name), encoding="utf-8") as fh:
        return json.load(fh)


def _project_literals():
    """收集项目 .py 里出现过的**全部字符串字面量**。

    用 AST 而不是正则：正则抓不到隐式拼接（`"第一行\\n" "第二行"`），而 AST
    已经把 `ast.Constant` 折叠成完整字符串 —— 这正是本口径赖以成立的前提。
    """
    found = set()
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with io.open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
            except Exception:
                continue        # 语法错误由 ruff 负责报，这里不重复
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant)
                        and isinstance(node.value, str)):
                    found.add(node.value)
    return found


class _DeadKeyMixin:
    """共用的死键判定。

    刻意**不继承** `unittest.TestCase` —— 否则它自己会被发现成一条测试
    （`PACK` 为空，直接 FileNotFoundError）。两个包各自混入一次。
    """

    PACK = ""

    def _dead_keys(self):
        pack = _load(self.PACK)
        literals = _project_literals()
        return sorted(k for k in pack
                      if k not in literals and k not in _ALLOWLIST)

    def test_no_dead_keys(self):
        dead = self._dead_keys()
        self.assertEqual(
            dead, [],
            msg=f"i18n/{self.PACK} 里有 {len(dead)} 个键没有任何代码引用"
                "（功能改写后留下的化石）。请删掉它们；"
                "若确认仍在使用，把它加进本文件的 _ALLOWLIST 并写清理由：\n  "
                + "\n  ".join(repr(k) for k in dead),
        )


class EnglishPackDeadKeyTest(_DeadKeyMixin, unittest.TestCase):
    """英文包 —— 死键最容易在这里堆积（它是后加的覆盖层）。"""

    PACK = "en-US.json"


class ChinesePackDeadKeyTest(_DeadKeyMixin, unittest.TestCase):
    """中文包 —— 只收录"与中文源串不同"的覆盖值，同样会积化石。"""

    PACK = "zh-CN.json"


class PackParityTest(unittest.TestCase):
    """两个包之间的一致性。"""

    def test_chinese_pack_is_fully_translated(self):
        """zh-CN 里有的键，en-US 必须都有。

        zh-CN 包是"中文界面下的覆盖值"，只收录与中文源串不同的条目；一旦某个
        键只在 zh-CN 里存在，英文界面就会**回退显示中文源串** —— 而这正是
        `LanguagePackCompletenessTest` 想拦、却因为该键没被 `tr()` 字面量引用
        而拦不住的情况。两道网互补，缺一不可。
        """
        missing = sorted(set(_load("zh-CN.json")) - set(_load("en-US.json")))
        self.assertEqual(
            missing, [],
            "以下键只存在于 zh-CN.json，英文界面会显示中文源串：\n  "
            + "\n  ".join(repr(k) for k in missing),
        )

    def test_no_escaped_newline_duplicates(self):
        """同一个句子不能同时存在「真换行」与「字面反斜杠 n」两条键。

        实测踩过：`>>> [未捕获异常]\\n` 这类键里，`\\n` 是**字面反斜杠 + n**
        （JSON 里的 `\\\\n`），而代码写的是 `tr(">>> [未捕获异常]\\n")`（真换行）。
        两条键长得几乎一样，只有一条会被命中，另一条永远沉默 —— 这种重复键
        极难靠肉眼发现，交给测试。
        """
        for name in ("en-US.json", "zh-CN.json"):
            pack = _load(name)
            dupes = sorted(
                k for k in pack
                if "\\n" in k and k.replace("\\n", "\n") in pack
            )
            with self.subTest(pack=name):
                self.assertEqual(
                    dupes, [],
                    f"i18n/{name} 里这些键是「真换行」版本的重复（后者才是活的）：\n  "
                    + "\n  ".join(repr(k) for k in dupes),
                )


if __name__ == "__main__":
    unittest.main()
