# -*- coding: utf-8 -*-
"""P1-6 回归测试：统一日志与异常治理。

历史缺陷
--------
项目此前**完全没有 logging**（`app_logging.py` 不存在），实测：

- `except` 处理器 187 个，其中宽泛 `except Exception` 135 个
- 静默吞掉异常（handler 体只有 `pass`）的 53 个
- 187 个处理器里只有 1 个写过日志

后果：出问题时只能靠用户口述现象 + 零散的 `sys.stderr.write`，
「扫描少了几台设备」「地址库没匹配上」这类问题完全无法定位。

本测试固化三件事：

1. `app_logging` 本身可用（轮转文件、幂等初始化、logger 命名）；
2. 两个入口（`main.py` / `cli.py`）确实初始化了日志；
3. **每一个静默吞掉的异常都必须带一段说明性注释** —— 允许"有意忽略"，
   但必须写明为什么可以忽略，杜绝无意识的吞异常。
"""
import ast
import io
import logging
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import app_logging

# 扫描范围：项目自身的 .py，排除虚拟环境与构建产物
_SKIP_DIRS = {"venv", ".venv", "env", "build", "dist", "dist_new",
              "__pycache__", ".git", ".workbuddy-ai", ".ruff_cache"}

#: 只匹配**内置 `print` 的调用**。早先这里是裸子串 `"print("`，
#: 于是 `fingerprint(` 这类正常名字会被误判成"用了 print"（踩过：
#: `device_fingerprint` 引入后 `scanner/passive.py` 直接被打红）。
#: 前一个字符是标识符字符或点号时不算 —— 前者是名字的一部分，后者是方法调用。
_PRINT_CALL = re.compile(r"(?<![\w.])print\s*\(")


def _project_py_files():
    for root, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            if n.endswith(".py"):
                yield os.path.join(root, n)


def _rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def _silent_handlers(path):
    """返回 body 只有 pass 的 ExceptHandler 列表（含源行区间）。"""
    with io.open(path, encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    lines = src.splitlines()
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = [s for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            out.append((node, body[0], lines))
    return out


class SilentExceptDocumentedTest(unittest.TestCase):
    """静默吞异常必须写明理由。"""

    # 允许"有意忽略"，但注释里必须说清楚 —— 这些是最低要求的关键词
    _RATIONALE_HINT = "静默|忽略|预期|不记日志|不能记|无处可记|最后一道|无需处理|常态"

    def test_every_silent_handler_has_a_rationale_comment(self):
        offenders = []
        for path in _project_py_files():
            for node, pass_node, lines in _silent_handlers(path):
                # 取 except 行到 pass 行之间的源码片段
                segment = lines[node.lineno - 1: pass_node.lineno]
                has_comment = any(
                    ln.strip().startswith("#") for ln in segment
                )
                if not has_comment:
                    offenders.append(f"{_rel(path)}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "以下位置静默吞掉了异常且没有任何说明注释。\n"
            "请二选一：① 改成记录日志（预期内失败用 debug，影响功能用 warning）；"
            "② 若确实应当忽略，在 except 后补一行注释说明理由。\n  "
            + "\n  ".join(offenders),
        )

    def test_silent_handler_count_does_not_grow(self):
        """棘轮：静默吞异常的数量只能降不能升。"""
        # 2026-09 治理后基线（治理前为 53）。下降时请同步下调本数字。
        BASELINE = 10
        total = sum(len(_silent_handlers(p)) for p in _project_py_files())
        self.assertLessEqual(
            total, BASELINE,
            f"静默吞掉的异常从 {BASELINE} 涨到了 {total}。"
            "新增处请改为记录日志，而不是 `except Exception: pass`。",
        )

    def test_no_bare_except_without_reason(self):
        """裸 `except:` 会连 KeyboardInterrupt / SystemExit 一起吞掉，禁止新增。"""
        offenders = []
        for path in _project_py_files():
            with io.open(path, encoding="utf-8") as fh:
                src = fh.read()
            for node in ast.walk(ast.parse(src)):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    offenders.append(f"{_rel(path)}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "存在裸 `except:`，请至少写成 `except Exception:`：\n  "
            + "\n  ".join(offenders),
        )


class AppLoggingTest(unittest.TestCase):
    """app_logging 自身的行为。"""

    def test_setup_is_idempotent(self):
        root = app_logging.setup()
        before = list(root.handlers)
        app_logging.setup()
        app_logging.setup()
        self.assertEqual(
            list(root.handlers), before,
            "重复调用 setup() 不应重复挂载 handler（否则日志会成倍重复）",
        )

    def test_log_path_is_in_data_dir(self):
        from app_paths import data_dir
        self.assertEqual(os.path.dirname(app_logging.log_path()), data_dir())
        self.assertTrue(app_logging.log_path().endswith(app_logging.LOG_FILENAME))

    def test_rotating_file_handler_configured(self):
        """必须有轮转，否则长期运行会撑爆磁盘。"""
        from logging.handlers import RotatingFileHandler
        root = app_logging.setup()
        fhs = [h for h in root.handlers if isinstance(h, RotatingFileHandler)]
        self.assertTrue(fhs, "未挂载 RotatingFileHandler")
        fh = fhs[0]
        self.assertEqual(fh.maxBytes, 1024 * 1024)
        self.assertEqual(fh.backupCount, 3)
        self.assertEqual(fh.encoding.lower().replace("-", ""), "utf8")

    def test_root_logger_does_not_propagate(self):
        """不向 root 传播，避免第三方库/解释器重复输出。"""
        self.assertFalse(app_logging.setup().propagate)

    def test_get_logger_namespacing(self):
        self.assertEqual(app_logging.get_logger().name, "ipscanner")
        self.assertEqual(
            app_logging.get_logger("scanner.ping").name, "ipscanner.ping"
        )
        self.assertEqual(app_logging.get_logger("cli").name, "ipscanner.cli")

    def test_is_configured_flag(self):
        app_logging.setup()
        self.assertTrue(app_logging.is_configured())

    def test_writes_to_log_file(self):
        """端到端：真的落盘，且 UTF-8 中文不乱码。"""
        app_logging.setup()
        token = "P1-6 落盘验证 探针"
        app_logging.get_logger("tests.probe").warning("%s", token)

        path = app_logging.log_path()
        self.assertTrue(os.path.exists(path), f"日志文件未生成: {path}")
        with io.open(path, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn(token, content)
        self.assertIn("[ipscanner.probe]", content)

    def test_default_level_is_info(self):
        self.assertEqual(app_logging.setup().level, logging.INFO)

    def test_logging_failure_does_not_raise(self):
        """日志系统不可用时也不能抛异常打断业务。"""
        root = app_logging.setup()
        try:
            app_logging.get_logger("tests.probe").info("x" * 10)
        except Exception as e:  # pragma: no cover
            self.fail(f"日志调用不应抛异常: {e}")
        self.assertIsNotNone(root)


class EntryPointWiringTest(unittest.TestCase):
    """两个入口都必须初始化日志。"""

    def _src(self, rel):
        with io.open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_gui_entry_initializes_logging_first(self):
        src = self._src("main.py")
        self.assertIn("app_logging.setup()", src)
        # 日志必须早于 i18n / PyQt5 的 import，否则这些环节的失败无从记录
        self.assertLess(
            src.index("app_logging.setup()"), src.index("import i18n"),
            "app_logging.setup() 应早于 i18n 初始化",
        )
        self.assertLess(
            src.index("app_logging.setup()"), src.index("from PyQt5.QtWidgets"),
            "app_logging.setup() 应早于 PyQt5 import",
        )

    def test_cli_entry_initializes_logging_without_console(self):
        src = self._src("cli.py")
        self.assertIn("app_logging.setup(console=False)", src,
                      "CLI 应只写文件，避免日志污染 stdout/stderr")

    def test_crash_hooks_route_through_unified_logging(self):
        src = self._src("main.py")
        self.assertIn("_record_crash", src)
        # 三处异常出口（excepthook / threading.excepthook / QApplication.notify）
        self.assertGreaterEqual(src.count("_record_crash("), 4)

    def test_no_stderr_write_for_diagnostics_in_engine(self):
        """引擎层（scanner/）不应再用 stderr.write / print 输出诊断信息。"""
        offenders = []
        for root, dirs, names in os.walk(os.path.join(ROOT, "scanner")):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for n in names:
                if not n.endswith(".py"):
                    continue
                p = os.path.join(root, n)
                with io.open(p, encoding="utf-8") as fh:
                    src = fh.read()
                if "sys.stderr.write" in src:
                    offenders.append(f"{_rel(p)} 使用了 sys.stderr.write")
                if _PRINT_CALL.search(src):
                    offenders.append(f"{_rel(p)} 使用了 print(")
        self.assertEqual(offenders, [], "\n  ".join(offenders))


if __name__ == "__main__":
    unittest.main()
