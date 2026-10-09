# -*- coding: utf-8 -*-
"""P1-5 回归测试：工程化脚手架的完整性。

历史缺陷
--------
仓库此前没有 README / LICENSE / pyproject.toml / CI，`requirements.txt` 用的是
`>=` 而非 `==`：

    PyQt5>=5.15.11
    openpyxl>=3.1.5
    xlrd>=2.0.1

后果是任何一次全新安装都可能拉到未经本项目验证的新版本；桌面 GUI 对 Qt 小版本
差异尤其敏感，上游一旦引入不兼容改动，用户侧的表现是"装完就崩"。同时，
手写的 PyInstaller spec 被 `.gitignore` 里的 `*.spec` 一并忽略，导致发布构建的
配方（hiddenimports / datas）根本没入库，别人无法复现同一份 exe。

本测试把这些约定固化成断言，防止后续回退。
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import tomllib                      # Python 3.11+
except ImportError:                     # pragma: no cover - Python 3.10
    tomllib = None


def _read(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as fh:
        return fh.read()


def _requirements_entries(rel_path):
    """把 requirements 文件解析成 [(原始行号, 内容)]，跳过注释/空行/-r 指令。"""
    entries = []
    for lineno, raw in enumerate(_read(rel_path).splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        entries.append((lineno, line))
    return entries


def _has_marker(line):
    """该依赖行是否带 PEP 508 环境标记（`;` 之后为标记部分）。"""
    return ";" in line


def _package_name(line):
    """从依赖行取出包名（去掉 extras、版本约束与环境标记）。"""
    return re.split(r"[=<>!;\[]", line, maxsplit=1)[0].strip()


class RequirementsPinnedTest(unittest.TestCase):
    """依赖必须精确锁定；平台条件行是唯一例外，且受白名单管控。"""

    # 精确锁定：name==x.y.z（可带 extras）。
    PIN_RE = re.compile(r"^[A-Za-z0-9._-]+(\[[^\]]+\])?==[^\s;]+$")

    # 平台条件行的合法形式：name==ver 或 name>=ver，后接 `; 环境标记`。
    MARKER_LINE_RE = re.compile(
        r"^[A-Za-z0-9._-]+(\[[^\]]+\])?(==|>=)[^\s;]+;\s*\S.*$"
    )

    # 允许使用「环境标记 + 下界约束」的包白名单。
    # 默认答案是"精确锁版本"；只有当一个包在**各平台上没有共同可用版本**时，
    # 才允许分流。加新条目必须同时写清理由（见 requirements.txt 对应注释）。
    #   PyQt5-Qt5：Windows 只有 5.15.2 有 win wheel；macOS arm64 要 >=5.15.11；
    #              而 Linux 的 5.15.11~5.15.13 又没有 manylinux wheel。三平台无交集。
    MARKER_ALLOWED = {"PyQt5-Qt5"}

    def test_runtime_requirements_all_pinned(self):
        for lineno, line in _requirements_entries("requirements.txt"):
            if _has_marker(line):
                continue      # 平台条件行由 test_marker_lines_are_allowlisted 校验
            with self.subTest(line=line):
                self.assertRegex(
                    line, self.PIN_RE,
                    f"requirements.txt:{lineno} 未精确锁定版本（应写成 name==x.y.z）：{line}",
                )

    def test_dev_requirements_all_pinned(self):
        for lineno, line in _requirements_entries("requirements-dev.txt"):
            if _has_marker(line):
                continue
            with self.subTest(line=line):
                self.assertRegex(
                    line, self.PIN_RE,
                    f"requirements-dev.txt:{lineno} 未精确锁定版本：{line}",
                )

    def test_no_open_ended_specifiers(self):
        """显式拦截 `>=` / `~=` / 裸包名 —— 这是本次修复针对的具体写法。

        例外：带环境标记的平台条件行允许用 `>=` 下界 —— 三平台没有共同可用
        版本时，精确锁死会让某个平台直接装不上。这些行必须落在 MARKER_ALLOWED
        白名单内，并由 test_marker_lines_are_allowlisted 校验形式。
        """
        for rel in ("requirements.txt", "requirements-dev.txt"):
            for lineno, line in _requirements_entries(rel):
                if _has_marker(line):
                    continue
                with self.subTest(file=rel, line=line):
                    for bad in (">=", "<=", "~=", ">", "<", "!="):
                        self.assertNotIn(
                            bad, line,
                            f"{rel}:{lineno} 含开放版本约束 {bad!r}：{line}",
                        )

    def test_marker_lines_are_allowlisted(self):
        """平台条件行不能悄悄扩散：包名必须在白名单里，且形式受限。"""
        for rel in ("requirements.txt", "requirements-dev.txt"):
            for lineno, line in _requirements_entries(rel):
                if not _has_marker(line):
                    continue
                with self.subTest(file=rel, line=line):
                    self.assertIn(
                        _package_name(line), self.MARKER_ALLOWED,
                        f"{rel}:{lineno} 用了环境标记但不在 MARKER_ALLOWED 白名单：{line}",
                    )
                    self.assertRegex(
                        line, self.MARKER_LINE_RE,
                        f"{rel}:{lineno} 平台条件行形式非法"
                        f"（应为 name==ver 或 name>=ver; 标记）：{line}",
                    )

    def test_dev_requirements_pulls_in_runtime(self):
        self.assertIn("-r requirements.txt", _read("requirements-dev.txt"))

    def test_dev_requirements_cover_build_and_lint(self):
        text = _read("requirements-dev.txt").lower()
        self.assertIn("pyinstaller", text)
        self.assertIn("ruff", text)


class VersionSyncTest(unittest.TestCase):
    """版本号只有一个来源（version.py），且漂移会被抓住。"""

    def test_version_matches_pyproject(self):
        import version

        pyproject = _read("pyproject.toml")
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
        self.assertIsNotNone(m, "pyproject.toml 里找不到 [project] version")
        self.assertEqual(
            m.group(1), version.__version__,
            "pyproject.toml 的 version 与 version.py 的 __version__ 不一致，请同步",
        )

    def test_exe_basename_derives_from_version(self):
        import version

        self.assertEqual(version.EXE_BASENAME, f"IPScanner_{version.__version__}")

    def test_cli_reads_version_from_version_module(self):
        """cli.py 必须引用 version.py，不得再写死字面量。"""
        import version

        src = _read("cli.py")
        self.assertIn("from version import __version__", src)
        self.assertNotIn(
            f'__version__ = "{version.__version__}"', src,
            "cli.py 里又出现了写死的版本号，请改为引用 version.py",
        )

    def test_gui_about_dialog_reads_version_from_version_module(self):
        """关于对话框的版本号必须来自 version.py。

        历史缺陷：`main_window.py` 写死「版本 1.6.0」，而版本号同时散落在
        cli.py 与 spec 文件名里 —— 发版漏改一处就会出现「exe 叫 1.6.0、
        关于对话框写着 1.5.0」这种用户可见的不一致，且没有测试会发现。
        """
        import version

        src = _read("main_window.py")
        self.assertIn("from version import __version__", src)
        self.assertNotIn(
            f"版本 {version.__version__}", src,
            "关于对话框又写死了版本号，请改为引用 version.py",
        )

    def test_spec_is_version_agnostic(self):
        """spec 文件名固定，产物名由 version.py 派生。

        旧方案是 `IPScanner_1.6.0.spec`：每次发版改文件名，CI 只能按 mtime
        猜当前该构建哪个，还得同步 README / .gitignore / CI 三处。
        """
        import version

        self.assertTrue(
            os.path.exists(os.path.join(ROOT, "IPScanner.spec")),
            "应存在固定名 IPScanner.spec",
        )
        self.assertIn("from version import EXE_BASENAME", _read("IPScanner.spec"))
        stale = sorted(
            f for f in os.listdir(ROOT)
            if re.match(r"^IPScanner_\d+\.\d+\.\d+\.spec$", f)
        )
        self.assertEqual(stale, [], f"仍存在带版本号的 spec 文件: {stale}")
        self.assertEqual(version.EXE_BASENAME, f"IPScanner_{version.__version__}")

    @unittest.skipIf(tomllib is None, "tomllib 需要 Python 3.11+")
    def test_pyproject_is_valid_toml(self):
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
            data = tomllib.load(fh)
        self.assertEqual(data["project"]["name"], "ipscanner")
        self.assertEqual(data["project"]["requires-python"], ">=3.10")
        # ruff 配置必须存在，否则 CI 的 `ruff check .` 会退回到默认全量规则集
        self.assertEqual(data["tool"]["ruff"]["lint"]["select"], ["F", "E9"])

    @unittest.skipIf(tomllib is None, "tomllib 需要 Python 3.11+")
    def test_pyproject_dependencies_match_requirements(self):
        """requirements.txt 与 pyproject 的依赖声明不能漂移。"""
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
            declared = set(tomllib.load(fh)["project"]["dependencies"])
        installed = {line for _, line in _requirements_entries("requirements.txt")}
        self.assertEqual(
            declared, installed,
            "pyproject.toml 的 dependencies 与 requirements.txt 不一致",
        )


class LicenseTest(unittest.TestCase):

    def test_license_file_exists_and_is_gpl3(self):
        text = _read("LICENSE")
        self.assertIn("GNU GENERAL PUBLIC LICENSE", text)
        self.assertIn("Version 3, 29 June 2007", text)
        # 完整性抽查：条款正文与结尾的「如何应用」章节都在
        self.assertIn("TERMS AND CONDITIONS", text)
        self.assertIn("15. Disclaimer of Warranty", text)
        self.assertIn("How to Apply These Terms", text)
        self.assertGreater(len(text), 30000, "LICENSE 看起来被截断了")

    def test_pyproject_declares_license(self):
        self.assertIn('license = { file = "LICENSE" }', _read("pyproject.toml"))

    def test_readme_states_license(self):
        readme = _read("README.md")
        self.assertIn("GPL", readme)
        self.assertIn("LICENSE", readme)


class ReadmeTest(unittest.TestCase):

    def setUp(self):
        self.readme = _read("README.md")

    def test_has_english_overview(self):
        self.assertIn("## English Overview", self.readme)

    def test_documents_core_sections(self):
        for heading in ("## 功能特性", "## 快速开始", "## 命令行",
                        "## 项目结构", "## 许可证", "## 免责声明"):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.readme)

    def test_documents_data_directory_fallback(self):
        """数据目录回退策略是用户最容易踩的坑，必须写清楚。"""
        self.assertIn("LOCALAPPDATA", self.readme)

    def test_has_safety_disclaimer(self):
        """网络扫描工具必须明确告知授权边界，这是合规底线。"""
        self.assertIn("授权", self.readme)
        self.assertIn("免责声明", self.readme)

    def test_snmp_version_claim_matches_the_implementation(self):
        """README 不得声称支持 SNMP v1 —— 实现里没有这条路径。

        `scanner/snmp.py` 构造报文时硬编码 `version=1`，那是 **v2c**（v1 应为 0），
        全项目不存在任何 v1 代码路径。此前 README 的「项目结构」里写着
        `snmp.py # SNMP v1/v2c`，与同文件「已知限制」里的「v1 不支持」自相矛盾 ——
        用户读到哪一句完全取决于他先翻到哪一段。
        """
        self.assertNotIn("v1/v2c", self.readme)
        self.assertIn("SNMP v2c", self.readme)

    def test_ci_badge_points_at_real_workflow(self):
        """README 的 CI 徽章必须指向**真实存在**的 workflow 文件。

        断言的是"徽章 URL 里的 workflow 路径确实存在"，而不是某个偶然出现在
        正文里的字符串。旧写法匹配的是正文中一句"发版时需更新 CI 引用"的说明 ——
        那句话随 spec 改名（不再需要手改 CI）一起删掉后，测试就假失败了。
        一个名为 points_at_real_workflow 的测试，就该真的去检查文件是否存在。
        """
        m = re.search(r"actions/workflows/([\w.-]+)", self.readme)
        self.assertIsNotNone(m, "README 里找不到 CI 徽章的 workflow 路径")
        workflow = os.path.join(".github", "workflows", m.group(1))
        self.assertTrue(
            os.path.exists(os.path.join(ROOT, workflow)),
            f"CI 徽章指向的 workflow 文件不存在: {workflow}",
        )


class CiWorkflowTest(unittest.TestCase):

    def setUp(self):
        self.text = _read(os.path.join(".github", "workflows", "ci.yml"))

    def test_exists_and_triggers_on_main(self):
        self.assertIn("branches: [main]", self.text)
        self.assertIn("pull_request", self.text)

    def test_runs_tests_and_lint(self):
        self.assertIn("python run_tests.py", self.text)
        self.assertIn("python -m ruff check .", self.text)

    def test_matrix_covers_declared_python_range(self):
        for v in ('"3.10"', '"3.11"', '"3.12"', '"3.13"'):
            with self.subTest(version=v):
                self.assertIn(v, self.text)

    def test_sets_offscreen_qt_platform(self):
        """无显示环境下不设 offscreen，PyQt5 import 会失败。"""
        self.assertIn("QT_QPA_PLATFORM: offscreen", self.text)

    def test_installs_dev_requirements(self):
        self.assertIn("requirements-dev.txt", self.text)

    def test_smoke_tests_the_cli(self):
        self.assertIn("cli.py scan", self.text)
        self.assertIn("--no-mdns", self.text)


class EditorConfigTest(unittest.TestCase):

    def test_exists_and_is_root(self):
        text = _read(".editorconfig")
        self.assertIn("root = true", text)
        self.assertIn("end_of_line = lf", text)
        self.assertIn("charset = utf-8", text)

    def test_batch_scripts_keep_crlf(self):
        text = _read(".editorconfig")
        self.assertIn("end_of_line = crlf", text)


class GitAttributesTest(unittest.TestCase):

    def test_exists_and_normalizes_line_endings(self):
        text = _read(".gitattributes")
        self.assertIn("text=auto", text)
        self.assertIn("*.bat text eol=crlf", text)

    def test_spec_files_are_no_longer_ignored(self):
        """手写 spec 必须能入库，否则发布构建无法复现。"""
        rules = []
        for raw in _read(".gitignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                rules.append(line)
        self.assertNotIn(
            "*.spec", rules,
            ".gitignore 不应整体忽略 *.spec（手写的 IPScanner_*.spec 需要入库）",
        )
        self.assertIn("/main.spec", rules)
        self.assertIn("/cli.spec", rules)


class GraphicsItemImportTest(unittest.TestCase):
    """F821 回归守卫。

    历史缺陷：拓扑绘制的 `_add_switch_node()` 使用了 `QGraphicsRectItem`，
    但该名字从未被导入 —— 任何包含交换机的拓扑图一点「绘制拓扑」就抛
    NameError。ruff 的 F821 现在会拦住这类问题，这里再补一道不依赖 CI 的
    直接断言。

    （拆分后拓扑绘制位于 `ui_dialogs/topology.py`，断言随之指向该子模块。）
    """

    def test_topology_graphics_items_are_imported(self):
        from ui_dialogs import topology as _topo
        for name in ("QGraphicsRectItem", "QGraphicsEllipseItem",
                     "QGraphicsTextItem", "QGraphicsScene", "QGraphicsView"):
            with self.subTest(name=name):
                self.assertTrue(
                    hasattr(_topo, name),
                    f"ui_dialogs/topology.py 未导入 {name}，对应代码路径会抛 NameError",
                )


if __name__ == "__main__":
    unittest.main()
