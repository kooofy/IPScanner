# -*- coding: utf-8 -*-
"""i18n 惰性化与语言无关标识测试（P1-4）。

回归点（旧实现的三个缺陷）：
1. `tr()` 在 import 期求值并冻结 —— 切换语言后标签不变，必须重启进程。
   → 现在所有标签函数都是惰性翻译，语言包更新后立即生效。
2. 协议/服务/设备类别被当作**翻译后的显示文本**存储与比较 ——
   `proto == tr("HTTP")` 这类比较在语言变化后全部失配。
   → 现在内部一律用语言无关的规范值，显示时才翻译。
3. 匹配关键词表（厂商关键字）也被包了 tr() —— 一旦翻译就会匹配不到。
   → 现在这些表是字面量，并由测试保证不会被 tr() 包回去。
"""
import ast
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import db_util
import i18n
from scanner import constants as C
from scanner.classify import infer_device
from scanner.models import ScanResult


def tearDownModule():
    i18n.init("zh-CN")


class LazyLabelTest(unittest.TestCase):
    """标签必须随当前语言变化 —— 证明 tr() 是访问时求值而非 import 期冻结。"""

    def test_scan_level_label_is_lazy(self):
        i18n.init("zh-CN")
        zh = [C.scan_level_label(x) for x in ("quick", "standard", "all")]
        i18n.init("en-US")
        en = [C.scan_level_label(x) for x in ("quick", "standard", "all")]
        self.assertEqual(zh, ["快速 (21)", "标准 (1023)", "全端口 (65535)"])
        self.assertEqual(en, ["Quick (21)", "Standard (1023)", "All ports (65535)"])
        i18n.init("zh-CN")

    def test_scan_level_label_unknown_level_passthrough(self):
        self.assertEqual(C.scan_level_label("bogus"), "bogus")

    def test_legacy_module_dict_is_lazy(self):
        """旧常量名仍可用，且同样随语言变化（PEP 562 惰性属性）。"""
        i18n.init("zh-CN")
        zh = C.SCAN_LEVEL_LABELS["quick"]
        i18n.init("en-US")
        en = C.SCAN_LEVEL_LABELS["quick"]
        self.assertEqual(zh, "快速 (21)")
        self.assertEqual(en, "Quick (21)")
        i18n.init("zh-CN")

    def test_port_name_is_lazy_and_unknown_returns_empty(self):
        self.assertEqual(C.port_name(80), "HTTP")
        self.assertEqual(C.port_name(65001), "")

    def test_legacy_port_names_dict(self):
        self.assertEqual(C.PORT_NAMES[80], "HTTP")
        self.assertEqual(C.PORT_NAMES[3389], "RDP")

    def test_unknown_module_attribute_raises(self):
        with self.assertRaises(AttributeError):
            C.this_attribute_does_not_exist

    def test_device_class_and_os_labels(self):
        i18n.init("en-US")
        self.assertEqual(C.device_class_label("打印机"), "Printer")
        self.assertEqual(C.device_class_label("电脑/服务器"), "PC/Server")
        self.assertEqual(C.os_label("网络设备"), "Network Device")
        self.assertEqual(C.device_class_label(""), "")
        i18n.init("zh-CN")
        self.assertEqual(C.device_class_label("打印机"), "打印机")

    def test_conflict_labels_are_lazy(self):
        from conflict_detector import (Conflict, CONFLICT_DUPLICATE_MAC,
                                       SEVERITY_HIGH)
        c = Conflict(conflict_type=CONFLICT_DUPLICATE_MAC,
                     severity=SEVERITY_HIGH, description="x")
        i18n.init("zh-CN")
        zh = (c.type_label, c.severity_label)
        i18n.init("en-US")
        en = (c.type_label, c.severity_label)
        self.assertEqual(zh, ("MAC 地址重复", "严重"))
        self.assertNotEqual(zh, en)
        i18n.init("zh-CN")


class CanonicalIdentifierTest(unittest.TestCase):

    def test_protocol_ports_keys_are_ascii_codes(self):
        for key in C.PROTOCOL_PORTS:
            self.assertTrue(key.isascii(), msg=f"协议键不是 ASCII: {key!r}")
        self.assertEqual(C.PROTOCOL_PORTS["HTTP"], 80)
        self.assertEqual(C.PROTOCOL_PORTS["RDP"], 3389)

    def test_service_label_is_lazy(self):
        i18n.init("zh-CN")
        zh = C.service_label(C.SVC_SMB)
        i18n.init("en-US")
        en = C.service_label(C.SVC_SMB)
        self.assertEqual(zh, "SMB共享")
        self.assertEqual(en, "SMB Share")
        i18n.init("zh-CN")

    def test_service_label_unknown_passthrough(self):
        self.assertEqual(C.service_label("WEIRD"), "WEIRD")
        self.assertEqual(C.service_label(""), "")

    def test_service_code_normalizes_legacy_values(self):
        self.assertEqual(C.service_code("SNMP"), "SNMP")
        self.assertEqual(C.service_code("SMB共享"), "SMB")
        self.assertEqual(C.service_code("mDNS"), "mDNS")
        self.assertEqual(C.service_code(""), "")
        self.assertEqual(C.service_code(None), "")
        # 翻译后的值需要借助当前语言的反查表
        i18n.init("en-US")
        try:
            self.assertEqual(C.service_code("SMB Share"), "SMB")
            self.assertEqual(C.service_code("Printer"), "Printer")   # 非服务代码
        finally:
            i18n.init("zh-CN")

    def test_infer_device_is_language_independent(self):
        """同一设备在中文/英文环境下必须推断出**完全相同**的类别值。"""
        def _mk():
            r = ScanResult(ip="192.168.1.5", status="online")
            r.open_ports = [515, 631]      # 打印协议组合
            return r

        i18n.init("zh-CN")
        zh = infer_device(_mk())
        i18n.init("en-US")
        en = infer_device(_mk())
        i18n.init("zh-CN")
        self.assertEqual(zh, en, msg="设备类别随语言变化，落库后会导致历史查询失配")
        self.assertEqual(zh[0], "打印机")

    def test_infer_device_mdns_signal_language_independent(self):
        def _mk():
            r = ScanResult(ip="192.168.1.6", status="online")
            r.service_details = [{"proto": C.SVC_MDNS, "port": 0,
                                  "banner": "_printer._tcp.local"}]
            return r

        i18n.init("zh-CN")
        zh = infer_device(_mk())
        i18n.init("en-US")
        en = infer_device(_mk())
        i18n.init("zh-CN")
        self.assertEqual(zh, en)
        self.assertEqual(zh[0], "打印机")

    def test_wmi_device_class_language_independent(self):
        from scanner.wmi import wmi_device_class
        i18n.init("zh-CN")
        zh = wmi_device_class("Dell Inc.", "PowerEdge R740")
        i18n.init("en-US")
        en = wmi_device_class("Dell Inc.", "PowerEdge R740")
        i18n.init("zh-CN")
        self.assertEqual(zh, en)
        self.assertEqual(zh, "服务器")

    def test_wmi_device_class_matches_chinese_vendor_name(self):
        """中文厂商名是匹配关键词，不能因为切到英文而失配。"""
        from scanner.wmi import wmi_device_class
        i18n.init("en-US")
        got = wmi_device_class("华为技术有限公司", "MateBook")
        i18n.init("zh-CN")
        self.assertEqual(got, "电脑")


class I18nCanonicalTest(unittest.TestCase):

    def test_canonical_maps_translation_back_to_source(self):
        i18n.init("en-US")
        self.assertEqual(i18n.canonical("Printer"), "打印机")
        self.assertEqual(i18n.canonical("打印机"), "打印机")
        self.assertEqual(i18n.canonical("not-a-known-string"), "not-a-known-string")
        self.assertEqual(i18n.canonical(""), "")
        self.assertEqual(i18n.canonical(None), None)
        i18n.init("zh-CN")

    def test_canonical_is_identity_for_unknown(self):
        i18n.init("zh-CN")
        self.assertEqual(i18n.canonical("随便什么"), "随便什么")


class HistoryCrossLanguageTest(unittest.TestCase):
    """历史库以规范值存储，跨语言查询必须能命中。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "hist.db")
        import history_store
        self.hs = history_store
        self.hs.save_snapshot([
            {"ip": "192.168.1.10", "status": "online",
             "device_class": "打印机", "hostname": "prn-1"},
            {"ip": "192.168.1.11", "status": "online",
             "device_class": "手机", "hostname": "phone-1"},
        ], note="基线", db_path=self.db)

    def tearDown(self):
        db_util.close_connection(self.db)

    def test_query_with_english_term_finds_chinese_stored_value(self):
        i18n.init("en-US")
        try:
            rows = self.hs.query_history(device_class="Printer", db_path=self.db)
        finally:
            i18n.init("zh-CN")
        self.assertEqual(len(rows), 1, msg="英文界面用 Printer 查不到已存的「打印机」")
        self.assertEqual(rows[0]["ip"], "192.168.1.10")

    def test_query_with_chinese_term_still_works(self):
        rows = self.hs.query_history(device_class="打印机", db_path=self.db)
        self.assertEqual(len(rows), 1)


class LanguagePackCompletenessTest(unittest.TestCase):
    """英文语言包必须覆盖代码里所有含中文的 tr() 源串。

    这是把 `_audit_i18n.py` 的检查固化下来：任何人新增一条中文 UI 文案却忘了
    加翻译，测试就会失败，而不是等用户发现"英文界面显示中文"。

    用 AST 而不是正则收集，是因为正则有两个**真实盲区**，都曾造成
    "英文界面显示中文" 却测试全绿：
      1. 单引号写法 `tr('原因')` —— 旧正则只匹配双引号；
      2. 跨行隐式拼接 `tr("第一行\\n" "第二行")` —— 旧正则要求引号后紧跟 `)`。
    AST 里 `ast.Constant` 已经把隐式拼接折叠成一个字符串，两种写法都能覆盖。
    """

    SKIP_DIRS = {"venv", "build", "dist", "__pycache__", ".git",
                 ".workbuddy", ".workbuddy-ai", ".codeartsdoer", ".joycode"}

    def _collect(self):
        found = set()
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with io.open(path, encoding="utf-8") as fh:
                        tree = ast.parse(fh.read())
                except Exception:
                    continue
                for node in ast.walk(tree):
                    if not (isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name)
                            and node.func.id == "tr"
                            and node.args):
                        continue
                    arg = node.args[0]
                    if not (isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)):
                        continue
                    if any("\u4e00" <= ch <= "\u9fff" for ch in arg.value):
                        found.add(arg.value)
        return found

    def test_all_chinese_source_strings_are_translated(self):
        with io.open(os.path.join(ROOT, "i18n", "en-US.json"),
                     encoding="utf-8") as f:
            pack = json.load(f)
        missing = sorted(s for s in self._collect() if s not in pack)
        self.assertEqual(
            missing, [],
            msg="以下中文界面文案缺少英文翻译，英文界面会显示中文：\n  "
                + "\n  ".join(repr(m) for m in missing),
        )


class TableDrivenLabelCoverageTest(unittest.TestCase):
    """变量驱动的 tr() 标签同样必须有翻译。

    `LanguagePackCompletenessTest` 走 AST 收集 **字面量** `tr("…")`，所以
    `for key, label in TABLE: tr(label)` 这种写法是它的盲区。这个盲区真实咬过
    一次：`FILTERS` / `COLUMN_PRESETS` 里 5 个标签（已匹配、巡检、资产、安全、
    全量）漏了英文，测试却全绿，英文界面直接显示中文。

    这里把"面向用户的标签表"显式列出来逐项校验 —— 新增此类表时记得登记。
    """

    def _label_tables(self):
        from design_tokens import _DENSITY_TEXT
        from risk_rules import _REASON_TEXT as _RISK_REASON_TEXT
        from risk_rules import _RISK_LEVEL_TEXT
        from filter_bar import FILTERS
        from main_window import (
            COLUMN_PRESETS, COLUMN_LABELS, THEME_MODES, VIEW_MODES,
        )
        from main_window_tree import _CHANGE_LABEL
        from scanner import constants as _sc
        from credentials import _PROTOCOL_TEXT
        from ui_msg import STANDARD_BUTTON_TEXT
        from cve_status_mixin import (
            _CVE_BADGE_TEXT, _CVE_HINT_TEXT, _CVE_SOURCE_TEXT,
        )
        return {
            "filter_bar.FILTERS": [label for _k, label in FILTERS],
            "main_window.COLUMN_PRESETS": [lbl for _k, lbl, _c in COLUMN_PRESETS],
            "main_window.COLUMN_LABELS": list(COLUMN_LABELS),
            "main_window.THEME_MODES": [lbl for _k, lbl in THEME_MODES],
            "main_window.VIEW_MODES": [lbl for _k, lbl in VIEW_MODES],
            "main_window_tree._CHANGE_LABEL": list(_CHANGE_LABEL.values()),
            # scanner.constants 的两张"显示名表"：值同样是**字面量**（模块顶层不能
            # 调 tr()，否则会被冻成导入期语言），AST 收集不到，只能显式登记。
            # `_PHASE_TEXT` 是扫描摘要条"当前阶段"的来源，漏翻只会在英文界面
            # 显示中文阶段名 —— 与 FILTERS/COLUMN_PRESETS 那次是同一类盲区。
            "scanner.constants._SCAN_LEVEL_TEXT":
                list(_sc._SCAN_LEVEL_TEXT.values()),
            "scanner.constants._PHASE_TEXT": list(_sc._PHASE_TEXT.values()),
            "scanner.constants._LOCATE_REASON_TEXT":
                list(_sc._LOCATE_REASON_TEXT.values()),
            "scanner.constants._LOCATE_REASON_HINT":
                list(_sc._LOCATE_REASON_HINT.values()),
            # design_tokens 的行高档位显示名（同上：字面量表）。
            "design_tokens._DENSITY_TEXT": list(_DENSITY_TEXT.values()),
            # credentials 的协议显示名表（同上：字面量表，AST 收集不到）。
            # 当前四个值都非中文（SNMP v1/v2c/v3、WMI），所以本测试不会因它变红；
            # 登记它是为了**将来**若有人把某协议显示名改成中文时能被拦住。
            "credentials._PROTOCOL_TEXT": list(_PROTOCOL_TEXT.values()),
            # risk_rules 的风险等级 / 理由显示名（同上：字面量表，AST 收集不到）。
            "risk_rules._RISK_LEVEL_TEXT": list(_RISK_LEVEL_TEXT.values()),
            "risk_rules._REASON_TEXT": list(_RISK_REASON_TEXT.values()),
            # ui_msg 的标准按钮表：值是**字面量**（模块顶层不能调 tr()，否则会被
            # 冻结成导入期语言），所以 AST 收集不到，必须在这里显式登记。
            "ui_msg.STANDARD_BUTTON_TEXT": list(STANDARD_BUTTON_TEXT.values()),
            # cve_status_mixin 的三张表（CVE 徽标 / 现状+下一步 / 来源显示名）：
            # 同上是**字面量表**，且它们由 `badge_text()` 等函数过 tr() 后再
            # format —— 漏登记就会在英文界面显示中文徽标，且没有任何告警。
            "cve_status_mixin._CVE_BADGE_TEXT": list(_CVE_BADGE_TEXT.values()),
            "cve_status_mixin._CVE_HINT_TEXT": list(_CVE_HINT_TEXT.values()),
            "cve_status_mixin._CVE_SOURCE_TEXT": list(_CVE_SOURCE_TEXT.values()),
        }

    def test_all_table_labels_are_translated(self):
        with io.open(os.path.join(ROOT, "i18n", "en-US.json"),
                     encoding="utf-8") as f:
            pack = json.load(f)
        missing = []
        for name, labels in self._label_tables().items():
            for label in labels:
                has_cjk = any("\u4e00" <= ch <= "\u9fff" for ch in label)
                if has_cjk and label not in pack:
                    missing.append(f"{name}: {label!r}")
        self.assertEqual(
            missing, [],
            msg="以下表驱动标签缺少英文翻译，英文界面会显示中文：\n  "
                + "\n  ".join(missing),
        )


class MatchTablePurityTest(unittest.TestCase):
    """厂商/OUI 匹配关键词表必须是字面量，绝不能包 tr()。

    这些表是拿设备返回的字符串去**匹配**的，一旦被翻译（例如把「华为」翻成
    "Huawei"），英文模式下就再也匹配不到中文厂商名了。
    """

    MATCH_TABLES = ("_OUI_CLASS_HINTS", "_IOT_VENDOR_KEYWORDS", "_PRINTER_BRANDS")

    def _source(self):
        with io.open(os.path.join(ROOT, "scanner", "constants.py"),
                     encoding="utf-8") as f:
            return f.read()

    def test_match_tables_contain_no_tr_calls(self):
        src = self._source()
        for name in self.MATCH_TABLES:
            start = src.index(name + " =")
            endmark = ")" if name == "_IOT_VENDOR_KEYWORDS" else "]"
            # 从表定义开始，找到与之配对的结束符
            end = src.index(endmark + "\n", start)
            block = src[start:end]
            self.assertNotIn(
                "tr(", block,
                msg=f"{name} 里出现了 tr() —— 匹配关键词不能被翻译",
            )

    def test_oui_class_hint_values_are_canonical_device_classes(self):
        """_OUI_CLASS_HINTS 的值会直接成为 device_class，必须是规范值。"""
        i18n.init("zh-CN")
        try:
            zh = {cls for _, cls in C._OUI_CLASS_HINTS}
            i18n.init("en-US")
            en = {cls for _, cls in C._OUI_CLASS_HINTS}
        finally:
            i18n.init("zh-CN")
        self.assertEqual(zh, en, msg="OUI 提示表的类别值随语言变化了")

    def test_column_aliases_are_language_independent(self):
        """Excel 列别名表必须与界面语言无关。

        真实事故：它原本写的是 `tr("ip地址")`。英文模式下这些别名在导入期就被求值成
        "IP Address"，于是随版本内置的中文模板 `设备清单模板.xlsx` 完全无法导入。
        正确做法是中英文别名**都以字面量**列在表里 —— Excel 用哪种语言写都能匹配，
        与界面语言彻底解耦。
        """
        import excel_handler

        i18n.init("zh-CN")
        try:
            zh = {f: tuple(v) for f, v in excel_handler.COLUMN_ALIASES.items()}
            i18n.init("en-US")
            en = {f: tuple(v) for f, v in excel_handler.COLUMN_ALIASES.items()}
        finally:
            i18n.init("zh-CN")
        self.assertEqual(zh, en, msg="Excel 列别名表随界面语言变化了")

    def test_column_detection_works_in_english_ui(self):
        """中文模板与英文表头都要能识别 —— 刻意在英文界面下验证。"""
        import excel_handler

        zh_hdr = ["IP地址", "MAC地址", "设备类型", "位置", "使用者", "备注"]
        en_hdr = ["IP Address", "MAC Address", "Device Type",
                  "Location", "User", "Remark"]

        i18n.init("en-US")          # 这正是原本出问题的场景
        try:
            zh_map = excel_handler.detect_columns(zh_hdr)
            en_map = excel_handler.detect_columns(en_hdr)
        finally:
            i18n.init("zh-CN")

        self.assertEqual(len(zh_map), 6, msg=f"中文表头识别失败: {zh_map}")
        self.assertEqual(sorted(zh_map), sorted(en_map))

    def test_phone_brand_display_keys_are_match_patterns(self):
        """_PHONE_BRAND_DISPLAY 的键是 OUI 匹配模式，不得随语言变化。"""
        i18n.init("zh-CN")
        try:
            zh = tuple(C._PHONE_BRAND_DISPLAY)
            i18n.init("en-US")
            en = tuple(C._PHONE_BRAND_DISPLAY)
        finally:
            i18n.init("zh-CN")
        self.assertEqual(zh, en, msg="_PHONE_BRAND_DISPLAY 的键随语言变化了")


class NoImportTimeTrTest(unittest.TestCase):
    """导入期不得求值 tr() —— P1-4 漏掉的那道兜底网。

    语言包在 `i18n.init()` 时才加载，而 `i18n.init()` 早于大部分业务模块的导入
    （`main.py` 里 i18n 在 main_window 之前初始化）。因此任何在**模块顶层**求值的
    `tr()` 都会被永久冻结成当时那个语言，且事后无法回溯重算。

    这道测试补上后立刻抓出两处真实事故：

    1. `excel_handler.COLUMN_ALIASES` 写的是 `tr("ip地址")`。英文模式下这些别名在
       导入期被求值成 `"IP Address"`，于是随版本内置的中文模板
       `设备清单模板.xlsx` **完全无法导入**（`detect_columns` 返回空字典，
       用户看到的是"未找到 IP/MAC 列"）。
    2. `scanner/constants._PHONE_BRAND_DISPLAY` 写的是 `tr("三星")`。英文界面下
       「设备类型」列的型号永远显示中文品牌名。

    判定规则（作用域感知，不能简单地 ast.walk 到底）：
      - 模块顶层语句、以及**类体**，都在 import 期执行；
      - 函数 / lambda 体是延迟执行 → 停止下探。
        这正是 `_LAZY_ALIASES` 用 lambda 实现惰性的原理，误判会把它一并否掉。

    ⚠️ 类体**不是**延迟执行。早先这里把 `ClassDef` 和函数一起当成"延迟执行"跳过，
    于是漏掉了一整类事故：`ui_dialogs.py` 里 8 个对话框把表头写成
    `COLS = [tr("IP 地址"), …]`，导入时就被冻成中文 —— 实测在
    `i18n.init("en-US")` 之后 `COLS[0]` 仍是 `"IP 地址"`，英文界面下这些对话框的
    表头永远是中文。现在类体也下探，这类写法一律得改成 `@property`。
    """

    SKIP_DIRS = {"venv", "build", "dist", "dist_new", "__pycache__",
                 ".git", ".github", "i18n"}

    @staticmethod
    def _module_level_tr_lines(path):
        with io.open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())

        found = []

        def walk(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.Lambda)):
                    continue          # 延迟执行，不下探
                if isinstance(child, ast.ClassDef):
                    walk(child)       # 类体在 import 期就执行 → 必须下探
                    continue
                if (isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Name)
                        and child.func.id in ("tr", "_tr")):
                    found.append(child.lineno)
                walk(child)

        walk(tree)
        return found

    def test_no_module_evaluates_tr_at_import_time(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fn in sorted(filenames):
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    lines = self._module_level_tr_lines(path)
                except SyntaxError as e:
                    self.fail(f"{os.path.relpath(path, ROOT)} 解析失败: {e}")
                rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                offenders += [f"{rel}:{ln}" for ln in lines]

        self.assertEqual(
            offenders, [],
            "以下位置在模块顶层调用了 tr()，会被冻结成导入时的语言。\n"
            "请改为惰性函数，或加进 scanner/constants.py 的 _LAZY_ALIASES：\n  "
            + "\n  ".join(offenders),
        )

    def test_scanner_layer_has_no_tr_at_import_time(self):
        """引擎层单独再查一遍：它必须零 GUI 依赖、可被 CLI 无头复用。"""
        offenders = []
        for fn in sorted(os.listdir(os.path.join(ROOT, "scanner"))):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(ROOT, "scanner", fn)
            offenders += [f"scanner/{fn}:{ln}"
                          for ln in self._module_level_tr_lines(path)]
        self.assertEqual(offenders, [], f"引擎层导入期 tr(): {offenders}")


if __name__ == "__main__":
    unittest.main()
