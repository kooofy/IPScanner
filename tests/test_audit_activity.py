# -*- coding: utf-8 -*-
"""扫描活动自查（v2.2 §3.3）测试：聚合层 + CLI 子命令 + GUI 对话框。

覆盖路线图 §3.3 的验收：
* 数据源只有 `audit_log`（不新增采集）—— 聚合结果与**直接读库**逐条对得上；
* 空数据必须给 `reason` + 下一步，**不给空表**（否则用户会得出"我没扫过"的反结论）；
* 时间窗 24h / 7d / 全部：过滤在 SQL 侧，边界精确；
* 聚合只认**结构化**汇总（`action=SUM_ACTION` + 语言无关 JSON detail），
  本地化自由文本事件一行都不许混进来 —— 否则切语言结论会漂移；
* CLI 的 JSON 键固定英文；GUI 与 CLI 两条写入路径**同口径**。

⚠ 文案断言一律用 `tr()` 现算期望值，不写死中文（英文 runner 上必挂）。
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests._qt_app import ensure_qt_app  # noqa: E402

ensure_qt_app()

import audit_log  # noqa: E402
import cli  # noqa: E402
import db_util  # noqa: E402
import i18n  # noqa: E402
from i18n import tr  # noqa: E402
from ui_dialogs.audit_activity import (  # noqa: E402
    AuditActivityDialog, _COLUMN_LABELS, _HINT_ESTIMATE, _HINT_SCOPE,
    _REASON_TEXT, _WINDOW_TEXT,
)

HOUR = 3600.0


def _new_db():
    """临时库路径（每个用例一个，互不干扰）。"""
    return os.path.join(tempfile.mkdtemp(prefix="audit_activity_"), "audit.db")


def _insert(db, ts, detail, action=audit_log.SUM_ACTION,
            category=audit_log.CAT_SCAN):
    """直插一行，**时间戳由调用方控制**（窗口边界测试的关键）。"""
    if isinstance(detail, (dict, list)):
        detail = json.dumps(detail)
    with audit_log._conn(db) as conn:
        conn.execute(
            "INSERT INTO audit_logs (ts, category, action, detail) "
            "VALUES (?,?,?,?)", (ts, category, action, detail))
        conn.commit()


def _summary(range_="192.168.1.0/24", ips=254, online=5, protocols=("HTTP",),
             ports=21, throttle="fast", source="cli"):
    return {
        "ranges": [{"range": range_, "ips": ips}],
        "ips": ips, "online": online, "protocols": list(protocols),
        "ports_scanned": ports, "throttle": throttle, "source": source,
    }


class AggregationTest(unittest.TestCase):
    """聚合口径：与直接读库交叉验证，逐项对得上。"""

    def setUp(self):
        self.db = _new_db()
        self.now = time.time()

    def test_empty_db_gives_reason_not_empty_table(self):
        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual(s["reason"], audit_log.REASON_NO_RECORDS)
        self.assertEqual(s["ranges"], [])
        self.assertEqual(s["scan_count"], 0)
        self.assertEqual(s["protocols"], {})
        self.assertIsNone(s["first_ts"])
        self.assertIsNone(s["last_ts"])
        # 键集合固定 —— CLI 的 JSON 契约依赖它
        self.assertEqual(set(s), {
            "reason", "window_hours", "scan_count", "range_count", "total_ips",
            "total_online", "estimated_probes", "port_scan_count", "protocols",
            "throttles", "ranges", "first_ts", "last_ts"})

    def test_cross_check_against_raw_rows(self):
        """聚合结果 == 手工按库里的行算出来的结果（逐字段）。"""
        rows = [
            (self.now - 3 * HOUR, _summary("192.168.1.0/24", 254, 5, ("HTTP",), 21)),
            (self.now - 2 * HOUR, _summary("192.168.1.0/24", 254, 7, ("HTTP", "SSH"), None)),
            (self.now - 1 * HOUR, _summary("10.0.0.0/24", 254, 12, ("HTTP", "SNMP"), 100,
                                          throttle="polite", source="gui")),
        ]
        for ts, detail in rows:
            _insert(self.db, ts, detail)

        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual(s["reason"], "")
        self.assertEqual(s["scan_count"], len(rows))
        self.assertEqual(s["total_ips"], sum(r["ips"] for _, r in rows))
        self.assertEqual(s["total_online"], sum(r["online"] for _, r in rows))
        self.assertEqual(s["port_scan_count"],
                         sum(1 for _, r in rows if r["ports_scanned"]))
        expected_protocols = {}
        for _, r in rows:
            for p in r["protocols"]:
                expected_protocols[p] = expected_protocols.get(p, 0) + 1
        self.assertEqual(s["protocols"], expected_protocols)
        self.assertEqual(s["throttles"], {"fast": 2, "polite": 1})
        expected_probes = sum(
            r["ips"] + (r["online"] * r["ports_scanned"] if r["ports_scanned"] else 0)
            for _, r in rows)
        self.assertEqual(s["estimated_probes"], expected_probes)
        self.assertEqual(s["range_count"], 2)
        self.assertAlmostEqual(s["first_ts"], rows[0][0], places=3)
        self.assertAlmostEqual(s["last_ts"], rows[-1][0], places=3)

    def test_window_filtering_is_exact(self):
        _insert(self.db, self.now - 48 * HOUR, _summary())   # 两天前
        _insert(self.db, self.now - 3 * HOUR, _summary())    # 三小时前
        _insert(self.db, self.now - 60, _summary())          # 一分钟前
        self.assertEqual(
            audit_log.activity_summary(24, db_path=self.db)["scan_count"], 2)
        self.assertEqual(
            audit_log.activity_summary(168, db_path=self.db)["scan_count"], 3)
        self.assertEqual(
            audit_log.activity_summary(None, db_path=self.db)["scan_count"], 3)
        # 窗口比所有事件都新 → 明确的"无记录"，不是空表
        self.assertEqual(
            audit_log.activity_summary(0.0001, db_path=self.db)["reason"],
            audit_log.REASON_NO_RECORDS)

    def test_window_hours_normalized_to_int(self):
        """JSON 契约：24 而不是 24.0；None 原样保留。"""
        _insert(self.db, self.now - 60, _summary())
        self.assertEqual(audit_log.activity_summary(24, db_path=self.db)["window_hours"], 24)
        self.assertIsInstance(audit_log.activity_summary(24, db_path=self.db)["window_hours"], int)
        self.assertIsNone(audit_log.activity_summary(None, db_path=self.db)["window_hours"])

    def test_invalid_window_raises(self):
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                audit_log.activity_summary(bad, db_path=self.db)

    def test_localized_free_text_events_are_excluded(self):
        """本地化事件（action/detail 是 tr() 结果）一行都不许进聚合。"""
        _insert(self.db, self.now - 60, _summary())
        # 故意插一条**本地化自由文本**事件（action/detail 都是 tr() 结果），
        # 它不该被聚合 —— 这里不写 tr()，免得被 i18n 完整性测试当成界面文案收走。
        audit_log.log_event(audit_log.CAT_SCAN, "开始扫描",
                            "范围: 192.168.1.0/24 (254 个IP)", db_path=self.db)
        audit_log.log_event(audit_log.CAT_EXPORT, audit_log.SUM_ACTION,
                            json.dumps(_summary(ips=99999)), db_path=self.db)
        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual(s["scan_count"], 1)
        self.assertEqual(s["total_ips"], 254)

    def test_malformed_details_are_skipped_not_counted(self):
        _insert(self.db, self.now - 60, _summary())
        for bad in ("not-json", "[1, 2]", "null", '"text"'):
            _insert(self.db, self.now - 30, bad)
        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual(s["scan_count"], 1)
        self.assertEqual(s["total_ips"], 254)

    def test_ranges_accumulate_and_sort_recent_first(self):
        _insert(self.db, self.now - 3 * HOUR, _summary("10.0.0.0/24", 254))
        _insert(self.db, self.now - 2 * HOUR, _summary("192.168.1.0/24", 254))
        _insert(self.db, self.now - 1 * HOUR, _summary("192.168.1.0/24", 254))
        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual([a["range"] for a in s["ranges"]],
                         ["192.168.1.0/24", "10.0.0.0/24"])
        top = s["ranges"][0]
        self.assertEqual(top["scans"], 2)
        self.assertEqual(top["ips"], 508)
        self.assertEqual(top["estimated_probes"], 508)

    def test_estimated_probes_is_lower_bound(self):
        """只含主机发现 + 在线设备端口探测；没扫端口就不加端口项。"""
        self.assertEqual(
            audit_log.estimated_probes(_summary(ips=254, online=5, ports=21)),
            254 + 5 * 21)
        self.assertEqual(
            audit_log.estimated_probes(_summary(ips=254, online=5, ports=None)),
            254)


class SummaryNormalizationTest(unittest.TestCase):
    """写入端兜底：畸形入参不抛、不留 "None" 这类假值。"""

    def setUp(self):
        self.db = _new_db()

    def _stored(self):
        rows = audit_log.read_scan_summaries(db_path=self.db)
        self.assertEqual(len(rows), 1)
        return rows[0]["summary"]

    def test_non_dict_summary_still_leaves_a_trace(self):
        """记账失败也要留一行（否则自查视图看不出"这次扫描没记上"）。"""
        audit_log.log_scan_summary(None, db_path=self.db)
        s = self._stored()
        self.assertEqual(s["ips"], 0)
        self.assertEqual(s["ranges"], [])
        self.assertEqual(
            audit_log.activity_summary(24, db_path=self.db)["scan_count"], 1)

    def test_non_string_protocols_dropped_and_deduped(self):
        audit_log.log_scan_summary({
            "protocols": ["HTTP", None, 5, "HTTP", " SSH ", ""],
        }, db_path=self.db)
        self.assertEqual(self._stored()["protocols"], ["HTTP", "SSH"])

    def test_counts_coerced_and_clamped(self):
        audit_log.log_scan_summary({
            "ips": "x", "online": -5, "ports_scanned": "y",
            "ranges": [{"range": "", "ips": 1}, "10.0.0.0/24",
                       {"range": "10.0.1.0/24", "ips": -3}],
        }, db_path=self.db)
        s = self._stored()
        self.assertEqual(s["ips"], 0)
        self.assertEqual(s["online"], 0)
        self.assertEqual(s["ports_scanned"], 0)   # 类型错按 0（"扫了 0 个端口"）
        self.assertEqual([r["range"] for r in s["ranges"]],
                         ["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual([r["ips"] for r in s["ranges"]], [0, 0])

    def test_ports_scanned_none_means_no_port_scan(self):
        audit_log.log_scan_summary(_summary(ports=None), db_path=self.db)
        self.assertIsNone(self._stored()["ports_scanned"])
        self.assertEqual(
            audit_log.activity_summary(24, db_path=self.db)["port_scan_count"], 0)


class WritePathParityTest(unittest.TestCase):
    """GUI 与 CLI 两条写入路径同口径：同一套键，同一张视图读得出来。"""

    def setUp(self):
        self.db = _new_db()

    def test_cli_writer_keys_match_schema(self):
        args = type("A", (), {"db": self.db})()
        cli._audit_scan_summary(
            args, ["192.168.1.0/24"], 254, 5, [80, 443], ["HTTP"], policy=None)
        rows = audit_log.read_scan_summaries(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(tuple(sorted(rows[0]["summary"])),
                         tuple(sorted(audit_log.SUM_SCHEMA_KEYS)))
        self.assertEqual(rows[0]["summary"]["source"], "cli")

    def test_gui_writer_keys_match_schema(self):
        from scan_mixin import ScanMixin

        class _Check:
            def isChecked(self):
                return True

        stub = type("S", (), {
            "ip_range_items": ["192.168.1.0/24"],
            "scan_level": "quick",
            "port_scan_check": _Check(),
            "selected_protocols": ["HTTP"],
            "throttle_policy": "fast",
        })()

        with _patch_db_path(self.db):
            ScanMixin._audit_scan_summary(stub, {"online": 5})

        rows = audit_log.read_scan_summaries(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(tuple(sorted(rows[0]["summary"])),
                         tuple(sorted(audit_log.SUM_SCHEMA_KEYS)))
        s = rows[0]["summary"]
        self.assertEqual(s["source"], "gui")
        self.assertEqual(s["online"], 5)
        self.assertEqual(s["ips"], 254)
        self.assertTrue(s["ports_scanned"])

    def test_both_paths_land_in_one_view(self):
        from scan_mixin import ScanMixin

        class _Check:
            def isChecked(self):
                return False

        stub = type("S", (), {
            "ip_range_items": ["10.0.0.0/24"], "scan_level": "quick",
            "port_scan_check": _Check(), "selected_protocols": [],
            "throttle_policy": "polite",
        })()
        args = type("A", (), {"db": self.db})()
        cli._audit_scan_summary(args, ["192.168.1.0/24"], 254, 5, None, [])
        with _patch_db_path(self.db):
            ScanMixin._audit_scan_summary(stub, {"online": 1})
        s = audit_log.activity_summary(24, db_path=self.db)
        self.assertEqual(s["scan_count"], 2)
        self.assertEqual(s["range_count"], 2)


@contextlib.contextmanager
def _patch_db_path(db):
    """把 `audit_log.DB_PATH` 指向临时库（GUI 写入端不走 db_path 参数）。"""
    old = audit_log.DB_PATH
    audit_log.DB_PATH = db
    try:
        yield
    finally:
        audit_log.DB_PATH = old


class CliAuditTest(unittest.TestCase):
    """CLI `audit` 子命令：JSON 键固定英文、无数据给原因、退出码恒 0。"""

    def setUp(self):
        self.db = _new_db()
        self._old = audit_log.DB_PATH
        audit_log.DB_PATH = self.db

    def tearDown(self):
        audit_log.DB_PATH = self._old

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        lang = i18n.current_lang()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        finally:
            i18n.init(lang)
        return code, out.getvalue(), err.getvalue()

    def test_parser_defaults(self):
        p = cli.build_parser()
        args = p.parse_args(["audit"])
        self.assertEqual(args.window, "24")
        self.assertEqual(args.format, "table")
        self.assertIs(args.func, cli.cmd_audit)

    def test_no_records_explains_reason_and_next_step(self):
        code, out, _ = self._run(["audit"])
        self.assertEqual(code, cli.EXIT_OK)
        hint, action = cli._AUDIT_REASON_TEXT[audit_log.REASON_NO_RECORDS]
        self.assertIn(hint, out)
        self.assertIn("下一步：", out)            # 必须给下一步
        self.assertIn(action, out)
        self.assertNotIn("扫描 0 次", out)        # 不给"空表"式的零值汇总

    def test_no_records_json_keeps_english_reason(self):
        code, out, _ = self._run(["audit", "--format", "json"])
        self.assertEqual(code, cli.EXIT_OK)
        data = json.loads(out)
        self.assertEqual(data["reason"], audit_log.REASON_NO_RECORDS)
        self.assertEqual(data["scan_count"], 0)

    def test_table_output_reports_counts(self):
        now = time.time()
        _insert(self.db, now - 60, _summary(protocols=("HTTP", "SNMP")))
        code, out, _ = self._run(["audit"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(tr("扫描 {n} 次 · 涉及 {m} 个网段").format(n=1, m=1), out)
        self.assertIn("HTTP ×1", out)
        self.assertIn("SNMP ×1", out)
        self.assertIn("192.168.1.0/24", out)

    def test_window_switch_changes_counts(self):
        now = time.time()
        _insert(self.db, now - 48 * HOUR, _summary("10.0.0.0/24"))
        _insert(self.db, now - 60, _summary("192.168.1.0/24"))
        code, out, _ = self._run(["audit"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(tr("扫描 {n} 次 · 涉及 {m} 个网段").format(n=1, m=1), out)
        code, out, _ = self._run(["audit", "--window", "168"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(tr("扫描 {n} 次 · 涉及 {m} 个网段").format(n=2, m=2), out)
        code, out, _ = self._run(["audit", "--window", "all"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn(tr("扫描 {n} 次 · 涉及 {m} 个网段").format(n=2, m=2), out)

    def test_json_keys_are_stable_english(self):
        _insert(self.db, time.time() - 60, _summary())
        code, out, _ = self._run(["audit", "--format", "json", "--window", "all"])
        self.assertEqual(code, cli.EXIT_OK)
        data = json.loads(out)
        for key in ("reason", "window_hours", "scan_count", "range_count",
                    "total_ips", "total_online", "estimated_probes",
                    "port_scan_count", "protocols", "throttles", "ranges"):
            self.assertIn(key, data)

    def test_db_flag_is_ignored_with_warning(self):
        """--db 是历史快照库；审计库是另一个文件 ⇒ 必须明说不采纳。"""
        _insert(self.db, time.time() - 60, _summary())
        other = _new_db()
        code, out, err = self._run(["audit", "--db", other])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("--db", err)
        self.assertIn("192.168.1.0/24", out)     # 仍然读审计库，没被指错


class DialogTest(unittest.TestCase):
    """只读对话框：控件文本与可见性（offscreen 下截图全白，不看图）。"""

    def setUp(self):
        self.db = _new_db()
        self._old = audit_log.DB_PATH
        audit_log.DB_PATH = self.db

    def tearDown(self):
        audit_log.DB_PATH = self._old

    def test_column_count_derives_from_labels(self):
        dlg = AuditActivityDialog()
        self.assertEqual(dlg.table.columnCount(), len(_COLUMN_LABELS))
        self.assertEqual(dlg.table.horizontalHeaderItem(0).text(),
                         tr(_COLUMN_LABELS[0]))
        dlg.deleteLater()

    def test_rows_match_ranges_and_summary_reports_counts(self):
        now = time.time()
        _insert(self.db, now - 3 * HOUR, _summary("192.168.1.0/24", 254, 5))
        _insert(self.db, now - 60, _summary("10.0.0.0/24", 254, 7))
        dlg = AuditActivityDialog()
        self.assertEqual(dlg.table.rowCount(), 2)
        self.assertEqual(dlg.table.item(0, 0).text(), "10.0.0.0/24")
        text = dlg.summary_label.text()
        self.assertIn(tr("扫描 {n} 次 · 涉及 {m} 个网段").format(n=2, m=2), text)
        self.assertIn(tr("累计覆盖 {n} 个地址 · 在线设备 {m} 台次").format(
            n=508, m=12), text)
        self.assertIn(tr(_HINT_ESTIMATE), dlg.hint_label.text())
        self.assertTrue(dlg.next_label.isHidden())     # 有数据时不显示"下一步"
        dlg.deleteLater()

    def test_empty_state_shows_reason_and_next_step(self):
        dlg = AuditActivityDialog()
        self.assertEqual(dlg.table.rowCount(), 0)
        hint, action = _REASON_TEXT[audit_log.REASON_NO_RECORDS]
        self.assertEqual(dlg.summary_label.text(), tr(hint))
        self.assertIn(tr(action), dlg.next_label.text())
        self.assertFalse(dlg.next_label.isHidden())   # 空态必须显示"下一步"
        self.assertEqual(dlg.hint_label.text(), "")   # 空态不显示发包口径
        dlg.deleteLater()

    def test_switching_window_reloads(self):
        now = time.time()
        _insert(self.db, now - 48 * HOUR, _summary("10.0.0.0/24"))
        _insert(self.db, now - 60, _summary("192.168.1.0/24"))
        dlg = AuditActivityDialog()
        self.assertEqual(dlg.table.rowCount(), 1)
        idx = [i for i in range(dlg.window_combo.count())
               if dlg.window_combo.itemData(i) is None][0]
        dlg.window_combo.setCurrentIndex(idx)
        self.assertEqual(dlg.table.rowCount(), 2)
        self.assertIn(tr("全部历史"), dlg.summary_label.text())
        dlg.deleteLater()

    def test_window_choices_cover_supported_windows(self):
        """GUI 的时间窗表必须与 `audit_log.WINDOW_CHOICES` 一致（两处不能漂）。"""
        self.assertEqual(set(_WINDOW_TEXT), set(audit_log.WINDOW_CHOICES.values()))


class LabelsTest(unittest.TestCase):
    """字面量标签表必须有英文译文（登记在 test_i18n_lazy 之外再自证一遍）。"""

    def test_all_labels_translated(self):
        with io.open(os.path.join(ROOT, "i18n", "en-US.json"),
                     encoding="utf-8") as f:
            pack = json.load(f)
        labels = (list(_WINDOW_TEXT.values()) + list(_COLUMN_LABELS)
                  + [t for pair in _REASON_TEXT.values() for t in pair]
                  + [_HINT_ESTIMATE, _HINT_SCOPE])
        missing = [lbl for lbl in labels if lbl not in pack]
        self.assertEqual(missing, [])


def tearDownModule():
    """收尾统一关掉单例连接。

    每个用例一个临时库，而 `db_util` 的连接是**按路径缓存的单例** ——
    不显式关掉，解释器退出时会刷一串 `ResourceWarning: unclosed database`，
    把真正的失败信息淹掉。
    """
    db_util.close_all()


if __name__ == "__main__":
    unittest.main()
