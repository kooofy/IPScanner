# -*- coding: utf-8 -*-
"""资产生命周期字段（v2.3 §3.4）测试：纯计算 + V7 迁移 + 读写。

本文对着 `docs/ROADMAP_V2.3.md` §3.4 的四条验收写：

1. 加列后**旧库升级不丢数据**（`MigrationTest`）；
2. `custom_json` 的键**原样存取**、不经 `tr()`（`CustomJsonTest`）；
3. 保修到期**按本地时区**推导（`WarrantyStateTest` 用本地时间戳构造 `now`）；
4. 未填保修日期的设备**不报"已过期"**（`WarrantyStateTest` +
   `FilterByWarrantyTest`：`unset` 与 `expired` 必须能分辨）。

另有一条**比验收更要紧**的不变量，单独立了 `ScanNeverOverwritesManualTest`：

> 生命周期字段是**人工填的台账**，例行扫描绝不能把它们抹掉。

它是本项最容易踩的坑 —— 若把这 6 列混进 `_ASSET_COLS`，扫描的 UPSERT 会
"最近一次非空才覆盖"地刷它们，一次扫描就把 `owner` 变空串，而且是**静默**的。
"""
import ast
import contextlib
import datetime
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import asset_lifecycle  # noqa: E402
import cli  # noqa: E402
import db_util  # noqa: E402
import history_store  # noqa: E402
import i18n  # noqa: E402


def _new_db():
    """临时库路径（每个用例一个，互不干扰）。"""
    return os.path.join(tempfile.mkdtemp(prefix="lifecycle_"), "scan_history.db")


def _dev(ip_suffix, status="online", ports="80"):
    """一台设备（MAC 由后缀推出，保证身份键稳定）。"""
    return {
        "ip": "192.168.1.%s" % ip_suffix,
        "status": status,
        "mac": "aa:bb:cc:dd:ee:%02d" % int(ip_suffix),
        "open_ports": ports,
    }


def _scan(db, devs, ts=None):
    return history_store.save_snapshot(
        devs, ts=time.time() if ts is None else ts, db_path=db)


def _key(ip_suffix=1):
    """`_dev(n)` 对应的资产身份键（MAC 优先，与写入端同规则）。"""
    return history_store.identity_key(
        "aa:bb:cc:dd:ee:%02d" % int(ip_suffix), "192.168.1.%s" % ip_suffix)


def _columns(db, table="assets"):
    c = sqlite3.connect(db)
    try:
        return {r[1] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()}
    finally:
        c.close()


def _version(db):
    c = sqlite3.connect(db)
    try:
        return int(c.execute("PRAGMA user_version").fetchone()[0])
    finally:
        c.close()


# ─────────────────────── 纯计算：模块自身的约束 ───────────────────────

class ModulePurityTest(unittest.TestCase):
    """`asset_lifecycle` 是纯计算模块 —— 这条守着"它永远能裸跑"。"""

    def test_module_imports_only_the_standard_library(self):
        """只允许 `datetime` / `json` / `re`。

        🔴 多出来的每一个 import 都会让它**不再可裸跑**：`i18n` 会带来语言状态
           （判定随界面语言漂移）、`PyQt5` 会要求 QApplication、`sqlite3` 会把
           纯函数变成"要建库才能测"、任何第三方包都是新依赖。
        """
        with open(os.path.join(ROOT, "asset_lifecycle.py"),
                  encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        self.assertEqual(names, {"datetime", "json", "re"}, names)

    def test_status_values_are_ascii_and_lowercase(self):
        """规范值要落库、要被比较 —— 绝不能是 `tr()` 的结果。"""
        self.assertTrue(asset_lifecycle.WARRANTY_STATUSES)
        for s in asset_lifecycle.WARRANTY_STATUSES:
            self.assertTrue(s.isascii(), s)
            self.assertEqual(s, s.strip().lower(), s)

    def test_lifecycle_columns_are_stable(self):
        self.assertEqual(
            asset_lifecycle.LIFECYCLE_COLUMNS,
            ("purchase_date", "warranty_end", "owner", "serial",
             "location_tree", "custom_json"))


# ─────────────────────────── 日期解析 ───────────────────────────

class ParseDateTest(unittest.TestCase):

    def test_common_formats_are_accepted(self):
        want = datetime.date(2026, 5, 1)
        for text in ("2026-05-01", "2026/5/1", "2026.05.01",
                     "20260501", "2026年5月1日", " 2026-05-01 "):
            self.assertEqual(asset_lifecycle.parse_date(text), want, text)

    def test_date_and_datetime_instances_pass_through(self):
        self.assertEqual(asset_lifecycle.parse_date(datetime.date(2026, 5, 1)),
                         datetime.date(2026, 5, 1))
        self.assertEqual(
            asset_lifecycle.parse_date(datetime.datetime(2026, 5, 1, 23, 59)),
            datetime.date(2026, 5, 1))

    def test_impossible_dates_are_rejected(self):
        # 格式对、日期错（闰年 / 月份天数）—— 必须挡住，不能猜。
        for text in ("2026-13-01", "2026-02-30", "2026-00-10", "2026-04-31",
                     "2025-02-29"):
            self.assertIsNone(asset_lifecycle.parse_date(text), text)

    def test_incomplete_or_junk_input_is_rejected(self):
        for value in ("2026-5", "2026", "", "   ", "昨天", None, 20260501, 5.0,
                      [], {}, "2026-05-01T00:00"):
            self.assertIsNone(asset_lifecycle.parse_date(value), repr(value))

    def test_strict_parser_raises_on_bad_input(self):
        with self.assertRaises(ValueError):
            asset_lifecycle.parse_date_strict("2026-02-30")
        with self.assertRaises(ValueError):
            asset_lifecycle.parse_date_strict("not a date", field="保修日期")

    def test_strict_parser_treats_none_and_blank_as_clear(self):
        # 空 = "清空这个字段"，不是"格式错误" —— 用户就是要把填错的值删掉。
        self.assertIsNone(asset_lifecycle.parse_date_strict(None))
        self.assertIsNone(asset_lifecycle.parse_date_strict(""))
        self.assertIsNone(asset_lifecycle.parse_date_strict("   "))

    def test_strict_error_message_names_the_field(self):
        with self.assertRaises(ValueError) as ctx:
            asset_lifecycle.parse_date_strict("xx", field="warranty_end")
        self.assertIn("warranty_end", str(ctx.exception))


# ─────────────────────────── 保修状态 ───────────────────────────

class WarrantyStateTest(unittest.TestCase):

    def test_unset_is_not_expired(self):
        """§3.4 验收 4：未填保修日期**不能**报"已过期"。"""
        state = asset_lifecycle.warranty_state("")
        self.assertEqual(state["status"], asset_lifecycle.WARRANTY_UNSET)
        self.assertIsNone(state["days_left"])
        self.assertIsNone(state["end"])
        self.assertFalse(asset_lifecycle.is_warranty_alerting(state))

    def test_now_defaults_to_today(self):
        """`now` 省略时用**今天**（本地）—— GUI 与 CLI 走的默认路径。"""
        state = asset_lifecycle.warranty_state(datetime.date.today().isoformat())
        self.assertEqual(state["days_left"], 0)
        self.assertEqual(state["status"], asset_lifecycle.WARRANTY_EXPIRING)

    def test_alerting_predicate_tolerates_junk(self):
        self.assertFalse(asset_lifecycle.is_warranty_alerting(None))
        self.assertFalse(asset_lifecycle.is_warranty_alerting("expired"))
        self.assertFalse(asset_lifecycle.is_warranty_alerting({}))
        self.assertTrue(
            asset_lifecycle.is_warranty_alerting({"status": "expired"}))

    def test_garbage_date_degrades_to_unset(self):
        # 读取路径要容忍脏值：库里可能有人手工改坏过。
        for bad in ("2026-02-30", "下周", "abc"):
            self.assertEqual(
                asset_lifecycle.warranty_state(bad)["status"],
                asset_lifecycle.WARRANTY_UNSET, bad)

    def test_days_left_and_boundaries(self):
        today = datetime.date(2026, 5, 1)
        cases = [
            ("2026-04-30", -1, asset_lifecycle.WARRANTY_EXPIRED),
            ("2026-05-01", 0, asset_lifecycle.WARRANTY_EXPIRING),   # 今天到期
            ("2026-05-31", 30, asset_lifecycle.WARRANTY_EXPIRING),  # 恰好第 30 天
            ("2026-06-01", 31, asset_lifecycle.WARRANTY_OK),
        ]
        for text, days, status in cases:
            state = asset_lifecycle.warranty_state(text, now=today)
            self.assertEqual(state["days_left"], days, text)
            self.assertEqual(state["status"], status, text)

    def test_warn_days_is_respected_and_clamped(self):
        today = datetime.date(2026, 5, 1)
        # 提前量放大到 100 天 ⇒ 31 天后到期也进"即将到期"。
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-06-01", now=today,
                                           warn_days=100)["status"],
            asset_lifecycle.WARRANTY_EXPIRING)
        # 提前量给 0 ⇒ 只有"今天到期"算即将到期。
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-06-01", now=today,
                                           warn_days=0)["status"],
            asset_lifecycle.WARRANTY_OK)
        # 负数 / 垃圾值夹到默认档，不抛。
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-06-01", now=today,
                                           warn_days=-5)["warn_days"], 0)
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-06-01", now=today,
                                           warn_days="x")["warn_days"],
            asset_lifecycle.DEFAULT_WARRANTY_WARN_DAYS)

    def test_end_is_normalised_to_iso(self):
        state = asset_lifecycle.warranty_state("2026/5/1",
                                               now=datetime.date(2026, 5, 1))
        self.assertEqual(state["end"], "2026-05-01")

    def test_days_left_uses_the_local_timezone(self):
        """§3.4 验收 3：按**本地时区**推导。

        `time.mktime()` 把 struct_time 当**本地时间**解释，`fromtimestamp()`
        也按本地时区还原 ⇒ 两端同一时区，断言与 CI 所在时区无关。
        若实现误用 `utcfromtimestamp()`，东八区会整体挪早 8 小时。
        """
        local_noon = time.mktime((2026, 5, 1, 12, 0, 0, 0, 0, -1))
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-05-10",
                                           now=local_noon)["days_left"], 9)
        # 本地时间戳与"同一天的 date"必须给出同一个结论。
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-05-10", now=local_noon),
            asset_lifecycle.warranty_state("2026-05-10",
                                           now=datetime.date(2026, 5, 1)))

    def test_aware_datetime_is_converted_to_local(self):
        aware = datetime.datetime(2026, 5, 1, 12, 0,
                                  tzinfo=datetime.timezone.utc)
        local_day = aware.astimezone().date()
        self.assertEqual(
            asset_lifecycle.warranty_state("2026-05-10",
                                           now=aware)["days_left"],
            (datetime.date(2026, 5, 10) - local_day).days)


class FilterByWarrantyTest(unittest.TestCase):
    """`--warranty-days N` 的挑选逻辑（GUI 的提醒列表也用同一份）。"""

    TODAY = datetime.date(2026, 5, 1)

    def _rows(self):
        return [
            {"identity_key": "a", "ip": "10.0.0.1", "warranty_end": ""},
            {"identity_key": "b", "ip": "10.0.0.2", "warranty_end": "2026-01-01"},
            {"identity_key": "c", "ip": "10.0.0.3", "warranty_end": "2026-05-10"},
            {"identity_key": "d", "ip": "10.0.0.4", "warranty_end": "2030-01-01"},
        ]

    def test_only_expired_and_expiring_are_returned(self):
        matched, skipped = asset_lifecycle.filter_by_warranty(
            self._rows(), days=30, now=self.TODAY)
        self.assertEqual([r["identity_key"] for r in matched], ["b", "c"])
        self.assertEqual(skipped, 1, "未填保修日期的那台要计数")

    def test_unset_rows_never_show_up_as_expired(self):
        """§3.4 验收 4 的 CLI 侧：没填 ≠ 已过期。"""
        matched, _skipped = asset_lifecycle.filter_by_warranty(
            self._rows(), days=30, now=self.TODAY)
        self.assertNotIn("a", [r["identity_key"] for r in matched])
        for row in matched:
            self.assertNotEqual(row["warranty_status"],
                                asset_lifecycle.WARRANTY_UNSET)

    def test_most_overdue_comes_first(self):
        matched, _ = asset_lifecycle.filter_by_warranty(
            self._rows(), days=30, now=self.TODAY)
        days = [r["warranty_days_left"] for r in matched]
        self.assertEqual(days, sorted(days))
        self.assertEqual(matched[0]["warranty_status"],
                         asset_lifecycle.WARRANTY_EXPIRED)

    def test_rows_are_copies_with_extra_keys(self):
        rows = self._rows()
        matched, _ = asset_lifecycle.filter_by_warranty(
            rows, days=30, now=self.TODAY)
        self.assertNotIn("warranty_status", rows[1], "不能改调用方的行")
        for row in matched:
            self.assertIn("warranty_status", row)
            self.assertIn("warranty_days_left", row)
            self.assertIn("warranty_end", row)

    def test_warn_days_window_shrinks_the_result(self):
        # 0 天窗口：只有"今天到期**或已过期**"才进 —— 9 天后到期的 c 被排除。
        matched, _ = asset_lifecycle.filter_by_warranty(
            self._rows(), days=0, now=self.TODAY)
        self.assertEqual([r["identity_key"] for r in matched], ["b"])

    def test_warn_days_window_widens_the_result(self):
        # 窗口放宽到 2000 天 ⇒ 2030 年才到期的 d 也进（"提前量"就是干这个的）。
        matched, _ = asset_lifecycle.filter_by_warranty(
            self._rows(), days=2000, now=self.TODAY)
        self.assertEqual([r["identity_key"] for r in matched], ["b", "c", "d"])

    def test_empty_and_dirty_input_is_tolerated(self):
        self.assertEqual(asset_lifecycle.filter_by_warranty(None), ([], 0))
        self.assertEqual(asset_lifecycle.filter_by_warranty([]), ([], 0))
        matched, skipped = asset_lifecycle.filter_by_warranty(
            ["not a dict", None, 42], now=self.TODAY)
        self.assertEqual((matched, skipped), ([], 0))

    def test_missing_warranty_key_counts_as_unset(self):
        matched, skipped = asset_lifecycle.filter_by_warranty(
            [{"identity_key": "x"}], now=self.TODAY)
        self.assertEqual((matched, skipped), ([], 1))


# ─────────────────────────── 自定义字段 ───────────────────────────

class CustomJsonTest(unittest.TestCase):

    def test_dict_and_json_text_normalise_the_same(self):
        want = '{"a": 1, "b": "x"}'
        self.assertEqual(asset_lifecycle.normalize_custom_json({"a": 1, "b": "x"}),
                         want)
        self.assertEqual(asset_lifecycle.normalize_custom_json(
            '{"b": "x", "a": 1}'), want)

    def test_key_order_does_not_create_fake_changes(self):
        """同样字段集 ⇒ 逐字节相同的文本（否则快照比对全是假变更）。"""
        self.assertEqual(
            asset_lifecycle.normalize_custom_json({"b": 2, "a": 1}),
            asset_lifecycle.normalize_custom_json({"a": 1, "b": 2}))

    def test_keys_are_stored_verbatim(self):
        """§3.4 验收 2：键**原样**存取，不经过 `tr()`。

        中文键、下划线、大小写混写一律照存 —— 判据是"拿比较还是显示"：
        用户写的键是拿来**比较**的（"哪些机器有 `rack` 字段"）。
        """
        raw = {"机架": "A3", "rack_id": "R-9", "CamelKey": 1, "带 空格": True}
        text = asset_lifecycle.normalize_custom_json(raw)
        self.assertEqual(asset_lifecycle.parse_custom_json(text), raw)
        self.assertIn("机架", text)
        self.assertIn("rack_id", text)
        self.assertIn("CamelKey", text, "大小写不能被改")
        self.assertNotIn("\\u", text, "中文不该被转义成 \\uXXXX")

    def test_none_and_blank_mean_clear(self):
        for value in (None, "", "   "):
            self.assertEqual(asset_lifecycle.normalize_custom_json(value), "")

    def test_invalid_input_raises(self):
        for bad in ("{不是 json", '{"a": 1', "[]", "3", '"str"', 5, ["a"]):
            with self.assertRaises(ValueError):
                asset_lifecycle.normalize_custom_json(bad)

    def test_unserialisable_values_raise_a_clear_error(self):
        # dict 里塞了 set / 自定义对象 ⇒ `json.dumps` 抛 TypeError。
        # 转成 ValueError 让调用方只需捕获一种异常。
        with self.assertRaises(ValueError):
            asset_lifecycle.normalize_custom_json({"a": {1, 2}})

    def test_reader_tolerates_dirty_values(self):
        for bad in (None, "", "{坏", "[1,2]", "3", "null"):
            self.assertEqual(asset_lifecycle.parse_custom_json(bad), {})

    def test_reader_passes_dicts_through(self):
        self.assertEqual(asset_lifecycle.parse_custom_json({"a": 1}), {"a": 1})

    def test_round_trip_is_stable(self):
        raw = {"机架": "A3", "楼层": 3}
        once = asset_lifecycle.normalize_custom_json(raw)
        again = asset_lifecycle.normalize_custom_json(
            asset_lifecycle.parse_custom_json(once))
        self.assertEqual(once, again)


# ─────────────────────────── V7 迁移 ───────────────────────────

class MigrationTest(unittest.TestCase):

    def test_schema_version_is_seven(self):
        self.assertEqual(history_store.SCHEMA_VERSION, 7)

    def test_new_database_has_every_lifecycle_column(self):
        db = _new_db()
        _scan(db, [_dev(1)])
        cols = _columns(db)
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, cols)

    def test_v7_marker_is_a_column_marker(self):
        """v7 **只加列不建表** ⇒ 必须用列标记，否则老库会被重放 ALTER。"""
        markers = {m[:2]: m for m in history_store._LEGACY_TABLES}
        self.assertIn(("assets", "custom_json"), markers)
        self.assertEqual(markers[("assets", "custom_json")],
                         ("assets", "custom_json", 7))

    def test_upgrading_a_v6_database_keeps_data(self):
        """§3.4 验收 1：加列后旧库升级**不丢数据**。"""
        db = _new_db()
        with db_util.connection(db, pragmas=history_store._PRAGMAS) as conn:
            db_util.apply_migrations(conn, history_store.MIGRATIONS[:6])
            conn.execute(
                "INSERT INTO assets (identity_key, mac, ip, status, "
                "first_seen, last_seen, seen_count) "
                "VALUES ('aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:01', "
                "'192.168.1.1', 'online', 1.0, 1.0, 3)")
            conn.commit()
        # 🔴 必须关掉：`db_util` 按路径缓存单例连接，不关的话下面会复用这条
        #    **已经 init 过**的连接，V7 迁移根本不会跑。
        db_util.close_connection(db)

        rows = history_store.list_assets(db_path=db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "192.168.1.1")
        self.assertEqual(rows[0]["seen_count"], 3)
        self.assertEqual(_version(db), history_store.SCHEMA_VERSION)
        cols = _columns(db)
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, cols)
        # 老行在生命周期列上是空串（不是 NULL / 缺键）。
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertEqual(rows[0][c], "")

    def test_upgrading_is_idempotent(self):
        db = _new_db()
        _scan(db, [_dev(1)])
        with history_store._conn(db) as conn:
            history_store._init_db(conn, db)
            history_store._init_db(conn, db)
        self.assertEqual(_version(db), history_store.SCHEMA_VERSION)

    def test_legacy_inference_finds_v7_by_column(self):
        """🔴 本项最容易踩的坑：抹掉版本号后**必须**推断出 7。

        推断偏低 ⇒ v7 的 `ALTER TABLE ADD COLUMN` 被重放 ⇒
        `duplicate column name` ⇒ 库直接打不开。
        """
        db = _new_db()
        _scan(db, [_dev(1)])
        db_util.close_connection(db)
        c = sqlite3.connect(db)
        c.execute("PRAGMA user_version = 0")
        c.commit()
        c.close()

        with history_store._conn(db) as conn:
            inferred = db_util.effective_version(conn, history_store._LEGACY_TABLES)
        self.assertEqual(inferred, 7, "列标记没生效，v7 会被重放")
        # 真跑一遍也不该炸（这就是"库打不开"的现场）。
        self.assertTrue(history_store.list_assets(db_path=db))

    def test_a_real_v6_database_without_a_version_infers_six(self):
        """真 v6 形态 + 版本号被抹掉 → 推断 6（靠 `trend_observations` 表标记），
        然后**只补跑 v7**。

        这条与 `test_legacy_inference_finds_v7_by_column` 是一对：一个证明
        "v6 库不会被误判成最新"（否则 v7 永不执行、查询报 `no such column`），
        一个证明"v7 库不会被误判成 v6"（否则 `ALTER TABLE` 重放、库打不开）。
        """
        db = _new_db()
        with db_util.connection(db, pragmas=history_store._PRAGMAS) as conn:
            db_util.apply_migrations(conn, history_store.MIGRATIONS[:6])
            conn.commit()
        db_util.close_connection(db)
        c = sqlite3.connect(db)
        c.execute("PRAGMA user_version = 0")
        c.commit()
        # ⚠ 必须在**裸连接**上推断：`history_store._conn()` 会先把迁移跑到最新，
        #   再问版本号就永远是最新版（那样这条测试形同虚设）。
        self.assertEqual(
            db_util.infer_legacy_version(c, history_store._LEGACY_TABLES), 6)
        c.close()

        # 正常打开一次 → 只补跑 v7。
        history_store.list_assets(db_path=db)
        self.assertEqual(_version(db), history_store.SCHEMA_VERSION)
        for col in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(col, _columns(db))


# ─────────────────── 扫描绝不覆盖人工字段（最关键） ───────────────────

class ScanNeverOverwritesManualTest(unittest.TestCase):

    def test_lifecycle_columns_are_disjoint_from_scanned_columns(self):
        self.assertFalse(
            set(history_store._ASSET_LIFECYCLE_COLS)
            & set(history_store._ASSET_COLS),
            "生命周期列混进 _ASSET_COLS ⇒ 扫描的 UPSERT 会刷掉人工填的值")

    def test_lifecycle_columns_are_absent_from_the_upsert_sql(self):
        for c in history_store._ASSET_LIFECYCLE_COLS:
            self.assertNotIn(c, history_store._ASSET_UPSERT)

    def test_a_routine_scan_keeps_manual_values(self):
        db = _new_db()
        _scan(db, [_dev(1)])
        key = _key(1)
        self.assertEqual(
            history_store.update_asset_lifecycle(
                key, db_path=db,
                owner="张三", serial="SN-0001", purchase_date="2024-03-01",
                warranty_end="2030-01-01", location_tree="A栋/3层/机房",
                custom_json={"rack": "A3"}),
            1)
        # 一次例行扫描：设备状态变了、端口关了、主机名还是空的。
        _scan(db, [_dev(1, status="offline", ports="")])
        rec = history_store.get_asset(key, db_path=db)
        self.assertEqual(rec["owner"], "张三")
        self.assertEqual(rec["serial"], "SN-0001")
        self.assertEqual(rec["purchase_date"], "2024-03-01")
        self.assertEqual(rec["warranty_end"], "2030-01-01")
        self.assertEqual(rec["location_tree"], "A栋/3层/机房")
        self.assertEqual(json.loads(rec["custom_json"]), {"rack": "A3"})
        # 而"随观测刷新"的列确实被刷新了 —— 证明 UPSERT 真的跑了。
        self.assertEqual(rec["status"], "offline")

    def test_manual_values_survive_a_backfill_style_write(self):
        """回填走的是同一个 `_ASSET_UPSERT`，同样不能碰人工字段。"""
        db = _new_db()
        _scan(db, [_dev(1)])
        key = _key(1)
        history_store.update_asset_lifecycle(key, owner="李四", db_path=db)
        with history_store._conn(db) as conn:
            history_store._backfill_assets(conn)
            conn.commit()
        self.assertEqual(history_store.get_asset(key, db_path=db)["owner"], "李四")


# ─────────────────────────── 读写路径 ───────────────────────────

class LifecycleStoreTest(unittest.TestCase):

    def setUp(self):
        self.db = _new_db()
        _scan(self.db, [_dev(1)])
        self.key = _key(1)

    def test_list_assets_exposes_every_lifecycle_key(self):
        row = history_store.list_assets(db_path=self.db)[0]
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, row)

    def test_get_asset_exposes_every_lifecycle_key(self):
        rec = history_store.get_asset(self.key, db_path=self.db)
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, rec)

    def test_update_returns_row_count(self):
        self.assertEqual(
            history_store.update_asset_lifecycle(
                self.key, owner="王五", db_path=self.db), 1)
        self.assertEqual(
            history_store.update_asset_lifecycle(
                "aa:bb:cc:dd:ee:ff", owner="无人", db_path=self.db), 0)
        self.assertEqual(
            history_store.update_asset_lifecycle("", owner="x", db_path=self.db),
            0)

    def test_write_is_committed_and_survives_a_reopen(self):
        """🔴 读完**必须关掉连接**再看 —— 这条守的是"写完忘了 commit"。

        `db_util.connection()` 只是「取单例连接 + 加锁 yield」，**不代提交**。
        同进程内紧接着读**同一把缓存连接**能读到未提交的数据，于是"忘了 commit"
        的测试会全绿；而进程一退出（`db_util.shutdown()` 直接 close），改动就
        消失了 —— 用户看到的是"填完保存了、下次打开全没了"。
        2026-10-15 实际踩过一次（`assets --set` 写不进库，单测却全绿）。
        """
        history_store.update_asset_lifecycle(
            self.key, owner="张三", warranty_end="2030-01-01", db_path=self.db)
        db_util.close_connection(self.db)
        rec = history_store.get_asset(self.key, db_path=self.db)
        self.assertEqual(rec["owner"], "张三")
        self.assertEqual(rec["warranty_end"], "2030-01-01")

    def test_update_with_no_fields_is_a_noop(self):
        self.assertEqual(
            history_store.update_asset_lifecycle(self.key, db_path=self.db), 0)

    def test_unknown_field_raises_instead_of_being_ignored(self):
        """拼错字段名必须当场报错 —— 静默忽略会让用户以为填好了。"""
        with self.assertRaises(ValueError) as ctx:
            history_store.update_asset_lifecycle(
                self.key, ower="拼错了", db_path=self.db)
        self.assertIn("ower", str(ctx.exception))

    def test_invalid_date_raises(self):
        with self.assertRaises(ValueError):
            history_store.update_asset_lifecycle(
                self.key, warranty_end="2026-02-30", db_path=self.db)
        with self.assertRaises(ValueError):
            history_store.update_asset_lifecycle(
                self.key, purchase_date="去年", db_path=self.db)

    def test_invalid_custom_json_raises(self):
        with self.assertRaises(ValueError):
            history_store.update_asset_lifecycle(
                self.key, custom_json="{坏", db_path=self.db)

    def test_failed_write_changes_nothing(self):
        history_store.update_asset_lifecycle(self.key, owner="原值", db_path=self.db)
        with self.assertRaises(ValueError):
            history_store.update_asset_lifecycle(
                self.key, owner="新值", warranty_end="不是日期", db_path=self.db)
        self.assertEqual(
            history_store.get_asset(self.key, db_path=self.db)["owner"], "原值",
            "一条 UPDATE 里含非法值 ⇒ 整条都不该落盘")

    def test_empty_string_clears_a_field(self):
        history_store.update_asset_lifecycle(self.key, owner="张三", db_path=self.db)
        history_store.update_asset_lifecycle(self.key, owner="", db_path=self.db)
        self.assertEqual(
            history_store.get_asset(self.key, db_path=self.db)["owner"], "")

    def test_omitted_fields_are_untouched(self):
        history_store.update_asset_lifecycle(
            self.key, owner="张三", serial="SN-1", db_path=self.db)
        history_store.update_asset_lifecycle(self.key, owner="李四", db_path=self.db)
        rec = history_store.get_asset(self.key, db_path=self.db)
        self.assertEqual(rec["owner"], "李四")
        self.assertEqual(rec["serial"], "SN-1", "没传的字段不该被清空")

    def test_dates_are_normalised_on_write(self):
        history_store.update_asset_lifecycle(
            self.key, warranty_end="2030/1/5", db_path=self.db)
        self.assertEqual(
            history_store.get_asset(self.key, db_path=self.db)["warranty_end"],
            "2030-01-05")

    def test_custom_json_round_trips_through_the_database(self):
        """§3.4 验收 2 的落库版：键原样进、原样出。"""
        raw = {"机架": "A3", "rack_id": "R-9"}
        history_store.update_asset_lifecycle(
            self.key, custom_json=raw, db_path=self.db)
        rec = history_store.get_asset(self.key, db_path=self.db)
        self.assertEqual(asset_lifecycle.parse_custom_json(rec["custom_json"]), raw)

    def test_custom_json_accepts_a_json_string(self):
        history_store.update_asset_lifecycle(
            self.key, custom_json='{"a": 1}', db_path=self.db)
        self.assertEqual(
            history_store.get_asset(self.key, db_path=self.db)["custom_json"],
            '{"a": 1}')

    def test_whitespace_is_trimmed_for_plain_text_fields(self):
        history_store.update_asset_lifecycle(
            self.key, owner="  张三  ", db_path=self.db)
        self.assertEqual(
            history_store.get_asset(self.key, db_path=self.db)["owner"], "张三")

    def test_warranty_filter_feeds_straight_from_list_assets(self):
        """端到端：`list_assets()` 的行直接喂 `filter_by_warranty()`。"""
        key2 = _key(2)
        _scan(self.db, [_dev(1), _dev(2)])
        history_store.update_asset_lifecycle(
            self.key, warranty_end="2020-01-01", db_path=self.db)
        history_store.update_asset_lifecycle(
            key2, warranty_end="2035-01-01", db_path=self.db)
        rows = history_store.list_assets(db_path=self.db)
        matched, skipped = asset_lifecycle.filter_by_warranty(
            rows, days=30, now=datetime.date(2026, 5, 1))
        self.assertEqual([r["identity_key"] for r in matched], [self.key])
        self.assertEqual(skipped, 0)

    def test_legacy_database_with_no_assets_yet_degrades(self):
        """只建到 v1 的老库（还没有 `assets` 表）→ 打开即补齐，读写都不抛。

        读路径的 `_table_has_assets()` / `_assets_have_lifecycle()` 是**安全网**：
        正常情况下 `_conn()` 已跑过迁移，但"资产表是增强而非前置条件"这条
        承诺（见 `_read_assets` docstring）不该只靠迁移来兑现。
        """
        old = os.path.join(tempfile.mkdtemp(), "old_v1.db")
        c = sqlite3.connect(old)
        c.executescript(history_store._SQL_V1)
        c.commit()
        c.close()
        self.assertEqual(history_store.list_assets(db_path=old), [])
        self.assertEqual(
            history_store.update_asset_lifecycle(
                "aa:bb:cc:dd:ee:01", owner="x", db_path=old), 0)
        db_util.close_connection(old)


# ─────────────────────────── CLI（v2.3 §3.4）───────────────────────────

class CliAssetColumnTest(unittest.TestCase):
    """CLI 列定义的对齐不变量（纯结构，不需要库）。"""

    def test_every_lifecycle_column_is_in_the_asset_columns(self):
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, cli._ASSET_COLUMNS)

    def test_table_headers_line_up_with_the_table_columns(self):
        """`render_table()` 按索引取 `headers[i]` —— 少一个直接 IndexError。"""
        self.assertEqual(len(cli._ASSET_TABLE_HEADERS),
                         len(cli._ASSET_TABLE_COLUMNS))
        self.assertEqual(len(cli._EXPIRY_HEADERS), len(cli._EXPIRY_COLUMNS))

    def test_every_warranty_status_has_a_display_text(self):
        for s in asset_lifecycle.WARRANTY_STATUSES:
            self.assertIn(s, cli._WARRANTY_STATUS_TEXT)


class CliAssetsTest(unittest.TestCase):
    """`assets --warranty-days` / `assets --set`。

    ⚠️ 这里的断言**可以**钉中文字面量：CLI 的输出按设计恒为中文（它不 import
       `i18n`）。反过来，凡是经 `tr()` 的文案都必须在 GUI 测试里用 `tr()` 推导
       —— 2026-10-15 踩过（CI runner 的 locale 是 en-US，中文断言本机过、CI 挂）。
    """

    def setUp(self):
        self.db = _new_db()
        _scan(self.db, [_dev(1), _dev(2), _dev(3)])
        self.key1, self.key2, self.key3 = _key(1), _key(2), _key(3)

    def _run(self, *extra):
        buf = io.StringIO()
        lang = i18n.current_lang()
        try:
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["assets", "--db", self.db] + list(extra))
        finally:
            # 🔴 `cli.main()` 内部会 `i18n.init(None)` —— 在 en-US 的 CI 上
            # 会把**整个进程**的语言切成英文且不还原，后续测试模块的 `tr()`
            # 期望值全变英文（而 CLI 输出恒为中文）⇒ 2026-10-16 CI 实测
            # `test_audit_activity` 两个用例就是这么挂的。照
            # `test_audit_activity._run()` 的做法保存恢复。
            i18n.init(lang)
        return rc, buf.getvalue()

    def _run_split(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        lang = i18n.current_lang()
        try:
            with (contextlib.redirect_stdout(out),
                  contextlib.redirect_stderr(err)):
                rc = cli.main(["assets", "--db", self.db] + list(extra))
        finally:
            i18n.init(lang)
        return rc, out.getvalue(), err.getvalue()

    @staticmethod
    def _days(n):
        return (datetime.date.today() + datetime.timedelta(days=n)).isoformat()

    def test_cli_call_does_not_leak_process_language(self):
        """🔴 守卫：CLI 调用不得把进程语言切走（2026-10-16 CI 实测）。

        `cli.main()` 内部会 `i18n.init(None)` —— 在 en-US 的 CI 上把**整个
        进程**的语言切成英文且不还原。本模块按字母序排在 `test_audit_activity`
        前面，那里两个用例用 `tr()` 现算期望值（CLI 输出恒为中文），语言一旦
        泄漏就全挂。这条钉住 `_run` / `_run_split` 的保存恢复语义。
        """
        before = i18n.current_lang()
        self._run("-f", "json")
        self.assertEqual(i18n.current_lang(), before)
        self._run_split("-f", "json")
        self.assertEqual(i18n.current_lang(), before)

    # ── 写入路径 ─────────────────────────────────────────────────────

    def test_set_by_mac_writes_and_commits(self):
        rc, out = self._run("--set", "aa:bb:cc:dd:ee:01",
                            "--field", "owner=张三",
                            "--field", "warranty_end=2030-01-01")
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("已更新", out)
        # `cli.main()` 的 finally 会 `db_util.shutdown()`（关连接、WAL checkpoint）
        # ⇒ 下一次调用必然是**新连接**读的，这条顺带证明了 commit 真的发生了。
        rc, out = self._run("-f", "json")
        self.assertEqual(rc, cli.EXIT_OK)
        row = next(r for r in json.loads(out) if r["identity_key"] == self.key1)
        self.assertEqual(row["owner"], "张三")
        self.assertEqual(row["warranty_end"], "2030-01-01")

    def test_set_by_ip_and_by_identity_key(self):
        rc, _ = self._run("--set", "192.168.1.2", "--field", "owner=李四")
        self.assertEqual(rc, cli.EXIT_OK)
        rc, _ = self._run("--set", self.key3, "--field", "owner=王五")
        self.assertEqual(rc, cli.EXIT_OK)
        _rc, out = self._run("-f", "json")
        owners = {r["identity_key"]: r["owner"] for r in json.loads(out)}
        self.assertEqual(owners[self.key2], "李四")
        self.assertEqual(owners[self.key3], "王五")

    def test_set_writes_custom_json_verbatim(self):
        rc, _ = self._run("--set", self.key1, "--field",
                          'custom_json={"机架": "A3", "rack_id": "R-9"}')
        self.assertEqual(rc, cli.EXIT_OK)
        _rc, out = self._run("-f", "json")
        row = next(r for r in json.loads(out) if r["identity_key"] == self.key1)
        self.assertEqual(json.loads(row["custom_json"]),
                         {"机架": "A3", "rack_id": "R-9"})

    def test_set_rejects_an_impossible_date(self):
        rc, out = self._run("--set", self.key1,
                            "--field", "warranty_end=2026-02-30")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("2026-02-30", out)

    def test_set_rejects_an_unknown_field(self):
        rc, out = self._run("--set", self.key1, "--field", "ower=张三")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("ower", out)
        self.assertIn("owner", out, "报错要给出可用字段名")

    def test_set_reports_a_missing_device(self):
        rc, out = self._run("--set", "10.9.9.9", "--field", "owner=x")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("找不到设备", out)

    def test_set_needs_at_least_one_field(self):
        rc, out = self._run("--set", self.key1)
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("--field", out)

    def test_set_rejects_a_malformed_field(self):
        rc, out = self._run("--set", self.key1, "--field", "owner")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("KEY=VALUE", out)

    def test_set_cannot_be_combined_with_count(self):
        rc, out = self._run("--set", self.key1, "--field", "owner=x", "--count")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("--count", out)

    def test_set_cannot_be_combined_with_warranty_days(self):
        rc, _out = self._run("--set", self.key1, "--field", "owner=x",
                             "--warranty-days", "30")
        self.assertEqual(rc, cli.EXIT_ERROR)

    def test_set_warns_that_filters_are_ignored(self):
        _rc, _out, err = self._run_split(
            "--set", self.key1, "--field", "owner=x", "--network", "10.0.0.0/8")
        self.assertIn("已忽略", err)

    # ── 保修到期提醒 ─────────────────────────────────────────────────

    def test_warranty_days_lists_expired_and_expiring(self):
        self._run("--set", self.key1, "--field", "warranty_end=" + self._days(-1))
        self._run("--set", self.key2, "--field", "warranty_end=" + self._days(10))
        self._run("--set", self.key3, "--field", "warranty_end=" + self._days(900))
        rc, out = self._run("--warranty-days", "30")
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn(self.key1, out)
        self.assertIn(self.key2, out)
        self.assertNotIn(self.key3, out, "900 天后到期的机器不该进 30 天窗口")
        self.assertIn("已过期", out)
        self.assertIn("即将到期", out)
        # 最该处理的排最前：过期那台在第 3 行（表头 + 分隔线之后）。
        lines = [ln for ln in out.splitlines() if self.key1 in ln or self.key2 in ln]
        self.assertTrue(lines[0].startswith(self.key1), lines)

    def test_warranty_days_reports_skipped_unset_on_stderr(self):
        """§3.4 验收 4 的 CLI 侧：未填的设备**不报已过期**，但要报台数。"""
        self._run("--set", self.key1, "--field", "warranty_end=" + self._days(-1))
        _rc, out, err = self._run_split("--warranty-days", "30")
        self.assertNotIn(self.key2, out)
        self.assertNotIn(self.key3, out)
        self.assertIn("未填保修日期", err)
        self.assertIn("2", err)

    def test_warranty_days_says_why_when_nothing_matches(self):
        rc, out = self._run("--warranty-days", "30")
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("没有已过期", out)
        self.assertNotIn("身份键", out, "空结果不该给一张只有表头的表")

    def test_warranty_days_json_shape_is_language_neutral(self):
        self._run("--set", self.key1, "--field", "warranty_end=" + self._days(-1))
        _rc, out = self._run("--warranty-days", "30", "-f", "json")
        payload = json.loads(out)
        self.assertEqual(sorted(payload),
                         ["assets", "count", "days", "skipped_unset"])
        self.assertEqual(payload["days"], 30)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["skipped_unset"], 2)
        row = payload["assets"][0]
        self.assertEqual(row["warranty_status"],
                         asset_lifecycle.WARRANTY_EXPIRED)
        self.assertEqual(row["warranty_days_left"], -1)

    def test_warranty_days_csv_uses_the_expiry_columns(self):
        self._run("--set", self.key1, "--field", "warranty_end=" + self._days(-1))
        _rc, out = self._run("--warranty-days", "30", "-f", "csv")
        header = out.splitlines()[0].lstrip("\ufeff")
        self.assertEqual(header, ",".join(cli._EXPIRY_COLUMNS))

    def test_warranty_days_rejects_a_negative_window(self):
        rc, out = self._run("--warranty-days", "-1")
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("不能为负数", out)

    # ── 列举输出 ─────────────────────────────────────────────────────

    def test_listing_json_carries_every_lifecycle_key(self):
        _rc, out = self._run("-f", "json")
        row = json.loads(out)[0]
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, row)

    def test_listing_csv_header_carries_every_lifecycle_column(self):
        _rc, out = self._run("-f", "csv")
        header = out.splitlines()[0].lstrip("\ufeff").split(",")
        for c in asset_lifecycle.LIFECYCLE_COLUMNS:
            self.assertIn(c, header)

    def test_listing_table_renders_without_error(self):
        # 表头与列数一旦错位，`render_table()` 会直接 IndexError。
        rc, out = self._run()
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("保修到期", out)
        self.assertIn("身份来源", out)


def tearDownModule():
    """关闭本模块开的所有连接。

    `db_util` 按路径缓存**单例连接**，用例之间会串；而且不关就会在解释器退出时
    刷一屏 `ResourceWarning: unclosed database`（每个用例一个临时库）。
    """
    db_util.close_all()


if __name__ == "__main__":
    unittest.main()
