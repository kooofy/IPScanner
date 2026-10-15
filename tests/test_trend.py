# -*- coding: utf-8 -*-
"""趋势观测层（v2.3 §3.1）测试：纯计算 + 写入 + prune 隔离 + 迁移 + CLI。

覆盖路线图 §3.1 的验收，重点是那一条**前置约束**：

> `prune(max_keep=20)` 只留 20 份快照，`devices` 靠 `ON DELETE CASCADE`
> 跟着删 ⇒ 拿 `devices` 画曲线，曲线会随时间自己变短。

所以 `PruneIsolationTest` 是本文最重要的部分：**趋势必须建在 prune 之外**。
（佐证：`watch --help` 原文就写着「快照上限 20 条，持续轮询会把历史冲掉」，
所以它默认不敢写快照。）

其余验收：事件**只在变化时写行**、`event_type` 是语言无关规范值、
迁移幂等、写入失败不升级成扫描失败、空数据给 `reason` 不给空表。
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cli  # noqa: E402
import db_util  # noqa: E402
import history_store  # noqa: E402
import trend_store  # noqa: E402


def _new_db():
    """临时库路径（每个用例一个，互不干扰）。"""
    return os.path.join(tempfile.mkdtemp(prefix="trend_"), "scan_history.db")


def _dev(ip_suffix, status="online", ports="80"):
    """一台设备（MAC 由后缀推出，保证身份键稳定）。"""
    return {
        "ip": "192.168.1.%s" % ip_suffix,
        "status": status,
        "mac": "aa:bb:cc:dd:ee:%02d" % int(ip_suffix),
        "open_ports": ports,
    }


def _scan(db, devs, ts=None, **trend):
    """落一次扫描。`ts` 由调用方控制（窗口边界测试的关键）。"""
    return history_store.save_snapshot(
        devs, ts=time.time() if ts is None else ts, db_path=db,
        trend=trend or None)


# ─────────────────────────── 纯计算 ───────────────────────────

class TrendStorePureTest(unittest.TestCase):
    def test_online_ratio_basic(self):
        self.assertAlmostEqual(trend_store.online_ratio(1, 4), 0.25)
        self.assertAlmostEqual(trend_store.online_ratio(4, 4), 1.0)

    def test_online_ratio_zero_total_is_zero_not_exception(self):
        # "总数为 0"（没有观测）与"在线率为 0%"（观测到了但都不在线）是两件事，
        # 这里只保证前者不抛、不为 NaN。
        self.assertEqual(trend_store.online_ratio(0, 0), 0.0)

    def test_online_ratio_clamps_when_online_exceeds_total(self):
        # 上游写错了也不能给出 >1 的比率 —— 夹住，且不能抛。
        self.assertEqual(trend_store.online_ratio(5, 4), 1.0)

    def test_normalize_hours_returns_int_for_whole_numbers(self):
        # JSON 契约：24 而不是 24.0，否则用户的 diff / 断言无谓地抖。
        self.assertEqual(trend_store.normalize_hours("24h"), 24)
        self.assertIsInstance(trend_store.normalize_hours("7d"), int)
        self.assertIsNone(trend_store.normalize_hours("all"))

    def test_window_start_rejects_unknown_window(self):
        # 拼 SQL 的下界必须是可信值：静默当"全部"会让用户以为真没数据。
        with self.assertRaises(ValueError):
            trend_store.window_start(window="999h")

    def test_window_start_all_is_none(self):
        self.assertIsNone(trend_store.window_start(window="all"))

    def test_window_start_is_hours_ago(self):
        now = 1_000_000.0
        self.assertAlmostEqual(
            trend_store.window_start(now=now, window="24h"), now - 24 * 3600.0)

    def test_bucket_by_day_takes_max_scale_and_last_time(self):
        # 同一天多次扫描：规模取当天最大（取均值会被"只扫了一个子网那次"拉低），
        # 时间取当天最后一次。
        base = time.time()
        rows = [
            {"time": base, "total": 4, "online": 2, "offline": 2},
            {"time": base + 60, "total": 10, "online": 5, "offline": 5},
        ]
        out = trend_store.bucket_by_day(rows)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["samples"], 2)
        self.assertEqual(out[0]["total"], 10)
        self.assertEqual(out[0]["online"], 5)

    def test_series_sorted_by_time_and_rejects_bad_granularity(self):
        base = time.time()
        rows = [
            {"time": base + 100, "total": 4, "online": 4, "offline": 0},
            {"time": base, "total": 4, "online": 0, "offline": 4},
        ]
        out = trend_store.online_ratio_series(rows)
        self.assertEqual([p["ratio"] for p in out], [0.0, 1.0])
        with self.assertRaises(ValueError):
            trend_store.online_ratio_series(rows, granularity="week")

    def test_online_ratio_rejects_non_numeric(self):
        self.assertEqual(trend_store.online_ratio("x", 4), 0.0)
        self.assertEqual(trend_store.online_ratio(2, None), 0.0)

    def test_malformed_rows_are_skipped_not_raised(self):
        # 坏时间戳 / 非数字字段：**跳过**而不是抛 ——
        # 一行脏数据不该让整条曲线消失（曲线是"看趋势"的唯一入口）。
        base = time.time()
        rows = [
            {"time": None, "total": 4, "online": 2},
            {"time": "not-a-number", "total": 4, "online": 2},
            {"time": 0, "total": 4, "online": 2},
            {"time": base, "total": "x", "online": "y"},
        ]
        buckets = trend_store.bucket_by_day(rows)
        self.assertEqual(len(buckets), 1, "只有最后一行的时间戳合法")
        self.assertEqual(buckets[0]["total"], 0)
        series = trend_store.online_ratio_series(rows)
        self.assertEqual(len(series), 1)
        self.assertEqual(series[0]["total"], 0)
        self.assertEqual(series[0]["ratio"], 0.0)


# ─────────────────────────── 写入 ───────────────────────────

class TrendWriteTest(unittest.TestCase):
    def test_each_scan_writes_exactly_one_trend_row(self):
        db = _new_db()
        for k in range(3):
            _scan(db, [_dev(1), _dev(2, "offline")], ts=time.time() + k)
        rows = history_store.read_scan_trend(db_path=db)
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(r["total"], 2)
            self.assertEqual(r["online"], 1)
            self.assertEqual(r["offline"], 1)

    def test_trend_written_even_without_meta(self):
        # 不传 trend 也要写一行：total/online 从 devices 直接算得出。
        db = _new_db()
        _scan(db, [_dev(1)])
        rows = history_store.read_scan_trend(db_path=db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "")
        self.assertIsNone(rows[0]["ports_scanned"])

    def test_meta_is_stored_language_neutral(self):
        db = _new_db()
        _scan(db, [_dev(1)], ranges=["192.168.1.0/24"], ports_scanned=22,
              duration_s=1.5, source="cli")
        row = history_store.read_scan_trend(db_path=db)[0]
        self.assertEqual(json.loads(row["ranges_json"]), ["192.168.1.0/24"])
        self.assertEqual(row["ports_scanned"], 22)
        self.assertEqual(row["source"], "cli")

    def test_first_seen_written_once_per_device(self):
        db = _new_db()
        _scan(db, [_dev(1)], ts=time.time())
        first = history_store.read_asset_events(db_path=db)
        self.assertEqual([e["event_type"] for e in first],
                         [trend_store.EVENT_FIRST_SEEN])
        _scan(db, [_dev(1)], ts=time.time() + 10)
        again = history_store.read_asset_events(db_path=db)
        self.assertEqual(len(again), 1, "第二次扫描不该再报 first_seen")

    def test_identical_scan_writes_no_new_event(self):
        # 🔴 防膨胀的关键：连续两轮结果完全相同 ⇒ 一行都不写。
        db = _new_db()
        devs = [_dev(1), _dev(2, "offline")]
        _scan(db, devs, ts=time.time())
        before = len(history_store.read_asset_events(db_path=db))
        _scan(db, devs, ts=time.time() + 10)
        _scan(db, devs, ts=time.time() + 20)
        after = len(history_store.read_asset_events(db_path=db))
        self.assertEqual(after, before, "结果没变就不该产生新事件")

    def test_status_flip_recorded_online_to_offline(self):
        db = _new_db()
        _scan(db, [_dev(1, "online")], ts=time.time())
        _scan(db, [_dev(1, "offline")], ts=time.time() + 10)
        flips = history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_STATUS_FLIP)
        self.assertEqual(len(flips), 1)
        detail = json.loads(flips[0]["detail_json"])
        self.assertEqual(detail, {"from": "online", "to": "offline"})

    def test_scanning_status_is_not_a_flip(self):
        # `scanning` 是中间态，一次未完成的扫描不该被记成掉线。
        db = _new_db()
        _scan(db, [_dev(1, "online")], ts=time.time())
        _scan(db, [_dev(1, "scanning")], ts=time.time() + 10)
        self.assertEqual(len(history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_STATUS_FLIP)), 0)

    def test_port_close_and_open_only_cover_real_ports(self):
        # 🔴 只比对"实际开放的端口" —— all 档 65535 个端口，逐端口落库会胀爆。
        db = _new_db()
        _scan(db, [_dev(1, "online", "80,443")], ts=time.time())
        _scan(db, [_dev(1, "online", "80,8080")], ts=time.time() + 10)
        closed = history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_PORT_CLOSE)
        opened = history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_PORT_OPEN)
        self.assertEqual(json.loads(closed[0]["detail_json"])["ports"], [443])
        self.assertEqual(json.loads(opened[0]["detail_json"])["ports"], [8080])

    def test_no_port_event_when_nothing_changed(self):
        db = _new_db()
        _scan(db, [_dev(1, "online", "80,443")], ts=time.time())
        _scan(db, [_dev(1, "online", "443,80")], ts=time.time() + 10)  # 顺序不同
        self.assertEqual(len(history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_PORT_OPEN)), 0)
        self.assertEqual(len(history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_PORT_CLOSE)), 0)

    def test_trend_failure_does_not_fail_the_scan(self):
        # 趋势是增强，不是前提：写入失败只 warning，快照照常落、退出码不变。
        db = _new_db()
        real = history_store._build_asset_events
        try:
            history_store._build_asset_events = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("模拟趋势写入失败"))
            sid = _scan(db, [_dev(1)])          # 不该抛
        finally:
            history_store._build_asset_events = real
        self.assertIsInstance(sid, int)
        self.assertEqual(len(history_store.list_snapshots(db_path=db)), 1)


# ───────────────────  prune 隔离（本轮的核心约束）  ───────────────────

class PruneIsolationTest(unittest.TestCase):
    def test_trend_survives_snapshot_pruning(self):
        """🔴 核心：快照被裁到 20 份，趋势一行不少。"""
        db = _new_db()
        devs = [_dev(1), _dev(2, "offline")]
        total = 33
        for k in range(total):
            _scan(db, devs, ts=time.time() + k)
        self.assertEqual(len(history_store.list_snapshots(db_path=db)), 20)
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), total,
                         "趋势不该被 20 份快照上限冲掉")

    def test_events_survive_snapshot_pruning(self):
        db = _new_db()
        _scan(db, [_dev(1, "online")], ts=time.time())
        _scan(db, [_dev(1, "offline")], ts=time.time() + 1)
        for k in range(25):
            _scan(db, [_dev(1, "offline")], ts=time.time() + 10 + k)
        self.assertEqual(len(history_store.list_snapshots(db_path=db)), 20)
        self.assertEqual(len(history_store.read_asset_events(
            db_path=db, event_type=trend_store.EVENT_STATUS_FLIP)), 1,
            "事件流同样不能被 prune 冲掉")

    def test_prune_trend_removes_old_rows_by_days(self):
        db = _new_db()
        old = time.time() - 10 * 86400
        _scan(db, [_dev(1)], ts=old)
        _scan(db, [_dev(1)], ts=time.time())
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), 2)
        deleted = history_store.prune_trend(keep_days=5, db_path=db)
        self.assertGreaterEqual(deleted, 1)
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), 1)

    def test_prune_trend_none_means_keep_everything(self):
        db = _new_db()
        _scan(db, [_dev(1)], ts=time.time() - 10 * 86400)
        self.assertEqual(history_store.prune_trend(keep_days=None, db_path=db), 0)
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), 1)


# ─────────────────────────── 迁移 ───────────────────────────

class MigrationTest(unittest.TestCase):
    def test_schema_version_is_six(self):
        self.assertEqual(history_store.SCHEMA_VERSION, 6)

    def test_migration_is_idempotent(self):
        # 已升级到 V6 的库再 _init_db 一次：不报错、不重复建表、数据不翻倍。
        db = _new_db()
        _scan(db, [_dev(1)])
        with history_store._conn(db) as conn:
            history_store._init_db(conn, db)
            history_store._init_db(conn, db)
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), 1)

    def test_upgrading_a_v5_database_keeps_existing_data(self):
        # 旧库（V5，没有趋势表）升级到 V6：只**建新表**，不碰既有数据。
        db = _new_db()
        with db_util.connection(db, pragmas=history_store._PRAGMAS) as conn:
            db_util.apply_migrations(conn, history_store.MIGRATIONS[:5])
            conn.execute(
                "INSERT INTO snapshots (time, device_count) VALUES (?, ?)", (1.0, 1))
            conn.execute(
                "INSERT INTO devices (snapshot_id, ip, status, mac) "
                "VALUES (1, '10.0.0.1', 'online', 'aa:bb:cc:dd:ee:01')")
            conn.commit()
        # 🔴 必须关掉：`db_util` 按路径缓存单例连接，不关的话下面 `_scan()`
        #    会复用这条**已经 init 过**的连接，V6 迁移根本不会跑 ——
        #    症状是 `no such table: trend_observations`。
        db_util.close_connection(db)
        # 正常路径打开 → 应升到 V6 并建出趋势表；旧快照一条都不能少。
        _scan(db, [_dev(1)])
        self.assertEqual(len(history_store.list_snapshots(db_path=db)), 2)
        self.assertEqual(len(history_store.read_scan_trend(db_path=db)), 1,
                         "升级前的那次扫描没有趋势行（那时还没这功能）")

    def test_legacy_table_marker_matches_migration(self):
        # v6 是建表（不是只加列）⇒ 用表名标记；写成列标记会推断不出版本。
        names = {t[0]: t for t in history_store._LEGACY_TABLES}
        self.assertIn("trend_observations", names)
        self.assertEqual(names["trend_observations"], ("trend_observations", 6))


# ─────────────────────────── 规范值 ───────────────────────────

class EventTypeTest(unittest.TestCase):
    def test_event_types_are_ascii_identifiers(self):
        for et in trend_store.EVENT_TYPES:
            self.assertTrue(et.isascii(), et)
            self.assertEqual(et, et.strip().lower(), et)

    def test_no_chinese_in_event_types(self):
        # 拿 tr() 结果落库 ⇒ 切一次界面语言结论就漂移（v2.2 §3.3 的教训）。
        for et in trend_store.EVENT_TYPES:
            self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in et), et)

    def test_stored_event_types_are_within_the_table(self):
        db = _new_db()
        _scan(db, [_dev(1, "online", "80")], ts=time.time())
        _scan(db, [_dev(1, "offline", "80,443")], ts=time.time() + 1)
        seen = {e["event_type"] for e in history_store.read_asset_events(db_path=db)}
        self.assertTrue(seen)
        self.assertTrue(seen.issubset(set(trend_store.EVENT_TYPES)), seen)


# ─────────────────────────── 稳定性（v2.3 §3.2） ───────────────────────────

class StabilityTest(unittest.TestCase):
    def _flips(self, statuses, step=600.0):
        """按状态序列落多次扫描，返回全部事件。"""
        db = _new_db()
        base = time.time() - 100000
        for k, st in enumerate(statuses):
            _scan(db, [_dev(1, st)], ts=base + k * step)
        return history_store.read_asset_events(db_path=db)

    def test_mtbf_and_mttr_from_alternating_states(self):
        # online/offline/online/offline/online：掉线 2 次、恢复 2 次
        # 两次掉线间隔 = 2*step，掉线→恢复 = step
        s = trend_store.stability(
            self._flips(["online", "offline", "online", "offline", "online"]))
        self.assertEqual(s["failures"], 2)
        self.assertEqual(s["flips"], 4)
        self.assertAlmostEqual(s["mtbf_seconds"], 1200.0)
        self.assertAlmostEqual(s["mttr_seconds"], 600.0)
        self.assertEqual(s["mtbf_samples"], 1)
        self.assertEqual(s["mttr_samples"], 2)

    def test_single_failure_gives_no_mtbf(self):
        # 🔴 只掉线一次 ⇒ 算不出"两次掉线之间"。给 None + reason，
        #    **不返回 0.0 冒充结果**（v2.2 §3.4-a「不猜」原则）。
        s = trend_store.stability(self._flips(["online", "offline"]))
        self.assertIsNone(s["mtbf_seconds"])
        self.assertEqual(s["reason"], trend_store.REASON_INSUFFICIENT_SAMPLES)
        self.assertEqual(s["mtbf_samples"], 0)

    def test_no_events_at_all(self):
        s = trend_store.stability([])
        self.assertEqual(s["devices"], 0)
        self.assertIsNone(s["mtbf_seconds"])
        self.assertEqual(s["reason"], trend_store.REASON_INSUFFICIENT_SAMPLES)

    def test_flappers_sorted_by_flip_count(self):
        db = _new_db()
        base = time.time() - 100000
        for k in range(4):
            _scan(db, [_dev(1, "online" if k % 2 == 0 else "offline"), _dev(2)],
                  ts=base + k * 600)
        s = trend_store.stability(history_store.read_asset_events(db_path=db))
        self.assertEqual(s["flappers"][0]["identity_key"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(s["flappers"][0]["flips"], 3)

    def test_first_seen_devices_newest_first(self):
        db = _new_db()
        base = time.time() - 100000
        _scan(db, [_dev(1)], ts=base)
        _scan(db, [_dev(1), _dev(2)], ts=base + 600)
        out = trend_store.first_seen_devices(
            history_store.read_asset_events(db_path=db))
        self.assertEqual([d["ip"] for d in out], ["192.168.1.2", "192.168.1.1"])

    def test_first_seen_limit(self):
        db = _new_db()
        base = time.time() - 100000
        _scan(db, [_dev(1)], ts=base)
        _scan(db, [_dev(1), _dev(2)], ts=base + 600)
        events = history_store.read_asset_events(db_path=db)
        self.assertEqual(len(trend_store.first_seen_devices(events, limit=1)), 1)

    def test_malformed_events_are_skipped_not_raised(self):
        # 坏 JSON / 非法时间戳 / 非 online-offline 的 `to` —— 一律跳过。
        # 一行脏事件不该让"看趋势"整个崩掉。
        events = [
            {"event_type": trend_store.EVENT_STATUS_FLIP, "ts": 1.0,
             "identity_key": "k1", "detail_json": "{not json"},
            {"event_type": trend_store.EVENT_STATUS_FLIP, "ts": "abc",
             "identity_key": "k1", "detail_json": '{"to": "offline"}'},
            {"event_type": trend_store.EVENT_STATUS_FLIP, "ts": 2.0,
             "identity_key": "k1", "detail_json": '{"to": "scanning"}'},
            {"event_type": trend_store.EVENT_FIRST_SEEN, "ts": "abc",
             "identity_key": "k1", "detail_json": "{not json"},
        ]
        self.assertEqual(trend_store.stability(events)["devices"], 0)
        self.assertEqual(trend_store.first_seen_devices(events), [])


# ─────────────────────────── CLI ───────────────────────────

class DurationPartsTest(unittest.TestCase):
    """时长分档：**只有一份**（CLI 与 GUI 都调它），分支必须逐个测到。"""

    def test_none_and_junk_are_insufficient(self):
        for bad in (None, "abc", float("nan"), float("inf"), float("-inf")):
            self.assertEqual(
                trend_store.duration_parts(bad),
                (None, trend_store.DURATION_UNIT_NONE))

    def test_negative_clamps_to_zero_seconds(self):
        self.assertEqual(trend_store.duration_parts(-5),
                         (0.0, trend_store.DURATION_UNIT_SECOND))

    def test_buckets_and_conversion(self):
        # 秒 / 分钟 / 小时 / 天 四档各来一个，顺带核数值换算。
        self.assertEqual(trend_store.duration_parts(30),
                         (30.0, trend_store.DURATION_UNIT_SECOND))
        self.assertEqual(trend_store.duration_parts(90)[1],
                         trend_store.DURATION_UNIT_MINUTE)
        self.assertAlmostEqual(trend_store.duration_parts(90)[0], 1.5)
        self.assertEqual(trend_store.duration_parts(7200)[1],
                         trend_store.DURATION_UNIT_HOUR)
        self.assertAlmostEqual(trend_store.duration_parts(7200)[0], 2.0)
        self.assertEqual(trend_store.duration_parts(172800)[1],
                         trend_store.DURATION_UNIT_DAY)
        self.assertAlmostEqual(trend_store.duration_parts(172800)[0], 2.0)


class CliTrendTest(unittest.TestCase):
    def _run(self, db, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["trend", "--db", db] + list(extra))
        return rc, buf.getvalue()

    def test_empty_db_explains_reason_and_next_step(self):
        db = _new_db()
        rc, out = self._run(db, "--window", "24h")
        self.assertEqual(rc, 0)
        self.assertIn("下一步：", out)
        self.assertNotIn("在线率趋势", out)

    def test_out_of_window_is_distinct_from_no_records(self):
        # 🔴 两种空的下一步完全不同（该跑扫描 vs 该放大窗口），不能报成同一种。
        db = _new_db()
        _scan(db, [_dev(1)], ts=time.time() - 10 * 86400)
        _, far = self._run(db, "--window", "24h")
        self.assertIn("不在所选时间窗内", far)
        _, empty = self._run(_new_db(), "--window", "24h")
        self.assertIn("没有任何趋势观测记录", empty)
        self.assertNotEqual(far, empty)

    def test_table_output_lists_every_observation(self):
        db = _new_db()
        for k in range(3):
            _scan(db, [_dev(1), _dev(2, "offline")], ts=time.time() + k)
        rc, out = self._run(db, "--window", "all")
        self.assertEqual(rc, 0)
        self.assertIn("在线率趋势", out)
        # 数**表格行**（以时间戳开头），不数百分比出现次数 ——
        # 摘要里的"当前/均值/最低/最高"也会出现同样的数字，数它会算错。
        rows = [ln for ln in out.splitlines()
                if re.match(r"^  \d{4}-\d{2}-\d{2} \d{2}:\d{2}", ln)]
        self.assertEqual(len(rows), 3)
        self.assertIn("当前 50.0%", out)

    def test_json_keys_are_english_and_fixed(self):
        db = _new_db()
        _scan(db, [_dev(1)], ts=time.time())
        rc, out = self._run(db, "--window", "all", "-f", "json")
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(
            sorted(payload),
            ["granularity", "new_devices", "points", "reason", "samples",
             "stability", "window", "window_hours"])
        self.assertEqual(sorted(payload["points"][0]),
                         ["online", "ratio", "time", "total"])
        self.assertIsNone(payload["reason"])

    def test_table_output_includes_stability_and_new_devices(self):
        db = _new_db()
        base = time.time() - 100000
        for k, st in enumerate(["online", "offline", "online"]):
            _scan(db, [_dev(1, st)], ts=base + k * 600)
        rc, out = self._run(db, "--window", "all")
        self.assertEqual(rc, 0)
        self.assertIn("稳定性", out)
        self.assertIn("MTBF", out)
        self.assertIn("新出现设备", out)

    def test_table_warns_when_mtbf_sample_is_insufficient(self):
        # 只有一次掉线 ⇒ 明说"这是采样近似、不等于稳定"，而不是静默给 0。
        db = _new_db()
        base = time.time() - 100000
        for k, st in enumerate(["online", "offline"]):
            _scan(db, [_dev(1, st)], ts=base + k * 600)
        rc, out = self._run(db, "--window", "all")
        self.assertEqual(rc, 0)
        self.assertIn("样本不足", out)
        self.assertIn("不等于稳定", out)


# ─────────────────────── GUI 对话框（v2.3 §3.2） ───────────────────────
#
# Qt 相关导入放在这里而不是文件顶部：本模块的纯计算 / 写入 / CLI 用例都不需要
# Qt，把 `ensure_qt_app()` 提到顶部会让它们都付一次 Qt 初始化成本。
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests._qt_app import ensure_qt_app  # noqa: E402

ensure_qt_app()

from i18n import tr  # noqa: E402
from ui_dialogs.trend_view import (  # noqa: E402
    TrendViewDialog, _COLUMN_LABELS, _GRANULARITY_TEXT, _REASON_TEXT,
    _WINDOW_TEXT,
)


class TrendViewDialogTest(unittest.TestCase):
    """只读对话框：控件文本与可见性（offscreen 下截图全白，不看图）。

    🔴 对话框直接读 `history_store.DB_PATH`，所以这里像 `test_audit_activity`
    一样**临时替换默认库路径**（`db_util` 按路径缓存连接，新路径 = 新连接）。
    """

    def setUp(self):
        self.db = _new_db()
        self._old = history_store.DB_PATH
        history_store.DB_PATH = self.db

    def tearDown(self):
        history_store.DB_PATH = self._old

    def test_column_count_derives_from_labels(self):
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.columnCount(), len(_COLUMN_LABELS))
        self.assertEqual(dlg.table.horizontalHeaderItem(0).text(),
                         tr(_COLUMN_LABELS[0]))
        dlg.deleteLater()

    def test_rows_and_summary_report_counts(self):
        now = time.time()
        for k in range(3):
            _scan(self.db, [_dev(1), _dev(2, "offline")], ts=now - (3 - k) * 5)
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.rowCount(), 3)
        self.assertIn("50.0%", dlg.summary_label.text())
        self.assertTrue(dlg.next_label.isHidden())   # 有数据时不显示"下一步"
        dlg.deleteLater()

    def test_empty_state_shows_reason_and_next_step(self):
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.rowCount(), 0)
        hint, action = _REASON_TEXT[trend_store.REASON_NO_RECORDS]
        self.assertEqual(dlg.summary_label.text(), tr(hint))
        self.assertIn(tr(action), dlg.next_label.text())
        self.assertFalse(dlg.next_label.isHidden())   # 空态必须显示"下一步"
        dlg.deleteLater()

    def test_out_of_window_is_distinct_from_no_records(self):
        # 🔴 库里有数据但都在窗外 ⇒ 提示"放大窗口"，不是"去跑扫描"。
        _scan(self.db, [_dev(1)], ts=time.time() - 10 * 86400)
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.rowCount(), 0)
        hint, _ = _REASON_TEXT[trend_store.REASON_OUT_OF_WINDOW]
        self.assertEqual(dlg.summary_label.text(), tr(hint))
        dlg.deleteLater()

    def test_switching_window_reloads(self):
        _scan(self.db, [_dev(1)], ts=time.time() - 10 * 86400)
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.rowCount(), 0)
        idx = [i for i in range(dlg.window_combo.count())
               if dlg.window_combo.itemData(i) == "all"][0]
        dlg.window_combo.setCurrentIndex(idx)
        self.assertEqual(dlg.table.rowCount(), 1)
        dlg.deleteLater()

    def test_granularity_day_aggregates(self):
        base = time.time() - 3600
        for k in range(3):
            _scan(self.db, [_dev(1)], ts=base + k)
        dlg = TrendViewDialog()
        self.assertEqual(dlg.table.rowCount(), 3)
        idx = [i for i in range(dlg.gran_combo.count())
               if dlg.gran_combo.itemData(i) == "day"][0]
        dlg.gran_combo.setCurrentIndex(idx)
        self.assertEqual(dlg.table.rowCount(), 1)
        dlg.deleteLater()

    def test_window_choices_match_store(self):
        """GUI 的时间窗 / 粒度表必须与 `trend_store` 一致（两处不能漂）。"""
        self.assertEqual(set(_WINDOW_TEXT), set(trend_store.WINDOW_CHOICES))
        self.assertEqual(set(_GRANULARITY_TEXT),
                         set(trend_store.GRANULARITY_CHOICES))


def tearDownModule():
    """关闭本模块开的所有连接（db_util 按路径缓存单例，用例间会串）。"""
    db_util.close_all()


if __name__ == "__main__":
    unittest.main()
