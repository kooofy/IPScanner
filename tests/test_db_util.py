# -*- coding: utf-8 -*-
"""`db_util.apply_migrations()` —— schema 迁移链的通用机制。

这一层的价值全在"**不重放已应用的迁移**"上：迁移 1~3 恰好全是
`CREATE TABLE IF NOT EXISTS`，重放也看不出问题；但只要有一条 `ALTER TABLE`，
重放就会报错（`duplicate column name`）或改错数据。所以这里的测试**刻意用一条
真的不可重复执行的迁移**来验证守卫，而不是用幂等的建表语句糊过去。
"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db_util


#: 版本 1 是幂等的建表；版本 2 是**不可重复执行**的加列 —— 正是守卫要挡住的那种。
_MIGS = [
    (1, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT DEFAULT '');", "建表"),
    (2, "ALTER TABLE t ADD COLUMN extra TEXT DEFAULT '';", "加列"),
]
_LEGACY = (("t", 1),)


class ApplyMigrationsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "m.db")

    def _conn(self):
        c = sqlite3.connect(self.path)
        self.addCleanup(c.close)
        return c

    def _version(self, c):
        return int(c.execute("PRAGMA user_version").fetchone()[0])

    def _columns(self, c):
        return {r[1] for r in c.execute("PRAGMA table_info(t)").fetchall()}

    # ── 新库 ──────────────────────────────────────────────────────────

    def test_new_database_runs_every_migration(self):
        c = self._conn()
        self.assertEqual(db_util.apply_migrations(c, _MIGS), 2)
        self.assertEqual(self._version(c), 2)
        self.assertIn("extra", self._columns(c))

    def test_empty_file_counts_as_new(self):
        open(self.path, "wb").close()
        c = self._conn()
        self.assertEqual(db_util.apply_migrations(c, _MIGS), 2)
        self.assertEqual(self._version(c), 2)

    def test_returns_the_final_version(self):
        c = self._conn()
        self.assertEqual(
            db_util.apply_migrations(c, _MIGS), db_util.apply_migrations(c, _MIGS))

    # ── 守卫：不重放 ───────────────────────────────────────────────────

    def test_migration_two_really_is_not_repeatable(self):
        """反向验证：这条迁移真的重复执行会报错。

        否则下面那条"没重放"的断言就是空的 —— 一个幂等的迁移本来也不会报错。
        """
        c = self._conn()
        c.executescript(_MIGS[0][1])
        c.executescript(_MIGS[1][1])
        with self.assertRaises(sqlite3.OperationalError) as ctx:
            c.executescript(_MIGS[1][1])
        self.assertIn("duplicate column name", str(ctx.exception))

    def test_applied_migrations_are_not_replayed(self):
        """已盖章到 2 的库再跑一次，不该重放迁移 2（否则上面那条会抛的错会冒出来）。"""
        c = self._conn()
        db_util.apply_migrations(c, _MIGS)
        self.assertEqual(db_util.apply_migrations(c, _MIGS), 2)
        self.assertEqual(self._version(c), 2)

    def test_repeated_calls_are_stable(self):
        c = self._conn()
        for _ in range(4):
            self.assertEqual(db_util.apply_migrations(c, _MIGS), 2)
        self.assertEqual(self._columns(c), {"id", "name", "extra"})

    # ── 老库（无版本号）───────────────────────────────────────────────

    def test_legacy_database_is_stamped_at_the_inferred_version(self):
        """表已存在、版本号是 0 → 推断为 1，**只**补跑迁移 2。"""
        c = self._conn()
        c.executescript(_MIGS[0][1])
        c.execute("INSERT INTO t (name) VALUES ('老数据')")
        c.commit()
        self.assertEqual(self._version(c), 0)

        self.assertEqual(db_util.apply_migrations(c, _MIGS, legacy_tables=_LEGACY), 2)
        self.assertEqual(self._version(c), 2)
        self.assertIn("extra", self._columns(c))
        self.assertEqual(
            c.execute("SELECT name FROM t").fetchone()[0], "老数据")

    def test_legacy_database_keeps_its_rows(self):
        c = self._conn()
        c.executescript(_MIGS[0][1])
        for i in range(3):
            c.execute("INSERT INTO t (name) VALUES (?)", ("n%d" % i,))
        c.commit()
        db_util.apply_migrations(c, _MIGS, legacy_tables=_LEGACY)
        self.assertEqual(
            [r[0] for r in c.execute("SELECT name FROM t ORDER BY id")],
            ["n0", "n1", "n2"])

    def test_legacy_database_without_a_known_table_is_treated_as_new(self):
        """一个只有陌生表的库 → 推断为 0 → 当新库走完整链。"""
        c = self._conn()
        c.executescript("CREATE TABLE unrelated (x TEXT);")
        self.assertEqual(
            db_util.infer_legacy_version(c, _LEGACY), 0)
        self.assertEqual(db_util.apply_migrations(c, _MIGS, legacy_tables=_LEGACY), 2)
        self.assertIn("extra", self._columns(c))

    def test_infer_picks_the_highest_present_table(self):
        """老库形态不止一种 —— 取"最后一张已存在的表"的版本。"""
        c = self._conn()
        self.assertEqual(db_util.infer_legacy_version(c, _LEGACY), 0)
        c.executescript("CREATE TABLE t (id INTEGER);")
        self.assertEqual(db_util.infer_legacy_version(c, _LEGACY), 1)

    def test_infer_ignores_the_order_of_the_table_list(self):
        c = self._conn()
        c.executescript("CREATE TABLE t (id INTEGER);")
        reversed_legacy = tuple(reversed(_LEGACY))
        self.assertEqual(db_util.infer_legacy_version(c, reversed_legacy), 1)

    # ── 未来库（版本比程序新）─────────────────────────────────────────

    def test_a_newer_database_is_not_downgraded(self):
        """用新版建的库被旧版程序打开：不降级、不报错、原样返回。"""
        c = self._conn()
        c.executescript("PRAGMA user_version = 99")
        self.assertEqual(db_util.apply_migrations(c, _MIGS, legacy_tables=_LEGACY), 99)
        self.assertEqual(self._version(c), 99)
        self.assertEqual(self._columns(c), set())

    def test_a_newer_database_is_reported(self):
        """版本比程序新的库必须**记一条 warning**。

        这条不是装饰：反向验证发现"未来库早退"那段逻辑**本身是冗余的** ——
        即使去掉它，`version <= current` 的守卫也会跳过全部迁移，行为一模一样。
        所以这条日志是该分支**唯一可观测的效果**，没有它就等于这段代码不存在。
        """
        c = self._conn()
        c.executescript("PRAGMA user_version = 99")
        with self.assertLogs("ipscanner.db_util", level="WARNING") as cm:
            db_util.apply_migrations(c, _MIGS, legacy_tables=_LEGACY)
        self.assertTrue(any("v99" in line for line in cm.output), cm.output)

    # ── 参数与边界 ────────────────────────────────────────────────────

    def test_legacy_tables_defaults_to_empty(self):
        """不传 `legacy_tables` = 没有老库要认领，新库照常建。"""
        c = self._conn()
        self.assertEqual(db_util.apply_migrations(c, _MIGS), 2)

    def test_without_legacy_tables_a_pre_existing_schema_is_not_recognised(self):
        """不传 `legacy_tables` 时，已存在的表**认不出来** → 会被当成新库重放。

        这是刻意的：推断依赖调用方声明"哪些表属于哪一版"，`db_util` 不认识业务
        表名。这条同时说明 `legacy_tables` 不是可有可无的装饰 —— **漏了它，
        老库就会被重放**（迁移 1~3 恰好幂等所以看不出来，第 4 版起就会炸）。
        """
        c = self._conn()
        c.executescript(_MIGS[0][1])
        with self.assertRaises(sqlite3.OperationalError) as ctx:
            db_util.apply_migrations(c, _MIGS)
        self.assertIn("already exists", str(ctx.exception))

    def test_table_exists_helper(self):
        c = self._conn()
        self.assertFalse(db_util._table_exists(c, "t"))
        c.executescript("CREATE TABLE t (id INTEGER);")
        self.assertTrue(db_util._table_exists(c, "t"))
        self.assertFalse(db_util._table_exists(c, "nope"))


if __name__ == "__main__":
    unittest.main()
