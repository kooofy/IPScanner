# -*- coding: utf-8 -*-
"""审计日志分类的语言无关性测试（P1-1）。

回归点：旧实现把 tr() 的结果直接当分类值入库，中文环境写「扫描」、英文环境写
「Scan」。同一个逻辑分类在库里变成两个不同的值，导致：
  - 按分类筛选只能命中其中一半记录；
  - 分类统计数字翻倍/错乱；
  - 切换界面语言后历史记录看起来"消失"了。
现在入库一律是规范代码，显示时才翻译。
"""
import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import audit_log
import db_util
import i18n


class CategoryCodeTest(unittest.TestCase):

    def test_codes_are_ascii_and_stable_across_languages(self):
        """分类常量必须是语言无关的 ASCII 代码，切语言不改变其值。"""
        for lang in ("zh-CN", "en-US"):
            i18n.init(lang)
            for code in audit_log.CATEGORIES:
                self.assertTrue(code.isascii(),
                                msg=f"{lang} 下分类代码不是 ASCII: {code!r}")
        i18n.init("zh-CN")

    def test_codes_match_expected_set(self):
        self.assertEqual(set(audit_log.CATEGORIES), {
            "scan", "conflict", "range", "result",
            "library", "export", "device", "system",
        })

    def test_label_is_translated_and_lazy(self):
        """category_label 必须随当前语言变化 —— 证明 tr() 是惰性求值的。"""
        i18n.init("zh-CN")
        zh = audit_log.category_label(audit_log.CAT_SCAN)
        self.assertEqual(zh, "扫描")

        i18n.init("en-US")
        en = audit_log.category_label(audit_log.CAT_SCAN)
        self.assertEqual(en, "Scan")

        self.assertNotEqual(zh, en, msg="切换语言后分类显示名未变化")
        i18n.init("zh-CN")

    def test_label_of_unknown_code_returns_code(self):
        """历史数据里出现未知分类时不能显示为空。"""
        self.assertEqual(audit_log.category_label("weird_code"), "weird_code")
        self.assertEqual(audit_log.category_label(""), "")

    def test_normalize_accepts_code_and_both_languages(self):
        self.assertEqual(audit_log.normalize_category("scan"), "scan")
        self.assertEqual(audit_log.normalize_category("扫描"), "scan")
        self.assertEqual(audit_log.normalize_category("Scan"), "scan")
        self.assertEqual(audit_log.normalize_category("SCAN"), "scan")
        self.assertEqual(audit_log.normalize_category("冲突检测"), "conflict")
        self.assertEqual(audit_log.normalize_category("Conflict"), "conflict")
        self.assertEqual(audit_log.normalize_category("设备操作"), "device")
        self.assertEqual(audit_log.normalize_category(""), "")
        self.assertEqual(audit_log.normalize_category(None), "")
        self.assertEqual(audit_log.normalize_category("mystery"), "mystery")


class CategoryPersistenceTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "audit.db")

    def tearDown(self):
        db_util.close_connection(self.db)

    def test_written_value_is_code_regardless_of_language(self):
        """中英文环境各写一条，库里存的必须都是 'scan'。"""
        for lang in ("zh-CN", "en-US"):
            i18n.init(lang)
            audit_log.log_event(audit_log.CAT_SCAN, "开始扫描", "192.168.1.0/24",
                                db_path=self.db)
        i18n.init("zh-CN")

        rows = audit_log.query_logs(db_path=self.db)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["category"] for r in rows}, {"scan"})

    def test_filter_matches_across_languages(self):
        """用规范代码筛选，应同时命中两种语言环境下写入的记录。"""
        for lang in ("zh-CN", "en-US"):
            i18n.init(lang)
            audit_log.log_event(audit_log.CAT_SCAN, "开始扫描", db_path=self.db)
            audit_log.log_event(audit_log.CAT_EXPORT, "导出结果", db_path=self.db)
        i18n.init("zh-CN")

        self.assertEqual(audit_log.count_logs(db_path=self.db), 4)
        self.assertEqual(audit_log.count_logs(audit_log.CAT_SCAN, db_path=self.db), 2)
        self.assertEqual(audit_log.count_logs(audit_log.CAT_EXPORT, db_path=self.db), 2)
        self.assertEqual(len(audit_log.query_logs(category="scan", db_path=self.db)), 2)

    def test_filter_accepts_legacy_translated_value(self):
        """旧版调用方若仍传翻译后的值，也要能筛到（兼容层）。"""
        audit_log.log_event(audit_log.CAT_SCAN, "开始扫描", db_path=self.db)
        self.assertEqual(len(audit_log.query_logs(category="扫描", db_path=self.db)), 1)
        self.assertEqual(len(audit_log.query_logs(category="Scan", db_path=self.db)), 1)


class LegacyMigrationTest(unittest.TestCase):
    """老库里的「翻译后分类」必须被自动改写为规范代码。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "legacy.db")
        # 直接用裸 SQL 造一个"旧版本"库：分类列存的是翻译后的字符串
        conn = sqlite3.connect(self.db)
        conn.executescript(
            """
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                detail TEXT DEFAULT ''
            );
            """
        )
        for cat in ("扫描", "Scan", "导出", "Export", "设备操作", "Device"):
            conn.execute(
                "INSERT INTO audit_logs (ts, category, action, detail) VALUES (?,?,?,?)",
                (1.0, cat, "动作", "详情"),
            )
        conn.commit()
        conn.close()

    def tearDown(self):
        db_util.close_connection(self.db)

    def test_migration_rewrites_legacy_values(self):
        # 任意一次访问都会触发 _init_db → 迁移
        rows = audit_log.query_logs(db_path=self.db)
        self.assertEqual(len(rows), 6)
        cats = sorted(r["category"] for r in rows)
        self.assertEqual(cats, ["device", "device", "export", "export",
                                "scan", "scan"])
        # 不应再有任何中文/英文原值残留
        for r in rows:
            self.assertTrue(r["category"].isascii(), msg=r["category"])

    def test_migration_is_idempotent(self):
        audit_log.query_logs(db_path=self.db)
        first = sorted(r["category"] for r in audit_log.query_logs(db_path=self.db))
        # 再访问一次不应产生变化
        second = sorted(r["category"] for r in audit_log.query_logs(db_path=self.db))
        self.assertEqual(first, second)

    def test_after_migration_filter_works(self):
        self.assertEqual(audit_log.count_logs("scan", db_path=self.db), 2)
        self.assertEqual(audit_log.count_logs("export", db_path=self.db), 2)
        self.assertEqual(audit_log.count_logs("device", db_path=self.db), 2)


if __name__ == "__main__":
    unittest.main()
