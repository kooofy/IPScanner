# -*- coding: utf-8 -*-
"""`tools/build_cve_snapshot.py`（v2.1 §2.3 路径 B）的 smoke。

CI 里有一个同名 job（`quality-cve-build`）在跑同一条命令；这里把它搬进
单测，是为了让**每台开发机**在改解析规则时立刻看到红，而不必等 CI。

关键口径（模型文档 §9.3）：
* 全离线、全确定性 —— 输入是 `tests/fixtures/cve/` 下的结构性样本；
* 产出必须能过 `load_snapshot()`（`--check` 的自校验就是干这个的）；
* 非 `vulnerable` 的 cpeMatch **不能**进产物；
* 一条 CPE 都收敛不出来的 CVE **跳过**（匹配不上的留着只是噪声）。
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TOOL = os.path.join(ROOT, "tools", "build_cve_snapshot.py")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "cve")

from scanner import cve_snapshot as cs


class BuildScriptTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.out = os.path.join(self._tmp.name, "cve_build")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, *extra):
        cmd = [sys.executable, TOOL,
               "--nvd-file", os.path.join(FIXTURES, "nvd_sample.json"),
               "--kev-file", os.path.join(FIXTURES, "kev_sample.json"),
               "--epss-file", os.path.join(FIXTURES, "epss_sample.csv"),
               "--out", self.out,
               "--generated-at", "2026-10-01T00:00:00Z"] + list(extra)
        # 🔴 显式 encoding="utf-8"：CI runner 的 locale 是 cp1252，
        # `text=True` 默认按 locale 解码。子进程侧已 reconfigure 成 UTF-8
        # （见 `tools/build_cve_snapshot.py::_force_utf8_stdio`），
        # 两边不写死同一个编码就会得到乱码或断言失败。
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)

    def _run_env(self, extra_env, *extra):
        """同 `_run`，但给子进程额外注入环境变量（用来伪造 CI 的代码页）。"""
        cmd = [sys.executable, TOOL,
               "--nvd-file", os.path.join(FIXTURES, "nvd_sample.json"),
               "--kev-file", os.path.join(FIXTURES, "kev_sample.json"),
               "--epss-file", os.path.join(FIXTURES, "epss_sample.csv"),
               "--out", self.out,
               "--generated-at", "2026-10-01T00:00:00Z"] + list(extra)
        env = dict(os.environ)
        env.update(extra_env)
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env,
                              timeout=180)

    def test_build_and_self_check(self):
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("自校验通过", proc.stdout)
        json_path = os.path.join(self.out, "cve_snapshot.json")
        self.assertTrue(os.path.isfile(json_path))
        # 两份清单都在（加载器认 .sha256，发布口径认 SHA256SUMS）
        for name in ("cve_snapshot.sha256", "SHA256SUMS"):
            self.assertTrue(os.path.isfile(os.path.join(self.out, name)), name)

    def test_output_is_loadable_and_checksum_verified(self):
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        snap = cs.load_snapshot(os.path.join(self.out, "cve_snapshot.json"))
        self.assertIn(snap.state, (cs.STATE_OK, cs.STATE_STALE))
        self.assertEqual(len(snap.entries), 2)
        self.assertIs(snap.checksum_verified, True)

    def test_non_vulnerable_cpe_match_is_excluded(self):
        """NVD 里 `vulnerable: false` 的 cpeMatch 是「未受影响的排除项」。"""
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with io.open(os.path.join(self.out, "cve_snapshot.json"),
                     encoding="utf-8") as fh:
            doc = json.load(fh)
        all_cpe = [c for row in doc["cves"] for c in row["cpe"]]
        for cpe in all_cpe:
            self.assertNotIn("something_else", cpe)

    def test_cve_without_usable_cpe_is_skipped(self):
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with io.open(os.path.join(self.out, "cve_snapshot.json"),
                     encoding="utf-8") as fh:
            doc = json.load(fh)
        ids = [row["cve_id"] for row in doc["cves"]]
        self.assertNotIn("CVE-2019-99999", ids)
        self.assertIn("CVE-2021-44228", ids)

    def test_kev_and_epss_are_merged(self):
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with io.open(os.path.join(self.out, "cve_snapshot.json"),
                     encoding="utf-8") as fh:
            doc = json.load(fh)
        by_id = {row["cve_id"]: row for row in doc["cves"]}
        self.assertIs(by_id["CVE-2021-44228"]["kev"], True)
        self.assertAlmostEqual(by_id["CVE-2021-44228"]["epss"], 0.94412)
        self.assertAlmostEqual(by_id["CVE-2021-44228"]["epss_percentile"],
                               0.99994)
        # summary 落的是英文描述（不是西班牙语那条）
        self.assertIn("Log4Shell", by_id["CVE-2021-44228"]["summary"])

    def test_max_entries_keeps_the_worst_first(self):
        proc = self._run("--check", "--max-entries", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with io.open(os.path.join(self.out, "cve_snapshot.json"),
                     encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(len(doc["cves"]), 1)
        # 两条都是 KEV，EPSS 高的那条（44228 = 0.94412）必须留下
        self.assertEqual(doc["cves"][0]["cve_id"], "CVE-2021-44228")

    def test_missing_input_file_fails_loudly(self):
        proc = subprocess.run(
            [sys.executable, TOOL, "--nvd-file",
             os.path.join(FIXTURES, "does-not-exist.json"),
             "--out", self.out], cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("读输入失败", proc.stderr)

    def test_help_mentions_offline_only(self):
        proc = subprocess.run([sys.executable, TOOL, "--help"], cwd=ROOT,
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("不联网", proc.stdout)

    def test_runs_when_stdout_code_page_is_cp1252(self):
        """🔴 回归：stdout 被重定向到管道时，Windows 按 **ANSI 代码页**
        （CI runner = cp1252）编码且 `strict` —— 本脚本输出全是中文，
        不 `reconfigure` 就 `UnicodeEncodeError`、退出码 1。

        2026-10-13 的 CI 上这样红过：8 个 `test_cve_snapshot_build` 用例 +
        `quality-cve-build` job 全挂，而**本机控制台是 UTF-8 所以本地全绿**
        （只在 CI 复现的经典形态）。用 `PYTHONIOENCODING` 伪造代码页钉住它。
        """
        proc = self._run_env({"PYTHONIOENCODING": "cp1252"}, "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("自校验通过", proc.stdout)
        self.assertIn("已写出", proc.stdout)


if __name__ == "__main__":
    unittest.main()
