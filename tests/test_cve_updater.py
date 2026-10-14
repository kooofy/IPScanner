# -*- coding: utf-8 -*-
"""`cve_updater`（v2.2 §3.1 在线更新）的单测。

对应 `docs/CVE_SNAPSHOT_MODEL.md` §10.3 的四条验收逐条挂号：

1. 取回后**先验 SHA256**，不匹配 → 拒绝落盘、保留旧数据；
2. 失败（超时 / 404 / 限流 / 摘要不符 / 写不了盘）只降级、**永不抛**、
   **永不升级成扫描失败**；
3. 落盘位置是 `data_dir()`（可注入），且**没人调用就不联网**；
4. `SOURCE_*` 扩了「在线下载」态（在 `test_cve_snapshot.py` 那侧断言）。

🔴 **本文件全程不碰网络**：所有用例都注入 `fetch` 桩。
唯一带 `urllib` 的地方是"默认 transport 存在"这类**结构**断言，不执行它。
"""
import ast
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import cve_updater as cu


def _snapshot_bytes(entries=2, *, generated_at="2026-10-13T00:00:00Z"):
    """造一份结构合法的快照字节（内容不必真，够过结构检查即可）。"""
    doc = {
        "schema": "ipscanner.cve_snapshot/1",
        "generated_at": generated_at,
        "max_age_days": 30,
        "cves": [
            {
                "cve_id": "CVE-2021-%04d" % (10000 + i),
                "cpe": ["cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*"
                        % (i, i)],
                "kev": True,
                "epss": 0.5,
                "summary": "stub entry %d" % i,
            }
            for i in range(entries)
        ],
    }
    return json.dumps(doc).encode("utf-8")


def _sums_bytes(payload, name="cve_snapshot.json"):
    return ("%s  %s\n"
            % (hashlib.sha256(payload).hexdigest(), name)).encode("utf-8")


class _Fetcher:
    """可编程的 transport 桩：按 URL 返回字节或抛异常，并记录调用。

    用类而不是 lambda，是为了能断言"**根本没发请求**"（调用次数）。
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        handler = self.routes.get(url)
        if handler is None:
            raise OSError("connection refused (stub)")
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler(url, timeout)
        return handler


class SuccessTest(unittest.TestCase):
    """正常路径：下载 → 校验 → 原子落盘。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cve_upd_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.url = "https://example.invalid/data/cve_snapshot.json"
        self.sums_url = "https://example.invalid/data/cve_snapshot.sha256"

    def test_downloads_verifies_and_writes(self):
        payload = _snapshot_bytes(entries=3)
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)

        self.assertTrue(res["ok"], res)
        self.assertEqual(res["reason"], cu.REASON_OK)
        self.assertEqual(res["entry_count"], 3)
        self.assertTrue(res["checksum_verified"])
        self.assertEqual(res["bytes"], len(payload))
        self.assertEqual(res["path"],
                         os.path.join(self.tmp, "cve_snapshot.json"))
        with io.open(res["path"], "rb") as fh:
            self.assertEqual(fh.read(), payload)

    def test_writes_checksum_manifest_alongside(self):
        """清单也要落盘 —— 否则这份数据此后无法自验（§3.4）。"""
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)

        sums_path = os.path.join(self.tmp, "cve_snapshot.sha256")
        self.assertTrue(os.path.isfile(sums_path))
        with io.open(sums_path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(hashlib.sha256(payload).hexdigest(), text)
        self.assertIn("cve_snapshot.json", text)

    def test_manifest_only_location_is_accepted(self):
        """清单只有一条、文件名对不上（用户手工裁剪过）→ 按那一条比对。"""
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload, name="x.json")})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["checksum_verified"])

    def test_no_leftover_tmp_files(self):
        """落盘必须是原子的：不能留下 *.tmp。"""
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(
            [n for n in os.listdir(self.tmp) if n.endswith(".tmp")], [])

    def test_round_trip_through_runtime_loader(self):
        """🔴 端到端：下载回来的文件必须能被**运行期加载器**接受。

        这是本模块与 `scanner/cve_snapshot.py` 的**契约测试** —— 两个模块
        刻意不互相 import，唯一的保障就是"产出的文件加载器认"。
        """
        from scanner import cve_snapshot as cs
        payload = _snapshot_bytes(entries=4)
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertTrue(res["ok"], res)

        snap = cs.load_snapshot(res["path"])
        self.assertEqual(snap.state, cs.STATE_OK)
        self.assertEqual(len(snap.entries), 4)
        self.assertIs(snap.checksum_verified, True)

    def test_reports_source_as_online(self):
        """下载落盘在 data_dir() → 加载器把它认成「在线下载」（v2.2 §3.1）。

        （v2.1 时同一动作报 `data-dir`；v2.2 加了来源标记文件后，
        下载来的这份有了更精确的身份 —— `test_no_mark_falls_back_to_data_dir`
        钉住"没有标记仍报 data-dir"，两条一起锁住语义。）
        """
        from scanner import cve_snapshot as cs
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        snap = cs.load_snapshot(res["path"])
        self.assertEqual(snap.source, cs.SOURCE_ONLINE)


class NoUrlTest(unittest.TestCase):
    """地址没填 / 是占位符 → **一个包都不发**。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cve_upd_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _assert_no_request(self, url):
        fetch = _Fetcher({})
        res = cu.update_snapshot(url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], cu.REASON_NO_URL)
        self.assertEqual(fetch.calls, [], "占位地址不该发起任何请求")

    def test_empty_url(self):
        self._assert_no_request("")

    def test_placeholder_url(self):
        from scanner import cve_snapshot as cs
        # 与运行期常量联动：占位符一天不填，这里就该一直是 no-url
        self._assert_no_request(cs.DEFAULT_SNAPSHOT_URL)

    def test_angle_bracket_placeholder(self):
        self._assert_no_request("https://example.invalid/<your-repo>/x.json")


class FailureTest(unittest.TestCase):
    """失败一律降级：`ok=False` + 一个 `reason` + **不抛** + 不毁旧数据。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cve_upd_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.url = "https://example.invalid/data/cve_snapshot.json"
        self.sums_url = "https://example.invalid/data/cve_snapshot.sha256"
        # 先放一份"好用的旧数据"，验证失败时它必须原样保留
        self.old = _snapshot_bytes(entries=1)
        with io.open(os.path.join(self.tmp, "cve_snapshot.json"),
                     "wb") as fh:
            fh.write(self.old)

    def _assert_old_kept(self):
        with io.open(os.path.join(self.tmp, "cve_snapshot.json"),
                     "rb") as fh:
            self.assertEqual(fh.read(), self.old, "旧数据被毁了")

    def test_network_error_degrades(self):
        fetch = _Fetcher({self.url: OSError("timed out")})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], cu.REASON_DOWNLOAD_FAILED)
        self._assert_old_kept()

    def test_http_404_degrades(self):
        fetch = _Fetcher({self.url: Exception("HTTP Error 404")})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_DOWNLOAD_FAILED)
        self._assert_old_kept()

    def test_empty_body_degrades(self):
        fetch = _Fetcher({self.url: b""})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_DOWNLOAD_FAILED)
        self._assert_old_kept()

    def test_checksum_mismatch_rejected(self):
        payload = _snapshot_bytes(entries=9)
        wrong = _sums_bytes(_snapshot_bytes(entries=2))      # 摘要对不上
        fetch = _Fetcher({self.url: payload, self.sums_url: wrong})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], cu.REASON_CHECKSUM_FAILED)
        self.assertFalse(res["checksum_verified"])
        self._assert_old_kept()

    def test_missing_manifest_refused_by_default(self):
        """没有清单可验 = 没验 → 默认拒绝（§10.3 第 1 条）。"""
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload})           # 清单 404
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], cu.REASON_NO_MANIFEST)
        self._assert_old_kept()

    def test_missing_manifest_allowed_when_opted_out(self):
        """联调模式（require_checksum=False）下无清单可以过 —— 但只此一途。"""
        payload = _snapshot_bytes()
        # 桩服务器往往不备清单：两个地址里只有本体能取到
        fetch = _Fetcher({self.url: payload})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp,
                                 require_checksum=False)
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["checksum_verified"])

    def test_invalid_json_rejected(self):
        payload = b"<html>not json</html>"
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_INVALID)
        self._assert_old_kept()

    def test_empty_cves_rejected(self):
        payload = _snapshot_bytes(entries=0)
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_INVALID)
        self._assert_old_kept()

    def test_oversized_body_rejected(self):
        """超过配额的内容**不落盘**（配额在下载途中就拦）。"""
        import cve_updater
        orig = cve_updater.MAX_DOWNLOAD_BYTES
        cve_updater.MAX_DOWNLOAD_BYTES = 64
        self.addCleanup(setattr, cve_updater, "MAX_DOWNLOAD_BYTES", orig)
        payload = _snapshot_bytes(entries=50)         # 显然 > 64 字节
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_TOO_LARGE)
        self._assert_old_kept()

    def test_non_bytes_transport_result_handled(self):
        """桩返回了 str（不是 bytes）→ 当格式错，不在下面炸。"""
        fetch = _Fetcher({self.url: "not-bytes"})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertEqual(res["reason"], cu.REASON_INVALID)

    def test_write_failure_degrades(self):
        """落盘写不动（目录是文件）→ write-failed，不抛。"""
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        blocker = os.path.join(self.tmp, "blocker")
        with io.open(blocker, "w", encoding="utf-8") as fh:
            fh.write("x")             # 拿一个**文件**当输出目录
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=blocker)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], cu.REASON_WRITE_FAILED)

    def test_never_raises_on_arbitrary_transport_exception(self):
        """transport 抛什么都不能穿出去（§3.3）。"""
        for exc in (RuntimeError("boom"), KeyError("x"),
                    ValueError("bad"), ConnectionResetError("rst")):
            fetch = _Fetcher({self.url: exc})
            res = cu.update_snapshot(self.url, fetch=fetch,
                                     target_dir=self.tmp)
            self.assertFalse(res["ok"], exc)
            self.assertTrue(res["reason"])

    def test_result_is_json_serializable(self):
        """失败结果必须能直接 JSON 化（CLI `--json` 会用）。"""
        fetch = _Fetcher({self.url: OSError("nope")})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        json.dumps(res)                       # 不抛即通过


class NoAmbientNetworkTest(unittest.TestCase):
    """🔴 「没人调用就不联网」—— 结构可判定。"""

    def _module_source(self):
        with io.open(os.path.join(ROOT, "cve_updater.py"),
                     encoding="utf-8") as fh:
            return fh.read()

    def test_module_import_has_no_side_effects(self):
        """import 本模块**不建立任何连接**：只允许 import 网络库，不允许用。"""
        tree = ast.parse(self._module_source())
        # 顶层（模块级）只允许：docstring / import / 赋值 / 函数与类定义。
        # 🔴 裸表达式（如一次模块级的函数调用）一律拒绝 —— 那正是
        # 「import 期就联网」的形态。
        for node in tree.body:
            if isinstance(node, ast.Expr):
                self.assertIsInstance(
                    node.value, ast.Constant,
                    "cve_updater 顶层出现了非 docstring 的表达式语句"
                    "（import 期副作用？）")

    def test_default_fetch_is_the_only_network_call_site(self):
        """网络调用点唯一：`urlopen` 只能出现在 `_default_fetch` 里。

        这样"哪些代码会发包"是可以静态回答的 —— 将来有人把 request 拼到
        别处，这条断言会红。
        """
        src = self._module_source()
        tree = ast.parse(src)
        callers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Attribute)
                        and sub.attr in ("urlopen", "urlretrieve")):
                    callers.append(node.name)
        self.assertEqual(sorted(set(callers)), ["_default_fetch"])

    def test_updater_not_imported_by_scanner_package(self):
        """`scanner/` 一个文件都不许 **import** 本模块 —— 否则零网络不变量破了。

        🔴 判据是 **AST 里的 import**，不是文本子串：文档里提一句
        `cve_updater.py`（解释架构）是合法的，真正会破不变量的是
        `import cve_updater`。
        """
        scan_dir = os.path.join(ROOT, "scanner")
        offenders = []
        for name in sorted(os.listdir(scan_dir)):
            if not name.endswith(".py"):
                continue
            with io.open(os.path.join(scan_dir, name),
                         encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""]
                else:
                    continue
                if any((m or "").split(".")[0] == "cve_updater"
                       for m in mods):
                    offenders.append("%s: %s" % (name, mods))
        self.assertEqual(offenders, [], "scanner/ 引用了 cve_updater")

    def test_scanner_cve_snapshot_stays_zero_network(self):
        """本模块的存在**没有**污染加载器：它仍不 import 网络库。"""
        with io.open(os.path.join(ROOT, "scanner", "cve_snapshot.py"),
                     encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
        forbidden = ("urllib", "requests", "socket", "http", "ssl",
                     "ftplib", "smtplib", "telnetlib", "asyncio")
        found = set()
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for n in names:
                if (n or "").split(".")[0] in forbidden:
                    found.add(n)
        self.assertEqual(found, set(), "cve_snapshot.py 被引入了网络库")


class ReasonValueTest(unittest.TestCase):
    """`REASON_*` 是**规范值**：调用方拿它选文案，不能是显示文本。"""
    def test_reasons_are_language_independent(self):
        reasons = [v for k, v in vars(cu).items()
                   if k.startswith("REASON_")]
        self.assertTrue(reasons)
        for value in reasons:
            self.assertIsInstance(value, str)
            self.assertFalse(
                any("\u4e00" <= ch <= "\u9fff" for ch in value),
                "REASON_* 里出现了中文（%r）—— 规范值必须语言无关" % value)

    def test_reason_values_are_unique(self):
        reasons = [v for k, v in vars(cu).items() if k.startswith("REASON_")]
        self.assertEqual(len(reasons), len(set(reasons)))


class FilenameContractTest(unittest.TestCase):
    """🔴 `cve_updater` 与 `scanner.cve_snapshot` **不互相 import**，
    只共享三个文件名常量 —— 这些"约定"必须由测试钉住，否则某天有人
    改了其中一处，更新出来的文件加载器就找不到了（而且不会报任何错）。"""

    def test_filenames_match_loader(self):
        from scanner import cve_snapshot as cs
        self.assertEqual(cu.DATA_FILENAME, cs.DATA_FILENAME)
        self.assertEqual(cu.SUMS_FILENAME, cs.SUMS_FILENAME)
        self.assertEqual(cu.ONLINE_MARK_FILENAME, cs.ONLINE_MARK_FILENAME)


class OnlineSourceTest(unittest.TestCase):
    """v2.2 §3.1 第 4 条：徽标要能显示「来源：在线下载」。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cve_upd_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.url = "https://example.invalid/data/cve_snapshot.json"
        self.sums_url = "https://example.invalid/data/cve_snapshot.sha256"

    def test_mark_file_written_on_success(self):
        payload = _snapshot_bytes()
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertTrue(os.path.isfile(
            os.path.join(self.tmp, "cve_snapshot.online")))

    def test_mark_file_not_written_on_failure(self):
        """失败的更新绝不能留下一份"声称在线下载"的标记。"""
        fetch = _Fetcher({self.url: OSError("nope")})
        cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(os.path.isfile(
            os.path.join(self.tmp, "cve_snapshot.online")))

    def test_checksum_failure_leaves_no_mark(self):
        payload = _snapshot_bytes(entries=9)
        wrong = _sums_bytes(_snapshot_bytes(entries=2))
        fetch = _Fetcher({self.url: payload, self.sums_url: wrong})
        cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertFalse(os.path.isfile(
            os.path.join(self.tmp, "cve_snapshot.online")))

    def test_loader_reports_online_source(self):
        """端到端：下载 → 加载器把 source 判成 online-download。"""
        from scanner import cve_snapshot as cs
        payload = _snapshot_bytes(entries=3)
        fetch = _Fetcher({self.url: payload,
                          self.sums_url: _sums_bytes(payload)})
        res = cu.update_snapshot(self.url, fetch=fetch, target_dir=self.tmp)
        self.assertTrue(res["ok"], res)
        snap = cs.load_snapshot(res["path"])
        self.assertEqual(snap.source, cs.SOURCE_ONLINE)
        # 来源不影响可用性：仍然是新鲜、可查的一份数据
        self.assertEqual(snap.state, cs.STATE_OK)
        self.assertTrue(snap.usable)

    def test_no_mark_falls_back_to_data_dir(self):
        """没有标记的旧文件仍报 data-dir（行为与 v2.1 完全一致）。"""
        from scanner import cve_snapshot as cs
        payload = _snapshot_bytes()
        path = os.path.join(self.tmp, "cve_snapshot.json")
        with io.open(path, "wb") as fh:
            fh.write(payload)
        snap = cs.load_snapshot(path)
        self.assertEqual(snap.source, cs.SOURCE_DATA)


if __name__ == "__main__":
    unittest.main()
