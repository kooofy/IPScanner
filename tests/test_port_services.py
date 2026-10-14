# -*- coding: utf-8 -*-
"""端口映射外置测试（v2.2 §3.2）。

对应 ``docs/ROADMAP_V2.2.md`` §3.2 的三条验收标准：

1. **外部文件真实生效**：放进 ``data_dir()`` 的改过的
   ``port_services.json`` 被采用。进程内 ``reload()`` 只证明缓存会失效，
   **子进程**才证明"重启后新进程会去读 data_dir()"——两级都验。
2. **文件损坏 / 缺失 / 结构不符 → 回退内置**：不抛异常、不静默变空表；
   ``ports`` / ``names`` 两张表**各自独立**回退（一张坏不影响另一张）；
   单条畸形只跳过它自己。
3. **打包覆盖**：新数据文件进两个 spec 的 ``datas``，且断言到**具体文件**
   （不能只断言目录）。

另钉两条兼容性契约：

* ``scanner.constants.COMMON_PORTS`` / ``PORT_NAMES`` / ``scanner.COMMON_PORTS``
  旧入口语义不变（惰性别名，不再冻结 import 期快照 —— 否则外置文件更新后
  必须重启进程才可见，违背 §3.2 的验收口径）；
* 外置只改"扫描哪些端口、端口显示名"，**不影响 CVE / 暴露面识别口径**
  （``exposure.cpe_for_product()`` 在覆盖前后必须一致）。
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import port_services as PS


class DataFileTest(unittest.TestCase):
    """数据文件本身：必须在仓库里、且与内置兜底表一致（搬家不改默认行为）。"""

    def test_data_file_exists_at_repo_root(self):
        self.assertTrue(
            os.path.exists(os.path.join(ROOT, PS.DATA_FILENAME)),
            "port_services.json 不在仓库根目录，打包时会漏掉",
        )

    def test_data_file_matches_builtin_fallback(self):
        """外置只是搬家：出厂文件与内置兜底表必须逐值一致。

        开发模式下 ``data_dir()`` 就是仓库根，真正生效的是 JSON；兜底表只在
        文件坏掉时兜底。两者不一致 = 静默改默认行为，必须在这里被拦住。
        """
        with open(os.path.join(ROOT, PS.DATA_FILENAME), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(sorted(data["ports"]), sorted(PS._FALLBACK_PORTS))
        self.assertEqual({int(k): v for k, v in data["names"].items()},
                         PS._FALLBACK_NAMES)

    def test_data_path_prefers_user_dir_over_resource(self):
        """三层加载的第一层：data_dir() 里的用户文件优先于内置资源。"""
        from app_paths import resource_dir
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(PS, "data_dir", return_value=tmp):
                # 用户目录还没有该文件 → 指回 resource_dir（打包内的那份）
                self.assertEqual(
                    PS.data_path(),
                    os.path.join(resource_dir(), PS.DATA_FILENAME))
                # 一旦放进用户目录，同一个函数立刻改指用户文件
                target = os.path.join(tmp, PS.DATA_FILENAME)
                with open(target, "w", encoding="utf-8") as f:
                    json.dump({"ports": [80]}, f)
                self.assertEqual(PS.data_path(), target)


class ExternalOverrideTest(unittest.TestCase):
    """外部文件生效 / 各类回退 / 单条畸形。每个用例后都 reload 归位。"""

    def tearDown(self):
        PS.reload()

    def _patch_dir(self, tmp):
        return mock.patch.object(PS, "data_dir", return_value=tmp)

    def _write(self, tmp, obj):
        with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                  encoding="utf-8") as f:
            json.dump(obj, f)

    def test_external_file_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": [80, 443, 4444],
                              "names": {"80": "HTTP", "4444": "自定义端口"}})
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(), [80, 443, 4444])
                self.assertEqual(PS.port_names(),
                                 {80: "HTTP", 4444: "自定义端口"})
                self.assertEqual(PS.counts(), (3, 2))
                self.assertEqual(PS.raw_port_name(4444), "自定义端口")

    def test_external_ports_only_keeps_builtin_names(self):
        """只覆盖 ports：names 保持内置（两张表独立回退的正面）。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": [81, 82]})
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(), [81, 82])
                self.assertEqual(PS.port_names(),
                                 {p: n for p, n in PS._FALLBACK_NAMES.items()})

    def test_missing_file_falls_back_to_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                    PS, "data_path",
                    return_value=os.path.join(tmp, "no_such_file.json")):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS))
                self.assertEqual(PS.port_names(), dict(PS._FALLBACK_NAMES))

    def test_corrupt_json_falls_back_to_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, PS.DATA_FILENAME)
            with open(path, "w", encoding="utf-8") as f:
                f.write("{ this is not json ")
            with mock.patch.object(PS, "data_path", return_value=path):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS))
                self.assertEqual(PS.port_names(), dict(PS._FALLBACK_NAMES))

    def test_top_level_not_object_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, PS.DATA_FILENAME)
            with open(path, "w", encoding="utf-8") as f:
                json.dump([1, 2, 3], f)
            with mock.patch.object(PS, "data_path", return_value=path):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS))

    def test_empty_object_falls_back_both_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, PS.DATA_FILENAME)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({}, f)
            with mock.patch.object(PS, "data_path", return_value=path):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS))
                self.assertEqual(PS.port_names(), dict(PS._FALLBACK_NAMES))

    def test_ports_wrong_type_falls_back_names_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": "80,443",
                              "names": {"80": "HTTP"}})
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS), "ports 坏掉应只回退它自己")
                self.assertEqual(PS.port_names(), {80: "HTTP"},
                                 "names 是好的，不能跟着回退")

    def test_names_wrong_type_falls_back_ports_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": [80, 443], "names": ["HTTP"]})
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(), [80, 443],
                                 "ports 是好的，不能跟着回退")
                self.assertEqual(PS.port_names(), dict(PS._FALLBACK_NAMES))

    def test_empty_arrays_fall_back(self):
        """空数组 = 结构不符：绝不能静默变空表让上层"什么都没扫"。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": [], "names": {}})
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(),
                                 list(PS._FALLBACK_PORTS))
                self.assertEqual(PS.port_names(), dict(PS._FALLBACK_NAMES))

    def test_single_malformed_entries_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {
                "ports": [80, "80x", 0, 70000, 443, 443],
                "names": {"80": "HTTP", "x": "坏键", "445": "   ",
                          "99999": "越界"},
            })
            with self._patch_dir(tmp):
                PS.reload()
                self.assertEqual(PS.common_ports(), [80, 443])
                self.assertEqual(PS.port_names(), {80: "HTTP"})
                self.assertEqual(PS.counts(), (2, 1))

    def test_raw_port_name_rejects_non_port(self):
        self.assertEqual(PS.raw_port_name("not-a-port"), "")
        self.assertEqual(PS.raw_port_name(None), "")
        self.assertEqual(PS.raw_port_name(64999), "")

    def test_reload_refreshes_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, {"ports": [80]})
            with self._patch_dir(tmp):
                PS.reload()
                first = PS.common_ports()
                self.assertEqual(first, [80])
                self._write(tmp, {"ports": [81, 82]})
                PS.reload()
                self.assertEqual(PS.common_ports(), [81, 82])


class ConstantsIntegrationTest(unittest.TestCase):
    """constants / scanner 包 / engine / ports 四个调用点的接线。"""

    def tearDown(self):
        PS.reload()

    def test_quick_level_reads_external_table(self):
        from scanner.constants import get_ports_for_level
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                      encoding="utf-8") as f:
                json.dump({"ports": [81, 82]}, f)
            with mock.patch.object(PS, "data_dir", return_value=tmp):
                PS.reload()
                self.assertEqual(get_ports_for_level("quick"), [81, 82])
                # 另两级不受外置表影响
                self.assertEqual(get_ports_for_level("standard"),
                                 list(range(1, 1024)))
                self.assertEqual(get_ports_for_level("all"),
                                 list(range(1, 65536)))

    def test_legacy_alias_semantics_unchanged(self):
        from scanner import constants as C
        from scanner.constants import COMMON_PORTS, PORT_NAMES
        self.assertEqual(COMMON_PORTS, PS.common_ports())
        self.assertEqual(PORT_NAMES,
                         {p: C.port_name(p) for p in PS.port_names()})

    def test_package_forwarding_reflects_reload(self):
        """scanner.COMMON_PORTS 不能再冻结 import 期快照。"""
        import scanner
        default = scanner.COMMON_PORTS
        self.assertIn(80, default)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                      encoding="utf-8") as f:
                json.dump({"ports": [4444]}, f)
            with mock.patch.object(PS, "data_dir", return_value=tmp):
                PS.reload()
                self.assertEqual(scanner.COMMON_PORTS, [4444])
                self.assertNotEqual(scanner.COMMON_PORTS, default)
                # names 未覆盖 → PORT_NAMES 走内置
                from scanner import constants as C
                expected = {k: C.port_name(k) for k in PS._FALLBACK_NAMES}
                self.assertEqual(scanner.PORT_NAMES, expected)
        with self.assertRaises(AttributeError):
            scanner.THIS_NAME_DOES_NOT_EXIST

    def test_engine_and_ports_use_shared_loader(self):
        from scanner import engine, ports as sp
        self.assertIs(engine.common_ports, PS.common_ports)
        self.assertIs(sp.common_ports, PS.common_ports)
        from scanner.constants import PROTOCOL_PORTS
        proto = list(PROTOCOL_PORTS.values())
        # 默认表覆盖全部协议端口 → 允许复用完整扫描结果
        self.assertTrue(
            engine._proto_ports_already_scanned(True, None, proto))
        self.assertFalse(
            engine._proto_ports_already_scanned(True, [80], proto))
        self.assertFalse(
            engine._proto_ports_already_scanned(False, None, proto))
        # 外置表生效后，同一个调用点必须跟着变
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                      encoding="utf-8") as f:
                json.dump({"ports": [80]}, f)
            with mock.patch.object(PS, "data_dir", return_value=tmp):
                PS.reload()
                self.assertFalse(
                    engine._proto_ports_already_scanned(True, None, proto))


class ExposureRegressionTest(unittest.TestCase):
    """外置端口映射不得影响 CVE / 暴露面识别口径（§3.2 验收第 5 条）。

    注意 exposure 的识别链（banner / SNMP sysDescr → 产品别名 → CPE）**不读
    端口表**，所以这是一条"边界不变式"测试：外置可以改显示名和扫描目标，
    但摸不到候选 CVE 的口径。将来谁给 exposure 加了端口相关的推断，这里会红。
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()
        PS.reload()

    _LOG4J = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"

    def _snapshot(self):
        from scanner import cve_snapshot as cs
        doc = {
            "schema": cs.SCHEMA,
            "generated_at": "2026-10-01T00:00:00Z",
            "max_age_days": 30,
            "cves": [
                {"cve_id": "CVE-2021-44228", "cpe": [self._LOG4J],
                 "kev": True, "epss": 0.97, "summary": "Log4Shell"},
            ],
        }
        path = os.path.join(self.dir, "cve_snapshot.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(doc, ensure_ascii=False))
        return cs.load_snapshot(
            path, now=cs.parse_timestamp("2026-10-13T00:00:00Z"))

    @staticmethod
    def _results():
        from scanner.models import ScanResult
        a = ScanResult(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01")
        a.service_details = [{"proto": "HTTP", "port": 80,
                              "banner": "Apache Log4j 2.14.1"}]
        b = ScanResult(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:03")
        return [a, b]

    def _hits_repr(self, snapshot):
        from scanner import exposure
        report = exposure.match_results(self._results(), snapshot)
        return [(h.ip, h.product, h.cpe, h.version,
                 [(c.cve_id, c.kev) for c in h.candidates])
                for h in report.hits]

    def test_cve_candidates_identical_across_override(self):
        """完整管线：注入同一快照，覆盖前后 hits 必须**逐条相同**。"""
        snapshot = self._snapshot()
        before = self._hits_repr(snapshot)
        self.assertTrue(before, "样本必须先真的有命中，否则这条回归是空转")
        with open(os.path.join(self.dir, PS.DATA_FILENAME), "w",
                  encoding="utf-8") as f:
            json.dump({"ports": [9999], "names": {"9999": "覆盖后"}}, f)
        with mock.patch.object(PS, "data_dir", return_value=self.dir):
            PS.reload()
            self.assertEqual(self._hits_repr(snapshot), before)

    def test_cpe_lookup_unaffected_by_external_override(self):
        from scanner import exposure
        before = exposure.cpe_for_product("Apache Log4j 2.14.1")
        self.assertIsNotNone(before)
        self.assertEqual(before[2], "2.14.1")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                      encoding="utf-8") as f:
                json.dump({"ports": [9999],
                           "names": {"9999": "覆盖后"}}, f)
            with mock.patch.object(PS, "data_dir", return_value=tmp):
                PS.reload()
                self.assertEqual(exposure.cpe_for_product(
                    "Apache Log4j 2.14.1"), before)
                self.assertIsNone(exposure.cpe_for_product(""))


class SpecBundlingTest(unittest.TestCase):
    """新增资源必须进两个 spec 的 datas，且断言到具体文件（不只目录）。"""

    def _spec_datas_sources(self, spec_rel):
        with open(os.path.join(ROOT, spec_rel), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"datas\s*=\s*\[(.*?)\]", text, re.S)
        self.assertIsNotNone(m, f"{spec_rel} 里找不到 datas=[...]")
        pairs = re.findall(r"\(\s*'([^']+)'\s*,\s*'([^']+)'\s*\)",
                           m.group(1))
        return [src for src, _dst in pairs]

    def test_gui_spec_bundles_port_services_json(self):
        sources = self._spec_datas_sources("IPScanner.spec")
        self.assertIn("port_services.json", sources,
                      f"IPScanner.spec 的 datas 未覆盖 port_services.json：{sources}")

    def test_cli_spec_bundles_port_services_json(self):
        sources = self._spec_datas_sources("IPScanner_cli.spec")
        self.assertIn("port_services.json", sources,
                      f"IPScanner_cli.spec 的 datas 未覆盖 port_services.json：{sources}")


class RestartE2ETest(unittest.TestCase):
    """"重启后生效"用子进程完整模拟：data_dir 指向别处 + 全新解释器。

    这也同时验证 **import 期不读盘**（惰性加载约定）：子进程在两个 import
    之后先断言 ``ps._cache is None``，再发起第一次调用。
    """

    _CHILD = (
        "import json, sys\n"
        "tmp = sys.argv[1]\n"
        "import app_paths\n"
        "app_paths._data_dir_cache = tmp\n"
        "import port_services as ps\n"
        "import scanner.constants as sc\n"
        "assert ps._cache is None, 'import 期就读了盘，违反惰性加载约定'\n"
        "ports = ps.common_ports()\n"
        "names = ps.port_names()\n"
        "assert sc.get_ports_for_level('quick') == ports, "
        "'scanner.constants 未走外置表'\n"
        "assert sc.get_ports_for_level('standard') == list(range(1, 1024)), "
        "'standard 级不该被外置表影响'\n"
        "assert ps.raw_port_name(4444) == '自定义端口'\n"
        "print(json.dumps({'ports': ports, 'names': names,"
        " 'counts': list(ps.counts())}))\n"
    )

    def test_external_file_takes_effect_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, PS.DATA_FILENAME), "w",
                      encoding="utf-8") as f:
                json.dump({"ports": [80, 443, 4444],
                           "names": {"80": "HTTP", "443": "HTTPS",
                                     "4444": "自定义端口"}}, f)
            out = subprocess.run(
                [sys.executable, "-c", self._CHILD, tmp],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(out.returncode, 0,
                             msg=f"子进程失败：{out.stderr}")
            payload = json.loads(out.stdout.strip().splitlines()[-1])
            self.assertEqual(payload["ports"], [80, 443, 4444])
            self.assertEqual(payload["names"],
                             {"80": "HTTP", "443": "HTTPS",
                              "4444": "自定义端口"})
            self.assertEqual(payload["counts"], [3, 3])


if __name__ == "__main__":
    unittest.main()
