#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地生成 `cve_snapshot.json`（v2.1 §2.3 路径 B：离线自助工具）。

**这个脚本不是运行时功能**：
- 不进任何 PyInstaller spec 的 `datas`；
- 不被 `scanner/` import；
- 只在**本机手工离线**运行（读你已经下载好的三个上游文件的本地副本）。

**为什么不让它自己去外网抓**：同一份输入在不同网络环境下抓到的内容不同，
产出就不可复现。手工喂本地文件，`generated_at` 与内容严格对应调试才有意义
（模型文档 §9.3）。

输入（全部公开、免费，格式见 `docs/CVE_SNAPSHOT_MODEL.md` §2.1）
--------------------------------------------------------------
* `--nvd-file`  NVD JSON 2.0 feed（`vulnerabilities[].cve.configurations.nodes[].cpeMatch[].criteria`），
                也兼容 1.1 的 `CVE_Items[].configurations.nodes[].cpe_match[].cpe23Uri`；
* `--kev-file`  CISA KEV `known_exploited_vulnerabilities.json`（`vulnerabilities[].cveID`）；
* `--epss-file` FIRST EPSS 每日 CSV（`cve,epss,percentile`，允许 `#` 注释行 / gzip）。

输出
----
* `<out>/cve_snapshot.json` —— 消费端格式（`ipscanner.cve_snapshot/1`）；
* `<out>/cve_snapshot.sha256` 与 `<out>/SHA256SUMS` —— 同一份内容两个名字：
  前者是**运行期加载器认的那个**（`scanner.cve_snapshot.SUMS_FILENAME`），
  后者是发布流程的既有口径。两处都写，避免「装了快照却忘了清单」。
* `--check` 会再用 `scanner.cve_snapshot.load_snapshot()` 回读产出并校验
  摘要 —— **写了没人跑过的脚本等于没写**，CI 的 smoke 就靠这个开关。

用法
----
    python tools/build_cve_snapshot.py \\
        --nvd-file  nvdcve-2.0-2024.json \\
        --kev-file   known_exploited_vulnerabilities.json \\
        --epss-file  epss_scores-current.csv.gz \\
        --out ./cve_data --check
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import sys
from typing import Dict, List, Optional, Set, Tuple

SCHEMA = "ipscanner.cve_snapshot/1"
DEFAULT_MAX_AGE_DAYS = 30
#: 与 `scanner.cve_snapshot.SUMMARY_MAX_CHARS` 同口径（生成时就截好）。
SUMMARY_MAX_CHARS = 200

_EXIT_OK = 0
_EXIT_FAIL = 1


# ── 输入解析 ───────────────────────────────────────────────────────────

def _open_text(path: str) -> str:
    """读文本文件，`.gz` 自动解压（EPSS 是 gzip 的 CSV）。"""
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_nvd(path: str) -> Dict[str, Dict[str, object]]:
    """NVD feed → ``{cve_id: {"cpe": [...], "summary": str}}``。

    只取**厂商/产品级**要用的东西；版本信息**刻意丢掉**（粗粒度匹配的口径，
    见 `docs/CVE_SNAPSHOT_MODEL.md` §4）。
    """
    doc = json.loads(_open_text(path))
    out: Dict[str, Dict[str, object]] = {}
    if isinstance(doc, dict) and isinstance(doc.get("vulnerabilities"), list):
        for item in doc["vulnerabilities"]:
            cve = (item or {}).get("cve") or {}
            cid = str(cve.get("id") or "").strip().upper()
            if not cid:
                continue
            slot = out.setdefault(cid, {"cpe": [], "summary": ""})
            slot["cpe"] = list(slot["cpe"]) + _nvd2_criteria(cve)
            slot["summary"] = slot["summary"] or _nvd2_summary(cve)
        return out
    if isinstance(doc, dict) and isinstance(doc.get("CVE_Items"), list):
        for item in doc["CVE_Items"]:
            cve = (item or {}).get("cve") or {}
            meta = cve.get("CVE_data_meta") or {}
            cid = str(meta.get("ID") or "").strip().upper()
            if not cid:
                continue
            slot = out.setdefault(cid, {"cpe": [], "summary": ""})
            slot["cpe"] = list(slot["cpe"]) + _nvd1_criteria(item)
            slot["summary"] = slot["summary"] or _nvd1_summary(cve)
        return out
    raise ValueError("无法识别的 NVD feed 结构（既无 vulnerabilities 也无 CVE_Items）")


def _nvd2_summary(cve: dict) -> str:
    """NVD 2.0 的英文描述（`descriptions[lang=en].value`）。"""
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if str((item or {}).get("lang") or "").lower().startswith("en"):
            return str((item or {}).get("value") or "").strip()
    return ""


def _nvd1_summary(cve: dict) -> str:
    """NVD 1.1 的英文描述（`description.description_data[lang=en].value`）。"""
    block = cve.get("description") or {}
    rows = block.get("description_data") if isinstance(block, dict) else None
    if not isinstance(rows, list):
        return ""
    for item in rows:
        if str((item or {}).get("lang") or "").lower().startswith("en"):
            return str((item or {}).get("value") or "").strip()
    return ""


def _nvd2_criteria(cve: dict) -> List[str]:
    out: List[str] = []
    configs = cve.get("configurations")
    if not isinstance(configs, list):
        return out
    for cfg in configs:
        for node in (cfg or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if not (match or {}).get("vulnerable", True):
                    continue          # 非 vulnerable 的 cpeMatch 是"未受影响"的排除项
                crit = str(match.get("criteria") or "").strip()
                if crit:
                    out.append(crit)
    return out


def _nvd1_criteria(item: dict) -> List[str]:
    out: List[str] = []
    configs = (item or {}).get("configurations")
    if not isinstance(configs, list):
        return out
    for cfg in configs:
        for node in (cfg or {}).get("nodes") or []:
            for match in (node or {}).get("cpe_match") or []:
                if not (match or {}).get("vulnerable", True):
                    continue
                crit = str(match.get("cpe23Uri") or "").strip()
                if crit:
                    out.append(crit)
    return out


def load_kev(path: str) -> Set[str]:
    """CISA KEV → ``{cve_id}``。文件里每个 `cveID` 都算「已被实际利用」。"""
    doc = json.loads(_open_text(path))
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else doc
    out: Set[str] = set()
    if isinstance(items, list):
        for item in items:
            cid = str((item or {}).get("cveID") or "").strip().upper()
            if cid:
                out.add(cid)
    return out


def load_epss(path: str) -> Dict[str, Tuple[float, float]]:
    """EPSS 每日 CSV → ``{cve_id: (score, percentile)}``。

    容忍 `#` 开头的模型版本注释行、空行、字段顺序之外的列。
    """
    out: Dict[str, Tuple[float, float]] = {}
    header: Optional[List[str]] = None
    for line in _open_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if header is None:
            if parts and parts[0].lower() == "cve":
                header = [p.lower() for p in parts]
                continue
            header = ["cve", "epss", "percentile"]   # 没表头就按约定列序
        try:
            idx_cve = header.index("cve")
            idx_score = header.index("epss") if "epss" in header else 1
            idx_pct = (header.index("percentile") if "percentile" in header
                       else 2)
        except ValueError:
            raise ValueError("EPSS CSV 表头缺少必要列（cve/epss/percentile）")
        if len(parts) <= max(idx_cve, idx_score, idx_pct):
            continue
        cid = parts[idx_cve].upper()
        try:
            score = float(parts[idx_score])
            pct = float(parts[idx_pct])
        except ValueError:
            continue
        if 0.0 <= score <= 1.0 and 0.0 <= pct <= 1.0:
            out[cid] = (score, pct)
    return out


# ── 粗粒度收敛（与 `scanner.cve_snapshot.coarsen_cpe` 同口径） ───────────
# 🔴 刻意在脚本里**复制一份**而不是 import：生成端要能独立跑（不依赖源码树
# 结构），而 `--check` 会在写完后用加载器回读，两边口径不一致当场就会红。

_CPE_PART_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789._-")


def coarsen(criteria: str) -> str:
    """``cpe:2.3:a:apache:log4j:2.14.1:…`` → ``cpe:2.3:a:apache:log4j:*…``。"""
    s = str(criteria or "").strip().lower()
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")
    elif s.startswith("cpe:/"):
        # CPE 2.2 URI 形式（老 NVD 1.1 feed）：剥掉 `cpe:/` 后补上部分号。
        parts = ["cpe", "2.3"] + s[len("cpe:/"):].split(":")
    else:
        return ""
    if len(parts) < 6:
        return ""
    part, vendor, product = parts[2], parts[3], parts[4]
    if part not in ("a", "o", "h"):
        return ""
    for token in (vendor, product):
        if not token or len(token) > 64:
            return ""
        if any(ch not in _CPE_PART_CHARS for ch in token):
            return ""
    return "cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*" % (part, vendor, product)


def _clean_summary(text: str) -> str:
    s = " ".join(str(text or "").split())
    return s[:SUMMARY_MAX_CHARS]


def build_document(nvd: Dict[str, Dict[str, object]],
                   kev: Set[str],
                   epss: Dict[str, Tuple[float, float]],
                   *, max_age_days: int = DEFAULT_MAX_AGE_DAYS,
                   generated_at: str = "",
                   max_entries: int = 0,
                   source_stamps: Optional[Dict[str, str]] = None
                   ) -> Dict[str, object]:
    """三个源的合流 → 快照文档（§4 格式）。

    * `kev` / `epss` 缺失 → **写 `null`**，不写 0/false：消费端必须能区分
      「无该信号」和「查了、是假的」（模型文档 §4 注）。
    * 一条 CVE 的 CPE 全部不可用时**跳过**（匹配不上，留着只是噪声）。
    """
    rows: List[Dict[str, object]] = []
    skipped = 0
    for cid in sorted(nvd):
        slot = nvd[cid] or {}
        cpes: List[str] = []
        for raw in slot.get("cpe") or []:            # type: ignore[union-attr]
            coarse = coarsen(str(raw))
            if coarse and coarse not in cpes:
                cpes.append(coarse)
        if not cpes:
            skipped += 1
            continue
        scored = epss.get(cid)
        rows.append({
            "cve_id": cid,
            "cpe": cpes,
            "kev": True if cid in kev else None,
            "epss": scored[0] if scored else None,
            "epss_percentile": scored[1] if scored else None,
            "summary": _clean_summary(str(slot.get("summary") or "")),
        })
    if max_entries and len(rows) > max_entries:
        # 截断时**优先保留 KEV + EPSS 高的**：裁剪不能把最该看的裁掉。
        rows.sort(key=lambda r: (
            0 if r["kev"] else 1,
            0 if r["epss"] is not None else 1,
            -(r["epss"] or 0.0),
            str(r["cve_id"]),
        ))
        rows = rows[:max_entries]
        rows.sort(key=lambda r: str(r["cve_id"]))
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "max_age_days": int(max_age_days),
        "sources": dict(source_stamps or {}),
        "cves": rows,
        "_skipped_no_cpe": skipped,
    }


# ── 输出 / 自校验 ──────────────────────────────────────────────────────

def write_output(doc: Dict[str, object], out_dir: str) -> Dict[str, str]:
    """写 `cve_snapshot.json` + 两份 SHA256 清单，返回各文件路径。"""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "cve_snapshot.json")
    payload = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    with io.open(json_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(payload)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    line = "%s  %s\n" % (digest, "cve_snapshot.json")
    written = {"json": json_path}
    for name in ("cve_snapshot.sha256", "SHA256SUMS"):
        path = os.path.join(out_dir, name)
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
        written[name] = path
    return written


def check_output(out_dir: str) -> Tuple[bool, str]:
    """回读产出：能不能被运行期加载器接受、摘要是否对得上。

    🔴 CI 的 smoke 就靠它 —— 生成格式漂了这里当场红，而不是等用户在
    自己机器上装上一份谁也查不动的快照。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    if root not in sys.path:
        sys.path.insert(0, root)
    # 刻意懒加载：生成路径不依赖源码树结构，只有 --check 才 import 运行期加载器
    from scanner import cve_snapshot as cs

    json_path = os.path.join(out_dir, "cve_snapshot.json")
    snap = cs.load_snapshot(json_path)
    if snap.state == cs.STATE_CORRUPT:
        return False, "产出被运行期加载器拒绝（%s）" % snap.path
    if not snap.entries:
        return False, "产出没有任何可用条目（state=%s）" % snap.state
    if snap.checksum_verified is not True:
        return False, "产出未能通过 SHA256 自校验（verified=%r）" % (
            snap.checksum_verified,)
    return True, "条目 %d，state=%s" % (len(snap.entries), snap.state)


# ── CLI ────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="build_cve_snapshot.py",
        description="离线生成 ipscanner 的 CVE 快照（不进运行期、不联网）")
    ap.add_argument("--nvd-file", required=True, help="NVD JSON feed 本地副本")
    ap.add_argument("--kev-file", default="",
                    help="CISA KEV known_exploited_vulnerabilities.json")
    ap.add_argument("--epss-file", default="",
                    help="FIRST EPSS 每日 CSV（可 .gz）")
    ap.add_argument("--out", default="./cve_data", help="输出目录（默认 ./cve_data）")
    ap.add_argument("--max-entries", type=int, default=0,
                    help="最多保留多少条（0=不限；超限时优先保留 KEV/高 EPSS）")
    ap.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS,
                    help="写进快照的新鲜度上限（默认 %d）" % DEFAULT_MAX_AGE_DAYS)
    ap.add_argument("--generated-at", default="",
                    help="快照生成时间 ISO 8601 UTC（默认取今天；刻意可覆写以便复现）")
    ap.add_argument("--check", action="store_true",
                    help="写完后用运行期加载器回读自校验")
    ap.add_argument("--quiet", action="store_true", help="只输出错误")
    return ap


def _force_utf8_stdio() -> None:
    """把 stdout / stderr 切到 UTF-8（与 `cli._force_utf8_stdio()` 同一理由）。

    Windows 上 stdout 被重定向到管道时（CI、``> out.json``、被 subprocess
    捕获），Python 用**系统 ANSI 代码页**编码且错误处理器是 ``strict`` ——
    本脚本的输出全是中文，一写就 ``UnicodeEncodeError``、退出码 1。
    CI 上实测过：`quality-cve-build` job 与 8 个 `test_cve_snapshot_build`
    用例就是这样红的（本机控制台是 UTF-8 所以本地全绿，**只在 CI 复现**）。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # 被替身替换（测试）或不支持改编码的流：跳过即可。
            continue


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    args = _build_parser().parse_args(argv)

    def _say(msg: str) -> None:
        if not args.quiet:
            sys.stdout.write(msg + "\n")

    import datetime as _dt

    generated_at = args.generated_at or _dt.datetime.now(
        _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        nvd = load_nvd(args.nvd_file)
        kev = load_kev(args.kev_file) if args.kev_file else set()
        epss = load_epss(args.epss_file) if args.epss_file else {}
    except (OSError, ValueError) as exc:
        sys.stderr.write("读输入失败：%s\n" % exc)
        return _EXIT_FAIL

    stamps: Dict[str, str] = {}
    for key, path in (("nvd", args.nvd_file), ("kev", args.kev_file),
                      ("epss", args.epss_file)):
        if not path:
            continue
        mtime = os.path.getmtime(path)
        stamps[key] = _dt.datetime.fromtimestamp(mtime, _dt.timezone.utc).strftime(
            "%Y-%m-%d")

    doc = build_document(nvd, kev, epss, max_age_days=args.max_age_days,
                         generated_at=generated_at, max_entries=args.max_entries,
                         source_stamps=stamps)
    skipped = doc.pop("_skipped_no_cpe", 0)
    total = len(doc["cves"])                                      # type: ignore[arg-type]
    if not total:
        sys.stderr.write("输入里没有任何带 CPE 的 CVE，放弃写出空快照\n")
        return _EXIT_FAIL

    written = write_output(doc, args.out)
    _say("已写出 %s（%d 条，KEV %d，EPSS 有分 %d）"
         % (written["json"], total,
            sum(1 for r in doc["cves"] if r["kev"]),   # type: ignore[union-attr]
            sum(1 for r in doc["cves"] if r["epss"] is not None)))  # type: ignore[union-attr]
    if skipped:
        _say("跳过 %d 条（CPE 全部不可用）" % skipped)
    _say("摘要清单：%s / %s" % (written["cve_snapshot.sha256"],
                                written["SHA256SUMS"]))

    if args.check:
        ok, detail = check_output(args.out)
        if not ok:
            sys.stderr.write("自校验失败：%s\n" % detail)
            return _EXIT_FAIL
        _say("自校验通过：%s" % detail)
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
