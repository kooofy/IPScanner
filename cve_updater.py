# -*- coding: utf-8 -*-
"""CVE 快照**在线更新**（v2.2 §3.1）。

为什么单独一个模块，而不是塞进 `scanner/cve_snapshot.py`
--------------------------------------------------------
`scanner/cve_snapshot.py` 带着一条**可判定的**不变量：**数据不出网**
（不 import `urllib` / `requests` / `socket`）。这条不变量由 AST 测试
（`tests/test_cve_snapshot.py::NoNetworkTest`）+ 子进程差集测试双重守着，
连模块里出现一个 `import urllib` 都会当场红。

所以联网逻辑**不能**写进去。本模块把联网那一半单独承载（位置对齐既有的
`oui_updater.py` / `notifier.py`：**仓库顶层**，不在 `scanner/` 下），
`cve_snapshot.py` 继续零网络。两者的衔接是**注入式 transport**：
本模块只依赖一个 `fetch(url) -> bytes` 可调用对象，默认实现走
`urllib.request`，测试里换成内存桩，**不碰网络**。

四条铁律（逐条对应 `docs/CVE_SNAPSHOT_MODEL.md` §10.3）
--------------------------------------------------------
1. **先验 SHA256 清单，不匹配就拒绝**：下载到**临时目录**，先按
   `scanner.cve_snapshot` 的口径校验摘要；对不上就整份丢弃、**保留旧数据**
   （旧数据比一份来路不明的数据更可信）。
2. **失败只降级、绝不升级**：超时 / 404 / 限流 / 摘要不符 / 磁盘写不动
   —— 一律只 `warning` + 返回 `ok=False`，**永不抛**、**永不让扫描失败**。
   扫描能不能做 CVE 比对只取决于本地快照的 `state`，与"这次下载成没成"无关。
3. **只在用户显式触发时联网**：本模块是**纯函数式**的（没人调就不会跑），
   且**没有任何 import 期副作用**。程序启动路径不 import 本模块 —— 启动
   自动联网会直接把"数据不出网"这条身份边界破掉。
4. **落盘在 `data_dir()`**：与"手动放置"是同一个位置（用户更新版优先），
   所以「在线下载」与「手动放文件」在同一条搜索路径上，
   `cve_snapshot.data_path()` 不需要知道数据是怎么来的。

落盘是**原子**的：先写 `*.tmp` → `os.replace()` 覆盖。这样"下到一半断电"
不会留下一份半截 JSON 把原来好用的数据毁掉（§3.3 的"保留旧数据"要靠它兜底）。

i18n 约定
---------
本模块**不 import i18n**：领域/传输层不放显示文案，`reason` 是**语言无关
的规范值**（见 `REASON_*`），显示文案由调用方（GUI / CLI）走 `tr()`。
"""
import hashlib
import os
import shutil
import tempfile
import urllib.error
import urllib.request

from app_logging import get_logger
from app_paths import data_dir

_log = get_logger(__name__)

#: 网络超时（秒）。快照是几百 KB 的小 JSON，30s 足够；再长只会让被墙的
#: 网络把用户卡在进度条上。
DEFAULT_TIMEOUT = 30

#: 下载配额上限（字节）。防止一个被劫持 / 写错的 URL 拖回来几个 G 把内存
#: 吃满 —— 一边读一边计数，超了就当失败（**不是**先下完再判）。
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024

#: 请求 UA。裸 urllib 的默认 UA 会被部分 CDN/WAF 直接 403。
_USER_AGENT = "IPScanner/1.0 (+offline-cve-snapshot)"

# ── 失败原因规范值（语言无关；调用方据此选文案）──────────────────────
REASON_OK = "ok"                        # 下载 + 校验 + 落盘全部成功
REASON_NO_URL = "no-url"                # 没有配置下载地址（占位符还没填）
REASON_DOWNLOAD_FAILED = "download-failed"  # 网络层失败（超时 / 404 / 限流…）
REASON_TOO_LARGE = "too-large"          # 超过 MAX_DOWNLOAD_BYTES
REASON_CHECKSUM_FAILED = "checksum-failed"  # SHA256 清单不匹配
REASON_INVALID = "invalid"              # 拿回来的不是可用快照（解析/结构）
REASON_WRITE_FAILED = "write-failed"    # 落盘失败（磁盘满 / 权限）
REASON_NO_MANIFEST = "no-manifest"      # 没有清单可校验（默认拒绝，见下）

#: 快照本体的默认文件名（与 `scanner.cve_snapshot.DATA_FILENAME` 一致）。
#: 刻意**不 import** `scanner.cve_snapshot`：本模块要能在运行期与加载器
#: 完全解耦（加载器在 `scanner/`，本模块在顶层），只共享"文件名"这个约定。
#: 🔴 这三个常量必须与加载器**逐字一致** —— `tests/test_cve_updater.py`
#: 的 `FilenameContractTest` 会在不一致时当场红（"约定"不能靠注释维持）。
DATA_FILENAME = "cve_snapshot.json"
SUMS_FILENAME = "cve_snapshot.sha256"
ONLINE_MARK_FILENAME = "cve_snapshot.online"


def _looks_like_placeholder(url: str) -> bool:
    """地址是否是**未填**的占位常量。

    `scanner/cve_snapshot.py` 里的 `DEFAULT_SNAPSHOT_URL` 现在是
    `.../CHANGE-ME/...` —— 用户还没建公开数据仓。不判这一下，用户点"更新"
    只会拿到一个没头没脑的 404（比"还没配置"更难懂）。
    """
    return (not url) or ("CHANGE-ME" in url) or ("<" in url and ">" in url)


def _default_fetch(url: str, timeout: int) -> bytes:
    """默认 transport：`urllib.request` 取回字节。

    **这是本模块唯一发网络请求的地方**。测试一律替换掉它（注入桩），
    所以单测不会碰网 —— 这也是"零网络不变量可测"的关键。
    超过 `MAX_DOWNLOAD_BYTES` 就中断并抛 `ValueError`（不算网络错）。
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        chunks = []
        total = 0
        while True:
            block = resp.read(65536)
            if not block:
                break
            total += len(block)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError("下载内容超过 %d 字节上限"
                                 % MAX_DOWNLOAD_BYTES)
            chunks.append(block)
        return b"".join(chunks)


def _parse_sums(text: str, filename: str):
    """解析 ``<hex>␠␠<文件名>`` 清单 → 该文件名的预期摘要（无则 ``None``）。

    与 `scanner.cve_snapshot.read_sums()` **同口径**（容忍空行 / `#` 注释 /
    单空格 / 行尾 `*`），但这里只关心**一个**文件名，所以更窄：找不到就
    退化成"清单只有一条时按那一条比"（用户手工裁剪过的清单很常见）。
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest = parts[0].lower()
        name = parts[-1].lstrip("*")
        if len(digest) != 64 or any(c not in "0123456789abcdef"
                                    for c in digest):
            continue
        entries.append((os.path.basename(name), digest))
    for name, digest in entries:
        if name == filename:
            return digest
    if len(entries) == 1:
        return entries[0][1]
    return None


def _validate_snapshot_bytes(payload: bytes):
    """把下载回来的字节解析成快照，返回 ``(ok, reason, entry_count)``。

    **不 import `scanner.cve_snapshot`**（保持解耦），只做最小结构检查：
    顶层必须是 JSON 对象、`cves` 是数组。真正的深度校验（CPE 收敛、
    CVE 号形状、逐条跳过）留到运行期加载器 —— 那里已有完整实现，
    这里重复一遍只会多一处会漂的真相。

    这样做的**代价**与**收益**：代价是垃圾内容只要"顶层是对象且 cves 是
    数组"就能过这一关；收益是离线更新层**不复制**解析规则，且
    `cve_snapshot.py` 的零网络不变量逐字节不变。真正拦住垃圾的是
    SHA256 清单（默认必须校验，见 `update_snapshot` 的 `require_checksum`）。
    """
    import json
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, REASON_INVALID, 0
    if not isinstance(doc, dict):
        return False, REASON_INVALID, 0
    cves = doc.get("cves")
    if not isinstance(cves, (list, tuple)) or not cves:
        # 空 `cves` 等于"装了但没得查"（加载器会给 STATE_EMPTY）——
        # 对更新动作而言这就是一次**无效**的更新，不覆盖现有数据。
        return False, REASON_INVALID, 0
    return True, REASON_OK, len(cves)


def update_snapshot(url: str = "", *,
                    fetch=None,
                    target_dir=None,
                    timeout: int = DEFAULT_TIMEOUT,
                    require_checksum: bool = True) -> dict:
    """从 ``url`` 下载快照并**校验通过后**落到 `data_dir()`。

    Args:
        url: 快照 JSON 的地址。空 / 占位 → 直接返回 `no-url`，不发任何请求。
        fetch: 注入的 transport，签名 ``fetch(url, timeout) -> bytes``。
            默认 `None` → 用 `_default_fetch`（真联网）。**测试必须注入**。
        target_dir: 落盘目录（默认 `data_dir()`；测试注入临时目录）。
        timeout: 网络超时秒数。
        require_checksum: 是否**强制**要求有摘要清单。默认 `True` ——
            §10.3 第 1 条要求"取回后先验 SHA256"，而"没有清单可验"等价于
            **没验**，此时拒绝落盘比装一份来路不明的数据更安全。
            置 `False` 只用于联调（本地桩服务器往往不备清单）。

    Returns:
        dict（键固定英文，可直接被 CLI `--json` 化）::

            {
              "ok": bool,
              "reason": str,          # REASON_* 之一
              "path": str,            # 成功时是落盘后的快照路径，否则 ""
              "entry_count": int,     # 成功时是条目数
              "checksum_verified": bool,   # 成功时一律 True
              "bytes": int,           # 实际下载字节数
            }

    🔴 **永不抛异常**：所有失败都收成 `ok=False` + 一个 `reason`。
    调用方（GUI 线程 / CLI）据此给提示，**绝不能**让下载失败连带把扫描搞崩。
    """
    fetch = fetch or _default_fetch
    out_dir = target_dir or data_dir()
    result = {"ok": False, "reason": REASON_OK, "path": "",
              "entry_count": 0, "checksum_verified": False, "bytes": 0}

    if _looks_like_placeholder(url):
        result["reason"] = REASON_NO_URL
        _log.warning("CVE 快照在线更新：未配置下载地址（占位符仍为 %r）", url)
        return result

    sums_url = url.rsplit("/", 1)[0] + "/" + SUMS_FILENAME
    tmp_dir = ""
    try:
        tmp_dir = tempfile.mkdtemp(prefix="ipscanner_cve_")
        tmp_json = os.path.join(tmp_dir, DATA_FILENAME)

        # ── 1. 取快照本体（失败只告警，不抛）──────────────────────────
        try:
            payload = fetch(url, timeout)
        except ValueError as e:                 # 超配额，不算网络错
            result["reason"] = REASON_TOO_LARGE
            _log.warning("CVE 快照在线更新：%s", e)
            return result
        except Exception as e:  # noqa: BLE001 — 网络层什么都可能抛
            result["reason"] = REASON_DOWNLOAD_FAILED
            _log.warning("CVE 快照在线更新失败（网络）：%s", e)
            return result

        if not isinstance(payload, (bytes, bytearray)):
            # 注入桩返回了奇怪类型 —— 当"格式不对"，不要让它在下面炸
            result["reason"] = REASON_INVALID
            _log.warning("CVE 快照在线更新：transport 返回了 %s，期望 bytes",
                         type(payload).__name__)
            return result

        payload = bytes(payload)
        result["bytes"] = len(payload)
        if not payload:
            result["reason"] = REASON_DOWNLOAD_FAILED
            _log.warning("CVE 快照在线更新：取回 0 字节（地址可能返回空）")
            return result
        if len(payload) > MAX_DOWNLOAD_BYTES:
            result["reason"] = REASON_TOO_LARGE
            _log.warning("CVE 快照在线更新：内容 %d 字节，超过上限",
                         len(payload))
            return result

        with open(tmp_json, "wb") as fh:
            fh.write(payload)

        # ── 2. 取摘要清单 + 校验（§10.3 第 1 条）──────────────────────
        expected = None
        try:
            sums_payload = fetch(sums_url, timeout)
            if isinstance(sums_payload, (bytes, bytearray)):
                expected = _parse_sums(
                    bytes(sums_payload).decode("utf-8", errors="replace"),
                    DATA_FILENAME)
        except Exception as e:  # noqa: BLE001 — 清单取不到不是致命错
            _log.debug("CVE 快照在线更新：摘要清单取回失败（%s）", e)

        if expected is None:
            if require_checksum:
                result["reason"] = REASON_NO_MANIFEST
                _log.warning("CVE 快照在线更新：没有可用的 SHA256 清单，"
                             "按策略拒绝落盘（保留现有数据）")
                return result
            _log.warning("CVE 快照在线更新：无摘要清单，已按调用方要求"
                         "放宽校验（联调模式）")
        else:
            actual = hashlib.sha256(payload).hexdigest()
            if actual != expected:
                result["reason"] = REASON_CHECKSUM_FAILED
                _log.warning("CVE 快照在线更新：SHA256 不匹配"
                             "（期望 %s… 实得 %s…），已丢弃并保留现有数据",
                             expected[:12], actual[:12])
                return result
            result["checksum_verified"] = True

        # ── 3. 结构检查 ───────────────────────────────────────────────
        ok, reason, count = _validate_snapshot_bytes(payload)
        if not ok:
            result["reason"] = reason
            _log.warning("CVE 快照在线更新：取回内容不是可用快照，保留现有数据")
            return result

        # ── 4. 原子落盘（同目录 tmp → os.replace）──────────────────────
        try:
            os.makedirs(out_dir, exist_ok=True)
            final_json = os.path.join(out_dir, DATA_FILENAME)
            staged = final_json + ".tmp"
            shutil.copyfile(tmp_json, staged)
            os.replace(staged, final_json)
            # 清单也一并落盘：下次程序启动时 `load_snapshot()` 能就地校验，
            # 否则用户拿到的是一份"下过一次但此后无法自验"的数据。
            if expected is not None:
                sums_text = "%s  %s\n" % (expected, DATA_FILENAME)
                staged_sums = os.path.join(out_dir, SUMS_FILENAME) + ".tmp"
                with open(staged_sums, "w", encoding="utf-8",
                          newline="\n") as fh:
                    fh.write(sums_text)
                os.replace(staged_sums,
                           os.path.join(out_dir, SUMS_FILENAME))
            # 来源标记：让加载器能把这份识别成「在线下载」（v2.2 §3.1 第 4 条）。
            # 内容无关紧要 —— 加载器只查存在性。放在**最后**写：前面任何一步
            # 失败都不会留下一个"声称在线下载、实际没落盘"的标记。
            with open(os.path.join(out_dir, ONLINE_MARK_FILENAME), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write("online\n")
        except OSError as e:
            result["reason"] = REASON_WRITE_FAILED
            _log.warning("CVE 快照在线更新：落盘失败（%s）", e)
            return result

        result.update(ok=True, reason=REASON_OK, path=final_json,
                      entry_count=count)
        _log.info("CVE 快照在线更新成功：%d 条 → %s", count, final_json)
        return result
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
