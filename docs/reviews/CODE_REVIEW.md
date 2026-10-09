# IPScanner 代码评审与改进建议

> ## 状态：已关闭 · 2026-10-09 · 关闭版本 v1.7.4
>
> 本文档的评审意见已处理完毕，此后**仅作历史记录，不再更新**。
> 发现新问题请另开文档，不要在本文件里追加条目。
>
> | 项 | 值 |
> |---|---|
> | 评审对象 | `kooofy/IPScanner` @ `f15341a`（v1.6.0） |
> | 关闭版本 | v1.7.4 |
> | 落地情况 | 12 项 → **8 项已落地**，4 项明确不做 / 待办（见下） |
> | 落地位置与验证 | `README.md`（本目录） |
>
> **未落地的 4 项（已确认，不要再当"遗漏"重提）**
>
> | 编号 | 事项 | 现状 |
> |---|---|---|
> | P1-4 | `ui_dialogs.py` 拆分（评审时 1747 行） | **未做**；已长到 1898 行，列为下一轮结构改造目标 |
> | P2-3 | 插件 / Fetcher 机制 | **未做**；仍无 `plugins/` 目录 |
> | P2-4 | macOS / Linux CI | **未做**；`.github/workflows/ci.yml` 仍只有 `windows-latest` |
> | P2-5 | `oui.db` 入 Git LFS | **未做**；`.gitattributes` 无 lfs 条目 |
>
> 已落地的 8 项：P0-1 / P0-2 / P0-3 / P1-1 / P1-2 / P1-3 / P2-1 / P2-2，逐项证据见
> `README.md`（本目录）的「CODE_REVIEW.md 落地对照」表。

> 评审对象：`kooofy/IPScanner` @ `f15341a`（main 分支，v1.6.0）
> 评审方式：通读 15.5k 行源码 + 6.6k 行测试，实际执行测试套件与关键代码路径复现问题
> 评审日期：2026-10-06

---

## 0. 评审范围与方法

| 项目 | 说明 |
| --- | --- |
| 源码规模 | 15,529 行 Python（不含测试） |
| 测试规模 | 6,605 行 / 534 个测试方法 |
| 实测基线 | 无 PyQt5 环境下跑 `unittest discover`：474 用例中 443 通过，31 个 error **全部**是 `ModuleNotFoundError: No module named 'PyQt5'`，无真实失败 |
| 复现验证 | 下列 P0 问题均通过直接执行代码复现，非静态推测 |

**结论先行**：这是一个工程质量**显著高于同类开源个人项目**的代码库 —— 注释密度、测试覆盖、i18n 纪律、安全防护（凭据加密 / 命令注入白名单 / argv 防泄露）都做到了商业软件水准。它的短板不在"写得糙"，而在**性能架构的天花板**和**几处跨模块状态管理的隐性缺陷**。

---

## 1. 项目画像

**定位**：Windows 内网运维巡检工具 —— 局域网存活发现 + 资产识别 + 台账闭环。
**形态**：PyQt5 GUI + 无头 CLI，共用同一套 `scanner/` 引擎。
**架构**：

```
main_window.py (MainWindow)
  ├─ TreeMixin / ScanMixin / ExportMixin / HistoryMixin
  ├─ LibraryMixin / NetworkToolMixin / OuiMixin
  └─ ui_threads.py (QThread 后台) ──→ scanner/ (纯 Python，零 Qt 依赖)
                                        ├─ engine.py  三阶段流水线编排
                                        ├─ ping/ports/dns/netbios/wmi
                                        ├─ snmp + snmp_v3 + aes(纯标准库)
                                        └─ classify/osfp 指纹推断
```

**分层是干净的**：`scanner/` 完全不依赖 PyQt，可被 CLI 与单测独立驱动 —— 这是它敢做无头模式、敢写 534 个测试的结构基础。`ui_logic.py` 把业务逻辑从 Qt 里剥出来也是正确的一步。

---

## 2. 与同类产品对比

| 维度 | **IPScanner** | Advanced IP Scanner | Angry IP Scanner | Nmap/Zenmap | SoftPerfect NetScan | Fing |
| --- | --- | --- | --- | --- | --- | --- |
| 平台 | Windows 为主 | Windows | 跨平台(Java) | 跨平台 | Windows | 移动/桌面 |
| 开源 | ✅ GPL-3.0 | ❌ 闭源免费 | ✅ GPL | ✅ | ❌ 商业 | ❌ SaaS |
| 中文界面 | ✅ 原生双语 | ⚠️ 有中文 | ⚠️ 部分 | ❌ | ❌ | ⚠️ |
| 发现速度 | 中（子进程 ping） | **极快**（原生 ICMP） | 快 | 快 | 快 | 中 |
| IPv6 | ❌（但会被静默接受，见 P0-1） | ❌ | ✅ | ✅ | ✅ | ✅ |
| 端口扫描 | ✅ 三档 + connect/syn/udp | ✅ 简单 | ✅ 任意列表 | ✅✅ 事实标准 | ✅ | ⚠️ 弱 |
| 服务版本指纹 | ⚠️ 4 协议读 banner | ❌ | ⚠️ 插件 | ✅✅ nmap-service-probes | ⚠️ | ⚠️ |
| OS 指纹 | ⚠️ TTL + 简易 TCP 栈 | ❌ | ❌ | ✅✅ | ❌ | ❌ |
| 脚本/插件引擎 | ❌ | ❌ | ✅ Fetcher 插件 | ✅✅ NSE 600+ | ❌ | ❌ |
| 凭据化深度识别 | ✅✅ **WMI(DCOM+WinRM) + SNMPv3** | ❌ | ❌ | ⚠️ 需自写脚本 | ✅ WMI/SNMP | ❌ |
| 凭据安全存储 | ✅✅ **DPAPI + 仅环境变量传参** | — | — | ⚠️ | ⚠️ | — |
| 资产台账 | ✅✅ **Excel 台账匹配** | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| 历史快照/变更 diff | ✅✅ SQLite 快照 + 变更检测 | ❌ | ❌ | ❌ | ⚠️ | ⚠️ 云端 |
| IP 冲突检测 | ✅ 分级 | ⚠️ 提示 | ❌ | ❌ | ❌ | ⚠️ |
| 拓扑发现 | ✅ CDP/LLDP + SNMP | ⚠️ 树状 | ❌ | ⚠️ 需脚本 | ⚠️ | ⚠️ |
| 审计日志 | ✅ 分类可检索 | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| 无头 CLI 自动化 | ✅✅ **退出码语义固定 + 稳定 JSON** | ⚠️ 弱 | ⚠️ 弱 | ✅✅ | ⚠️ | ❌ |
| 定时/告警 | ❌（靠外部计划任务） | ❌ | ❌ | ⚠️ 需自建 | ✅ 定时扫描 | ✅ 推送告警 |
| 单测覆盖 | ✅✅ **534 个用例** | — | ⚠️ | ✅ | — | — |

**一句话定位**：`Advanced IP Scanner 的交互体验 × Nmap 的部分深度 × 商业网管软件的资产台账闭环`，但**速度是它唯一的明显代差**。

---

## 3. 本项目的差异化特色（值得保留和强化的护城河）

### 3.1 资产台账闭环 —— 同类开源工具无人做到

这是最被低估的优势。竞品几乎都停在"扫出来一张表"，而本项目做到了完整闭环：

```
扫描 → 历史快照(SQLite) → 变更 diff → IP 冲突分级 → 子网利用率
     ↘ Excel 台账匹配(位置/使用人/备注) → 拓扑图 → 审计日志
```

`change_detector.py` / `conflict_detector.py` / `history_store.py` / `excel_handler.py` 这套组合，对标的是商业网管软件的能力。**这是应该继续加码的方向，不是砍掉的方向。**

### 3.2 凭据安全的工程严谨度 —— 罕见

- `scanner/cred_store.py`：WMI/SNMPv3 口令经 **DPAPI** 加密落盘，且**只通过子进程环境变量传递**，绝不出现在 argv（`README.md:172-190` 专门解释了为什么 —— argv 会出现在 `ps` / 任务管理器里）。
- `network_tool_mixin.py:29` `validate_target()`：白名单字符集校验，从根上消除 `cmd /k` 命令注入。
- CLI 的 SNMPv3 口令**只从环境变量读**，没有 `--password` 选项。

这种"先想清楚攻击面再写功能"的取向，在个人项目里极其少见。

### 3.3 SNMPv3 USM + 纯标准库 AES —— 硬核且零体积代价

`scanner/aes.py` 自研 AES-128-CFB128，`scanner/snmp_v3.py` 728 行实现 USM 认证（HMAC-MD5-96 / HMAC-SHA-96）与加密。**不引入任何第三方密码学依赖**，打包体积零增加，还刻意不支持已废弃的 DES 而非静默降级成明文（`README.md:358-360`）。这个取舍非常专业。

### 3.4 三阶段流水线 + 多路发现

`engine.py` 把 ping / enrich / ARP / mDNS 重叠执行，扫描耗时从 `ping + enrich` 压到 `max(ping, enrich)`。配合：
- **ARP 主动探测**（Windows `SendARP`，零管理员）发现禁 Ping 主机；
- **mDNS 组播**补发现不响应 ICMP/ARP 的 IoT / 打印机 / NAS；
- **RTT 自适应超时**（`engine.py:61-71`，用 perf_counter 而非 monotonic —— 注释里解释了 Windows 上 `monotonic` 在 ≤3.12 只有 15.6ms 分辨率）。

### 3.5 工程纪律（这是最"不像个人项目"的部分）

| 实践 | 证据 |
| --- | --- |
| 版本号单一来源 + 强制同步测试 | `version.py` + `tests/test_scaffolding.py::VersionSyncTest` |
| 规模保护防内存爆炸 | `range.py:20-25` `MAX_IPS_PER_RANGE`，注释解释了 `0.0.0.0/0` 会 append 出 42.9 亿字符串 |
| i18n 语言无关存储 | `constants.py:380-385` PEP 562 惰性翻译，禁止 `tr()` 结果入库 |
| ruff 只开正确性规则 | `pyproject.toml:63-74`，注释记录了曾靠 `F` 规则发现 `QGraphicsRectItem` 未导入的崩溃 |
| CI 四版本矩阵 + 产物完整性断言 | `ci.yml:100-109` 断言到 `_internal/assets/styles/light.qss` 具体文件 |
| 打包模式权衡有实测数据 | `README.md:292-307`，onedir vs onefile 的 EDR 误报分析 |

**注释里写"为什么"而不是"是什么"** —— 这个习惯贯穿全库，是这份代码最大的资产。

---

## 4. 修改意见

### P0 — 正确性缺陷（建议立即修，均已实测复现）

#### P0-1 `_syn_failed` / `_raw_cap_cache` 跨模块状态根本没共享

**这是本次评审发现的最严重问题。**

`scanner/ports.py:13` 用 `from .constants import _syn_failed` 引入，随后在 `ports.py:267-268` 写：

```python
global _syn_failed
_syn_failed = True
```

`global` 只作用于**本模块**命名空间。`from X import y` 之后，`y` 只是 `ports` 自己的一个名字，**重新赋值不会写回 `constants`**。实测结果：

```
设置 ports._syn_failed=True 后:
  ports._syn_failed     = True
  constants._syn_failed = False      ← 没同步
  engine._syn_failed    = <未定义>    ← 第三个独立变量
```

**由此产生三个连锁后果：**

1. **`engine.py:535-538` 的回退告警是死代码。** 它读的是 `engine._syn_failed`（该名字直到 `engine.py:189` 执行 `global _syn_failed` 才在 engine 模块被创建），而 `ports` 永远不会去写它 → 这个 `if` 恒为 False，用户**永远看不到**"SYN 发送被系统拒绝，已回退"的提示。

2. **`engine.py:188-189` 的"重置"是空操作。** 注释写着「重新尝试发送（之前若失败则重置，便于本次重新验证）」，但它重置的是 `engine._syn_failed`，而真正被 `ports` 读取的 `ports._syn_failed` **永不复位**。

3. **`ports._syn_failed` 会永久锁死。** 用户在**非管理员**下跑一次 SYN 扫描 → `ports._syn_failed` 置 True 且再不复位 → 之后即使提权到管理员、或换成 `udp` 模式，`ports.py:268/342` 都会直接短路回退，**静默地用 TCP 全连接**，且不给任何提示。

**修复建议**：把这类跨模块可变状态收敛到一个持有者。最小改动：

```python
# constants.py
import threading
_raw_cap_cache = None
_syn_failed = threading.Event()      # 用 Event 替代裸 bool

# ports.py —— 不要 from ... import 可变状态，改为 import 模块后属性访问
from . import constants as _C

def raw_capability():
    if _C._raw_cap_cache is not None:
        return _C._raw_cap_cache
    ...
    _C._raw_cap_cache = (True, "")

# engine.py
_C._syn_failed.clear()               # 每次扫描前复位
...
if effective_tcp_mode in ("syn", "udp") and _C._syn_failed.is_set():
    self.warnings.append(...)
```

顺带把 `_syn_failed` 换成 `threading.Event`，同时解决多线程读写裸 bool 的竞态。

**工作量**：小（半天内），但影响用户可感知的提示缺失 + 功能静默降级。

---

#### P0-2 IPv6 地址被静默接受，但全链路不支持

`scanner/range.py:53-56` 的 CIDR 分支**不校验 IP 版本**：

```python
if "/" in s:
    try:
        return ("cidr", ipaddress.ip_network(s, strict=False))   # IPv6 也能过
```

实测：

```
is_valid_range('2001:db8::/120')  → True
parse_ip_range('2001:db8::/126')  → ['2001:db8::', '2001:db8::1', '2001:db8::2', '2001:db8::3']
```

而 `README.md:354` 明确写着「只支持 IPv4；IPv6 网段无法扫描」。**文档与实现不一致**，用户输入 IPv6 后会得到一张**全部"离线"的假结果表**：

- `get_mac_for_ip()` 走 `arp -a <ipv6>` → 失败，MAC 全空；
- `SendARP` 是 IPv4-only；
- NetBIOS / WMI / SNMP 全部假设 IPv4；
- `engine.py:475` 的 `ipaddress.ip_address(ip) in net` 会因版本不匹配抛 `TypeError`，被 `except Exception` 吞掉，只留一条 debug。

**修复建议**（二选一，别做半吊子）：

- **短期（推荐）**：`_parse_spec` 里对所有分支加版本闸门，并在 UI/CLI 给出明确错误：
  ```python
  spec = _parse_spec(s)
  if spec is not None and _spec_version(spec) != 4:
      return None      # 或抛专用异常，让上层提示「暂不支持 IPv6」
  ```
  同时 `validate_target()` 里对 IPv6 的处理要保持一致（工具跳转目前是允许 IPv6 字面量的，见 `network_tool_mixin.py:46-49`，这块是对的）。

- **长期**：真做 IPv6 —— 需要 range 解析、原生 ICMPv6、邻居发现（NDP 替代 ARP）、mDNS（本来就是 IPv6 优先的）全链路支持，工作量不小。

**工作量**：短期小，长期大。

---

#### P0-3 文档与实现不一致（小但会误导使用者）

`requirements-dev.txt:9`：

```
# 发布构建用 pyinstaller IPScanner_1.6.0.spec（GUI）与 IPScanner_cli.spec（无头）
```

但仓库里根本没有 `IPScanner_1.6.0.spec` —— 实际文件是 `IPScanner.spec`。这行注释是"spec 改名"重构时漏改的，而 `README.md:286-287` 和 `IPScanner.spec:10` 都明确说明**spec 名已固定、产物名才带版本号**。按这行注释敲命令会直接报文件不存在。

**修复**：改成 `pyinstaller IPScanner.spec`。

**工作量**：1 分钟。

---

### P1 — 性能与架构

#### P1-1 线程池按设备、按调用反复新建，最坏 3000+ 线程

- `scanner/ports.py:143`：**每次 `scan_ports()` 调用**新建 `ThreadPoolExecutor(max_workers=min(64, len(ports)))`
- `scanner/engine.py:423-425`：enrich 池 50 个 worker
- `scanner/engine.py:247-249`：NetBIOS 池另开 50 个

最坏组合（standard 档 1023 端口）：50 个 enrich worker × 各自 64 线程的端口池 = **约 3200 个线程**，再加 ping 池 100 + NetBIOS 池 50。Windows 每线程默认保留 1MB 栈，GIL 争抢也会显著拖慢。

**建议**：
1. 端口扫描改用**全局单例有界池**，或用一个 `threading.Semaphore` 统一限制"同时在飞的 socket 数"（这才是真正的资源约束，线程数只是表象）。
2. `bounded_pool.run_bounded()` 已经写好了有界并发 + 失败隔离 + 逐台回调的语义（`bounded_pool.py`），**完全可以复用到端口扫描层**，不必另造轮子。

**工作量**：中。

---

#### P1-2 存活探测走子进程，这是与竞品最大的速度代差

`scanner/ping.py:28-34`：每个 IP 起一个 `ping` 子进程。

- `/24` = 254 次进程创建；`/16`（当前上限 65536）= **65536 次**。
- Windows 进程创建约 10~20ms，加上子进程自身的 1s 超时，这就是"扫描慢"的根因。
- Advanced IP Scanner / nmap / arp-scan 全部用原生 ICMP 或自建 TCP 栈。

**建议**：Windows 上改用 `iphlpapi.dll` 的 `IcmpSendEcho`（ctypes，**零依赖、零管理员权限**，和已有的 `SendARP` 调用风格完全一致 —— `ping.py:140-166` 已经示范了这套 ctypes 写法），失败再回退子进程；Linux/macOS 用 `SOCK_RAW + IPPROTO_ICMP`（需 root，无权限时回退）。

预期效果：`/24` 扫描从数秒降到亚秒级，这是**用户体感提升最大的一项改动**。

**工作量**：中（约 1~2 天，含测试）。

---

#### P1-3 `NetworkScanner.scan()` 单函数约 400 行

`engine.py:147-544`：一个函数里塞了范围校验、权限探测、三阶段流水线、四个嵌套闭包、两处线程池、mDNS 合并、告警聚合。可测试性和可扩展性都到了临界点 —— **想加第四种发现方式（比如 LLDP 无 SNMP 发现、或者 WSD），必须动这个核心函数**。

**建议**：把三个 Phase 抽成独立的"发现策略"对象，`scan()` 只负责编排：

```python
class DiscoveryPhase(Protocol):
    name: str
    def run(self, ctx: ScanContext) -> None: ...

PHASES = [PingPhase(), ArpPhase(), MdnsPhase()]   # 新增方式 = 新增一个类，不动编排
```

`_merge_mdns` 已经是这个方向的第一步（为了可单测而抽出），继续推进即可。

**工作量**：中，但收益是长期的。

---

#### P1-4 `ui_dialogs.py` 1747 行 / `main_window.py` 1030 行

`ui_dialogs.py` 已经是全库最大的文件，装了拓扑视图、凭据对话框、历史查询、设置、SNMPv3 配置等**互不相关**的对话框。

**建议**：按用途拆成 `ui_dialogs/` 包（`topology.py` / `credentials.py` / `history.py` / `settings.py`），保留 `ui_dialogs/__init__.py` 做 re-export 以免打断现有 import。

**工作量**：中（纯搬运，风险低）。

---

### P2 — 能力增强（按"性价比 × 与定位的契合度"排序）

#### P2-1 ⭐ 定时扫描 + 变更告警 —— 最高性价比

`change_detector.py` 已经能算出"新增/消失/属性变更"，`history_store.py` 已经能存快照，CLI 已经有 `diff --fail-on-change` 和退出码 2 —— **所有零件都在，只差调度和通知**。

补上之后，产品定位就从"一次性扫描工具"升级为"**资产监控**"，这是竞品（除 Fing 外）都没做好的区间。

**建议**：
- GUI 里加"计划任务"面板（或直接生成 Windows 计划任务的 XML / `schtasks` 命令，让用户一键注册）；
- 通知渠道：Webhook（通用）+ 企业微信/钉钉机器人（国内运维刚需）+ 邮件；
- 触发条件复用 `detect_changes()` 的输出。

**工作量**：中，但产品价值最高。

#### P2-2 轻量服务版本指纹库

现在只有 HTTP/HTTPS/FTP/SSH 四个协议读 banner（`engine.py:296-304`），而竞品 nmap 有上万条规则。不必对标 nmap，但可以：
- 把 banner 正则抽成**可更新的外部数据文件**（和 `oui.db` 一样的模式，支持在线更新）；
- 覆盖 RDP / SMB / Telnet / VNC / Redis / MySQL / PostgreSQL / MongoDB 等内网高频服务。

**工作量**：中。收益是"识别准确率"这个核心指标。

#### P2-3 插件 / Fetcher 扩展机制

Angry IP Scanner 的护城河就是 Java Fetcher 插件。本项目 `scanner/` 分层干净，天然适合：

```python
# 约定：plugins/*.py 里暴露 fetch(result) -> dict
```

从用户目录加载第三方识别逻辑，社区可以自己补指纹。

**工作量**：中大。

#### P2-4 CI 覆盖 macOS / Linux

`README.md:361` 自己承认了：「CI 只在 Windows 上跑；macOS / Linux 未经自动化覆盖」。而代码里 `ping.py` / `ports.py` / `network_tool_mixin.py` 到处是 `platform.system()` 分支 —— 这些分支**从未被自动化验证过**。

**建议**：`ci.yml` 的 test job 加 `ubuntu-latest` / `macos-latest` 矩阵，GUI 测试用 `QT_QPA_PLATFORM=offscreen`（现在已经是这个配置，迁移成本极低）。

**工作量**：小。

#### P2-5 `oui.db`（2MB）入库

每次 clone 都要拉 2MB 二进制。可迁 Git LFS，或首次运行时下载。**优先级低**，属洁癖级优化。

---

### 不建议做的事（避免偏离定位）

| 想法 | 为什么不建议 |
| --- | --- |
| 做漏洞扫描（对标 Nessus/OpenVAS） | 需要 CVE 库 + 持续跟踪 + 合规资质，是另一个产品，会稀释"内网巡检"定位 |
| 做 Web 大平台 / 多租户 | 除非确有跨机集中管理需求，否则会把一个优秀的桌面工具拖成半成品 SaaS |
| 半吊子支持 IPv6 | 要么按 P0-2 短期方案**明确拒绝**，要么做完整链路。半支持比不支持更伤用户信任 |
| 引入第三方密码学库替换自研 AES | 现有实现零依赖、已过 1103 行测试覆盖，替换收益为负 |

---

## 5. 优先级汇总

| 编号 | 问题 | 类型 | 影响 | 工作量 |
| --- | --- | --- | --- | --- |
| P0-1 | `_syn_failed`/`_raw_cap_cache` 跨模块未共享，回退告警死代码 + 状态永久锁死 | 正确性 | 高 | 小 |
| P0-2 | IPv6 静默接受 → 假"全离线"结果 | 正确性 | 高 | 小（拒绝）/ 大（真支持） |
| P0-3 | `requirements-dev.txt` spec 文件名过期 | 文档 | 低 | 极小 |
| P1-1 | 端口扫描线程池反复新建，最坏 3200+ 线程 | 性能 | 中高 | 中 |
| P1-2 | ping 走子进程，与竞品最大速度代差 | 性能 | 高 | 中 |
| P1-3 | `scan()` 400 行，扩展需改核心 | 架构 | 中 | 中 |
| P1-4 | `ui_dialogs.py` 1747 行 | 架构 | 低中 | 中 |
| P2-1 | 定时扫描 + 变更告警 | 能力 | **高（产品价值）** | 中 |
| P2-2 | 服务版本指纹库 | 能力 | 中高 | 中 |
| P2-3 | 插件/Fetcher 机制 | 能力 | 中 | 中大 |
| P2-4 | macOS/Linux CI | 工程 | 中 | 小 |
| P2-5 | `oui.db` 入 LFS | 工程 | 低 | 小 |

**建议执行顺序**：`P0-3 → P0-1 → P0-2(短期) → P2-4 → P1-2 → P2-1 → P1-1 → P1-3 → P2-2`

先花半天把三个 P0 清掉（其中两个是真 bug，且修复成本极低），然后投入 P1-2 原生 ICMP（用户体感提升最大），再做 P2-1 把产品从"扫描工具"升级为"资产监控"。

---

## 附：值得表扬的三处细节

1. `ports.py:145-149` 用 `perf_counter` 而非 `monotonic`，注释解释了 Windows 上 Python ≤3.12 的 `monotonic` 只有 15.6ms 分辨率会导致 RTT 采样恒为空 —— 这种坑只有真跑过才发现。
2. `engine.py:107-125` `_merge_mdns` 对**已存在**结果打 `mdns_updated` 标记，注释说明"不打标记 UI 就不会重渲染，mDNS 补的信息用户永远看不到" —— 对 UI 数据流的理解很深。
3. `README.md:292-307` 用实测数据论证 onedir vs onefile，并指出 onefile 的自解压模式会触发 EDR 误报（本项目用原始套接字 + WMI + `net view`，本就是 EDR 高敏组合）—— 这是安全工程视角，不是普通开发者会想到的。
