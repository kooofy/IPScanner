# IPScanner v2.1 路线图（草案）

> **这份文档是什么**：`docs/ROADMAP_V2.0.md` §2 那张「v2.0 未收的 7 项及去向」表里，
> 被点名成 **v2.1 候选** 的三项（`adv #2` / `adv #4` / `adv #9`）的**兑现文档** ——
> 那张表说清了它们**去哪**，本文把这三条收敛成一轮可交付的范围，并补上第 4 项。
>
> **为什么现在写**：v2.0 四项已全 ✅ 并**已发布 `v2.0.0`**（release `9b27600` +
> 注解 tag `v2.0.0`）。v2.0 §6 的里程碑结语「2.3 + 2.4 = **v2.1**（或并进 v2.0 若提前）」
> 因为 2.3/2.4 提前并进了 v2.0，**v2.1 的名义配额空了** —— 于是候选池里最早被点名的
> 三条顺位递补上来。本文负责把「顺位递补」变成「先做哪件、为什么、怎么验收」。
>
> | 项 | 值 |
> |---|---|
> | 状态 | **草案** · 2026-10-12 |
> | 基线 | `kooofy/IPScanner` @ `15ce6e6`（v2.0.0 已发布 + §7 标注） |
> | 来源 | `ROADMAP_V2.0.md` §2（7 项去向表，点名 v2.1 候选）+ `docs/PRODUCT_ADVISORY.md` §4.1 / §5 / §9 |
> | 事实核验 | 本文所有「现状」栏均经**本次实测**（`grep` / 读源码），非引述 |

---

## 0. 重排原则（继续沿用 v1.9 / v2.0，不另立一套）

1. **一个 minor 只承载 4 项** —— 让「v2.1 交付了什么」能被一句话说清。
2. **四项各占一个不可替代的角色** —— 「结构 / 出口 / 显示 / 安全网」四分法在 v1.9、v2.0
   连着两轮好用，v2.1 沿用同构，但主题换成 **「看得更深」**（见 §1）。
3. **优先级不由「重要」决定，由「是否阻塞其它项」决定**。
4. **保持项目身份** —— 三条铁律继续生效：
   - **不引入第三方依赖**（`adv #2` 用 `asyncio` 而非 Npcap、`adv #4` 用 `ctypes` 直调
     Windows API 而非装库、`adv #9` 只读本地快照文件，都是为守住这条）；
   - **不开网络监听端口**；
   - **不装 agent、数据不出网**（`adv #9` 的「离线快照本地导入」就是这条的兜底）。
5. **每一项都要能独立回滚** —— `adv #2` 要替换 `ports.py` 的**扫描核心**，
   必须**新旧两条路径并存、用开关切换**，随时能退回 `ThreadPoolExecutor`。

> ⚠ v2.1 有个**新特点**：三项候选里有**两项强平台绑定**（`adv #2` 的提速主战场是
> Windows IOCP；`adv #4` 是 Windows 独占 API）。所以本轮的验收必须显式写清
> **「在非 Windows 上如何降级」**，不能让「只在本机绿」蒙混过关（见 §4 与各分项验收）。

---

## 1. v2.1 四项

v1.9/v2.0 的四分法是「结构 / 出口 / 显示 / 安全网」。v2.1 沿用同构，主题换成
**「看得更深 —— 扫得更快、看清无线归属、看清暴露面，且扫得礼貌」**：

| # | 角色 | 事项 | 优先级 | 工时 | 来源 |
|---|---|---|---|---|---|
| 2.1 | **结构** | 异步 connect 扫描（`asyncio` + IOCP，无 Npcap 提速） ✅ | **P0（主题项）** | 5–7 天 | `ROADMAP_V2.0.md` §2 `adv #2` |
| 2.2 | **可见性** | 无线切片（Native Wi-Fi API：信道拥塞 / 漫游日志 / SSID↔BSSID↔子网） | **P1** | 6–8 天 | §2 `adv #4` |
| 2.3 | **安全网** | 离线 CVE + KEV/EPSS 排序（**先立数据快照维护模型，再编码**） | **P1** | 6–9 天 | §2 `adv #9` |
| 2.4 | **出口** | 扫描节流与礼貌模式（并发上限 + 顺序随机化 + 包速率上限，且档位进导出/审计） | **P1** | 3–5 天 | `PRODUCT_ADVISORY.md` §4.1 |

**合计 20–29 人天 ≈ 5–6 周**（与 v2.0 的 18–27 / 4–6 周同量级）。
**进度：1/4**（2.1 ✅ 已落地，见 §2.1 落地记录）。

> **为什么 2.1 是主题项**：它是**唯一动扫描引擎核心**的改动，是「不加依赖就提升体感」
> 的最大单点（建议书 §4.1 原话）。它一落地，**所有**扫描（GUI 单次 / `watch` / CLI）
> 一起变快，杠杆最大 —— 所以排 P0，先做。
>
> **为什么 2.4 反而排到最后**：它**依赖 2.1 的引擎形态**（并发上限要挂在新的
> 异步调度器上、随机化顺序要改新的投递逻辑）。2.1 没定形之前做 2.4 等于返工 ——
> 这正是 §0 原则 3「优先级由阻塞关系决定」的直接体现。

---

## 2. 逐项详情

### 2.1 异步 connect 扫描（`asyncio` + IOCP，无 Npcap 提速）—— 主题项

**依据**：`PRODUCT_ADVISORY.md` §4.1（「异步 connect 扫描」行）+ §5 v1.9 候选第 2 条。
建议书原话：Windows 上 SYN 扫描要 Npcap，而 Npcap 免费授权只有 5 次安装、**明确禁止再分发**，
不能随包捆绑（§9 陷阱），于是永远退化成 connect；`asyncio` + ProactorEventLoop(IOCP)
能在**不需要任何驱动**的前提下开几千个并发 connect。

**现状实测**（基线 `15ce6e6`）：

```
scanner/ports.py:57   def _get_port_pool() -> concurrent.futures.ThreadPoolExecutor:
scanner/ports.py:63       _port_pool = concurrent.futures.ThreadPoolExecutor(
scanner/ports.py:93       result = sock.connect_ex((ip, port))
```

- 当前**就是**「线程池 + 阻塞 `connect_ex`」—— 与建议书描述完全吻合，`adv #2` **零实现**。
- 池的并发是 `min(64, len(ports))`（源码注释所述），受 GIL + 线程栈开销限制，
  单机几千端口的体感上不去。
- **没有任何** `asyncio` / `ProactorEventLoop` 引用。

**做法**：

1. 新增 `scanner/async_ports.py`（**零 PyQt / 零第三方**，与现有 `scanner/` 同规矩）：
   - `probe_ports_async(ip, ports, *, concurrency, timeout, rtt_callback) -> List[int]`，
     用 `asyncio.open_connection()`（走 IOCP）替代 `connect_ex`；返回**开放端口列表**
     （已排序），与 `scan_ports` 同契约；
   - 每个端口一个 task，用 `asyncio.Semaphore(concurrency)` 限流（并发档位复用 2.4 的定义）；
2. `ports.py` 增加**开关** `_probe_ports_async` vs 现有 `_probe_ports_threaded`，
   默认走异步；**保留线程池路径**，开关一关即可回退（§0 原则 5）。
3. 事件循环只在**进程内建一次**并复用（`ProactorEventLoop`），避免每次扫描重建开销。
4. 非 Windows：`ProactorEventLoop` 不可用时自动退回线程池路径（显式判 `sys.platform`
   + `asyncio` 自身能力，**不猜**）。

**可测验收**：

- **功能等价**：同一目标/端口集，新旧两条路径结果集**完全一致**（单测对拍，含
  开放/关闭/超时三类端口）；
- **提速可测**：对 `127.0.0.1` 上 2000 个关闭端口，异步路径耗时**显著低于**线程池路径
  （用 `perf_counter()`，**不用 `monotonic()`** —— 见用户级记忆的 Windows 分辨率坑）；
  断言给**相对比例**（如「异步 ≤ 线程池 × 0.6」）而非绝对秒数（CI 机器速度不可控）；
- **回退可测**：开关置回线程池路径后，行为不变；
- **非 Windows 降级可测**：模拟 `ProactorEventLoop` 不可用（monkeypatch），
  断言**自动**落到线程池且结果仍正确 —— 对应 §0 的「新特点」要求；
- 覆盖率闸门：`scanner/async_ports.py ≥ 85`（照 2.4 的 `ndp.py ≥ 85` 先例）。

#### 落地记录（2.1）

**交付**（2026-10-12）：

- 新增 `scanner/async_ports.py`（~200 行，**零 PyQt / 零第三方 / 零网络**）：
  - `requires_proactor() -> (bool, str)`：能力探测（本进程内缓存）；
  - `probe_ports_async(ip, ports, *, concurrency=1024, timeout=0.5, rtt_callback=None)
    -> List[int]`：`asyncio.open_connection` + `Semaphore` 限流 + `wait_for` 兜超时；
  - **同步阻塞**接口（内部 `run_until_complete`）——调用方全是同步代码，做成协程要改
    整条链路（GUI 线程 / CLI / 引擎），收益不抵改动面与风险；
  - 事件循环进程内单例（`ProactorEventLoop`）+ `shutdown_loop()` 供测试隔离。
- `scanner/ports.py`：connect 分支改为**异步优先**；新增三条回退护栏（可回滚）：
  1. 环境变量 `IPSCANNER_TCP_ENGINE=threaded|async`（未设=auto）；
  2. `ProactorEventLoop` 不可用 → 自动回退；
  3. 异步路径运行期抛错 → `warning` + **置位进程级 `_async_engine_failed`** + 本次
     立即回退线程池（后续直接走池，不再重试坏引擎）。
  新增 `tcp_engine()` / `reset_async_engine_state()` 供测试与诊断。
- `tests/test_async_ports.py`（30 测试）：对拍、并发上限、RTT、降级、失败回退、开关。

**实测提速**（本机 `127.0.0.1`，2000 个关闭端口，`perf_counter`）：

```
async : 0.652s
pool  : 1.299s   →  ratio ≈ 0.50（2× 提速）
```

**改动既有测试（诚实记账）**：connect 默认引擎从线程池改为异步后，以下测试断言的
是**旧契约**，已**有意更新**（非删除）——

- `tests/test_port_pool.py`：
  - `test_scan_ports_connect_uses_shared_pool` → 改名为
    `..._uses_shared_pool_when_threaded`，加 `IPSCANNER_TCP_ENGINE=threaded`（回退路径旧契约）；
  - 新增 `test_scan_ports_connect_bypasses_pool_when_async`（**新契约**：默认异步不走池）；
  - `test_no_inline_pool_creation_on_repeated_calls` 加 `threaded` 环境（否则异步根本不建池）；
  - 文件 docstring 补「v2.1 §2.1 起 connect 默认异步」的说明。
- `tests/test_rtt.py`：3 个用例补 `_force_threaded()` —— 它们 `patch("scanner.ports.scan_port")`
  模拟线程池路径，而异步路径不调用 `scan_port`。异步的 RTT 行为另由
  `tests/test_async_ports.py::RttCallbackTest` 覆盖。

**验收对照**：功能等价 ✅（对拍 5 用例）；提速 ✅（实测 2×）；回退 ✅（3 用例）；
非 Windows 降级 ✅（monkeypatch `requires_proactor` → 走池）；覆盖率 **96%**
（闸门定 **90%**，余量是 2 处防御性兜底：`loop.close()` 吞异常、`socket.timeout`
第二超时分支）。

**教训**：`asyncio.open_connection` 是**协程函数**，测试里若用 `async def` 打桩会返回
"协程的协程"；正确做法是打桩成**普通函数返回协程**（`def _fake(...): return _coro()`）。
另：`writer.close()` 抛错会被外层兜底成"关闭"，而**只有 `wait_closed()` 抛错**才走
"连接已成功、忽略关闭失败"那条分支 —— 测哪个分支要对准。

**⚠️ 追加教训（2026-10-13，CI 挂了 6 小时）**：上面新增的
`test_scan_ports_connect_bypasses_pool_when_async` 把 `_get_port_pool` 换成**裸
`MagicMock`**（没给 `return_value=real`）。**这在 Windows 上永远发现不了** —— 默认异步路径
根本不碰池，断言全绿；但 macOS/Linux 没有 `ProactorEventLoop`，引擎静默回退线程池，
于是 `as_completed()` 里 `event.wait()` 等一个**永不完事的 future**，进程永久挂死。
表现为：日志最后一行是测试名，然后 `##[error]The operation was canceled.`。

修法三条（缺一不可）：

1. 该测试加 `@unittest.skipUnless(_WINDOWS, …)`，并**在测试内先断言
   `ports.tcp_engine() == "async"`**，不是异步就 `skipTest`（后者防的是"失败标记泄漏
   导致悄悄换路径"，比前者更本质）；
2. `SharedPoolUsageTest.setUp/tearDown` 调 `ports.reset_async_engine_state()` ——
   `_async_engine_failed` 是跨模块共享状态，泄漏会让后续所有 connect 测试换路径；
3. CI 的 `单元测试` 步骤加 `timeout-minutes: 30`（全套正常 ~4 分钟；没有它这种 bug
   要烧满 GitHub 默认 360 分钟才被杀）。

**本地复现手段**（不必等 CI）：起一个 wrapper 在 import 任何项目模块前把
`sys.platform` 改成 `"linux"`、`platform.system` 改成返回 `"Linux"`，再 `discover` 跑全套。
判据：**0 error**、约 3 个假失败（`test_native_ping` 的 `ping` 二进制差异、
`test_app_paths` 的不可写目录），其余必须全绿。**2033 tests / 0 error / 3 假失败** 即为正常。

---

### 2.2 无线切片（Native Wi-Fi API：信道拥塞 / 漫游日志 / SSID↔BSSID↔子网）

**依据**：`PRODUCT_ADVISORY.md` §4.1（「无线层（只切一小片）」行）+ §5 v1.9 候选第 4 条。
建议书原话：Windows 上用 Native Wi-Fi API（`wlanapi`）能拿到信道拥塞、关联/漫游日志、
SSID↔BSSID↔子网三点；**monitor 模式在 Windows 上是死路，不要投入**（§9 陷阱）。

**现状实测**（基线 `15ce6e6`）：

```
grep -rn "wlanapi|netsh wlan|WlanOpenHandle|WLAN_INTERFACE" --include=*.py .   → 0 命中
```

- `adv #4` **零实现**：既不调 `wlanapi`，也不解析 `netsh wlan show ...`。

**做法**：

1. 新增 `scanner/wifi.py`（**零 PyQt**），两层取数：
   - **主路径**：`ctypes` 直调 `WlanOpenHandle` / `WlanEnumInterfaces` /
     `WlanQueryInterface`（`wlanapi.dll`），拿当前关联的 SSID/BSSID/信号/信道；
     —— **`ctypes` 是标准库**，不破「不加依赖」铁律；
   - **降级路径**：`netsh wlan show interfaces` / `show networks`，
     走与 2.4 完全同构的「**按 2+ 空格切列、绝不固定列宽**」解析法
     （`netsh` 列宽随系统语言/版本变，固定切片会静默错位 —— 这是 2.4 的教训）；
2. **漫游日志**：读 `Microsoft-Windows-WLAN-AutoConfig/Operational` 事件日志
   （`wevtutil qe ... /f:xml` 或 `wlanapi` 通知回调），抽「关联/断开 SSID + 时间戳」序列；
3. **SSID↔BSSID↔子网**：把当前关联的 SSID/BSSID 与 2.4 已挂靠的 IPv6 / 既有 IPv4
   子网做**关联提示**，产出「这台设备连的是哪个 AP / 哪个 SSID」；
4. **数据只解析、不落盘、不出网**；输出结构挂进现有 GUI 的「网络工具」Mixin 或新面板
   （网络接口信息属该 Mixin 职责）。

**可测验收**：

- **解析对拍**：`wlanapi` 结构体解析 + `netsh` 文本解析，用**真机抓的样本**覆盖
  （判定口径完全照 2.4：真样本进 `tests/fixtures/`，非手造）；
- **切列不脆**：构造「列宽被系统改过」的 `netsh` 样本，断言仍能正确切分
  （防止重蹈固定切片覆辙）；
- **非 Windows 降级可测**：`wlanapi.dll` 不存在时 → 明确返回「本平台无此能力」
  而非抛异常（与 2.4 的 `ipv6_enabled()`「机器没有 ≠ 没看到」同构）；
- **漫游日志解析**：给定一段 XML 事件样本，断言抽出的「SSID + 时间戳」序列正确；
- 覆盖率闸门：`scanner/wifi.py ≥ 85`。

> ⚠ 本项**平台绑定最强**（Windows 独占 API）。若你希望它同时服务 macOS/Linux，
> 应单列 —— 本文**明确只做 Windows + 文本降级**，不承诺跨平台等价（见 §4）。

---

### 2.3 离线 CVE + KEV/EPSS 排序 —— **前置：先立数据快照维护模型**

**依据**：`PRODUCT_ADVISORY.md` §4.1（「离线 CVE + KEV/EPSS 排序」行）+ §5 v1.9 候选第 9 条
+ `ROADMAP_V2.0.md` §2「**v2.1 候选（前置是产品问题）**」+ §5 未决项 1。
建议书原话：banner → CPE → CVE 关联，用 **CISA KEV**（已被实际利用）与 **FIRST EPSS**
（利用概率）排序；两者都免费、有 API；**但必须离线可用**，把快照作为可更新数据文件导入，
扫描数据一律不出网。

**现状实测**（基线 `15ce6e6`）：

```
grep -rni "cve|kev|epss" --include=*.py .   → 仅 venv/ 第三方命中，项目代码 0 命中
```

- `adv #9` **零实现**。

**🔴 第 0 步（产品决策，先于任何编码）**：v2.0 §5 未决项 1 已经点名 ——
「离线 CVE 数据快照的维护模型：谁生成？多久更新一次？离线包放哪、怎么验签？」
**答不上来之前不编码**。本项在 v2.1 的落地**必须以这一问的答案为入口**。

> ✅ **第 0 步已完成**：见 **`docs/CVE_SNAPSHOT_MODEL.md`**（草案 · 2026-10-12）。
> 结论摘要：快照 = **只读数据文件**（声明式扩展，非可执行代码）；
> 由**上游聚合方生成、本项目只消费**；放 `data_dir()`（用户更新版）→ 回退
> `resource_dir()`（内置种子），沿用 `oui.db` / `service_fingerprints.json` 同一套策略；
> 新鲜度由快照自带 `generated_at` + `max_age_days` 判定，**过期显式降级**；
> 完整性用 **SHA256 摘要清单**（同发布流程口径，不做 PGP）。
> 该文档 §7 还列出 4 个**编码前需拍板**的待决点（内置种子 / `summary` 字段 /
> 生成脚本是否做 / 快照托管位置）。

**做法**（在第 0 步有结论后）：

1. 新增 `scanner/exposure.py` + `scanner/cve_snapshot.py`（**零 PyQt / 零第三方 /
   零网络**，只读本地快照文件）：
   - `cve_snapshot.py`：加载「简化的 CVE→CPE 映射 + KEV 标记 + EPSS 分值」本地快照
     （格式在第 0 步定；若为 JSON/CSV，用标准库即可）；
   - `exposure.py`：**banner → 粗粒度 CPE → 候选 CVE**，按 KEV 优先、EPSS 次之排序，
     产出「暴露面启发式」评分；
2. **诚实降级（硬约束）**：`PRODUCT_ADVISORY.md` §9 明确 —— 风险评分只能是
   **暴露面启发式**，**绝不能**给出暗示「已实测可利用」的结论。
   输出文案必须写清「这是**匹配到**的候选，不是**验证过**的漏洞」；
   快照缺失/过期时**明确报告**「无 CVE 数据可查」，不静默给空结果（照 2.4 的
   「机器没启用 IPv6」与「没看到邻居」必须区分的老规矩）；
3. CLI 侧：`ipscanner export` 或扫描文本报告增加「暴露面」段（跟随当前筛选，
   **不直接读 `all_results`** —— 见长期记忆的导出筛选坑）；
4. **一切数据留在本地**：不自动联网拉取，快照靠用户手动更新（这是「不出网」的兜底）。

**可测验收**：

- **第 0 步必须有落纸产物**（维护模型说明进本文或独立 `docs/`），否则本项**不开工**；
- **排序正确**：给定合成快照，断言 KEV 命中的 CVE 排在最前、同组内按 EPSS 降序；
- **诚实降级**：断言输出**从不**出现「已验证/可利用」类措辞（文案断言，可入测试）；
- **无数据 ≠ 无漏洞**：快照缺失时输出「无数据」，且与「查了、没有匹配」在
  返回值/文案上**可区分**；
- **零网络**：单测断言本模块**不导入任何网络库 / 不发任何请求**（同 2.4 的
  `NoExtraPacketsTest` 思路）；
- **不出网**：FastAPI 无——断言无 `urllib`/`requests`/`socket` 调用；
- 覆盖率闸门：`scanner/exposure.py ≥ 85`、`scanner/cve_snapshot.py ≥ 90`。

---

### 2.4 扫描节流与礼貌模式（并发上限 + 顺序随机化 + 包速率上限）

**依据**：`PRODUCT_ADVISORY.md` §4.1（「扫描节流与礼貌模式」行）。
建议书原话：企业网里全速 SYN 会被 IDS 判定为扫描攻击；给一个「并发上限 + 随机化顺序 +
每分钟包数上限」的礼貌档，并在导出/审计里记录该档位。

**现状实测**（基线 `15ce6e6`）：

- 当前并发由 `ports.py._get_port_pool()` 的 `min(64, len(ports))` 与扫描器
  `max_workers` 决定（**硬编码档位**，无用户可调的上限 / 随机化 / 包速率概念）；
- 审计/导出里**没有**「本次扫描用的礼貌档位」这一字段。

**做法**：

1. 新增 `scanner/throttle.py`（**零 PyQt**）：`ThrottlePolicy` 数据类
   （`max_concurrency` / `shuffle` / `packets_per_minute`）+ 一个**令牌桶**
   节流器（纯标准库 `time` + `threading`/`asyncio`，同时服务 2.1 的异步路径与线程池路径）；
2. 三档预设：`fast`（现状，兼容旧行为）/ `balanced` / `polite`；
3. **顺序随机化**：目标/端口投递前 shuffle（用可注入 seed 以便单测）；
4. **档位进审计**：`audit_log` 记录本次扫描用的策略名 + 关键参数
   （照长期记忆：审计分类要用**语言无关**的规范值，**绝不**落 `tr()` 结果）；
5. **接进 CLI**：`scan` / `watch` 增 `--throttle {fast,balanced,polite}`；
6. **依赖 2.1**：并发上限挂到 2.1 的 `Semaphore` 上 —— 所以本项排在 2.1 之后。

**可测验收**：

- **上限生效**：断言任一时刻在途连接数 ≤ `max_concurrency`（用一个记账 fake）；
- **随机化可测**：注入固定 seed → 投递顺序可复现且 ≠ 声明序（不是「看起来乱」）；
- **令牌桶可测**：给定 `packets_per_minute`，断言单位时间内的投递数不超过上限
  （用**假时钟**推进，不真 sleep）；
- **档位落审计**：断言 `audit_log` 里记录的是**规范值**（语言无关），切语言不变；
- **兼容旧行为**：`fast` 档结果与改造前逐条一致；
- 覆盖率闸门：`scanner/throttle.py ≥ 90`。

---

## 3. 移出项及去向（v2.0 §2 表里尚未处置的，一次说清）

`ROADMAP_V2.0.md` §2 的 7 项里，3 项（`adv #2`/`adv #4`/`adv #9`）本文收进 §1；
其余 4 项的去向在此并轨说明，免得再留一笔糊涂账：

| 原编号 | 事项 | 本文裁定 | 理由 |
|---|---|---|---|
| v1.8 #6 | 只读 HTTP API（`serve`）+ webhook | **继续出局** | **开监听端口**与「本地、无账号、不开服务」身份冲突（§0 原则 4）。文件型导出（1.2）已拿到同样集成价值 |
| v1.8 #8 | 通知渠道走 Apprise | **继续出局** | **引入第三方依赖**。自研 `notifier.py` 已覆盖 webhook / 企微 / 钉钉 / 邮件四类，边际收益不抵身份代价 |
| adv #7 | Prometheus `/metrics` + Nagios + SNMP trap | **继续出局（拆分裁定，同 v2.0）** | `/metrics` 与 SNMP trap 都要**常驻监听/常驻进程**，违反原则 4。**Nagios 插件契约**（一次性执行、退出码表达状态）不违反，**仍是补丁轨道候选**（见 §5） |
| v1.8 #15 / adv #8 | 拓扑手工校正 | **已交付** ✅ | v1.9 后第 1 项，见 `ROADMAP_V1.9.md` §3.1 + §3.2 |

> **一句话**：v2.1 只做**不用常驻、不加依赖、不破身份边界**的事，且新增一条自约束 ——
> **只做能独立验收的**。凡要「开端口 / 加依赖 / 装 agent / 依赖未决产品决策」的，
> 要么继续关闭，要么等前置答上来。

---

## 4. 与建议书 §5 v1.9 / §9 陷阱清单的差异（我改了什么、为什么）

建议书 §5 把 §1 这四项都排在**「v1.9 —— 规模与身份」**（6–10 周）里，与其它 5 项并列。
本文做了三处调整：

1. **拆轮**：建议书那份 v1.9 有 9 项，本文只取其中 4 项成 v2.1，其余（设备身份、拓扑导出、
   凭据档等）已在 v2.0 或 v1.9 分期消化 —— 一轮只装 4 项是「一句话说清」的纪律（§0 原则 1）。
2. **给 `adv #9` 加前置门**：建议书把它当普通候选，本文按 v2.0 §5 未决项 1 的裁定，
   给它加一道**「先答数据快照维护模型」的产品门**（2.3 第 0 步）。理由：这是产品决策
   不是编码，硬做会做出一个没人维护的快照（比没有更糟）。
3. **明确不承诺跨平台等价**：建议书没点破 `adv #2`/`adv #4` 的**平台强绑定**，
   本文在两处验收里显式要求「非 Windows 如何降级」，避免「只在本机绿」蒙混（见 §0 尾注）。

**与 §9 陷阱清单一致性核验**：

- `adv #2`：**不捆绑 Npcap**（§9 明令）—— 本文用 `asyncio` 绕开，✅；
- `adv #4`：**不做 monitor 模式**（§9「Windows 上是死路」）—— 本文只取 Native Wi-Fi API
  能拿到的那一片，✅；
- `adv #9`：**不给「已实测可利用」结论**（§9「那是责任而不是功能」）—— 2.3 硬约束，✅。

---

## 5. 顺序

```
2.1 异步 connect 扫描（P0，主题项）
 └─ 先做：唯一动扫描核心的改动，杠杆最大；
    且 2.4 的并发上限要挂在它的调度器上（阻塞关系，见 §0 原则 3）。

2.2 无线切片（P1）      ┐
2.3 离线 CVE（P1）      ┘ 都与 2.1 无耦合 → 可并行或穿插。
   ⚠ 2.3 先过「第 0 步」产品门，过不了就往后挪、不占 2.1 的车道。

2.4 扫描节流与礼貌模式（P1，出口）
 └─ 依赖 2.1 定形；建议紧随 2.1 之后做，避免新引擎裸奔（无节流）。
```

**里程碑**：2.1 + 2.2 完成 = 可发 **v2.1** 的**最低可发**；
2.3 + 2.4 完成 = **v2.1 完整**（四项齐）。
若 2.3 的产品门迟迟不过，**2.1 + 2.4 + 2.2 三项亦可成轮**（打破四项惯例需在 §8 变更记录写明）。

**补丁轨道**：始终可承接「与主题无关、能独立验收」的小项 ——
`Nagios 插件契约`（§3 adv #7 的合规半边）是本轨道**已挂名的头号候选**。

---

## 6. 一页速览

```
v2.1「看得更深 —— 扫得更快、看清无线归属、看清暴露面，且扫得礼貌」
├─ 2.1 异步 connect 扫描（asyncio + IOCP，无 Npcap）    P0  ← 结构（主题）★ 地基
├─ 2.2 无线切片（Native Wi-Fi API：拥塞/漫游/SSID↔子网）P1  ← 可见性
├─ 2.3 离线 CVE + KEV/EPSS（先立快照维护模型）          P1  ← 安全网（有产品门）
└─ 2.4 扫描节流与礼貌模式（并发/随机化/包速率 + 审计）   P1  ← 出口（依赖 2.1）

进度：1/4 完成（**2.1 ✅**；2.2/2.3/2.4 未开工；落地记录见 §2.1）

不做（明确）：HTTP API / Apprise / Prometheus 常驻 / SNMP trap /
             Npcap 捆绑 / monitor 模式站点勘测 —— 依旧因「开端口 / 加依赖 / 装 agent」出局

前置：2.3 必须先答「数据快照谁维护、多久更新、怎么验签」（v2.0 §5 未决项 1）
      —— ✅ **已答**：见 `docs/CVE_SNAPSHOT_MODEL.md`

工时：20–29 人天 ≈ 5–6 周（2.1 + 2.2 = 可发 v2.1 最低可发）

v2.0 收口：四项 ✅ + 已发布 v2.0.0（release 9b27600 + 注解 tag v2.0.0）
```

---

## 7. 引用约定

- 引用**建议书**写 `建议书 §4.1` / `建议书 §9` 形式；
- 引用**上一轮路线图**写 `ROADMAP_V2.0.md §2` / `§5` 形式；
- 引用**代码现状**写 `文件:行号`（行号对应基线 `15ce6e6`，改版后可能漂移）；
- 本路线图**只增不改**已交付项的落地记录；若中途变更取舍，
  **新增一节「§8 变更记录」**写明改了什么、为什么，**不要**回头改写 §1/§2 的验收标准。
