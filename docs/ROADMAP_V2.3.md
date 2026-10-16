# IPScanner v2.3 路线图（草案）

> **这份文档是什么**：`docs/ROADMAP_V2.2.md` 收口并发布 `v2.2.0` 后，**下一轮该做什么**的决策文档。
>
> | 项    | 值                                                                                                                                    |
> | ---- | ------------------------------------------------------------------------------------------------------------------------------------ |
> | 状态   | **定稿 · §3 四项已定案**（用户 2026-10-15 拍板「四项照此执行」；**落地中，从 3.1 开始**）                                                                       |
> | 主题   | **A「能看清变化」**（用户 2026-10-15 在四个方向中选定）                                                                                                  |
> | 基线   | `kooofy/IPScanner` @ `79e9305`（**v2.2.0 已发布**，release `413314426` + 注解 tag `v2.2.0`）                                                    |
> | 来源   | `ROADMAP_V2.2.md` §2 候选池、`docs/PRODUCT_ADVISORY.md` §4.3/§4.6、`TRAPS.md` §「已知未修问题」                                                          |
> | 事实核验 | 🔴 本文所有「现状」栏均经**本次实测**（`grep` / 读源码 / 数行数），**非引述建议书** —— 理由见 §2.1                                                                             |
> | 本文范围 | **只出文档，不写代码**。§3 四项定案后逐项落地                                                                                                                  |

---

## 0. 重排原则（继续沿用 v1.8 / v1.9 / v2.0 / v2.1 / v2.2，不另立一套）

1. **一个 minor 只承载 4 项** —— 让「v2.3 交付了什么」能被一句话说清。
2. **四项 = 主题项 + 三项支撑**（v2.2 改的体例，继续生效）。
3. **优先级不由「重要」决定，由「是否阻塞其它项」决定**。
4. **保持项目身份** —— 三条铁律继续生效：
   - **不引入第三方依赖**；
   - **不开网络监听端口**；
   - **不装 agent、数据不出网**。
5. **每一项都要能独立回滚**，且**只做能独立验收的**。

> ✅ **v2.3 与 v2.2 最大的不同：本轮四项全部不撞身份边界。**
> v2.2 的候选池里「最想要的」全部踩 §0 原则 4，本轮的趋势 / 生命周期 / 暴露时长 / 报表
> 都是**纯本地、纯文件、零依赖**。所以本轮的关键不是「怎么不破边界」，
> 而是 §2.1 那件事：**别拿过时的建议书当排期依据**。

---

## 1. 主题：**A「能看清变化」**（用户 2026-10-15 选定）

> 一句话：**让工具能回答「这段时间里，网络发生了什么、什么时候开始的」。**

### 1.1 为什么是它

用户 2026-10-15 在四个方向（A 能看清变化 / B 能交付 / C 能接进 / D 能站住）中选 **A**。
选它的核心理由是**一条实证发现**：

> `PRODUCT_ADVISORY.md` §4.3 把「资产表 + 观测表两层模型」定为 **P0（v2 主题）**，
> 并在收益里写明：
> 「趋势类功能变得可能：在线率曲线、首次出现告警、**端口长期暴露时长**、MTBF/抖动」。
>
> **那张资产表在 v2.0 就建好了**（`history_store.py` L168），迁移链已到 `SCHEMA_VERSION = 5`。
> **两年过去，这批果实一个都没收** —— 全仓 grep 不到任何趋势 / 曲线 / 暴露时长实现。
>
> ⇒ v2.3 是「收果实」的一轮：**数据基础已经齐了，缺的只是把它变成用户看得见的东西。**

### 1.2 未选的三个方向及其去向

| 方向                  | 一句话                                        | 去向                                                                                 |
| ------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------- |
| **B 能交付**（报表投递闭环） | PDF 报表 + 定时投递 + diff 报表 + 拓扑 PNG/SVG       | **不占 v2.3 名额**。⚠️ 其中「PDF」与「定时投递」是**最便宜的确定收益**，可作为 §3 落地后的**补丁轨道顺带项**（若四项提前完成） |
| **C 能接进**（出口与事件规范）  | 自定义输出模板 + CloudEvents 事件 + 授权工单落库         | **不占名额**。⚠️ 「CloudEvents 结构化事件」与 §3.1 的**事件流**高度同源 —— 若 §3.1 落地顺利，C 的成本会大幅下降，可留作 v2.4 主题 |
| **D 能站住**（工程与分发还债）  | `main_window` 拆分 + winget/scoop + SBOM + PySide6 | **维持现状**。`main_window.py` 已 **2044 行**（实测），但拆分不给用户新价值；PySide6 维持 v2.0 裁定（但 Qt 5.15.2 已停安全更新这一代价继续记账） |

---

## 2. 候选池与裁定

### 2.1 🔴 实证：`PRODUCT_ADVISORY.md` 的优先级表已严重过时

**排 v2.3 前先跑了一轮实证，结果与建议书差异极大。**
这些项**不能再当候选**（否则会排进去一堆早就做完的事）：

| 建议书项                                    | 原优先级        | 实证：已在哪                                                                                                     |
| ---------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------- |
| 资产表 + 观测表两层模型                            | **P0（v2 主题）** | ✅ **v2.0 已建**：`history_store.py` L168 `assets` 表（`identity_key` 主键、`first_seen`/`last_seen`/`seen_count` **单调累积不回退**）+ L195 `devices` 补 `identity_key` 列；L47 起 `user_version` 迁移链 |
| MAC/IP → 交换机端口定位（「Netdisco 招牌能力」）         | P1           | ✅ CLI `locate` 子命令                                                                                             |
| 端口利用率 / 空闲口                               | P2           | ✅ CLI `ports` 子命令                                                                                              |
| 拓扑文本导出（tree / markdown / ascii）           | P1           | ✅ CLI `topology` 子命令                                                                                           |
| Nmap XML **产出**                           | P1           | ✅ `export --format nmap`                                                                                      |
| Nmap XML **读入**                           | P1           | ✅ `import` 子命令                                                                                                |
| Zabbix LLD / NetBox CSV / Oxidized `router.db` | P2           | ✅ `export` 四种格式全有                                                                                             |
| HTML 报表**模板化**（模板是数据文件、可复制到数据目录改一份即生效）      | P1           | ✅ `report` 子命令 + `assets/report_templates/*.html`                                                             |
| 凭据库分层（按网段 profile + `env:` 引用）             | P2           | ✅ `credentials` 子命令                                                                                           |
| `user_version` 迁移链 / BER fuzz / pip-audit / 零利用体检 | P1           | ✅ 均已完成                                                                                                        |

> 🔴 **给未来几轮的规矩**：`PRODUCT_ADVISORY.md` 写于 **v1.7.6 基线**（2026 年），
> 其 §4/§5 的优先级表**只当"想法来源"，不当"待办清单"**。
> 排期前必须像本文 §2.1 这样跑一遍实证。

### 2.2 本轮的真空白（实证，即 §3 的取材范围）

| 空白                    | 实证                                                                                             |
| --------------------- | ---------------------------------------------------------------------------------------------- |
| **趋势 / 时间序列**         | 全仓无在线率曲线、无端口暴露时长、无 MTBF·抖动。只有 `SubnetUtilizationDialog`（**单次**快照在线率）与 `device_timeline()`（单设备、有 `limit`） |
| **生命周期字段**            | `assets` 表现有 **16 列**（实测），**无** 采购 / 保修 / 负责人 / 位置树 / EOL。`detail_panel.py` L175 只在详情页显示 `wmi_serial`，没进资产台账 |
| **变更事件不落库**           | `change_detector` 有 6 种变更（`new_device` / `device_gone` / `ip_changed` / `mac_changed` / `hostname_changed` / `mac_randomized`），但**每次扫描现算现用，不写库** —— 历史无法回溯 |
| **PDF / 定时投递**        | 全仓 grep 不到 `pdf`；`schedule` 只注册定时**扫描**，无定期报表投递                                                     |

### 2.3 撞身份边界的（继续出局，不每轮重提）

| 候选                             | 撞哪条铁律   | 裁定                                                                        |
| ------------------------------ | ------- | ------------------------------------------------------------------------- |
| 只读 HTTP API (`serve`) + webhook | 开监听端口   | **继续出局**。文件型导出（v1.9 §1.2）已拿到同样集成价值                                         |
| 通知渠道走 Apprise                    | 引入第三方依赖 | **继续出局**。自研 `notifier.py` 已覆盖 webhook / 企微 / 钉钉 / 邮件四类                      |
| Prometheus `/metrics`            | 常驻监听    | **继续出局**。用户可用 cron/schtasks 定期跑并落文件                                        |
| SNMP trap 出站                     | 常驻进程    | **继续出局**。与「按需扫描」定位冲突                                                       |
| ~~PySide6 迁移~~                  | 不撞边界    | **维持 v2.0「明确不做」**。⚠️ 继续记账：Windows 版捆绑 Qt 运行时 **5.15.2（2021-07）**，上游开源分支已停止安全更新 |

### 2.4 未修欠账（维持现状，不进 v2.3）

- `P2-13` 无代码签名 = **`申请中`**（唯一待办是用户本人在 signpath.org 提交，见 `docs/SIGNPATH_APPLICATION.md`）；获批后才做签名流水线接线。
- **SNMPv1 / DES** 不支持（明确报错、不静默降级，现状正确）。
- **IPv6 扫描**不支持（只做可见性；一个 /64 有 2⁶⁴ 地址，语义上不成立）。

---

## 3. v2.3 四项（**已定案** 2026-10-15）

```
v2.3 主题 A「能看清变化」—— 趋势与生命周期
├─ 3.1 趋势观测层（独立表 + 事件流，不参与 prune）      P0 ← 主题项（做新事·数据基础）
├─ 3.2 在线率曲线与稳定性（MTBF / 抖动 / 首现告警）       P1 ← 显示
├─ 3.3 端口长期暴露时长                                P1 ← 合规
└─ 3.4 资产生命周期字段 + EOL 提醒                      P2 ← 资产
```

> 🔴 **3.1 是唯一"必做"的**：3.2 / 3.3 都直接读它的数据，3.4 依赖它的 `_SQL_V6` 迁移。
> 若只能做一项，做 3.1。

### 3.1 趋势观测层（**主题项**）

**依据**：§4 前置问题（prune 只留 20 份快照）+ §2.2「变更事件不落库」。
**为什么是主题**：它是四项里唯一"做新事"的 —— 3.2 / 3.3 都是在它之上做显示，
3.4 借它的迁移版本。它把「工具只能看此刻」变成「工具能看一段时间」。

**现状（实测）**：

- `prune(max_keep=20)`（`history_store.py` L1241）：只保留最近 **20 条**快照，
  更早的 `snapshots` 删掉，**`devices` 靠外键 `ON DELETE CASCADE` 跟着删**。
- `assets` 表的 `first_seen` / `last_seen` / `seen_count` 是**单调累积**列（L187 注释：
  「prune() 会删掉旧快照，而首见时间不该跟着被删掉」）⇒ 能算"存在时长"，
  **算不出"在线率曲线"**。
- `watch` 子命令的 `--help` 原文承认这个限制：
  「**快照上限 20 条，持续轮询会把历史冲掉**」，所以它默认**不写快照**。

**做法**：

1. **新表 `trend_observations`**（每次扫描**一行聚合摘要**）：
   `id / time / total / online / offline / new_count / gone_count / ranges_json /
   ports_scanned / duration_s / source`
   🔴 **不设 `snapshot_id` 外键、不参与 `prune()`**，独立保留（默认 **365 天**，可配）。
   一行几十字节 ⇒ 一年 365 行仅几十 KB。
2. **新表 `asset_events`**（**事件流**，只在**变化时**写行）：
   `id / ts / identity_key / event_type / detail_json`
   `event_type` 规范值：`first_seen` / `status_flip` / `port_open` / `port_close` /
   `ip_changed` / `mac_changed` / `mac_randomized`
   🔴 **规范值语言无关，绝不 `tr()`**（照 v2.2 §3.3 `SUM_SCHEMA_KEYS` 的教训）。
3. **迁移 `_SQL_V6`**（当前 `SCHEMA_VERSION = 5`，`MIGRATIONS` 追加第 6 项）。
   ⚠️ 照既有约定：**迁移 1~3 用 `IF NOT EXISTS` 是刻意的**，V6 属"引入后"的迁移 ——
   结构不符时**报错**比静默跳过好。
4. **CLI `trend`** 子命令：`--window {24h,7d,30d,all}`（照 v2.2 §3.3 `audit --window` 的惯例）
   + `--granularity {raw,day}` + `-f {table,json}`。
5. **写入失败绝不升级成扫描失败**（与 v2.2 三项的失败口径同一条）。

**验收标准**：

- [x] `prune(max_keep=20)` 跑 **33** 次后，`trend_observations` **仍有 33 行**（趋势不被冲掉）
      —— `PruneIsolationTest.test_trend_survives_snapshot_pruning`，同批快照只剩 20 份
- [x] `devices` 被 prune 删空后，`trend_observations` 仍能画出完整在线率曲线（同上）
- [x] 事件**只在变化时写行**：连续两轮扫描结果完全相同 ⇒ **不新增 `asset_events` 行**
- [x] `event_type` 全部是**语言无关规范值**（测试断言 ASCII + 无中文 + ⊆ 常量表）
- [x] 迁移幂等：对已升级到 V6 的库再跑一次 `_init_db()` **不报错、不重复建表**
- [x] 旧库（V5）升级后**既有数据一条不丢**
      —— ⚠️ **不回填**：趋势表是全新的，`v6` 只 `CREATE TABLE`，历史扫描**不可能**
      凭空变出趋势行。升级前的扫描在趋势里查不到，这是事实不是缺陷。
- [x] 趋势写入抛异常时：**扫描仍正常完成、退出码不变**（只 `warning`）
- [x] 空数据给 `reason` + 下一步，**不给空表**（照 v2.2 §3.3 `no_records` 的口径）
- [x] CLI 零 PyQt（照既有铁律）

**风险**：事件流**写多了会胀库**。缓解：① 只在变化时写；② 给 `asset_events` 也定保留策略；
③ **逐端口事件只记实际开放的端口**（见 §3.3，不记 65535 个）。

### 3.2 在线率曲线与稳定性

**依据**：`PRODUCT_ADVISORY.md` §4.3 收益清单第 3 条（在线率曲线 / 首次出现告警 / MTBF·抖动）。

**现状（实测）**：`overview.py` 有四张 `_StatCard`（设备总数 / 在线 / 离线 / 在线率），
但**全是"此刻"的值**；`SubnetUtilizationDialog` 也是单次快照。
`device_timeline(mac/ip, limit)` 是**单设备**轨迹，不是全网曲线。

**做法**：

1. **在线率曲线**：读 `trend_observations` 按时间桶（`--granularity day` 时按天聚合），
   支持全局与按网段（网段从 `ranges_json` 拆）。
   ⚠️ 落地时**改为**「写入端按网段各记一份计数」（`ranges_json` 存
   `[{"range","total","online"}]`）—— 只存网段名的话，读端**拆不回**单网段，
   按网段曲线根本无法实现。详见下方「落地要点」与 §10。
2. **抖动与 MTBF**：基于 `asset_events` 的 `status_flip`。
   - 抖动 = 窗口内状态翻转**次数**；
   - MTBF = 相邻 `offline → online` 间隔的**均值**。
   ⚠️ 只有一次翻转时**不给 MTBF**（样本不足），照 v2.2 §3.4-a「不猜」的原则给 `reason`。
3. **首次出现告警**：`first_seen` 落在窗口内的设备数 + 列表，窗口可配。
4. **GUI**：概览页加趋势位（或新对话框「趋势与稳定性」），照 `audit_activity.py` 的
   「时间窗下拉 + 刷新 + 表格 + 空态下一步」结构。
5. ⚠️ **红线**：只陈述事实（"这台设备 7 天内掉线 12 次"），
   **不给可利用结论**（不推断"该设备有故障/该换"）。

**验收标准**：

- [x] 曲线数据点数量 == 窗口内的观测次数（`raw` 粒度下逐一对应）
      —— `TrendViewDialogTest.test_rows_and_summary_report_counts` /
      `CliTrendTest.test_table_output_lists_every_observation`
- [x] 空窗口 / 仅一次观测：**给 `reason` + 下一步**，不画空图、不报 0
      —— `TrendViewDialogTest.test_empty_state_shows_reason_and_next_step`；
      两种空的原因**分开报**（`test_out_of_window_is_distinct_from_no_records`：
      窗外数据该放大窗口，库里没数据该去跑扫描）
- [x] MTBF 只有一次翻转时**明确说样本不足**，不返回 0.0 冒充结果
      —— `StabilityTest`；`CliTrendTest.test_table_warns_when_mtbf_sample_is_insufficient`
- [x] 曲线值**语言无关**（JSON 键固定英文），本地化只发生在显示层
      —— `CliTrendTest.test_json_keys_are_english_and_fixed`；时长单位由
      `trend_store.duration_parts()` 只给**规范值**（`second`/`minute`/…），
      CLI 与 GUI 各自 `tr()` 后拼（领域层不 import `i18n`）
- [x] GUI 标签表登记进 `tests/test_i18n_lazy.py::_label_tables()` + `en-US.json`
      —— `ui_dialogs.trend_view` 四张表 +「样本不足」+ 采样提示，共 7 项

**落地要点（2026-10-15）**：

- 纯计算在 `trend_store.py`（零 DB / 零 PyQt / 零 i18n）：`stability()` /
  `first_seen_devices()` / `duration_parts()` / `row_range_counts()` /
  `range_names()`。
- CLI `trend` 增 `stability` / `new_devices` 两块（JSON 键固定英文）；表格分节打印，
  样本不足时明写「样本不足」+「不等于稳定」，🔴 **不显示 0 冒充结果**。
- GUI 新 `ui_dialogs/trend_view.py`（照 `audit_activity.py` 结构：时间窗 + 粒度
  + **范围** 三个下拉 + 刷新 + 表格 + 空态下一步）；分析菜单「在线率趋势...」+
  `HistoryMixin._show_trend_view()`。
- ✅ **按网段曲线**（做法 #1 的后半）已补：写入端算每网段计数
  （`history_store._range_counts()`，`ranges_json` 存
  `[{"range","total","online"}]`），读端 `online_ratio_series(range_name=…)`；
  CLI `trend --range`、GUI「范围」下拉。新增 `REASON_NO_RANGE_DATA` ——
  "选了网段但窗口内没有它的计数"与"窗外没数据"**分开报**，并列出可用网段。
- ✅ **趋势元数据接线**已补（即 §10 偏离 ①②，同一根因）：CLI
  `_scan_trend_meta()`（`scan`/`diff` 带 ranges/ports/duration，`import`/`watch`
  带 source）、GUI `scan_mixin._scan_trend_meta()`。回归守卫
  `ScanTrendWiringTest`（mock 掉真扫描，断言 `trend=` 真传下去 —— 不接线时
  全局曲线看着正常，只有按网段曲线是空的，肉眼极难发现）。
- 🔴 新增验收口径：`--range` 的三个数必须**互不相同**（全局 75% / 网段 A 50% /
  网段 B 100%），否则"断言按网段生效"是恒真的假测试。

### 3.3 端口长期暴露时长

**依据**：`PRODUCT_ADVISORY.md` §4.3「端口长期暴露时长」。

**现状（实测）**：`assets.open_ports` 只存**当前**开放的端口串，**没有时间维度** ——
「这个 23 端口是昨天开的还是开了两年」现在答不上来。

**做法**：

1. 复用 §3.1 的 `asset_events`：`port_open` / `port_close` 事件。
2. **暴露时长** = 当前时间 − 最近一次**未闭合**的 `port_open` 时间；
   已闭合的区间给出「开放区间列表」。
3. 🔴 **只记实际开放的端口** —— 照 v2.2 §3.3「逐端口直方图有意不做」的教训
   （`all` 档 65535 个端口，逐端口落库会胀爆；这里只记**真的开着**的那几个）。
4. CLI：挂在 `trend` 或新增 `exposure` 子命令下；GUI：设备详情面板加一列。

**验收标准**：

- [x] 端口从开到关再开 ⇒ 时长**从最近一次 open 起算**，不是从首次
      —— `PortExposureTest.test_reopen_counts_from_the_latest_open_not_the_first`
      （开→关→再开，断言 `seconds == 50` 而不是 2050）
- [x] 已关闭的端口**不报"正在暴露"**
      —— `test_closed_port_is_not_reported_as_exposed`；CLI 走另一分支说
      「当前没有仍开放着的端口」（`CliPortExposureTest`）
- [x] 只对实际开放端口写事件：**全关设备不产生任何 `port_*` 事件**
      —— `TrendWriteTest.test_all_ports_closed_device_writes_no_port_event`
- [x] 时长单位明确（天/小时），JSON 输出**语言无关**
      —— `CliPortExposureTest.test_json_keys_are_language_neutral`（只出秒数）；
      分档仍**只有一份**（`trend_store.duration_parts()`），
      单位文案在 `ui_utils.format_duration()`

**落地要点（2026-10-15）**：

- 纯计算 `trend_store.port_exposure(events, now=, identity_key=, top=)`：
  按设备、按端口重放 `port_open` / `port_close`；`close` 收一段闭合区间，
  窗口结束时仍未闭合的 `seconds = now − since`。
- 🔴 **新增 `baseline` 端口事件**（`history_store._build_asset_events`）：
  首次观测时**已经开着**的端口也记一条 `port_open`，带 `baseline: true`。
  没有它，长期不动的端口（**正是这一项要回答的那一类**）在事件流里
  完全没有记录，「这个端口开了多久」永远答不出来。
  ⚠️ 它的时间戳是"我们第一次看到它"，**不是**"端口真的开了" ⇒ 消费方
  必须显示成「**至少** N」（`ui_utils.format_exposure_rows()`）。
  重复 `open`（中间没有 `close`）**不覆盖**起点 —— 保留更早的 = 更保守。
- CLI 挂在 `trend` 下，**不新开 `exposure` 子命令**：`scanner/exposure.py`
  已经是「banner → 候选 CVE 匹配」，同名会让两件事混淆；且 `trend` 本就是
  「这段时间网络变成了什么样」的入口。JSON 加 `port_exposure` 键。
- GUI：**设备详情面板**加「端口暴露」分区（照路线图原文），数据由
  `MainWindow._port_exposure_for()` 经 `history_store.asset_identity_key()`
  解析身份键后取；与「历史轨迹」同款缓存、**同点失效**
  （`history_mixin._save_snapshot`）。
- ⚠️ 时长单位表从 `ui_dialogs.trend_view` 提到 **`ui_utils`**
  （`detail_panel` 也要显示时长，两份实现必然漂移）；
  `cli._fmt_duration` **刻意不共享**（CLI 不 import `i18n`，输出恒为中文）。
- `asset_identity_key()` 用 **MAC 优先**匹配 `assets`，与 `device_timeline()`
  同规则；🔴 **不能**用 `identity_key(mac, ip)` 现算 —— 真正的键由写入端的
  `resolve_identity()` 决定（LAA 随机 MAC 走指纹降级），现算会与库里的对不上。

### 3.4 资产生命周期字段 + EOL 提醒

**依据**：`PRODUCT_ADVISORY.md` §4.3「资产生命周期字段（采购日期/保修/负责人/序列号/位置树）+ EOL 提醒」。

**现状（实测）**：`assets` 表 **16 列**（`identity_key` / `mac` / `ip` / `status` /
`hostname` / `vendor` / `device_class` / `os_guess` / `open_ports` / `services` /
`location` / `user` / `remark` / `first_seen` / `last_seen` / `seen_count`）——
**没有任何生命周期列**。`wmi_serial` 已在采集，但只在详情页显示（没入台账）。

**做法**：

1. `assets` 加列（`_SQL_V6` 与 §3.1 同版或另开 V7，落地时定）：
   `purchase_date` / `warranty_end` / `owner` / `serial` / `location_tree` / `custom_json`。
   ⚠️ 加列**必须走迁移链**，不能靠 `CREATE TABLE IF NOT EXISTS`（它不补列，见 L136 注释）。
2. **EOL / 保修到期提醒**：`--warranty-days N` 列出 N 天内到期的设备。
3. **自定义字段**（`custom_json`）：⚠️ **键名不翻译**（照 v2.2 铁律：
   判据是"拿比较还是显示" —— 用户写的键是拿来比较的）。
4. GUI：设备详情面板可编辑；CLI：`assets --warranty-days`。

**验收标准**：

- [x] 加列后**旧库升级不丢数据**
- [x] `custom_json` 的键**原样存取**，不经过 `tr()`
- [x] 保修到期计算**按本地时区**推导（⚠️ 测短时长用 `perf_counter()`；
  `fromtimestamp()` 按本地时区 ⇒ 断言必须同时区推导）
- [x] 未填保修日期的设备**不报"已过期"**（区分"未填"与"已过期"）

**落地要点（2026-10-16）**：

- **迁移**：新开 `_SQL_V7`（`SCHEMA_VERSION = 7`），`assets` 加 6 列。
  🔴 `_LEGACY_TABLES` 用**列标记** `("assets", "custom_json", 7)` —— v7 只加列
  不建表，用表名标记会让老库推断版本偏低 → 重放 `ALTER TABLE` → `duplicate
  column name` → 库打不开（照 v5 `("assets", "fingerprint", 5)` 的先例）。
- **新模块 `asset_lifecycle.py`**（纯计算：零 DB / 零 PyQt / 零 i18n / 零三方，
  AST 守卫钉死只许 `datetime`/`json`/`re`）：`parse_date`（宽松，**读**路径）
  vs `parse_date_strict`（**写**路径，非法当场抛）；`warranty_state()` 返回
  语言无关规范值 `unset`/`expired`/`expiring`/`ok`；`filter_by_warranty()`；
  `normalize_custom_json()`（键名原样）。
- **读写分层**：`_ASSET_LIFECYCLE_COLS` 与 `_ASSET_COLS`（随观测刷新的展示
  属性）严格分离 —— 扫描 UPSERT 绝不覆盖人工填写的台账；写入只走
  `update_asset_lifecycle()`。
- **CLI**：`assets --warranty-days N`（未填的**不进结果**、stderr 报跳过台数）
  + `assets --set <键/MAC/IP> --field K=V`（非法日期/未知字段当场报错，
  找不到资产返回 0 行由调用方报）；JSON/CSV 补 6 列。
- **GUI**：详情面板「资产信息」分区（未填=「未填」绝不「已过期」）+「编辑
  资产信息…」按钮 → 新 `ui_dialogs/asset_edit.py`；写入在 `library_mixin
  ._edit_asset`（对话框本身不碰库，取消不会留半截写入）。
- **踩到的坑**：`update_asset_lifecycle` 首版漏了 `conn.commit()` ——
  `db_util.connection()` 只加锁 yield、**不代提交**，同进程读缓存连接能读到
  ⇒ 单测全绿但进程一退出改动就没了。补了「关掉连接再读」的回归用例。

---

## 4. 🔴 前置问题（已答清）：趋势建在什么上面

> 这个问题在**选方向时就提出来了**：**`prune()` 会删旧快照，趋势不能建在会被删的数据上。**
> 不先答清就开工，做到一半会发现「曲线随时间自己变短」。

**答**：

| 数据                                       | 会被 prune 删吗                  | 能算什么                    |
| ---------------------------------------- | ----------------------------- | ----------------------- |
| `snapshots` / `devices`（上限 20，CASCADE）    | ✅ **会删**                      | ❌ **不能用来做趋势**           |
| `assets.first_seen` / `last_seen` / `seen_count` | ❌ 不删（**单调累积**，L187 注释刻意如此设计） | 存在时长、首见时间、末见时间         |
| **`trend_observations`（新，§3.1）**          | ❌ **不删**（无外键、独立保留 365 天）      | ✅ **在线率曲线、规模变化、新增/消失** |
| **`asset_events`（新，§3.1）**                | ❌ **不删**（只在变化时写行）             | ✅ **MTBF、抖动、端口暴露时长**    |

**结论**：趋势层的两张新表**必须与 `prune()` 解耦** —— 这是 §3.1 的核心约束，
也是 3.2 / 3.3 能否成立的前提。

**顺带解决的一个既有问题**：`watch` 现在**不敢写快照**（怕冲掉 20 条历史）。
若 §3.1 落地，`watch --once` 可以改为**只写趋势行、不写快照** ⇒
「持续轮询」与「保留历史」不再互斥（⚠️ 这一条**不在 v2.3 四项内**，只作为附带收益记账）。

---

## 5. 与 `PRODUCT_ADVISORY.md` 的差异（我改了什么、为什么）

| # | 建议书说的                                    | 本文改的                                                  | 为什么                                          |
| - | ---------------------------------------- | ----------------------------------------------------- | -------------------------------------------- |
| 1 | 资产表两层模型 = **P0 主题**                      | **已交付**（v2.0），不进 v2.3                                 | 实测 `assets` 表 + `identity_key` + 迁移链 V5 全在（§2.1） |
| 2 | 趋势类功能「建模后变得可能」，未排期                        | **升为 v2.3 主题**                                        | 果实未收（§1.1）                                   |
| 3 | 在线率曲线 / MTBF / 抖动 / 暴露时长散在 §4.3 收益里，无独立条目 | **拆成 §3.2 / §3.3 两项**                                 | 它们依赖不同的数据（聚合 vs 事件），拆开才能独立验收                  |
| 4 | 生命周期字段 = P2                              | **保留为 §3.4（P2）**                                      | 与趋势无依赖关系，放最后；若前三项超期则不占名额                       |
| 5 | 「查询下推 + 分页 + 后台线程」= P1                   | **不进 v2.3**                                           | 实测 `assets` 子命令已有 `--limit/--offset`/过滤；是否真需下推要另跑实证，不塞进本轮占位 |

---

## 6. 顺序

```
1. §3.1 趋势观测层（主题项 · 数据基础）   ← 必做，阻塞 3.2 / 3.3，3.4 借它的迁移
2. §3.2 在线率曲线与稳定性                ← 依赖 3.1
3. §3.3 端口长期暴露时长                  ← 依赖 3.1（同一张 asset_events）
4. §3.4 资产生命周期 + EOL                ← 独立，可插队
```

⚠️ 3.1 未完成前，**不要**开始 3.2 / 3.3 —— 否则会拿 `devices`（会被删）凑曲线，返工。

---

## 7. 一页速览

```
v2.3 主题：A「能看清变化」—— 趋势与生命周期（用户 2026-10-15 四选一选定）
   为什么：资产表 v2.0 就建好了，建议书点名的「趋势类果实」一直没收

├─ 3.1 趋势观测层（独立表 + 事件流，不参与 prune）        P0 ← 主题项  ✅ 已落地
├─ 3.2 在线率曲线与稳定性（MTBF / 抖动 / 首现告警）       P1         ✅ 已落地
├─ 3.3 端口长期暴露时长                                P1         ✅ 已落地
└─ 3.4 资产生命周期字段 + EOL 提醒                      P2         ✅ 已落地

🔴 前置（已答清）：prune(max_keep=20) ⇒ devices 会被删
   ⇒ 趋势必须建在不参与 prune 的新表上（trend_observations + asset_events）

🔴 排期铁律：PRODUCT_ADVISORY.md 优先级表已过时（写于 v1.7.6），
   多条 P1/P2 早已交付 —— 排期前必须实证（见 §2.1）

不做（明确，本文件一次说清）：
  代码签名流水线接线（SignPath）                →  「申请中」，等审批（不占名额）
  只读 HTTP API / Apprise / Prometheus / SNMP trap →  继续出局（开端口 / 加依赖 / 常驻）
  PySide6 迁移                                 →  维持 v2.0 裁定，代价继续记账
  SNMPv1 · DES · IPv6 扫描                     →  维持现状（现行为正确）

状态：§3 四项**全部落地并已发布 v2.3.0**（2026-10-16 收口：
          release 414425872 + 注解 tag v2.3.0；
          产物 IPScanner_2.3.0-win64.zip / IPScanner_cli_2.3.0.exe /
          SHA256SUMS.txt；Release run 38832913623 success、
          CI run 38832909636 十 job 全绿）
```

---

## 8. 决策记录

| # | 问题                        | 决定                                                                                         |
| - | ------------------------- | ------------------------------------------------------------------------------------------ |
| 1 | v2.3 主题选 A / B / C / D     | **选 A「能看清变化」**（用户 2026-10-15 拍板）                                                            |
| 2 | §3 四项是否照本文执行                | ✅ **照本文执行**（用户 2026-10-15 拍板「四项照此执行」，照 v2.2 流程：拍板后才开工）                                      |
| 3 | 3.4 是否占名额                  | ✅ **占名额**（照 §3 原样保留为 3.4，**不**挪到补丁轨道）                                                        |
| 4 | B 的 PDF / 定时投递是否顺带做         | ✅ **不顺带**（「四项照此执行」＝ B 的 PDF / 定时投递**不进本轮**）                                                  |

**下一步**：从 **3.1 趋势观测层**开始落地（它阻塞 3.2 / 3.3，3.4 借它的迁移版本）。

---

## 9. 引用约定

- 引用**建议书**写 `建议书 §4.3` / `§9` 形式；
- 引用**上一轮路线图**写 `ROADMAP_V2.2.md` §2 / `§3` 形式；
- 引用**代码现状**写 `文件:行号`（行号对应基线 `79e9305`，改版后可能漂移）；
- 本路线图**只增不改**已交付项的落地记录；若中途变更取舍，
  **新增一节「§10 变更记录」**写明改了什么、为什么，**不要**回头改写 §1/§3 的验收标准。

---

## 10. 变更记录

### 2026-10-15 · 用户拍板：主题 A + §3 四项照此执行

1. **主题 A「能看清变化」**（四选一：A 能看清变化 / B 能交付 / C 能接进 / D 能站住）。
   选它的核心理由是 §1.1 那条实证：资产表两层模型 v2.0 已建好，
   而建议书点名的「趋势类果实」一个都没收。
2. **§3 四项照本文执行**，不作调整 —— 即 3.4 **占名额**（不挪补丁轨道），
   B 的 PDF / 定时投递**不进本轮**。
3. **前置问题在拍板前已答清**（§4）：`prune(max_keep=20)` 会删 `devices`
   ⇒ 趋势建在不参与 prune 的新表上。这条是 3.1 的核心约束。
4. 落地顺序照 §6：**3.1 → 3.2 → 3.3 → 3.4**（3.1 未完成不开 3.2 / 3.3）。

### 2026-10-15 · §3.1 趋势观测层落地（含**一处偏离**，要对账）

**落地**：新模块 `trend_store.py`（纯计算：零 DB / 零 PyQt / 零 i18n）
+ `history_store` 的 `_SQL_V6`（两张表）+ `save_snapshot()` 挂写入
+ CLI `trend`。测试 `tests/test_trend.py`（36 例）；`trend_store.py` 覆盖 **99%**。

**🔴 偏离**：§3.1 原写 `trend_observations` 含 `new_count` / `gone_count`，
**实际没有这两列**。原因：这两个数只有"上一次快照"能比出来，而那份快照
随时可能被 `prune()` 删掉 —— 于是"新增 0 台"到底是**真没有**还是**基线丢了**，
用户无从分辨（v2.2 §3.4-a 定的"不猜"原则）。
⇒ 交给**事件流**：`first_seen` 天然就是"新出现的身份键"，不需要比上一次。
趋势行只记**规模与在线率**（`total` / `online` / `offline`），这正是曲线要的。

**顺带修掉的一个初版 bug**：`online_ratio_series()` 原用
`sorted(key=lambda x: float(x.get("time")))` —— 一行脏数据就让 `float()` 抛
`ValueError`，**整条曲线**消失；改为先过滤再排序（并加 `_as_int()` 兜底）。

**既有测试的连带修改**（不是"改测试让它过"，是它钉错了东西）：
- `tests/test_history_store.py` 的 `_TABLES` 补两张新表。
- `test_schema_version_is_five` → 改名 `test_fingerprint_migration_is_version_five`：
  它的本意是"指纹落在 v5"，不该钉死 `SCHEMA_VERSION`（那是"最后一版"）。
  当前版本的断言移到 `tests/test_trend.py::MigrationTest.test_schema_version_is_six`。

### 2026-10-15 · §3.2 在线率曲线与稳定性落地（含**两处偏离**，要对账）

**落地**：`trend_store.py` 增 `stability()` / `first_seen_devices()` /
`duration_parts()`；CLI `trend` 增 `stability` / `new_devices` 两块（JSON 键固定英文）；
GUI 新 `ui_dialogs/trend_view.py`（时间窗 + 粒度下拉 + 表格 + 空态下一步）+
分析菜单「在线率趋势...」+ `HistoryMixin._show_trend_view()`。
测试 `tests/test_trend.py` 增至 **52** 例（`trend_store.py` 覆盖 **99%**）。

**🔴 偏离 ①：按网段曲线本轮未做。**
§3.2 做法 #1 写「支持全局与按网段（网段从 `ranges_json` 拆）」，
**实际只做了全局曲线**。原因：`trend_observations` 存的是**每次扫描的全局聚合**
（一行一个 `total` / `online`），**没有按网段的拆分** —— 一次扫多个网段时，
拆不回"某个网段自己的在线率"。要做对，得让趋势写入端**按网段各记一份计数**
（改 `ranges_json` 形状或加列），属独立改动。**宁可不做，也不给会误导的曲线**
（把 A+B 的合计标成"网段 A 的在线率"，比没有更糟 —— 违反"只陈述事实"红线）。

**🔴 偏离 ②：趋势元数据列生产路径不写。**
§3.1 给 `trend_observations` 定了 `ranges_json` / `ports_scanned` /
`duration_s` / `source` 四个元数据列，但**生产代码没有一个调用方传 `trend=`**
（`grep -rn "trend=" --include=*.py` 只命中 `save_snapshot` 的定义与测试）。
即 `save_snapshot()` 默认写的那一行里，这四列恒为空 / `None`。
⇒ 影响：曲线本身**不受影响**（`total`/`online`/`offline` 是从 `devices` 现算的），
但 `source`（cli/gui）等列目前是**死数据**；这也是偏离 ① 无法落地的前置原因。

**处理**：两处**同一根因**（趋势写入端没拿到扫描上下文）。建议作为
**独立的小改动**收口：CLI `scan --save-snapshot` 与 GUI `_save_snapshot()`
各自把 `ranges` / `ports_scanned` / `duration_s` / `source` 传进
`save_snapshot(trend=…)`，之后按网段曲线才有数据基础。
**不占 §3 四项名额**，可与 3.3 / 3.4 并行，或另开补丁轨道。

### 2026-10-15 · §3.2 两处偏离收口（用户拍板「先处理那两处偏离」）

**结论**：偏离 ① 与 ② 是**同一根因**（趋势写入端没拿到扫描上下文），
所以一次收口；上一条的"处理"建议按原样执行，另把按网段曲线一并做完。

**改了什么**：

1. 🔴 `ranges_json` 的形状从「网段名列表」改成「每网段计数」
   `[{"range", "total", "online"}]`（`history_store._range_counts()`）。
   这是**必须**的：只写网段名，按网段曲线**根本无法实现**（读端拆不回单网段）。
   因为是 JSON 列，**不需要迁移** —— `_SQL_V6` 的列定义不变，只是内容变。
2. CLI `_scan_trend_meta()` / GUI `scan_mixin._scan_trend_meta()`：四条生产落库
   路径全部带上 `trend=`（`scan` / `diff` 带 ranges + ports + duration；
   `import` / `watch` 带 source）。
3. `trend_store`：`row_range_counts()` / `range_names()` /
   `online_ratio_series(range_name=…)`；新 `REASON_NO_RANGE_DATA`。
4. CLI `trend --range`、GUI「范围」下拉（首项恒为「全部网段」）。

**一处刻意的设计选择（记账）**：GUI 的「范围」下拉在**用户选的网段于新窗口
消失时保留该选择**（而不是静默切回「全部网段」）。否则 `REASON_NO_RANGE_DATA`
在 GUI 里是**不可达的死代码**；保留选择后用户能看到"这个网段在这个窗口内
没有数据"的说明，选择也不会被无声抹掉。

**验收**：`tests/test_trend.py` 74 例；`trend_store.py` 覆盖 **100%**；
`ScanTrendWiringTest` 专门守住"元数据真的传下去了" —— 这是最容易悄悄退化的点
（不接线时全局曲线照常，只有按网段曲线空着，肉眼极难发现）。

**遗留**：无。原偏离 ① 的"宁可不做也不给会误导的曲线"从此刻起不再适用 ——
现在给的是**按网段各算各的**真值，不是把全局合计贴上网段标签。

### 2026-10-15 · §3.3 端口长期暴露时长落地

**落地**：`trend_store.port_exposure()`（纯计算，事件重放）+
`history_store.asset_identity_key()`；CLI 挂在 `trend` 下（新 `port_exposure`
JSON 键 + 表格一节）；GUI 在**设备详情面板**加「端口暴露」分区
（`MainWindow._port_exposure_for()`）。测试 `tests/test_trend.py` 105 → **135** 例。

**🔴 一处对 §3.1 的有意修改（记账）：首次观测时会补一条 `baseline` 端口事件。**
`_build_asset_events()` 原先对"首次见到的设备"只写 `first_seen` 就 `continue`，
端口一行不写。这样**长期不动的端口**（**正是 §3.3 要回答的那一类** ——
「这个 23 端口开了两年」）在事件流里完全没有记录，功能等于空的。
现在改成：首次观测时**已经开着**的端口也记一条 `port_open`，
但 `detail_json` 里带 `baseline: true` —— 语义是
**「我们第一次看到它时它就是开着的」，不是「端口此刻开了」**。
所以消费方必须显示成「**至少** N」（真实开放时刻只会更早）。
⚠️ 这条改动**动了 §3.1 已落地的写入行为**，连带改掉 3 个 §3.1 的断言
（`test_first_seen_written_once_per_device` /
`test_port_close_and_open_only_cover_real_ports` /
`test_no_port_event_when_nothing_changed`）—— 它们原先钉的正是"首扫只写一行"。

**一处刻意的放置选择（记账）**：CLI **没有**新开 `exposure` 子命令。
`scanner/exposure.py` 已经是「banner → 候选 CVE 匹配」，叫 `exposure`
会让「端口暴露时长」和「漏洞暴露面」两件事在用户脑子里混在一起；
`trend` 本就是「这段时间网络变成了什么样」的入口，挂它下面语义连贯。

**一处顺带的提取（记账）**：时长单位表从 `ui_dialogs.trend_view` 提到
`ui_utils`（`DURATION_UNIT_TEXT` / `format_duration()` / `format_exposure_rows()`）。
理由：`detail_panel` 现在也要显示时长，两份实现必然漂移。
`cli._fmt_duration` **刻意不共享** —— CLI 不 import `i18n`、输出恒为中文，
共享会让 CLI 的输出随界面语言漂移。

**验收**：`tests/test_trend.py` **105** 例全绿（+31）；全量 **2685 OK**；
`trend_store.py` 覆盖 **100%**（门禁 90）、`history_store.py` **96%**（门禁 95）。

**⚠️ 一次 CI-only 红（已修，记账）**：本机 `run_tests.py` 2684 OK 全绿，
推上去 CI **7 个 job 全红**（ubuntu / macos / Windows 3.10–3.13 / 覆盖率门禁）——
`DetailPanelExposureTest` 里 `assertIn("至少", text)` 钉了**中文字面量**，
而 CI runner 的 locale 是 **en-US**（`i18n.init(None)` 解析成英文），
`tr()` 在那里返回 `at least`。触发链比"locale 不同"更具体：
`CliPortExposureTest` 调了 `cli.main()`，而 **`cli.main()` 会
`i18n.init(None)`**，把**整个进程**的语言切成 en-US。
修法：断言改成经 `tr()` 推导的**确切**文本，并补一条**两种语言都跑**的守卫
（`test_baseline_wording_holds_in_both_languages`）让本机就能复现。
🔴 教训：本机 zh-CN + CI en-US ⇒ 语言相关的缺陷**本机测不出来**，
与「只在别的平台上错」是同一类；GUI 断言一律 `tr("…")` 或语言无关量。

### 2026-10-16 · §3.4 资产生命周期字段 + EOL 提醒落地

**落地**：新模块 `asset_lifecycle.py`（纯计算：零 DB / 零 PyQt / 零 i18n /
零三方，AST 守卫钉死只许 import `datetime`/`json`/`re`）
+ `history_store` 的 `_SQL_V7`（`SCHEMA_VERSION = 7`，`assets` 加 6 列）
+ `update_asset_lifecycle()`（🔴 漏 `conn.commit()` 的坑见下）
+ CLI `assets --warranty-days N` / `assets --set <键/MAC/IP> --field K=V`
+ GUI 详情面板「资产信息」分区 + `ui_dialogs/asset_edit.py`
+ `library_mixin._edit_asset` 接线（写入在宿主，对话框不碰库）。
测试：`tests/test_asset_lifecycle.py`（87 例）+ `tests/test_asset_edit_dialog.py`
（27 例）；`asset_lifecycle.py` 覆盖 **100%**（CI 门禁 95）。

**🔴 迁移的坑（记账）**：v7 **只加列不建表** ⇒ `_LEGACY_TABLES` 必须用
**列标记** `("assets", "custom_json", 7)`，照 v5 `("assets", "fingerprint", 5)`
的先例。用表名标记会让老库推断版本偏低 → 重放 `ALTER TABLE` →
`duplicate column name` → **库打不开**。
`test_every_migration_can_be_inferred_from_a_table` 守着这条不变式。

**🔴 抓到一个真 bug（单测没覆盖到，记账）**：`update_asset_lifecycle()`
首版漏了 `conn.commit()`。`db_util.connection()` 只是「取单例连接 + 加锁
yield」，**不代提交** —— 同进程内紧接着读同一把缓存连接**能读到**，
所以单测全绿；进程一退出改动就没了。修法：显式 commit +
补一条「`close_connection()` 之后**再新建连接**读」的回归用例
（读缓存连接等于没验）。

**两处刻意的不共享（记账）**：① 保修状态文案表在 `ui_utils.WARRANTY_STATUS_TEXT`
与 `cli._WARRANTY_STATUS_TEXT` 各一份 —— CLI 不 import i18n、输出恒为中文，
共享会让 CLI 输出随界面语言漂移（与 §3.3 的 `format_duration` 同款理由，
各有一条测试守着两表的键集合同步）；② `format_warranty` 的日期行与状态行
分开 —— 「正常」是默认预期，每台都印「正常」只是噪音，而「即将到期」必须显眼。

**验收**：四条全部满足 —— ① 旧库经 v7 升级不丢数据（迁移测试守着）；
② `custom_json` 键原样存取不翻译（`normalize_custom_json` + 面板显示测试）；
③ 保修按本地时区推导（`_as_local_date()` 用 `fromtimestamp()`，
断言同时区推导，见 §3.4 原文要求）；④ 未填 = `unset` 状态，
**绝不**显示「已过期」（`test_unset_warranty_never_shows_expired` 钉死）。
