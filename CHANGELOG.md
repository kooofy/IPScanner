# Changelog

本项目所有值得注意的改动都记录在这里。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

**版本号约定**：`1.7.x` 是发布线 —— 功能与修复都走 `1.7.N` 递增，minor 位不当
「新功能」用（见 `version.py` 的说明）。一次发布 = 一个 `chore(release): 1.7.N`
提交 + 一个 `v1.7.N` tag + 一个 GitHub Release。

---

## [Unreleased]

v1.8 的四项已全部落地（定位查询 / 被动发现 / 历史查询后台化 / 发布与可见性包），
见 [`docs/ROADMAP_V1.8.md`](docs/ROADMAP_V1.8.md)。

### 新增
- **随机化 MAC 识别 —— 不让「隐私 MAC」把台账变成噪声**（路线图 §3 耦合提示 #11）。
  手机默认开启「私有 Wi-Fi 地址」，每次接入换一个随机 MAC；只按 MAC 认设备的台账
  会把它反复报成「新设备」。现在变更检测先用**设备指纹**把同一台设备认回来，
  新增的「随机 MAC 重现」变更（提示级）取代原先的「新增设备 + 设备消失
  （同 IP 时还有「设备被替换」）」三连假阳性。被动发现的「新出现」也过了同一道指纹关。
  - 判据是 MAC 首字节的 **LAA 位**（本地管理地址）—— 随机 MAC 的硬信号。它只是
    **必要不充分**条件（少数虚拟网卡也用 LAA），所以一定还要指纹一致才判定「同一台」。
  - **指纹只认身份锚点**（主机名 / 厂商 / 型号 / 序列号），**不**用设备类别、操作系统、
    服务这些上下文字段：它们在整网里被大量设备共享，会把两台同型号设备并成一台。
    「错认」比「漏认」严重得多，所以信号不足时**不猜**，如实报新增/消失。
  - 同一 IP 上换成另一个随机 MAC、又没取到可核对的指纹时，不再断言「设备被替换
    （严重）」—— 两边都是 LAA 时这个结论站不住脚，如实降级为提示并写明「未判定是否同一台」。
- `device_fingerprint.py`：设备指纹与随机 MAC 判定（纯标准库、零 Qt）。
- `history_store.latest_devices()`：最近一次快照的**设备列表**（被动发现基线；比只要 IP
  多出主机名 / 厂商，供指纹比对用）。
- **被动发现 —— 不发任何网络包地看「最近谁在我身边出现过」**。命令行
  `ipscanner watch`（默认单次轮询；`--interval` 持续轮询、`--count` 限次、
  `--fail-on-change` 有新设备时退出码 2）；GUI 在「设置 → 持续发现」开关
  （**默认关**），打开后每 30 秒在后台线程轮询一次，新出现的设备自动并入列表。
  - 数据来源是本机 **ARP 表整表**（Windows `arp -a` / Linux `/proc/net/arp` /
    macOS `arp -an`）与 **mDNS 组播监听**。默认走**只听模式**：
    绑 5353、加入组播组、只收不发 —— 一个包都不发，不惊动 IDS 与流量审计。
    需要更全的发现能力时才用 `--mdns-active` 显式开启主动查询（那会发组播包）。
  - **只报「新出现」，不报「消失」**：ARP 条目会过期，设备从表里消失不等于它下线了，
    报「消失」是假阳性。宁可不说，也不给用户一份会自己造谣的台账。
  - **默认不写快照**：快照有 20 条硬上限，持续轮询每周期写一条会在十分钟内把真实
    扫描历史全冲掉。要落库必须显式 `--save-snapshot`，且与 `--interval` 互斥。
  - 「新出现」的基线取自最近一次快照的设备 IP 集合，即「上次扫描之后新冒出来的设备」。
- `history_store.latest_device_ips()`：最近一次快照的设备 IP 集合（被动发现的基线）。
- `mdns_discover(listen_only=True)`：mDNS **只听模式**（零发包）。5353 被系统
  mDNS/Bonjour 占用时如实记 warning，而不是静默返回空。
- **设备定位 —— 回答「这台设备插在哪台交换机的哪个口」**，并给出与上一次相比
  **是否换过端口**。GUI 入口在「分析 → 设备定位...」（`Ctrl+L`）；命令行
  `ipscanner locate --mac AA:BB:CC:DD:EE:FF`（`--ip` / `--hostname` 二选一，
  支持 `--format json`）。
  - 匹配**优先用 MAC**：IP 会被 DHCP 回收后分配给另一台机器，MAC 才是设备身份。
  - **查不到时不猜**，而是区分四种「不知道」并给出下一步动作：从未采集过转发表 /
    采集了但交换机都读不到 / 转发表里没有这台设备 / 历史库里根本没有它。
  - 端口名只有桥接端口号（交换机不支持 BRIDGE-MIB 的 `ifName`）时标注「不可信」，
    不把它当成 `GigabitEthernet0/5` 糊弄过去。
  - 命令行下「未定位到」的退出码是 **4**（查询本身成功，是一个合法结论而非错误）。
- 扫描选项新增 **「读取交换机转发表」**（命令行 `--switch-map`），**默认关闭**：
  勾选后扫描末尾经 SNMP 读各交换机的 BRIDGE-MIB 转发表，随快照落库 —— 这是定位查询
  唯一的数据来源。默认关闭是因为每台交换机要 5 次 SNMP walk，且会在网络里产生额外的
  SNMP 流量（延续「不惊动 IDS」的一贯取舍）。
- 历史库新增 `switch_map` / `port_map` 两张表（带 `snapshot_id` 外键 + `ON DELETE
  CASCADE`，裁剪旧快照时自动清理），以及按 MAC 查最近端口的索引。

### 变更
- `cli.py` 顶部帮助的退出码说明补上 `4`（`locate` 未定位到）。
- README 命令行章节补上 `locate`、`--switch-map` 与 `watch` 的用法；退出码表新增 `4`。

## [1.7.7] - 2026-10-10

### 修复
- **历史条件查询不再冻住界面**。查询原本同步跑在 GUI 线程，8 万行量级要 2.5 秒，
  期间窗口完全无响应；现已搬进后台线程，并带进度提示与「停止」。
  实测全量查询 2562 ms → 1363 ms。
- 历史对比对话框不再一次性把所有快照的设备明细读进内存，改为按需读那两份。

### 新增
- **历史查询分页**：每页 500 行 +「加载更多」；**导出始终是完整结果**，不受分页影响。
- 历史查询的**网段 / IP 子串过滤下推到 SQL**，结果与 Python 侧逐行等价（有对拍测试）。
- `CHANGELOG.md`（本文件）。
- `.github/workflows/release.yml`：推 `v*` tag 自动跑测试、构建两个包、生成
  `SHA256SUMS.txt` 并创建 Release；构建前会校验 tag 与 `version.py` 一致。
- `CODE_SIGNING_POLICY.md` / `CODE_OF_CONDUCT.md`：代码签名政策（含签名批准角色）与
  贡献者行为准则 —— 为申请免费代码签名做准备。

### 文档
- README 首屏改为三句话，并新增「横向对比」小节（对照 Advanced IP Scanner /
  SoftPerfect / Total Network Inventory），其中**如实列出本项目短板**。
- 新增 [`docs/SIGNPATH_APPLICATION.md`](docs/SIGNPATH_APPLICATION.md)：免费代码签名的
  申请材料、提交前的准备清单、拿到证书后接入 `release.yml` 的位置。
- 新增 [`docs/ROADMAP_V1.8.md`](docs/ROADMAP_V1.8.md)：v1.8 路线图（15 项砍到 4 项）。
- 新增 [`docs/PRODUCT_ADVISORY.md`](docs/PRODUCT_ADVISORY.md) 产品建议书，以及
  [`docs/reviews/PRODUCT_ADVISORY_REVIEW.md`](docs/reviews/PRODUCT_ADVISORY_REVIEW.md)
  对其 17 项实测声明的逐条复核（1 处勘误）。

## [1.7.6] - 2026-10-10

### 变更
- `ui_dialogs.py`（1995 行 / 12 个对话框）拆为 `ui_dialogs/` 包（8 个子模块 +
  `__init__.py` re-export 门面），全仓最大文件降到 484 行。四个 Mixin 与全部既有测试的
  `from ui_dialogs import X` 导入面**一行未改**；拆分为逐字节搬迁，无逻辑改动。
  （关闭 `docs/reviews/CODE_REVIEW.md` 的 P1-4）

### 修复
- 修正 `docs/reviews/` 归档中「macOS / Linux CI 未做」的错误结论 —— 三平台 CI 实由
  `db84b58` 落地，只是归档时漏查。

## [1.7.5] - 2026-10-09

### 新增
- 拓扑发现改为**四档逐级退化**（LLDP/CDP 骨干 → BRIDGE-MIB 转发表接入关系 →
  已识别但无链路 → 网段分层）；交换机没开 LLDP/CDP 时，靠转发表仍能还原
  「终端挂在哪个物理口」。每一档都在图例里写明原因，不编造链路。

### 文档
- 历次代码 / 界面评审归档到 `docs/reviews/` 并标注「已关闭」。

## [1.7.4] - 2026-10-09

### 修复
- 拓扑视图只画在线设备 + 同心环自适应，修掉千台规模下的摩尔纹。
- 导出扫描结果跟随当前筛选，与「打印」的口径一致。

## [1.7.3] - 2026-10-09

### 修复
- 「扫描本机所在子网」等三个入口点击后真的开始扫描。

## [1.7.2] - 2026-10-09

### 新增
- **风险列**：每台设备一个 0–100 的服务暴露面评分（明文 Telnet/FTP/TFTP、无认证 VNC、
  SNMP v2c 团体字、"只有 HTTP 没有 HTTPS"、MAC/主机名冲突），悬停可看分数怎么加出来的。
- 首次启动的一次性授权声明弹窗（`CODE_REVIEW` P2-14）。
- **设计令牌**：圆角 / 间距 / 行高的唯一刻度（两档）。
- 扫描态摘要条（阶段 / 已扫 / 在线 / 有服务 / 用时 / 停止）。

### 变更
- 对话框配色收进令牌；空状态页与概览仪表盘打磨。
- 集中式对话框本地化 + 列宽按语言分流。

### 移除
- 死代码 `MainWindow._muted_color()`。

### 修复
- 「列数与表头不一致」引发的随机段错误。
- 「载入期回写」重置用户设置的 bug。
- macOS 上 `QMessageBox` 标题断言失败（CI `macos-latest`）。

### 文档
- 修 README 的 SNMP 版本矛盾；补「Windows 未知发布者 / 杀软误报」的处置说明。

## [1.7.1] - 2026-10-09

### 新增
- 界面层改造（P0–P3 共 13 项）。

### 修复
- 补齐主题刷新与本地化（批次 1）。
- 时间线用例硬编码本地日期，在 CI（UTC）上必挂。

### 文档
- 第二轮界面改造验收报告（对 `638c462` 的 13 项复核）。

## [1.7.0] - 2026-10-08

### 新增
- CLI 的 SNMPv3 参数（`--snmpv3-user` 等）；口令**只从环境变量读取**，不进 argv。
- WMI 传输在 DCOM 失败后自动回退 WinRM。

### 变更
- 代码评审后的一轮改进（性能、可扩展性、健壮性）。

### 修复
- 非 UTF-8 代码页下 CLI 输出中文崩溃（CI 冒烟测试挂掉）。
- RTT 计时改用 `perf_counter`（`monotonic` 在 ≤3.12 上只有 15.6 ms 精度）。
- 消除测试对「当前语言」的依赖（CI 四个解释器版本全挂）。
- `PyQt5-Qt5` 按平台分流（macOS arm64 没有 5.15.2 的 wheel）。

## [1.6.0] - 2026-08-04

### 变更
- 拆分 `MainWindow` 为多个 Mixin，并抽离纯逻辑与 DB 工具（为可测试性铺路）。

## [1.5.0] - 2026-07-28

### 新增
- macOS / Linux 适配、OUI 库自动更新、CDP/LLDP 真实拓扑。

## [1.0] - 2026-07-22

### 修复
- `oui.db` 作为只读资源打入 exe（`resource_dir` + `add-data`）。

---

[Unreleased]: https://github.com/kooofy/IPScanner/compare/v1.7.7...HEAD
[1.7.7]: https://github.com/kooofy/IPScanner/compare/v1.7.6...v1.7.7
[1.7.6]: https://github.com/kooofy/IPScanner/compare/v1.7.5...v1.7.6
[1.7.5]: https://github.com/kooofy/IPScanner/compare/v1.7.4...v1.7.5
[1.7.4]: https://github.com/kooofy/IPScanner/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/kooofy/IPScanner/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/kooofy/IPScanner/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/kooofy/IPScanner/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/kooofy/IPScanner/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/kooofy/IPScanner/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/kooofy/IPScanner/compare/v1.0...v1.5.0
