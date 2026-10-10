# 同类产品调研：开源 / 自建 / CLI 梯队

> 调研伙伴文件，服务于 `docs/PRODUCT_ADVISORY.md` 第 3、4 节。
> 方法：直读官方文档与仓库（该细分领域的搜索结果质量差，故以一手文档为准）。
> 未能当场验证的结论标 **[未验证]**。仓库活跃度取自 GitHub API（2026-10-09）。
>
> 原作者：本次评审的调研子代理；本文件由主评审整理归档。

---

## 1. 扫描器 / 安全邻接

| 工具 | 最强的地方 | 发现方式与数据模型 | 值得学/可集成 | 痛点 | 接口面 |
|---|---|---|---|---|---|
| **Nmap / NSE** | 端口/服务/OS 指纹的事实标准；脚本引擎能描述任何"网络形状"的任务 | 无数据库、无历史 —— 只产出扫描制品。服务探针在 `nmap-service-probes`，脚本索引在 `script.db` | **把 XML（`-oX`）作为交换格式**，DTD 见 [nmap.dtd](https://svn.nmap.org/nmap/docs/nmap.dtd)；`-oA` 一次出全部格式；`-oG` grepable 已弃用；`--resume` / `--append-output` / strftime 文件名 | 命令不直观；脚本**没有沙箱**（文档明确警告）；Zenmap 只是随附的旧查看器 | 5 种输出格式；[XML 是首选的程序化格式](https://nmap.org/book/man-output.html) |
| **NSE 脚本分类** | 便宜、社区维护的检查集 | 分类 `auth/broadcast/brute/default/discovery/dos/exploit/external/fuzzer/intrusive/malware/safe/version/vuln`；阶段 prerule/host/service/postrule | 抄它的 **default vs intrusive 分类法**与 `default` 入选标准（速度/有用性/啰嗦度/可靠性/侵入性/隐私）；`broadcast` + `newtargets` 可让脚本把新发现的主机加进队列 | `--script all` 很危险；脚本参数是全局命名空间 | `--script "default and safe"`、通配符、`--script-args`、`--script-help`（可 XML 输出）；[用法](https://nmap.org/book/nse-usage.html) |
| **arp-scan** | 本地子网最快最全的 L2 发现 | 无状态，每个目标一个 ARP 请求；厂商解码来自 `ieee-oui.txt`（由 IEEE MA-L/MA-M/MA-S/IAB 生成）**外加上一层用户覆盖文件** `mac-vendor.txt` | **`--format` 具名字段** `${ip} ${mac} ${vendor} ${rtt} ${vlan} ${dup} ${name}` —— 用户不改代码就能得到 CSV/JSON；`--plain` 供脚本；`--limit N` 不达标返回 **exit 1**（可用于"探活"判定）；用 `setcap cap_net_raw+p` 代替 SUID root | ARP **不可路由**（只能同子网，第一大支持问题）；需 CAP_NET_RAW；默认 256 kbit/s 在 /16 上很慢 | `--format`、`--ouifile`、`--macfile`、`--pcapsavefile`、退出码；[man page](https://manpages.ubuntu.com/manpages/resolute/man1/arp-scan.1.html) |
| **Angry IP Scanner** | 免安装跨平台 GUI，且有 fetcher 插件 API | 无历史/无库，结果表是临时的；Java，GPL-2.0 | 它的 **fetcher 插件模型**是可借鉴的扩展先例；目标输入支持"网段 / 随机 / 任意格式文件" | 依赖 Java 运行时；官网新闻停更（最后 2019，"招 Mac 维护者"）；**205 个未关闭 issue** vs 5 145 star | "导出多种格式"，有 CLI 但次要；[angryip.org](https://angryip.org/) |
| **Greenbone / OpenVAS** | 免费完整的漏洞管理栈 | PostgreSQL 里的资产+任务+报告模型；结果基于 CVE/NVT | 不是发现类同类，只作为**风险评分词汇表**的参考 | 社区容器栈多服务、难伺候；社区 feed 落后企业 feed **[具体差异未验证]** | GMP（XML over TLS）+ 较新的 REST；[社区文档](https://greenbone.github.io/docs/latest/) |
| **Nuclei** | 模板驱动的检查 + 真正的严重级别模型 | 无资产库；按次产出发现。YAML 模板、可签名；severity ∈ `info/low/medium/high/critical/unknown` | **严重级别词汇 + SARIF 导出**可作风险评分的参考；用 `-sign`/`-dut`（禁用未签名模板）代替"任意插件代码" | 作者自己警告它是 CLI 工具，"以服务方式运行 nuclei 有安全风险"；模板需持续更新 | `-j/-jsonl`、`-je`、`-me` markdown、**`-se` SARIF**、`-pe` PDF、`-rdb`；`-rate-limit`（默认 150/s）；`-lna` 阻止扫描私网；[文档](https://docs.projectdiscovery.io/opensource/nuclei/running) |

## 2. 监控 / NMS

| 工具 | 最强的地方 | 发现方式与数据模型 | 值得学/可集成 | 痛点 | 接口面 |
|---|---|---|---|---|---|
| **LibreNMS** | 零配置自动发现的广度（数百种 OS）+ 巨大的告警矩阵 | SNMP 轮询；**RRDtool 时序** + MySQL；采集 VLAN/**ARP/FDB**；设备列表即事实来源 | **ARP + FDB 采集 + "配置备份集成（Oxidized/RANCID）"** —— 证明"资产 + 备份"是一个工作流；已验证能力：自动发现、告警、ARP/VLAN/FDB、分布式轮询、NetFlow/sFlow/IPFIX、syslog、计费、API、自动更新 | 要运维 PHP/MySQL/RRD 栈；告警噪声；OS 支持矩阵是无底洞 | REST API 分类 `Devices/ARP/Inventory/Locations/Logs/Ports/Switching/Routing/PortSecurity/Alerts`；**40+ 告警传输**（Slack、Teams、PagerDuty、Alertmanager、**Snmptrap**、Syslog、通用 webhook）；指标可导出到 Graphite/InfluxDB/OpenTSDB/**Prometheus**/Kafka；[特性](https://docs.librenms.org/Support/Features/)、[传输](https://docs.librenms.org/Alerting/Transports/)、[API](https://docs.librenms.org/API/) |
| **Observium** | "它自己就把一切发现出来并画成图"，工程师几乎不用介入 | SNMP 轮询、RRD；**CDP/LLDP/FDP/AIP** 拓扑；458+ OS | 它的分档表是**警告而不是模板**：Community（免费、QPL、**半年一次 tarball**）vs Pro £250/年 vs Enterprise £1500/年 | 免费档被刻意削弱到无法真运维：实时更新、网络图、规则分组、BFD/IP-SLA/QoS、STP、路由协议指标、REST API、多服务器扩展都在付费列；Traffic Accounting 与阈值告警明确标 "Professional Edition" | REST API（付费档）；RANCID/collectd/munin/smokeping 集成；[observium.org](https://www.observium.org/) |
| **Zabbix** | 工业规模的 agent+agentless 监控 + 模板复用 | MySQL/PostgreSQL/TimescaleDB；**history + trends** 表；模板即配置数据 | **LLD（低层发现）是最值得抄的一个概念**：发现规则返回 JSON，item/trigger/graph/**host prototype** 自动建对象。LLD 来源包括 SNMP walk、**WMI 查询**、ODBC SQL、**Prometheus 数据**、JMX、IPMI、服务列表 + JSONPath 预处理 | 学习曲线与 UI 复杂度是长期抱怨；模板泛滥；数据库容量规划重 | JSON-RPC API（`host.get`/`item.create`/`configuration.export/import`）；支持 JS 的 webhook 媒介类型；**导出文件、流向外部系统、SNMP gateway**；[LLD 文档](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery) |
| **Nagios / Icinga** | 整个行业至今仍在说的"插件契约" | Nagios Core 是扁平配置文件；Icinga 2 加了 DSL + Director/DB | **逐字采纳插件契约**：退出码 `0 OK / 1 WARNING / 2 CRITICAL / 3 UNKNOWN`、只写 stdout、首行 <80 字符、`-v` 最多 3 级、保留选项 `-V -h -t -w -c -H -v -C -l`、10 秒运行预算、阈值区间 `[@]start:end` | 配置文件泛滥、靠手工编辑对象定义；无原生发现 | **Perfdata**：`'label'=value[UOM];[warn];[crit];[min];[max]`；NRPE、被动检查；[指南](https://nagios-plugins.org/doc/guidelines.html) |
| **The Dude（MikroTik）** | 免费自动发现 + 实时网络图 + 逐设备探测 | 专有二进制；本地存储 + 可选服务端 | 它的自动成图 UX 是小工具**现实可超越**的 | **已官方停止开发。** MikroTik 原文："development of Dude has been officially discontinued, and the software is now classified as legacy… no further updates or enhancements are planned" —— [RouterOS 7.26 手册](https://manual.mikrotik.com/docs/management-tools/dude/) | 无现代化接口 **[未验证]** |
| **Prometheus + snmp_exporter / blackbox_exporter** | 拉取式指标成为通用语；exporter 是薄适配层 | TSDB（无资产概念）；目标来自配置/服务发现 | **提供一个 `/metrics` 端点 + 文本暴露格式**（按站点/厂商/角色打标签），画图交给别人；也可产出 `snmp_exporter` 风格的目标列表 | 基数爆炸；超出保留期无历史；配置重载；SNMP exporter 需生成配置 | OpenMetrics 文本；Alertmanager webhook |

## 3. IPAM / DCIM 事实来源

| 工具 | 最强的地方 | 数据模型 | 值得学/可集成 | 痛点 | 接口面 |
|---|---|---|---|---|---|
| **NetBox**（v4.7.2，Django，Apache-2.0） | 经过人工整理的网络事实来源 | 关系型 DCIM+IPAM：region/site/location、机架/设备/组件、线缆/无线、电源、线路、VM/集群、prefix/range/**IP**、VRF、FHRP、ASN、VLAN、L2VPN、租户、联系人 | **它完全没有发现能力 —— 这正是 IPScanner 的入口。** 导出**已解析外键**的 CSV（manufacturer → device_type → role → site → device → interface → IP），把扫描器元数据放在 **custom fields**，用 **export template** 做可重复导出 | "任何设备都存在之前必须先建好整条外键链"是它最被抱怨的上手难点；"NetBox 不是发现工具" | **REST + GraphQL**、custom fields、export templates、**event rules（webhook）**、插件；UI 批量 CSV 导入；[文档](https://netboxlabs.com/docs/netbox/) |
| **Nautobot** | 面向"一切皆代码"的 NetBox 分支 | 同核心 + Git 作为数据源、Jobs 框架、Golden Config / SSoT | 它的 **Jobs + Git 数据源**是"配置即仓库、可评审"的范式；SSoT 作业模式 = 扫描器导入、人来评审 | 比 NetBox 重；生态小 | REST/GraphQL + Jobs API + webhook |
| **phpIPAM** | 自带扫描的轻量 PHP IPAM | MySQL；section/subnet/address + 扫描模块 | "IPAM 里带扫描"是被默认期待的能力 | **1 846 个未关闭 issue** vs 2 812 star，API 检测不到 license 文件 —— 可持续性风险 | REST API；[phpipam.net](https://phpipam.net) |

## 4. 配置备份与自动化

| 工具 | 最强的地方 | 数据模型 | 值得学/可集成 | 痛点 | 接口面 |
|---|---|---|---|---|---|
| **Oxidized**（Ruby，Apache-2.0，3 604★，71 open issues，活跃） | 现代版 RANCID；带版本的配置 diff | **Git/SVN/HTTP/SQL 输出**即配置版本历史；来源支持 CSV/`router.db`、SQL、HTTP | **从 IPScanner 的发现结果导出 `router.db` CSV（`host:model`）** 当天就能启用备份；取回某节点最新配置即可 diff「运行配置 vs 上次已知」 | 设备型号无底洞（各 OS 的提示符/分页怪癖）；**需要写权限凭据**，你未必有 | Node API（取最新版本/入队）+ web UI；diff 通知钩子 **[具体端点未验证]**；[ytti/oxidized](https://github.com/ytti/oxidized) |
| **RANCID** | 元祖；至今仍被 LibreNMS/Observium 内嵌 | CVS/SVN 工作副本；cron 驱动；邮件发 diff | 它的 **`router.db` + `.cloginrc`** 是被两家共同消费的最小公约数 | Perl + CVS 血统、几乎无 API、邮件 diff 噪声、凭据散落 | 只有文件 + 邮件；[LibreNMS RANCID 集成](https://docs.librenms.org/Extensions/Rancid/) |
| **NAPALM / Netmiko / Nornir** | Netmiko 是 SSH 传输、NAPALM 是厂商无关的 getter/setter、Nornir 是清单+任务编排 | NAPALM 的 **getter**（`get_facts`/`get_interfaces`/`get_arp_table`/`get_lldp_neighbors`）是一套合理的归一化设备模型 | **字段名尽量向 NAPALM getter 对齐**，扫描结果就能直接落进既有自动化 | NAPALM 175 open issues、最后推送 2026-08-12（**在放缓**）、驱动质量参差 | 仅 Python API；ntc-templates/TextFSM 解析 |

## 5. 新进者（2024–2026）

**NetAlertX** 是**最接近 IPScanner 的开源对照物**，也是最该研究的对手：Python、GPL-3.0、
**7 259 star**、仅 **25 个未关闭 issue**、最后推送 2026-10-09（Pi.Alert 的继任者）。

- **最强的地方**："已连接设备的事实来源" + 影子 IT / 未知设备告警，不需要 NMS。
- **发现方式**：插件对接 **arp-scan**、Pi-hole 数据库与 DHCP 租约导入、通用 DHCP 租约、
  **UniFi 控制器导入**、**SNMP 路由器导入** —— 也就是**借别的系统的租约数据**，不只靠自己扫。
- **数据模型**：`/data/db` 下的本地 SQLite；存在性/事件历史 + 变更检测。仓库话题带
  `ipam` / `dcim` / `asset-management`。
- **该抄的**：**Plugins API**（官方口号"15 分钟写一个自己的扫描器"）、**Workflows**
  （新设备自动归站点、按厂商自动分组、再次出现自动取消归档、N 天后自动删除）、
  **Sync Nodes**（多站点/VLAN 汇聚、中心告警）、**Prometheus 指标导出**、
  面向 n8n 的 webhook、**基于 Apprise 的 80+ 通知服务**。
- **它自己承认的痛点**：ARP 扫描器"可能发现不了别的子网的设备"；纯 Wi-Fi 网络需要换扫描器；
  规模上来需要通知节流；需要 `CAP_NET_RAW/NET_ADMIN`；**没有内置鉴权**（RBAC 推给反向代理）。
- **接口**：REST + **GraphQL（20214 端口）** + Prometheus 指标 + webhook；
  [文档](https://docs.netalertx.com/)、[指标](https://docs.netalertx.com/API_METRICS/)、
  [Workflows](https://docs.netalertx.com/WORKFLOWS)、[插件](https://docs.netalertx.com/PLUGINS_OVERVIEW)。

**Netdisco**（Perl/Python + PostgreSQL，927★，BSD-3，活跃）—— 开源里最好的 L2 拓扑/资产模型：
SNMP/CLI/设备 API 采集；**"用 MAC 或 IP 定位一台机器，并给出它所在的交换机端口"**；
**系统 IP 与位置的历史数据**；端口/VLAN/PoE 控制；按型号/厂商/软件查资产；arccharts 拓扑；
**带 Swagger 规范的 REST API**。→ **这是 IPScanner 的 BRIDGE-MIB 转发表数据能直接兑现的一个高价值功能**（见建议书 §4.4）。

**runZero**（商业）是"无凭据发现深度"的标杆；**NetBox Discovery / netbox-agent** 说明 NetBox Labs
正在向 IPScanner 所在的缺口移动 **[方向未验证]**。

---

## 6. 综合结论

### 6.1 表 stakes（v1.7 级别应当具备的）

1. 目标输入：CIDR、区间、`network:mask`、主机名、**文件/stdin 列表**、由网卡推导的 `--localnet`。
2. **本地子网 ARP 层发现** —— 唯一能拿到被防火墙挡住的主机的手段，并且要诚实说明"ARP 不可路由"。
3. ICMP echo/timestamp + TCP SYN/ACK 兜底，以及"假定在线"（等价 `-Pn`）。
4. 厂商/OUI 解析来自**可更新的 IEEE 注册文件** + **用户覆盖文件**（本地/自定义/随机 MAC）。
5. 端口与**服务版本识别来自签名文件**，而不是硬编码的端口名表。
6. 稳定的机器可读导出：**JSON + CSV + XML**，且有公开 schema。
7. **CLI 与 GUI 能力对齐**、非交互模式、确定性退出码。
8. **快照历史 + 变更 diff**（新增/消失/变更）。
9. **定时扫描 + 新设备/未知设备告警** —— 这是整个品类价值的核心。
10. 噪声控制：忽略/白名单、维护窗口、通知节流/去重、逐设备"已确认"。
11. SNMP v1/v2c/v3 + `sysDescr`/`sysObjectID` 指纹；反向 DNS；mDNS/NetBIOS/WMI 补全。
12. **LLDP/CDP + BRIDGE-MIB 拓扑**渲染。
13. 带 token 的本地 API + 出站 webhook。
14. 按 IP/MAC/厂商/主机名/端口/风险分的检索与筛选。
15. 可复现安装、清晰许可、不强制上云。

### 6.2 值得抄的差异化点

1. **既能产出也能读入 Nmap XML** —— 一步接入最大的扫描器生态；`-oA` 式多格式输出。
2. **NSE 式检查分类**（safe/discovery/intrusive/default），让主动检查带风险标签，默认保守。
3. **arp-scan 的 `--format` 具名字段 + `--plain`** —— 用户自定义输出模板，CSV/JSON 免费得到。
4. **厂商覆盖文件**（`mac-vendor.txt`）—— 让用户给自己设备命名、标记随机 MAC。
5. **Nagios 插件契约 + perfdata** —— 风险/新设备检查直接成为 Nagios/Icinga/Zabbix/Checkmk 的检查项。
6. **Zabbix LLD JSON 契约**作为导出形状：`{"data":[{"{#IP}":…,"{#MAC}":…}]}`。
7. **`router.db`（`host:model`）CSV 导出**给 Oxidized/RANCID。
8. **NetBox 形状的"外键已解析"导出 + 可选 REST 推送**。
9. **Netdisco 的「MAC → 交换机端口」定位**与**历史 IP/位置** —— "这个 MAC 插在哪、上周在哪"是 LAN 里价值最高的问题。
10. **NetAlertX Workflows**：声明式的事后规则（归站点、按厂商打标、再出现取消归档、N 天自动清理）。
11. **Nuclei 的严重级别词汇 + SARIF 导出**（可被 GitHub code scanning / SIEM 消费）。
12. **Prometheus 文本暴露**（`devices_total{site,vendor,role}`）—— 约 50 行代码换来看板公民身份。
13. **Oxidized 式带版本、可 diff 的快照**（快照成为一等制品）。
14. **可靠性语义**：`--resume`、追加而非覆盖、支持 strftime 的报告文件名。

### 6.3 集成机会（具体）

- **NetBox / Nautobot** — *导入*：拉取 site/role/device_type/prefix 以便预填下拉框，并把
  "台账 vs 实测"的差异做成功能。*导出*：外键已解析的 CSV（manufacturer → device_type → role →
  site → device → interface → IP）+ REST 推送创建缺失项；回写 last_seen/风险/custom fields。
  *格式*：NetBox export template 的 CSV + REST/GraphQL 的 JSON；反向漂移靠 NetBox event rules/webhook。
  注意外键顺序，否则导入必失败。
- **LibreNMS / Zabbix / Prometheus** — *导出*：LibreNMS `POST /api/v0/devices` 加设备；Zabbix **LLD JSON**
  建 host prototype；Prometheus `/metrics` 端点与/或 `snmp_exporter` 目标列表。
  *导入*：LibreNMS 的 ARP/FDB 端点用于拓扑补全；Zabbix host inventory 作为权威设备清单。
  *告警*：LibreNMS 有 `Snmptrap` 传输 —— IPScanner 应能发 **SNMP trap**，让告警落进既有 NMS 而不是新开一个收件箱。
- **Oxidized / RANCID** — *导出*：`router.db` CSV（`host:model`）+ `.cloginrc` 骨架，当天启用备份。
  *导入*：取回某节点最新配置版本，把"配置变了"和"资产变了"并列呈现。
- **Slack / Teams / webhook 生态** — 建议实现顺序：① 通用 JSON webhook；② **Slack Block Kit**；
  ③ **Teams Adaptive Card**；④ SMTP；⑤ **Alertmanager 兼容 payload**（接进既有 on-call 路由）；
  ⑥ 可选交给 **Apprise**，一次继承约 100 种服务（NetAlertX 的做法）。

### 6.4 陷阱（不要抄）

1. **自建时序指标库。** RRDtool/Prometheus TSDB 的降采样与保留策略是另一个产品；
   桌面扫描器应保留快照 + diff，把指标**推给**真正的 TSDB。
2. **带强制外键链的完整 DCIM/IPAM 真值模型。** 这正是 NetBox 最被抱怨的上手难点；
   本项目应允许自由格式台账，**可选**投影到 NetBox。
3. **分布式轮询 / 多服务器扩展。** LibreNMS dispatcher、Zabbix proxy、Observium 的付费多服务器
   之所以存在，是因为它真的难。多站点应该是**文件/API 交换**，不是装 agent。
4. **带凭据的配置备份。** Oxidized 维护 130+ 设备型号与一套提示符/分页 DSL；
   那是无底洞，且凭据责任真实存在。
5. **爆破/漏洞利用/DoS 类检查。** Nmap 明确警告脚本无沙箱，Nuclei 警告不要以服务方式运行。
   风险评分只能是**暴露面启发式**（"Telnet 开着、SNMP 用 public、默认凭据横幅"），
   绝不能给出暗示"已实测可利用"的 CVE 结论。
6. **未签名的插件市场。** Nmap 自己说第三方脚本可能损害你的系统；插件 API 在设计上就是 RCE。
   要么严格限制、要么白名单、要么只允许经过评审的进程内插件。
7. **Nagios 式配置 DSL。** 那正是所有人都在逃离的东西；用数据库/JSON 配置 + UI。
8. **Web UI + SSO + RBAC。** NetAlertX 把 RBAC 推给反向代理；桌面应用不该长出一个身份提供者。
   本地 token + 操作系统文件权限足够。
9. **在每个终端上装 agent。** WMI/SNMP/mDNS 正是 Windows 工具的魅力所在；装 agent 就毁掉了
   "跑起来就能看见一切"这一优势。
10. **把"协议/厂商覆盖面"当成目标。** LibreNMS/Observium 用海量 OS profile 换来的广度，
    小团队学不来；应把**一条指纹路径做到极致**（OUI + SNMP sysDescr/sysObjectID + mDNS + NetBIOS），
    长尾交给 NetBox/Oxidized。

### 6.5 两处需要更正的事实

1. Oxidized 的正式仓库是 **[ytti/oxidized](https://github.com/ytti/oxidized)**；
   `github.com/oxidized/oxidized` 是一个 0 star 的空占位。
2. **The Dude 是正式停止开发（discontinued），不只是停更** ——
   这消除了"带拓扑的桌面 GUI"这一细分里的一个竞争者，对 IPScanner 是一个真实的空缺机会。
