# IPScanner

[![CI](https://github.com/kooofy/IPScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/kooofy/IPScanner/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20~%203.13-blue.svg)](pyproject.toml)

局域网终端扫描与资产识别工具。PyQt5 图形界面 + 无头命令行，面向**内网巡检、资产盘点、
IP 冲突排查**等日常运维场景，参考 Advanced IP Scanner / Angry IP Scanner 的交互习惯。

---

## English Overview

**IPScanner** is a LAN host discovery and asset-identification tool for Windows-centric
networks, written in Python + PyQt5. It ships both a desktop GUI and a headless CLI
(`scan` / `diff` / `history`) so the same engine can drive interactive inspection and
scheduled automation.

Key capabilities:

- Range scanning over CIDR / IP ranges / multiple segments, with three port-scan depths
  (21 / 1023 / 65535 ports) and three probe modes (TCP connect / TCP SYN half-open / UDP).
- Liveness detection via ICMP **plus** active ARP probing, so hosts that block ping are
  still discovered.
- Device identification: MAC vendor lookup (updatable OUI database), device-type and
  model inference, OS fingerprinting, mDNS/DNS-SD discovery, NetBIOS names, and optional
  credential-based WMI interrogation.
- Asset history snapshots with change diffing, IP-conflict detection, subnet utilisation
  analysis, and CDP/LLDP topology mapping via SNMP.
- Bilingual UI (简体中文 / English), Excel / CSV / HTML / JSON export.

Licensed under **GPL-3.0** (required because PyQt5 is used under its GPL terms).
Requires Python 3.10–3.13. See [快速开始](#快速开始) for setup.

---

## 功能特性

### 扫描与发现

| 能力 | 说明 |
| --- | --- |
| 扫描范围 | 单个 IP、CIDR（`192.168.1.0/24`）、IP 区间（`10.0.0.1-10.0.0.200`）、多个网段批量 |
| 扫描深度 | `快速 (21)` / `标准 (1023)` / `全端口 (65535)` 三档 |
| 探测方式 | TCP 全连接 / TCP SYN 半开 / UDP 探测，可随时切换 |
| 存活探测 | ICMP Ping + **ARP 主动探测**（能发现禁 Ping 的主机）+ mDNS 组播发现 |
| 并发 | 线程数可调（默认 100），RTT 自适应端口超时 |

### 识别与指纹

- **MAC 厂商库**：内置 OUI 数据库，支持在线更新；未知厂商可按前缀批量查询。
- **设备类型与型号**：综合端口、服务 banner、mDNS、UPnP、SNMP、OUI 线索推断。
- **操作系统**：TTL 推测 + 服务 banner 版本提取。
- **mDNS / DNS-SD**：发现打印机、NAS、Apple 设备、IoT 等组播设备（无需扫描也可单独运行）。
- **NetBIOS**：UDP/137 NBSTAT 查询计算机名与工作组，零凭据、不需管理员。
- **WMI 远程识别**：经 PowerShell CIM 取权威硬件/系统信息（需管理员凭据；
  密码经 DPAPI 加密后本地存储，仅通过子进程环境变量传递，不出现在命令行）。
  支持 **DCOM 与 WinRM 双传输**：默认先试 DCOM，快速失败后自动回退 WinRM（只需
  5985 单端口，跨网段更易通过），也可在凭据对话框里指定单通路。
- **SMB 共享枚举**：列出目标开放共享。
- **SNMPv3（USM）**：支持用户级认证与加密，取代明文团体字。
  认证 `HMAC-MD5-96` / `HMAC-SHA-96`，加密 `AES-128-CFB128`；
  未配置用户时自动回退到 v2c 团体字探测。凭据同样经 DPAPI 加密落盘，
  配置对话框内可对指定 IP 直接"测试"连接。
  （不支持已废弃的 DES 隐私协议。）

### 资产管理与分析

- **历史快照**：每次扫描可存为快照，支持跨快照聚合查询（按设备类型 / 网段 / IP 过滤）。
- **变更对比**：对比两次快照，列出新增 / 消失 / 属性变更的设备。
- **IP 冲突检测**：识别同一 IP 对应多个 MAC 等异常，按严重级别分级。
- **子网利用率**：按 `/24` 聚合统计在线/离线数量与利用率。
- **拓扑发现**：基于 CDP/LLDP + SNMP 交换机端口映射绘制链路图。
- **地址库匹配**：导入 Excel 设备清单（`设备清单模板.xlsx`），扫描时自动匹配设备归属
  （位置 / 使用人 / 备注）。
- **审计日志**：记录扫描、导出、设置变更等关键操作，可按分类与关键字检索。
- **导出**：Excel / CSV / HTML / JSON。

### 内置网络工具

Ping、Tracert、Telnet、SSH、RDP、命令提示符、远程关机 / 重启。

> 出于安全考虑，这些工具的目标参数经过白名单校验，只接受 IP 字面量或纯 ASCII 主机名，
> 以杜绝命令注入。

---

## 快速开始

### 环境要求

- **Python 3.10 ~ 3.13**
- Windows 10/11（主平台）；macOS / Linux 亦可运行，但 WMI 识别等部分能力仅 Windows 可用
- 部分功能需要管理员权限（SYN 半开扫描、ARP 主动探测、远程关机/重启）

### 安装与运行

**方式一：一键脚本（Windows）**

```bat
run.bat
```

`run.bat` / `run.ps1` 会自动创建 `venv`、安装依赖并启动程序。首次运行需要几分钟。

**方式二：手动**

```bash
python -m venv venv
venv\Scripts\activate            # macOS / Linux: source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### 使用流程

1. 在顶部输入框填入网段（如 `192.168.1.0/24`），点「添加」或直接回车加入待扫列表；
   也可点「本机网段」自动填入。
2. 选择扫描深度与探测方式（`扫描 > 扫描设置...`）。
3. 点「开始扫描」。结果按行展示，双击设备行可展开端口/服务、WMI、NetBIOS 等细节。
4. 选中设备后可执行 WMI / NetBIOS 识别、打开内置网络工具。
5. `文件 > 导出` 导出结果；`历史` 菜单管理快照与变更对比。

---

## 命令行（无头模式）

`cli.py` 提供与 GUI 共用同一引擎的无头入口，适合计划任务、SSH 远程巡检、CI 集成。
输出格式稳定（JSON 键为英文、退出码语义固定），便于脚本消费。

```bash
# 扫描网段，输出 JSON
python cli.py scan -r 192.168.1.0/24 --level quick --format json

# 只输出在线设备，写入文件
python cli.py scan -r 10.0.0.1-10.0.0.200 --online-only --format csv -o result.csv

# 扫描并存为历史快照
python cli.py scan -r 192.168.1.0/24 --save-snapshot --note "周一巡检"

# 对比资产变更（相对上一次快照；有变更时退出码为 2）
python cli.py diff -r 192.168.1.0/24 --fail-on-change

# 跨快照聚合查询：所有打印机
python cli.py history --query --device-class 打印机 --format json

# 列出 / 导出历史快照
python cli.py history --list
python cli.py history --show 12 --format csv -o snapshot12.csv
```

**退出码**

| 码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 错误（如 `--fail-if-empty` 且无结果） |
| `2` | 检测到变更（仅 `diff --fail-on-change`） |
| `3` | 环境错误（如数据目录不可写） |

**语言**：`--lang zh-CN` / `--lang en-US`，默认跟随系统。

**编码**：stdout / stderr 一律以 **UTF-8** 输出，消费端请按 UTF-8 解码。
Windows 上输出被重定向到管道或文件时（CI、`> out.json`、`| jq`），
系统默认会改用 ANSI 代码页（英文系统为 cp1252），而 stdout 的默认错误处理器是
`strict` —— 一旦输出里有中文（设备名、`device_class`、表格）就会直接抛
`UnicodeEncodeError` 并以退出码 1 结束。CLI 在解析参数之前会主动把两个流切到
UTF-8，因此 `--help` 与所有输出在任何代码页下都能正常工作。

**SNMPv3（USM）**

口令**只从环境变量读取**，没有任何接受口令的命令行选项 —— argv 会出现在进程列表
（`ps` / 任务管理器）里，同机任何用户都能看到。

```bash
export IPSCANNER_SNMPV3_AUTH_KEY='认证口令'
export IPSCANNER_SNMPV3_PRIV_KEY='加密口令'

# authPriv：SHA 认证 + AES-128 加密
python cli.py scan -r 192.168.1.0/24 --snmpv3-user monitor \
    --snmpv3-auth sha --snmpv3-priv aes

# 用自定义环境变量名，便于在同一台机器上为不同目标准备不同凭据
python cli.py scan -r 10.0.0.0/24 --snmpv3-user monitor \
    --snmpv3-auth md5 --snmpv3-auth-env SITE_A_SNMP_KEY
```

指定 `--snmpv3-user` 会**自动启用** SNMP 协议识别，无需再写 `--protocols SNMP`。
口令缺失或组合非法（如只给 `--snmpv3-priv` 不给 `--snmpv3-auth`）时，
会在**扫描开始前**报错并以退出码 `1` 结束，不会白扫一个网段。

---

## 项目结构

```
IPScanner/
├─ main.py                    # GUI 入口（含全局异常兜底）
├─ cli.py                     # 无头 CLI 入口
├─ main_window.py             # 主窗口（由下列 Mixin 组合而成）
│  ├─ scan_mixin.py           #   扫描流程编排
│  ├─ history_mixin.py        #   历史快照 / 审计日志 / 拓扑
│  ├─ export_mixin.py         #   导出
│  ├─ library_mixin.py        #   地址库
│  ├─ oui_mixin.py            #   OUI 更新
│  ├─ network_tool_mixin.py   #   内置网络工具
│  └─ main_window_tree.py     #   结果树构建与刷新
├─ ui_threads.py              # 后台线程（扫描 / mDNS / WMI / NetBIOS / 拓扑 / OUI 更新）
├─ ui_dialogs.py              # 各类对话框（含拓扑视图）
├─ ui_logic.py                # 与 UI 解耦的纯业务逻辑（便于单测）
├─ scanner/                   # 扫描引擎（不依赖 PyQt，可独立复用）
│  ├─ engine.py               #   扫描编排
│  ├─ ping.py                 #   ICMP / ARP / 本机网段探测
│  ├─ ports.py                #   端口探测（connect / syn / udp）
│  ├─ classify.py             #   设备类型与型号推断
│  ├─ osfp.py                 #   操作系统指纹
│  ├─ dns.py                  #   mDNS / DNS-SD
│  ├─ netbios.py              #   NetBIOS NBSTAT
│  ├─ wmi.py                  #   WMI 远程识别
│  ├─ snmp.py                 #   SNMP v1/v2c（团体字）
│  ├─ snmp_v3.py              #   SNMPv3 / USM（认证与加密）
│  ├─ aes.py                  #   AES-128-CFB128（纯标准库，供 SNMPv3 加密）
│  └─ constants.py            #   常量与语言无关的规范代码
├─ topology_discovery.py      # 拓扑发现
├─ switch_mapper.py           # SNMP 交换机端口映射
├─ conflict_detector.py       # IP 冲突检测
├─ change_detector.py         # 资产变更检测
├─ history_store.py           # 历史快照存储（SQLite）
├─ audit_log.py               # 审计日志（SQLite）
├─ mac_library.py             # MAC 地址库
├─ excel_handler.py           # Excel 导入 / 导出
├─ i18n.py + i18n/            # 国际化（zh-CN / en-US）
├─ app_paths.py               # 开发态 / 打包态路径解析
├─ app_logging.py             # 统一日志（轮转文件）
├─ bounded_pool.py            # 有界并发执行工具
├─ tests/                     # 单元测试（标准库 unittest）
└─ IPScanner.spec             # GUI 版 PyInstaller 打包配方（onedir，名字不带版本号）
└─ IPScanner_cli.spec         # CLI 版打包配方（onefile）
```

---

## 数据文件与存放位置

运行时产生的数据统一放在**数据目录**，其位置按下列顺序自动探测（取第一个可写的）：

| 场景 | 位置 |
| --- | --- |
| 开发模式（源码运行） | 源码目录 |
| 打包后 · 便携 | exe 所在目录（绿色部署 / U 盘，数据随 exe 走） |
| 打包后 · 用户目录 | `%LOCALAPPDATA%\IPScanner`（Windows）／`~/.local/share/IPScanner` |
| 兜底 | 系统临时目录下的 `IPScanner` |

> 之所以要「exe 目录 → 用户目录」的回退：exe 放在 `C:\Program Files\` 这类受保护目录时
> 普通用户无写权限，直接在那里建 SQLite 会抛 `unable to open database file`，导致启动即崩溃。
> 当前实际位置可在 `帮助 > 关于` 里查看。

数据文件一览（多数已在 `.gitignore` 中，不入库）：

| 文件 | 内容 |
| --- | --- |
| `ipscanner.ini` | 界面偏好、扫描参数、网段列表、窗口几何 |
| `scan_history.db` | 历史快照与设备明细 |
| `audit_log.db` | 审计日志 |
| `mac_library.db` | 本地 MAC 地址库（含内部设备信息） |
| `oui.db` | MAC 厂商库（随版本内置，支持在线更新） |
| `ipscanner.log` | 运行日志（1 MB × 3 轮转） |
| `crash.log` | 未捕获异常堆栈 |

---

## 构建发布

使用 PyInstaller 打两个互相独立的包：GUI 版（onedir）与无头 CLI 版（onefile）。

```bash
pip install -r requirements-dev.txt

# GUI 版（产物：dist/IPScanner_<版本>/IPScanner_<版本>.exe）
pyinstaller --noconfirm IPScanner.spec

# 无头 CLI 版（产物：dist/IPScanner_cli.exe）
pyinstaller --noconfirm IPScanner_cli.spec
```

版本号唯一来源是 `version.py`，spec 名固定、产物名由版本号派生 —— 发版只需改
`version.py` 一处，不用再改 spec 文件名和 CI。

CLI 版显式排除了 PyQt5 与图形库，体积远小于 GUI 版，`console=True` 便于计划任务调用；
刻意保持 onefile（单文件便于直接拷到目标机或塞进容器）。

### 为什么 GUI 版用 onedir

实测（本机 SSD，PyQt5 全量打包）：

| 模式 | 磁盘占用 | 分发体积 | 启动 |
|---|---|---|---|
| **onedir**（GUI 默认） | 114 MB | 46.2 MB（zip） | 0.68~0.85s 到日志就绪 |
| onefile | 48 MB | 46.1 MB | 额外 0.24s 解压 |

分发体积几乎一致（46.2 vs 46.1 MB），代价是磁盘占用涨到 2.4 倍。选 onedir 的
**主因不是速度**（只省 0.24s），而是 onefile 的「自解压 48 MB 可执行内容后立即运行」
模式极易触发杀软/EDR 启发式误报 —— 本项目用原始套接字 + WMI + `net view`，
本就是 EDR 高敏组合。附带收益：可增量更新、traceback 里是真实文件路径。

> ⚠️ onedir 产物**必须整个目录一起分发**，不能只拷 exe ——
> 依赖与资源都在 `_internal/` 子目录里。

---

## 开发

### 运行测试

测试使用标准库 `unittest`，无需额外依赖：

```bash
python run_tests.py
# 等价于：python -m unittest discover -s tests -t .
```

无显示环境下也能安全导入 PyQt5（仅 import，不创建 `QApplication`）。

### 静态检查

```bash
pip install -r requirements-dev.txt
python -m ruff check .
```

规则集刻意只开「正确性」相关的 `F` / `E9`（未定义名、未使用导入/变量、语法错误），
不开格式类规则 —— 目标是拦住真实缺陷而非制造大面积风格 diff。配置见 `pyproject.toml`。

### 代码约定

- **语言无关的规范值**：服务/协议代码、设备类型、OS 家族、审计分类等内部标识一律用
  语言无关的值存储（ASCII 代码或中文源串），**只在显示时**经惰性翻译函数转成当前语言。
  绝不能把 `tr()` 的结果写进数据库或用作比较依据，否则数据会随界面语言分裂。
- **不要在任何模块顶层调用 `tr()`**：语言包在 `i18n.init()` 时才加载，import 期求值会被
  冻结成中文。需要常量形式的翻译文本时，用惰性函数（如 `scan_level_label()`）或
  PEP 562 模块 `__getattr__`。
- **匹配关键词不能翻译**：厂商名、品牌关键词等用于 `in` 匹配的字符串必须保持原样。
- **日志**：统一用 `app_logging.get_logger(__name__)`，不要新增 `print` /
  `sys.stderr.write` 来输出诊断信息。
- **异常**：`except Exception` 之后不要留空 —— 预期内的失败打 `debug`，影响功能的打 `warning`。

---

## 已知限制与后续计划

**当前限制**

- WMI 远程识别仅支持 Windows 目标，且需要有效管理员凭据。
- 只支持 IPv4；IPv6 网段无法扫描。
- WMI 传输：DCOM 需目标开放 135 + 动态 RPC 端口；WinRM 需目标启用 WinRM（默认
  5985）。WinRM 走 HTTP，**工作组环境**下还需把目标加入客户端 `TrustedHosts`
  （本工具只提示，不会替你改这项系统安全配置）。
- SNMPv3 支持认证 `HMAC-MD5-96` / `HMAC-SHA-96` 与加密 `AES-128-CFB128`；
  **不支持已废弃的 DES 隐私协议**（标准库无 DES，且现代设备默认关闭），
  指定 DES 会明确报错而不是静默降级成明文。v1 不支持（v3 与 v2c 已覆盖）。
- CI 只在 Windows 上跑；macOS / Linux 未经自动化覆盖。
- 打包体积较大：GUI 版（onedir）磁盘占用约 114 MB，压缩分发约 46 MB。

**后续计划**

- [x] SNMP v3（USM 认证与加密）
- [x] SNMPv3 的 CLI 参数（`--snmpv3-user` 等；口令走环境变量，避免出现在进程列表）
- [ ] IPv6 扫描支持
- [ ] WinRM 走 HTTPS(5986) + 可选的证书校验开关（当前固定 HTTP/5985）
- [ ] macOS / Linux 的 CI 覆盖

---

## 参与贡献

1. Fork 并新建分支（`feat/xxx`、`fix/xxx`）。
2. 改动尽量附带单元测试；提交前确保 `python run_tests.py` 与 `python -m ruff check .` 全绿。
3. 新增面向用户的字符串时，请同步更新 `i18n/en-US.json`
   （`tests/test_i18n_lazy.py::LanguagePackCompletenessTest` 会校验完整性）。
4. 提交 PR，说明改动动机与验证方式。

---

## 许可证

本项目以 **GNU General Public License v3.0** 发布，全文见 [LICENSE](LICENSE)。

> **为什么是 GPL-3.0**：本项目使用 PyQt5，而 PyQt5 本身以 GPL-3.0 / 商业双授权提供。
> 在未购买 Riverbank 商业授权的前提下公开分发本项目，整体按 GPL-3.0 释出是唯一合规的选择。
> 如果你需要以非 GPL 条款使用本项目，请先取得 PyQt5 的商业授权。

---

## 免责声明

本工具会主动向目标主机发送 ICMP、ARP、TCP、UDP 报文并进行服务探测。**请仅对你自己拥有
或已获得明确书面授权的网络使用。**

未经授权扫描他人网络在多数国家和地区属于违法行为（例如中国《网络安全法》《刑法》第 285 条、
美国《计算机欺诈与滥用法》CFAA、英国《计算机滥用法》）。使用者需自行承担全部法律责任，
作者不对任何误用或由此造成的损失负责。
