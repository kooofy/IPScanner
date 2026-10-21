# SignPath Foundation 免费代码签名 —— 申请材料

> **目的**：让发行版带上**可与仓库相互验证**的签名，消掉「Windows 已保护你的电脑 / 未知发布者」。
> **依据**：`docs/ROADMAP_V1.8.md` §1.4 第 2 项、`docs/ROADMAP_V2.2.md` §1.4 / §3.4.1。
> **状态**：**已提交**（2026-10-14 上午，北京时间；回执截图的文件时间戳为
> **10:51:20**，这是目前**最精确**的时刻锚点 —— 截图本身就是提交成功后拍的）。
> HubSpot 回执原文「Form submitted — Thank you, we'll be in touch soon.」，
> 回执截图已归档入库：`docs/screenshots/signpath-application-receipt-2026-10-14.png`
> （2026-10-19 补归档；此前只存在本机临时目录，随临时目录清理而丢失过）。
> 用户提供联系邮箱 `kooofy@gmail.com` 与姓名 **Xiaohua Lv**，发现渠道填
> Developer platforms (e.g. GitHub)。提交由助手经浏览器完成：
> 全部字段按 §3 / §3.0 填好后，reCAPTCHA Enterprise 图片挑战
> （"Select all squares with crosswalks"）由**用户本人解题**，随后自动提交成功。
> 审核沟通走邮件 —— 请保持 `kooofy@gmail.com` 畅通；后续步骤见 §5.2。

## 0. 决定反转记录（2026-10-14）

| 时间 | 决定 | 依据 |
|---|---|---|
| 2026-10-10 | **暂缓提交** | 仓库当天才公开，`Reputation` 一栏拿不出使用量证据（stars / 下载全 0） |
| **2026-10-14** | **启动申请** | 用户主动改变决定：「早开始攒信誉」的收益大于「材料弱一点」的风险 |

⚠️ **反转的代价必须如实记账**：`Reputation` 仍是本申请最弱的一栏，而且是**可以预判会被追问**
的一栏 —— 见 §3.1。决定做了就不再反复；**如果审核方要求补充使用量证据**，
唯一的正路是继续积累真实使用，而不是把申请书改得更花哨。

> 该决定同时推翻了 `docs/ROADMAP_V2.2.md` §1.4 记录的「不启动 SignPath 申请」，
> 连带：签名流水线从"移除"状态回到"待接线"，`P2-13`（无代码签名）从「未修」改为
> **「申请中」**。v2.2 的四项交付范围**不变** —— 申请本身不占开发名额（它是个外部等待过程）。

---

## 1. 为什么现在就要提交

新版 SmartScreen 的信誉是**按「同一签名身份持续发布」累积**的，不是一次性买断。
今天开始签名，一年后才攒得出「持续发布」的历史；晚一年提交，就晚一年开始攒。
这也意味着签名身份一旦确定**不要更换** —— 换身份等于信誉清零重来。

> 这一条是本项目里少数「**早做比做得好更重要**」的事：其余三项（README / CHANGELOG /
> release 工作流）都是当天能完成的，唯独签名要等外部审批。
>
> ⚖ **2026-10-10 曾据此判断「暂缓」**：当时 `Reputation` 拿不出使用量证据。
> 2026-10-14 用户决定**启动申请**，接受「材料里 Reputation 偏弱」这一代价
> —— 理由是这样才可能尽早开始攒信誉（见本文 §0 反转记录）。
> ⚠️ **代价要说清**：审核方**很可能追问使用量**。若真被追问，正确应对是
> 继续积累真实使用并如实回复，而不是修饰材料。

---

## 2. 资格自查（逐条对照）

SignPath Foundation 对开源项目的要求（来源：`signpath.org/apply.html`、`signpath.org`，
以及一份 2026-02 的实操申请记录；核对日期 2026-10-10，2026-10-14 复核资格行全部仍成立）：

| 要求 | IPScanner 现状（2026-10-14） | |
|---|---|:---:|
| OSI 认可的开源许可 | GPL-3.0（[`LICENSE`](../LICENSE)） | ✅ |
| 仓库公开 | `github.com/kooofy/IPScanner`（2026-10-10 起公开） | ✅ |
| 持续开发 | `2.1.x` 发布线仍在推进（v2.1.0，2026-10-13 发布） | ✅ |
| 授予对象是**项目**而非个人 | 证书签发给 SignPath Foundation，项目侧只需署名 | ✅ |
| 构建可复现 | `IPScanner.spec` / `IPScanner_cli.spec` 均入库，CI 有打包验证 | ✅ |
| 产物可免费下载 | 13 个 Release，每个带 `SHA256SUMS.txt` | ✅ |
| 代码签名政策 | [`CODE_SIGNING_POLICY.md`](../CODE_SIGNING_POLICY.md) 已入库 | ✅ |
| 行为准则 | [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) 已入库 | ✅ |

免费档给的是 **OV 级证书**（签发主体是 SignPath Foundation，私钥存在其 HSM 上，不落本地），
支持签名 EXE / MSI / Docker 镜像 / Office 宏等，CI 侧支持 GitHub Actions / Azure DevOps / Jenkins。
本项目只需要 GitHub Actions —— 产物构建已经落在
[`.github/workflows/release.yml`](../.github/workflows/release.yml) 里了。

### 2.1 条款级自查（`terms.html`，2026-10-19 补做）

⚠️ 上面那张表是照 `apply.html` 做的，**不完整** —— 真正有约束力的细则在
<https://signpath.org/terms.html>「SignPath Foundation conditions for Open Source
projects」。2026-10-19 补做条款级自查，**发现一条可能致命**：

| 条款 | IPScanner 现状 | 判定 |
|---|---|:---:|
| 🔴 **No hacking tools** | 核心功能是"扫网段 → 列开放端口 → 服务暴露面风险分 + CVE 候选"，与条款举例「identifying unprotected network ports」几乎字面重合 | **硬风险** |
| No malware | 无恶意代码 | ✅ |
| No proprietary code | 全 GPL-3.0，无闭源组件 | ✅ |
| Maintained / Released / Documented | 2.1.x 在推进、13 个 Release、README 有功能说明 | ✅ |
| Code signing policy（须用官方措辞） | `CODE_SIGNING_POLICY.md` 已用官方原句 | ✅ |
| Team roles（Authors / Reviewers / Approvers） | 同文件「Team roles (single-maintainer project)」已列 | ✅ |
| Privacy policy | 同文件「Privacy policy」已写"不发遥测、数据不出本机" | ✅ |
| Announce system changes / Provide uninstallation | 免安装包（解压即用、无安装器、不改系统配置）；⚠️ 但有 **Wake-on-LAN**（用户手动触发） | ⚠️ 需说明 |
| MFA（SignPath + 代码仓） | 仓库侧已开；SignPath 账号待用户本人确认 | ⚠️ 用户自证 |
| Artifact metadata restrictions | 未配置 | ⏳ 获批后才需要 |

🔴 **`No hacking tools` 原文**：

> Software must not include features designed to identify or exploit security
> vulnerabilities or circumvent security measures of their execution environment.
> **This includes security diagnosis tools that actively scan for and highlight
> exploitable vulnerabilities, e.g. by identifying unprotected network ports,
> missing password protection etc.**

**为什么这是硬风险**：本项目扫端口、按服务暴露面打 0–100 风险分、匹配 CVE 候选、
检测弱 TLS 与 SMB1 —— 这些正是条款所说的 "highlight exploitable vulnerabilities"。
`apply.html` 上**完全没有提这条**，所以 2026-10-14 提交时并不知道。

**可用的抗辩**（官方明确写过 "We will listen to arguments about your specific
situation"）：

1. 定位是**资产台账 / 巡检**（README 对标 Advanced IP Scanner、SoftPerfect、TNI），
   不是漏洞利用或渗透测试工具；
2. **零利用**：不做 exploit、不做凭据爆破、不绕过认证（已核实：仓库无
   `brute` / `wordlist` 相关代码）；
3. 结果用于**变更追踪与文档化**，不用于攻击。

**但如实记账**：不排除被拒，且这可能是比 `Reputation` **更硬**的拒绝理由。
若被拒，备选路线（未选）：自购 OV 代码签名证书 / Azure Trusted Signing（需组织资质）/
维持未签名发布并在 README 如实说明。跟进邮件草稿见
[`SIGNPATH_FOLLOWUP_EMAIL.md`](SIGNPATH_FOLLOWUP_EMAIL.md)。

---

## 3. 申请时要填的表单字段（可直接粘贴）

提交入口：<https://signpath.org/apply.html>

| 字段 | 填写内容 |
|---|---|
| Homepage URL | `https://github.com/kooofy/IPScanner` |
| Project repository URL | `https://github.com/kooofy/IPScanner` |
| License | `GPL-3.0`（仓库根目录有 [`LICENSE`](../LICENSE)） |
| Download page URL | `https://github.com/kooofy/IPScanner/releases` |
| Tagline | `Open-source LAN scanner and asset inventory for Windows networks` |
| Category | `developer-tools` |
| Build System | `GitHub Actions` |
| Reputation | 见下方 §3.1 —— **本项目最弱的一栏，必须先读** |
| Description | 见下方引文 |

> ⚠ **`Homepage URL` 与 `Download page URL` 别填反**：前者是「项目主页」，
> 表单说明里明确写了「可以是专门网站，**也可以是仓库页**」—— 本项目没有独立官网，
> 填仓库页即可（同一行两栏填同一个 URL 是正常的，不是笔误）。
> 后者必须指向**能免费下载产物**的 Releases 页，别填仓库首页。

### 3.0 实际表单字段（2026-10-14 在 `apply.html` 上用浏览器核对）

⚠️ 上面是**旧版字段表**（2026-10-10 核对）；实际表单是 iframe 里的 **HubSpot 表单**，
字段已变（新增 Project Name / First·Last Name / Email / Discovery Channel 等，
**License 字段已不存在**）。以本表为准：

| 实际表单字段 | 值 | 备注 |
|---|---|---|
| Project Name* | `IPScanner` | 新增 |
| Repository URL* | `https://github.com/kooofy/IPScanner` | |
| Homepage URL* | `https://github.com/kooofy/IPScanner` | 表单说明：官网或仓库页均可 |
| Download URL | `https://github.com/kooofy/IPScanner/releases` | 🔴 **新要求**：该页须提及项目使用 SignPath Foundation 做代码签名。Releases 页本身没有这句；README「未知发布者」一节有「正在申请」。若审核卡这条，先给下载区补署名句再提交 |
| Privacy Policy URL | 留空 | 表单：仅当软件收集用户数据时必填；本工具零联网、不收集 |
| Wikipedia URL (optional) | 留空 | 无条目 |
| Tagline* | `Open-source LAN scanner and asset inventory for Windows networks` | |
| Category* | `Developer Tools` | 实际选项比 `projects.yml` 反推的多（新增 `AI Tools`） |
| Description* | 见下方引文 | |
| Reputation* | 见下方 §3.1 | |
| Maintainer Type | `Individual maintainer(s)` | 实际选项：Independent community project / Non-profit / For-profit / Individual maintainer(s) / Other |
| Build System* | `GitHub Actions` | 实际仅两个选项（GitHub Actions / GitLab CI/CD） |
| First Name* | `Xiaohua` | 用户 2026-10-14 提供（「lv xiaohua」按西文顺序拆分） |
| Last Name* | `Lv` | 同上 |
| Email* | `kooofy@gmail.com` | 用户 2026-10-14 提供 |
| Company Name | 留空 | 可选 |
| Primary Discovery Channel* | `Developer platforms (e.g. GitHub)` | 用户授权代选（原话「帮填个合适的」）；如想更正可邮件告知 SignPath，此栏仅影响对方统计 |
| 复选框 ×3 | CoC 同意 ✓ / 营销通信 ✗ / 个人数据处理 ✓ | 第一、三个必勾 |
| reCAPTCHA | **Enterprise，v2 图片挑战** | 点提交后弹「Select all squares with crosswalks」，由**用户本人解题**，随后自动提交 |

**2026-10-14 结果**：全部字段填好并回读核验 → 点 Submit → reCAPTCHA 挑战由用户解题 →
**提交成功**（回执与截图存档，见顶部状态块）。从开页到提交成功整段 7m14s。

**`Tagline` 备选**（一句话、不带句号，会被展示在基金会官网上）：

1. `Open-source LAN scanner and asset inventory for Windows networks` ← 推荐，与现有项目风格一致
2. `Discover, identify and inventory every device on your local network — no cloud account required` ← 带上差异化卖点
3. `Scan your local network and inventory every device on it` ← 最短

**`Category` 的选项**（从基金会官网 `fdn-website` 的 `_data/projects.yml` 反推，332 个项目
实际用到的）：`developer-tools`（87）/ `gaming`（94）/ `productivity`（74）/ `science`（28）/
`graphics`（15）/ `audio`（11）/ `other`（10）/ `educational`（6）/ `accessibility`（6）。

选 **`developer-tools`** 的依据是**同类先例**，不是猜：

- `NETworkManager`（「A powerful tool for managing networks and troubleshoot network…」）
  —— 与 IPScanner 定位最接近，归在 `developer-tools`；
- 同档还有 `sniffnet`（流量监控）、`dnsmonster`（被动 DNS）、`Smartmontools`、
  `OpenModScan`（Modbus 工具）—— 都是面向技术用户的网络/诊断工具；
- `productivity` 那档收的偏消费级（`NetSpeedTray` 任务栏网速、条码工具、IRC 客户端）。

> IPScanner is an open-source LAN scanning and asset-inventory tool for
> Windows-centric networks, written in Python + PyQt5 and licensed under GPL-3.0.
> It ships a desktop GUI and a headless CLI from the same scanning engine.
> Distribution is two PyInstaller artifacts built on GitHub Actions: an onedir GUI
> bundle (`IPScanner_<version>-win64.zip`) and a single-file CLI
> (`IPScanner_cli_<version>.exe`).
>
> We are applying because unsigned downloads trigger SmartScreen's "Windows protected
> your PC" prompt, and because this tool legitimately sends ICMP / ARP / TCP / UDP
> probes and reads WMI over the network — behaviour that antivirus heuristics also
> flag. A signature tied to our public repository would let users verify that the
> binary they run was actually built from that repository.
>
> The build recipes (`IPScanner.spec`, `IPScanner_cli.spec`) and the release workflow
> are committed, so the release build is reproducible from the tagged source.

### 3.1 `Reputation` —— 本项目最弱的一栏（诚实评估）

**实测数据（2026-10-14 用 GitHub API 拉的，不是估计）**：

| 指标 | 2026-10-10 | 2026-10-14（现况） |
|---|---|---|
| 仓库创建 | 2026-07-17 | 2026-07-17 |
| **转为公开** | **2026-10-10（第 0 天）** | **2026-10-10（第 4 天）** |
| stars / forks / watchers / subscribers | **0 / 0 / 0 / 0** | **0 / 0 / 0 / 0** |
| Releases 数量 | 9（v1.0 → v1.7.7） | **13**（v1.0 → v2.1.0） |
| **产物下载次数** | **0** | **0** |
| 媒体报道 / 博客 / 社区讨论 | **无** | **无** |

**结论：这一栏仍然拿不出任何「被广泛使用」的证据 —— 公开才 4 天，这不是缺陷而是时间。**
不要试图用无关数据凑数：审核方点开链接就能看出 stars/downloads 是 0，硬编反而更糟。
诚实交代「私有开发 → 公开 4 天」比任何修饰都经得起核对。

**可以如实写的（工程可信度，不是使用量 —— 但正是签名要担保的那个性质）**：

> IPScanner was developed in a private repository until 2026-10-10, when it was
> published under GPL-3.0; external usage metrics are therefore not yet meaningful.
> What the project can demonstrate is verifiable engineering provenance:
>
> - 127 commits over 88 days of continuous development (2026-07-18 → 2026-10-13),
>   with 13 tagged releases (v1.0 → v2.1.0) published under this public repository.
> - 2,495 automated tests across 86 test files, run on every push and again on
>   every release tag.
> - Public CI across three platforms — Python 3.10–3.13 on ubuntu-latest and
>   macos-latest, plus Windows PyInstaller packaging verification:
>   https://github.com/kooofy/IPScanner/actions
> - Reproducible release builds: the PyInstaller recipes (`IPScanner.spec`,
>   `IPScanner_cli.spec`) and the release workflow are committed, and every release
>   publishes `SHA256SUMS.txt`:
>   https://github.com/kooofy/IPScanner/releases
> - Full public commit history from the first commit; the only maintainer is the
>   sole author of record.

**⚠ 若本项目已在真实环境里被使用**（单位 / 公司 / 实验室 / 客户网络等），
**一定要补上这一条 —— 它是目前唯一真实可用的「使用量」证据**，比上面所有工程指标
都更有说服力。写法：说明场景、规模、使用时长，并指明可核实的联系人身份。
（2026-10-14 提交时若已出现真实使用，此处**必须先更新**再勾选，别用旧文本。）

**（已作废的备选）** 2026-10-10 曾设想「先公开一段时间积累下载量再提交」。
2026-10-14 用户决定**不等了** —— 代价是审核方可能追问使用量，
收益是尽早开始累积 SmartScreen 信誉（§1）。

---

## 4. 提交前的加分准备（已全部完成）

| 准备项 | 作用 | IPScanner 现状 |
|---|---|:---:|
| 仓库根目录有 `LICENSE` | 证明是 OSI 许可 | ✅ 已有 |
| README 讲清「是什么 / 从哪下载 / 怎么构建」 | 审核方判断产物来源 | ✅ 已有 |
| CI 工作流公开 | 证明产物确实由本仓库构建 | ✅ `release.yml` |
| GitHub Releases 有可免费下载的产物 | 程序硬性要求「发行版可免费下载」 | ✅ 13 个 Release |
| **`CODE_SIGNING_POLICY.md`（代码签名政策）** | 说明「签什么、谁有权批准签名」 | ✅ 已入库 |
| **`CODE_OF_CONDUCT.md`（行为准则）** | 证明项目按开源项目方式运营 | ✅ 已入库 |
| **可收信的联系邮箱** | 审批沟通主要走邮件 | ✅ `kooofy@gmail.com`（2026-10-14 用户提供，已随申请提交） |

其中**代码签名政策是审核重点**：SignPath 的签名是**逐次审批**的，它必须知道在你这个
项目里**谁有权批准一次签名**。本项目的
[`CODE_SIGNING_POLICY.md`](../CODE_SIGNING_POLICY.md) 已把单人维护者同时列入
**Authors / Reviewers / Approvers** 三个角色，并写明「每次签名都需维护者显式批准」。

程序要求的署名声明（获批后必须原样出现）：

> Free code signing provided by SignPath.io, certificate by SignPath Foundation

---

## 5. 提交步骤

### 5.1 提交申请（✅ 已完成，2026-10-14）

实际执行方式：助手经浏览器打开 <https://signpath.org/apply.html>，按 §3.0 字段表
填完全部字段（含用户提供的姓名 **Xiaohua Lv**、邮箱 `kooofy@gmail.com`、
代选的发现渠道 Developer platforms (e.g. GitHub)），点 Submit 后
reCAPTCHA Enterprise 弹出图片挑战 —— **由用户本人解题**，随后自动提交成功。
HubSpot 回执：「Form submitted — Thank you, we'll be in touch soon.」

（原人工操作步骤保留备查：打开页面 → 按 §3 字段表逐项粘贴，**提交前最后确认
一遍字段值**，尤其是 Homepage / Download URL 别填反 → 联系邮箱填一个真能收信的
地址 → 提交。）

### 5.2 提交之后

> **跟进状态（2026-10-19 核查）**：提交后 **5 天未收到任何邮件**
> （`kooofy@gmail.com`，已核对垃圾邮件与「促销/更新」标签）。
> 已排除"邮箱填错"：文档记录、git 提交者、用户本人复述三者**逐字符一致**。
> SignPath 官网**没有公布审核时长**（`apply.html` 与首页均未写，`faq.html` 返回 404）
> ⇒ **5 天不构成异常**，但已到可以礼貌跟进的程度。
> ⚠️ 回执当时只是**页面文字**，不能拿"没收到确认信"当异常信号。

1. **审核期间保持邮箱畅通**，可能收到补充提问；若问使用量，按 §3.1 的口径如实回复。
2. 获批后：在 SignPath 里建项目 → 接 GitHub 集成 → 设计签名政策（逐次审批）。
3. 把签名步骤接到 `release.yml` 的**「构建 CLI 版（onefile）」与「打包分发产物」之间**
   （2026-10-14 已核对工作流实际步骤名）：
   必须先签 exe、再 `Compress-Archive`；顺序反了签的就是压缩包本身（无效）。
   仓库里两个待签产物分别是 `dist\IPScanner_<版本>\IPScanner_<版本>.exe`（GUI onedir）
   与 `dist\IPScanner_cli.exe`（CLI onefile）。
4. 把程序要求的署名声明写进 Release 说明与下载页（`--generate-notes` 之外补一行）：
   `Free code signing provided by SignPath.io, certificate by SignPath Foundation`
5. **首个带签名的版本另起一个 `2.1.N`**，不要复用已发布的 v2.1.0。

---

## 6. 注意事项

- **不要买 EV 证书**：2024 年起微软取消了 EV 的「即时免警告」特权，SmartScreen 信誉改为
  按文件 / 下载量累积，OV 与 EV 的新签名文件都得等信誉，而 EV 价格是 OV 的数倍。
  ✅ 本条**已于 2026-10-10 联网复核**（多个独立来源结论一致），原先标注的「未复核」已解除；
  真正掏钱前仍建议自己再看一眼最新政策。
  （该结论最初来自 `docs/PRODUCT_ADVISORY.md` §1.4，勘误见
  [`docs/reviews/PRODUCT_ADVISORY_REVIEW.md`](reviews/PRODUCT_ADVISORY_REVIEW.md) §4。）
- 免费档覆盖的是 **Windows Authenticode**（EXE / MSI 等）；**macOS 公证（notarization）**
  是 Apple 的另一条路，不在本次范围内。
- 签名不改变杀软**启发式**误报的根因（本项目用原始套接字 + WMI + `net view`，本就是 EDR
  高敏组合）—— 它解决的是「未知发布者」与「来源不可验证」，不是「行为像恶意软件」。
