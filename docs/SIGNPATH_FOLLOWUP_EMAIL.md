# SignPath 申请跟进邮件（英文草稿）

> 生成日期：2026-10-19　|　对应申请：2026-10-14 10:51（北京时间）提交

## 发送前必读

**收件地址**：`support@signpath.io` ✅ **已核实，不是推测**

2026-10-19 复核 <https://signpath.io/support>，官方原文：

> **Use for first interactions or single requests**
> Per Email at : support@signpath.io

即「首次接触 / 单次请求」就走这个邮箱 —— 正是我们这种"第一次问申请状态"的场景。
（此前只从 Terms 页的「举报违规」语境推断，现在有官方 Support 页直接背书。）

**备选**（前一封若两周无回音再换）：

| 地址 | 来源 | 适用 |
|---|---|---|
| `office@signpath.io` | [Imprint](https://signpath.io/imprint) 法定通信地址（SignPath GmbH，维也纳） | 正式函件、需要留痕 |
| `info@signpath.io` | 官网页脚 Contact | 通用咨询 |
| `security@signpath.io` | Support 页 | **只报漏洞，不要用** |

⚠️ `signpath.org` 侧的 `contact.html` / `faq.html` 都是 404，`apply.html` 也没留联系方式，
所以**没有一个"Foundation 专属"的咨询入口** —— 只能走 SignPath GmbH 的通用支持渠道。
写信时在开头就把项目名和提交日期写清，减少被转手的次数。

若你手上有别的渠道（例如 HubSpot 表单可能发过确认信），优先回那个线程。

---

## 三个发送用文件（内容相同，按发送方式选一个）

| 文件 | 用法 |
|---|---|
| `SIGNPATH_FOLLOWUP_EMAIL.eml` | **双击**用系统默认邮件客户端打开 —— 带 `X-Unsent: 1`，会直接进**可编辑的写信窗口**（不是只读邮件），确认后点发送即可。Outlook / Windows 邮件 支持；Thunderbird 打开后需"编辑为新邮件" |
| `SIGNPATH_FOLLOWUP_EMAIL.mailto.txt` | 里面是一整行 `mailto:` 链接。**用 Gmail 网页版**时：复制整行 → 粘到浏览器地址栏 → 回车，会直接打开已填好收件人/主题/正文的 Gmail 写信窗口（2737 字符，浏览器地址栏能承受；但**别**拿它双击运行，Windows 注册表对 mailto 参数有 ~2000 字符限制，会被截断） |
| `SIGNPATH_FOLLOWUP_EMAIL.txt` | 纯文本，全选复制粘到任何客户端。最保险，内容不会被任何解析器改动 |

三者正文**逐字相同**，都是「主版本 + 可选段落」的推荐组合（即建议加的版本）。
若你想改用**不加**可选段落的版本，用本文档下面的「主版本」原文。

---

## 主版本（状态询问）

**Subject:** Application status — IPScanner (submitted 14 Oct 2026)

Dear SignPath Foundation team,

I applied for a free SignPath.io subscription for my open-source project on
14 October 2026 and received the form confirmation, but I have not heard back
since. Could you let me know whether the application is being processed, and
whether you need any additional information from me?

Details of the application:

- Project: IPScanner — https://github.com/kooofy/IPScanner
- Contact email entered in the form: kooofy@gmail.com
- Submission date: 14 October 2026
  (form confirmation: "Form submitted — Thank you, we'll be in touch soon.")
- License: GPL-3.0

For context: IPScanner is a local-network asset inventory tool for everyday IT
operations. It discovers hosts on a subnet, records which services are
reachable, and keeps a history of what changed between scans. It is used for
asset audits, IP-conflict troubleshooting and internal network documentation.
It runs entirely on the operator's own machine — no account, no cloud service —
and it does not exploit vulnerabilities, perform credential attacks, or bypass
authentication.

I am happy to provide anything that would help the review — build instructions,
release artifacts, or details on how the project is maintained.

Thank you for your time.

Best regards,
Xiaohua Lv
https://github.com/kooofy/IPScanner

---

## 可选段落（主动说明「No hacking tools」条款）

把这段插在 "For context" 那段之后。**是否加，见下方权衡。**

> One point I would like to raise proactively: I read the condition regarding
> security diagnosis tools, and I want to be transparent about where IPScanner
> sits. It is an inventory and visibility tool, not a testing or exploitation
> tool — it never attempts to exploit what it finds, and it is meant to be run
> by administrators on networks they are responsible for. If that distinction
> is relevant to eligibility, I would be glad to discuss it. If the project
> falls outside the scope of a Foundation certificate, please tell me and I will
> not take up more of your time.

**加与不加的权衡**

| | 加 | 不加 |
|---|---|---|
| 好处 | 拿到明确答复更快；显得坦白；若被拒可尽早转向付费证书 | 不主动引出可能的拒绝理由 |
| 代价 | 可能把一个还在犹豫的申请直接推成「不」 | 可能白等数周，最后仍因同一条被拒 |

我的建议：**加**。理由是本项目的端口/暴露面功能与该条款的举例
（"identifying unprotected network ports"）几乎是字面重合，
审核方看到仓库大概率会自己提出来 —— 与其被动等，不如主动把话说清楚，
同时争取一次解释机会（官方明确写过 "We will listen to arguments about your
specific situation"）。
