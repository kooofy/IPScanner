# Comparable Products: Commercial / Freemium Desktop & Small-MSP LAN Scanning + Asset Inventory

Research companion for IPScanner (Windows/PyQt5 + CLI LAN scanner). Focus: commercial/freemium desktop and
small-MSP side of the market. Compiled from vendor pages, pricing pages, help centres, and review aggregators.

---

## 1. Product-by-product findings

### Advanced IP Scanner (Famatech)
**Positioning:** Free Windows LAN scanner for sysadmins; claims **70 million users**, portable, no install.
**Paid lever:** The tool itself is free — Famatech monetizes the adjacent **Radmin** remote-desktop product and
**Radmin VPN**. Advanced IP Scanner actively cross-sells RDP/Radmin remote control and remote shutdown.
**Features:** ping sweep, MAC/ARP detection, shared-folder access, RDP/Radmin launch, remote wake/shutdown,
CSV export.
**Gap:** no SNMP, no scheduled scans, no history/diff, no topology, no CLI, no API, no risk scoring.
**i18n:** UI localized into **~35 languages including 简体中文 and 繁體中文** — the strongest localization story
in the free tier of this market.

### Advanced Port Scanner (Famatech)
Same family and same free positioning. Multi-threaded TCP port scan, **service/version identification for
programs on detected ports**, one-click HTTP/HTTPS/FTP/share access, Wake-on-LAN, remote shutdown, remote
command execution. Windows-only consumer-grade UI. No scheduling, no database, no diffing.

### SoftPerfect Network Scanner
**Positioning:** Professional multipurpose admin tool; **Windows, macOS and Linux**; portable/USB edition.
This is the most feature-dense *desktop* competitor to IPScanner.
**Feature depth:** IPv4 **and IPv6** discovery; ping sweep; **MAC detection even across routers**; TCP + some
UDP/SNMP port scanning; **service banner grabbing**; **SSL/TLS certificate details incl. expiry**; hidden/writable
share discovery; **WMI, remote registry, file system, service manager** queries; logged-on users, accounts, uptime;
remote **SSH, PowerShell, VBScript and Python** execution; **Nmap integration** for OS discovery and vuln tests;
Wake-on-LAN, remote shutdown, network messaging; export to **HTML, XML, JSON, CSV, TXT**.
**Missing:** no historical snapshots/change diffing, no topology map (they sell a separate *Switch Port Mapper*),
no risk scoring, no built-in scheduler-driven alerting in the NMS sense.
**Pricing (verified on the store):** perpetual licence, **unlimited devices scanned** — the licence limits
*installations*, not devices scanned. Free unlimited-duration trial capped at **10 devices displayed**.
CNY store prices: single device Home ¥99 / Business ¥329; up to 5 devices ¥239 / ¥1,270; up to 10 devices
Business ¥2,340; **site licence unlimited ¥6,710**; **worldwide unlimited ¥20,100**. Includes 1 year of updates;
EDU/charity 50% discount. **This is the single most important price anchor for a paid IPScanner tier.**

### Fing (Fing Desktop / Fing Agent / Fing Mobile / Fing Web)
**Positioning:** Consumer-to-pro network scanner and 24/7 monitoring; **owned by Lansweeper since 2020**;
Fingbox hardware was **discontinued in 2024 and replaced by Fing Agent** (Raspberry Pi / Docker / Snap).
**Pricing (verified):** Free = **3 manual scans/day**, speed tests, network/ISP reporting, timeline limited to
"Today". **Premium $8.99/mo or $79.99/yr** = continuous monitoring, full event timeline, block/limit internet,
autoblock unknown devices, **2 monitored networks**, mobile+email notifications.
**Professional $19.99/mo or $179.99/yr** = shared workspaces, cross-network advanced search, multi-user
collaboration, filter templates, **3–18 monitored networks** (tiered slider), advanced reporting.
**Key concept to copy:** monetization is anchored on a **"monitored network"** unit — you need an active Fing
Desktop/Agent/Fingbox at the site. Pricing scales by *sites*, not devices.
**Strengths:** AI/ML device recognition engine trained since 2016, cloud sync, multi-platform (Windows/macOS/
iOS/Android/web), presence tracking, new-device detection.
**Weaknesses:** cloud account required, no SNMP/WMI depth, no real port-scan depth, no topology map, no CLI.

### Lansweeper
**Positioning:** Enterprise ITAM / "Cyber Asset Intelligence" (IT, OT, cloud, IoT); agentless + agent.
**Paid drivers:** continuously validated inventory, config-drift detection, security-control coverage evidence,
risk remediation workflows, orchestration/automation, deep ITSM integrations (ServiceNow, Jira SM, HaloITSM,
Freshservice, TOPdesk), SIEM (Splunk, Microsoft Sentinel), Armis connector.
**Pricing:** asset-based; **Starter ≤250 assets** (~$3k–6k/yr), **Pro 250–5,000 assets** ($8k–60k/yr),
**Enterprise 5,000+** ($50k–150k+). On-prem maintenance **18–22% of licence/yr, escalating 3–5%**.
Vendr reports **avg contract value $2,761** with typical 500–750-asset deals at **$10k–15k/yr**.
**Complaints:** overage/true-up fees **20–40% above base per-asset rate**; asset counts are usually
underestimated at scoping; cloud renewals without renegotiation rise **5–10%**.

### Total Network Inventory (TNI 6, Softinventive Lab)
The closest "affordable paid" analogue to IPScanner's inventory ambitions.
**Features:** agentless scanning of **Windows, macOS, Linux, FreeBSD** plus SNMP/VMware network devices;
optional **resident agent**; AD domain import; **file-per-device inventory database** (or DB-backed for
multi-user); hardware/software inventory; **software licence management (SAM)** with key storage and live
compliance calculation; **scheduled scanning** with per-group schedules; **Change Log** comparing snapshots
(added/removed/modified); **notifications of hardware/software issues**; **network map module** (manual
drag-and-drop, multi-level per site/floor, unlimited size); custom report builder; hardware sensor stats.
**Pricing:** perpetual, **30-day free trial**, **~$90 for 25 nodes** with 1 year of updates, Standard vs
**Professional** (SAM module, network map, sensor stats, hardware alerts gated to Pro); node = any device with
an IP; manually-added custom assets are **not** counted as nodes; **MSP/ITSP licensing available** for scanning
client machines; EDU/GOV −30%, competitive switch −50%.
**i18n:** UI in 14 languages **including 简体中文 and 繁體中文**.

### NetCrunch (AdRem Software)
**Positioning:** all-in-one agentless NMS for larger environments (up to 10,000 nodes / 100,000 interfaces).
**Paid drivers:** **730+ agentless monitoring targets**, policy-based configuration with inheritance and
"Monitoring Packs", built-in flow/NetFlow analysis, **automatic Layer-2 topology and VLAN maps**, config
backup + unauthorized-change detection, alert correlation/forecasting/escalation, OTLP + two-way REST API,
secure live dashboard sharing and iframe embedding, zero-trust browser-to-server tunnel, 20+ integrations.
**Packaging claim (marketing):** "no sensor counting, no hidden modules, no upsells"; subscription or perpetual;
pricing is **per node with every feature included**; free NetCrunch Tools bundle as a lead magnet.
*Note: I could not fetch the live AdRem price table (site redirects/timeouts) — exact per-node figures unverified.*

### UVexplorer (UVnetworks → **acquired by Paessler**)
The single most relevant topology competitor. **Auto-generated L2 maps down to port level**, export to
**Visio, PDF, SVG, Lucidchart**; port-level link discovery; **device configuration backup + config change
tracking**; scheduled discoveries; **network change notifications** (device appear/disappear, link change);
detailed inventory (serial numbers, IP/MAC, installed software, NICs, route tables, ARP caches, BIOS);
wireless management with **rogue AP detection**; VMware/Hyper-V discovery; L2 trace and rogue IP/MAC tools;
integrations with **PRTG, IT Glue, Hudu, ServiceNow, Slack, Lucidchart, Asset Panda**; PRTG server aggregation.
**Positioning:** "pay far less than competing solutions", compliance documentation (PCI, HIPAA, FISMA, SOX).
*Note: UVexplorer pricing pages now 404 — folded into Paessler; exact figures unverified.*

### Domotz
**Positioning:** agent-native RMM-lite for MSPs, IT teams, AV/smart-building integrators.
**Pricing (verified, Sep 2026):** flat **€35 per Collector (site) per month**, every feature included, unlimited
devices and unlimited users; volume ladder on 12-month term drops to **€31.50 @5, €28 @10, €25 @50, €22.50 @100,
€20 @250, €17.50 @500+**; residential integrators **€20 → €8 per home**; 14-day free trial, no credit card.
**Paid drivers:** MAC-address-based device identity (survives IP changes), custom open driver framework,
**remote power on/off/cycle**, **automated config backup/restore**, secure tunnels (HTTP/HTTPS/SSH/RDP/Telnet/TCP)
plus **VPN on Demand**, real-time topology, SNMP, PSA/ticketing integrations, API, mobile app, **MCP server**
for driving it from AI assistants, 16 deployment options incl. first-party Domotz Box appliance.
**Explicitly anti-Auvik positioning:** "no licensing audits, no surprise renewal hikes, no feature gating".

### Auvik
**Positioning:** cloud NMS for MSPs; **no published pricing**, custom quote per deal.
**Billing model (key lesson):** bills per device across **three categories — network devices (routers, switches,
firewalls, wireless controllers), infrastructure (servers, hypervisors), edge (workstations, laptops)** at
different rates; **APs, printers, IoT and UPS are monitored free** — a deliberate freemium hook inside a paid
product. Volume discounts only become meaningful at **100–250+ billable devices**.
**Strengths:** very fast agentless discovery (collector on any site server), automatic device categorisation,
**TrafficInsights** traffic analysis, config backup/history, network map, remote browser/terminal access.
**Complaints (heavy, from PeerSpot review verbatims):** alert noise and false positives out of the box
("a printer being out of paper", 50 emails when changing 25 IPs); **no maintenance-window / alert-mute window**;
dashboard **not customizable**; built-in reports too rigid; **missing server hardware monitoring**;
**network map cannot be manually corrected** and mis-attributes devices (workstations shown as APs, stale
disconnected nodes never removable); map links carry **no speed/utilization data** and single-colour links;
accuracy degrades on complex/multi-subnet sites; UI "clunky"/sluggish, topologies with 830 devices "not smooth",
Firefox unusable (Chrome only); steep learning curve, tier-1 techs cannot self-serve; **search requires exact
syntax with no autocomplete**; **hostnames often not retrieved (generic names)**; **no SMS/text alerts (email
only)**; remote tunnelling failures give **no error reason**; **no mobile app**; device proxy Mac client broken;
Ubiquiti config backup broken; can't buy an upgraded feature per-device (must upgrade the whole site).

### PRTG (Paessler)
**Positioning:** sensor-licensed monitoring, SMB→enterprise. **Freeware Edition = 100 sensors (~10 devices)**,
perpetual; 30-day trial unrestricted.
**Pricing (verified):** PRTG 500 **$200/mo** paid annually (~50 devices), 1000 $358/mo (~100 devices),
2500 $742/mo, 5000 $1,300/mo, 10000 $1,642/mo. **One licence key per server; licences cannot be combined.**
**Paid drivers:** maps & dashboards, alerting/notifications, distributed monitoring with remote probes,
customizable reporting, multiple UIs, network topology (now via acquired **UVexplorer** integration),
Sensor Hub for community sensors. Pain point: the **per-sensor "sensor tax"** and caps.

### ManageEngine OpManager
**Free tier (verified):** permanent free edition limited to **3 devices** — basic uptime/response time, CPU/mem/
disk, interface errors; basic email/SMS thresholds; unified NOC dashboard; VM monitoring (VMware/Hyper-V/Xen).
**Gated to paid:** multi-site discovery and topology maps, custom reports and long retention, RBAC/SSO,
ITSM/ticket/webhook integrations, escalation rules and maintenance windows. Paid is device-based, scalable to
thousands. **Free tier is too small to matter as a competitor but useful as a packaging reference.**

### SolarWinds
**IP Address Manager (IPAM)** and **Network Topology Mapper (NTM)**. NTM is a Windows desktop L2/L3 auto-
discovery and diagramming tool sold under a **per-device licence + annual maintenance** model (list prices
visible on resellers such as CDW). SolarWinds is now pushing per-node SaaS ("starts at $7/node/mo" per Domotz's
comparison table) and module-based Orion licensing. **Complaint pattern:** module bloat, heavy infrastructure,
slow legacy UX, per-node/per-module cost stacking. I could **not verify** whether NTM has been formally
end-of-sale — treat any EOL claim as unconfirmed.

### Intermapper (Fortra)
Long-standing network mapping/monitoring tool with a strong auto-discovery + live map reputation; licensed per
device count with tiered plans. **Fortra's pricing page returned HTTP 403** to automated fetch, so exact tiers
are unverified. Known reputation: excellent topology/map UX, older UI, expensive at scale.

### NetBrain
Enterprise-grade **no-code network automation + dynamic topology (digital twin)**. No public pricing; sold
enterprise-wide with flexible licensing via partners. Positioning is NetOps automation and troubleshooting at
scale, not inventory. Relevant to IPScanner only as the aspirational "topology that tells you why" end of the
market.

### NirSoft (PingInfoView, NetBScanner) / LizardSystems Network Scanner / Slitheris / iNet / LanScan
- **NirSoft PingInfoView:** free, tiny, multi-host ping monitor with logging and CSV/TXT export. No discovery,
  no inventory. Wins purely on being free, portable, and fast to start.
- **NetBScanner:** free NetBIOS scanner — machine name, workgroup, MAC, IP. Single-protocol utility.
- **LizardSystems Network Scanner:** free for **non-commercial use only**; paid licence for commercial use —
  a licence-annoyance model users dislike. Host discovery, ports, shares, NetBIOS, WoL, export.
- **Slitheris Network Discovery (Komodo Labs):** SMB-oriented discovery that goes deeper than ping/ARP —
  identifies device type/vendor/OS with a "get to know your network" wizard and asset detail views; licensed
  per number of devices. Good UX reference for "friendly discovery".
- **iNet / LanScan (macOS):** consumer/small-office Bonjour/Apple-centric scanners; LanScan is a paid Mac App
  Store utility with tiers (free version restricted, Pro/upgrade IAP) — pure "free tier is a demo" packaging.

---

## A. What users actually complain about (ranked)

1. **Per-device / per-sensor cost stacking ("the per-device tax").** Auvik bills workstations as "edge devices";
   PRTG counts sensors; Lansweeper counts every discovered asset and charges **20–40% overage** on top. Growth
   is punished. This is the #1 driver of switching.
2. **Alert noise and false positives, with no mute/maintenance window.** Auvik verbatims: printer-out-of-paper
   tickets, 50 emails from 25 IP changes, no way to whitelist a 1–4 a.m. backup window.
3. **Slow, collapsing UI and topology at scale.** 830-device map "not smooth"; browser-specific failures;
   dashboards that aren't customizable; search without autocomplete.
4. **Topology maps that are wrong and cannot be corrected.** Wrong parent/child, stale disconnected nodes that
   can't be deleted, workstations shown as APs, links with no speed/utilization, no manual editing.
5. **Device identification failures.** Generic names instead of hostnames; IP-based identity breaking on DHCP
   churn (Domotz explicitly weaponizes MAC-based identity against Auvik here).
6. **Opaque pricing and quote-only sales.** No published price, long sales cycle, renewal hikes, true-ups.
7. **Cloud/account mandates and privacy discomfort.** Fing requires an account; on-prem-only shops object.
8. **Shallow free tiers / nagging licences.** SoftPerfect trial shows only 10 devices; LizardSystems free is
   non-commercial only; OpManager free caps at 3 devices; Fing free caps at 3 scans/day.
9. **Steep learning curve / tier-1 techs locked out.** Enterprise UIs need training; simple "just scan and show
   me" workflows are missing.
10. **Missing API / automation / integrations on lower tiers** and missing IPv6 in desktop-grade tools.

---

## B. Feature highlights a v1.8 desktop tool should target

| # | Feature | Source product |
|---|---|---|
| 1 | **IPv6 discovery** alongside IPv4, end-to-end | SoftPerfect |
| 2 | **MAC-based device identity** that survives IP changes/DHCP churn | Domotz |
| 3 | **Snapshot history + human-readable change log** ("added / removed / modified") | TNI 6 |
| 4 | **Port-level L2 topology** with export to Visio/PDF/SVG | UVexplorer |
| 5 | **Device config backup + unauthorized-change detection** | NetCrunch, UVexplorer, Auvik |
| 6 | **Service banner grabbing + TLS certificate expiry tracking** | SoftPerfect |
| 7 | **Remote action bundle**: WoL, shutdown, RDP/SSH/VNC launch, remote command execution | SoftPerfect, Auvik, Domotz |
| 8 | **Scheduled scans per device group** with per-group schedules | TNI 6 |
| 9 | **Maintenance windows / alert suppression + alert correlation** to kill false positives | NetCrunch (Auvik's gap) |
| 10 | **Custom report builder + multi-format export** (HTML/CSV/JSON/XML/XLSX/PDF) | TNI 6, SoftPerfect |
| 11 | **"New device found" + rogue AP detection notifications** | UVexplorer, Fing |
| 12 | **Credentials vault** (SNMP v1/v2c/v3, WMI, SSH) with per-subnet profiles | Auvik, Lansweeper |
| 13 | **Rogue/duplicate IP and MAC detection + L2 trace** | UVexplorer |
| 14 | **Manual topology editing / pinning and annotations** (hybrid auto+manual map) | Auvik's biggest complaint; TNI map |
| 15 | **Headless CLI + JSON output + local REST/API + MCP server** for AI/automation | Domotz MCP; Auvik's closed AI |
| 16 | **License/software inventory with compliance calculation** | TNI Pro, Lansweeper |
| 17 | **Zero-cloud / local-first operation** with optional sync | the unserved on-prem segment |

---

## C. Packaging & monetization lessons

**Observed free-vs-paid splits in this category:**
- *Free = a demo with a hard cap.* SoftPerfect: 10 devices displayed. OpManager: 3 devices. Fing: 3 scans/day.
  LizardSystems: non-commercial only. Effect: high irritation, but very effective conversion pressure.
- *Free = genuinely free, monetize adjacent.* Advanced IP Scanner/Port Scanner are fully free; Famatech sells
  **Radmin** (remote desktop) and **Radmin VPN**. This is the cleanest OSS-friendly analogue.
- *Free = generous core, pay for persistence and scale.* PRTG 100 sensors perpetual; Domotz unlimited devices
  but pay per site; NetCrunch free companion tools; Lansweeper free trial only.
- *Paid unit varies wildly:* per **device** (Auvik, Lansweeper, TNI, SolarWinds), per **sensor** (PRTG), per
  **node/interface** (NetCrunch), per **site/collector** (Domotz, Fing "monitored network"), per **installation**
  (SoftPerfect). **Per-site and per-installation are the friendliest to buyers**; per-device is the most hated.

**Credible path for an OSS IPScanner:**
1. **Core stays free and unlimited** (devices *and* sites) — this is the wedge against SoftPerfect's 10-device
   trial, Fing's 3-scan limit, and OpManager's 3 devices. Free must be *unambiguously* better than those trials.
2. **Paid add-ons, not crippled core.** Candidates: multi-user/shared inventory server, credential vault with
   encryption + audit log, scheduled-scan service + alerting (email/Teams/Slack/webhook), PDF/Excel branded
   report packs, config-backup module, MSP multi-tenant workspace. TNI already proves people pay for exactly
   this bundle at **~$90 for 25 nodes perpetual** — so the price ceiling for a desktop SKU is low.
3. **Sponsorship / GitHub Sponsors + a "Pro" perpetual licence** mirroring SoftPerfect's ladder
   (single-seat → site → worldwide). Perpetual + 1 year of updates matches buyer expectations in this niche
   and avoids subscription fatigue.
4. **Dual licensing (GPL/AGPL + commercial)** if you want OEM/embedded reuse; risk: contributors and
   corporate users flee AGPL, and you must own or have CLA over all contributed code from day one.
5. **Enterprise integrations as the real revenue** — IT Glue/Hudu/ServiceNow/PRTG connectors, SSO/RBAC,
   audit export. UVexplorer and Lansweeper both monetize integrations; this is where per-seat money actually is.
6. **Support/SLA contracts** and paid deployment assistance (NetCrunch gives away free initial setup as a
   sales tool — the inverse works too).

**Risks:** (a) free tier too generous → no conversion; (b) crippling the free core destroys the word-of-mouth
that makes Advanced IP Scanner a 70M-user asset; (c) per-device pricing imports the category's most-hated
pattern; (d) AGPL dual-licensing requires a CLA and deters enterprise legal teams; (e) sponsorship revenue is
volatile and rarely funds a full-time maintainer; (f) if Fing/Lansweeper ship a free desktop tier, an OSS tool
must win on **no account, no cloud, no limits, scriptable**.

---

## D. Accessibility & i18n observations

- **Famatech is the benchmark:** Advanced IP Scanner and Advanced Port Scanner ship UI in **~35 languages
  including 简体中文 and 繁體中文**; the language list is exposed in the site footer and the app itself.
- **TNI 6** localizes its UI into **14 languages including 简体中文 and 繁體中文**. Reports and exports follow
  the UI language; the site has per-locale URLs (`/zh-cn/`, `/zh/`).
- **SoftPerfect** ships "multilingual packages" as a distinct download, signalling that localization is
  treated as a packaging artifact, not a build default.
- **ManageEngine** documents GUI language options as **English, Spanish, Chinese (Simplified/Traditional),
  Japanese, French, German, Italian** — and markets OS coverage "with multiple language options" as a feature.
- **Paessler PRTG** localizes the *website and marketing* into DE/ES/FR/IT/PT-BR but the product UI is
  primarily English — a common enterprise pattern: localize acquisition, not the console.
- **Fing** localizes the marketing site (ES/EN toggle visible) and the mobile apps broadly; reports are
  generated from cloud templates.
- **What is localized in practice:** UI chrome/labels, installer, docs/help centre, marketing site and pricing
  pages, and — less often — **report and export templates**. Very few localize CSV/JSON *field names*, which is
  where machine-readable exports usually leak English. **Recommendation for IPScanner:** localize UI, installer,
  CLI help/error text, and **report templates** (PDF/HTML) fully for zh-CN; keep CSV/JSON **keys stable and
  English** for scriptability, but localize human-facing header rows. Also localize date/number formats and
  ensure CJK font fallback in the Qt report renderer and in generated PDFs.
- **Accessibility is largely absent from this category's marketing.** No vendor in scope advertises WCAG
  conformance, screen-reader support for topology canvases, or keyboard-navigable maps. Auto-generated
  force-directed topology graphics are the hardest accessibility problem here; providing a **parallel textual
  topology tree / ASCII-art map export** would be a genuine differentiator (Auvik reviewers even said the
  "textual representation of the network map was more useful than the graphical view").

---

## E. Most authoritative URLs used

**Vendors / pricing**
- https://www.advanced-ip-scanner.com/
- https://www.advanced-port-scanner.com/
- https://www.softperfect.com/products/networkscanner/
- https://www.softperfect.com/order/?product=sns
- https://www.softperfect.com/order/licenses.htm
- https://www.fing.com/pricing/
- https://www.fing.com/about-us/ (ownership, Fingbox→Agent, Fing Professional 2025)
- https://www.fing.com/desktop/
- https://www.lansweeper.com/pricing/
- https://www.lansweeper.com/product/features/
- https://www.total-network-inventory.com/
- https://docs.softinventive.com/tni/pricing-and-licensing/licensing-faq/
- https://www.adremsoft.com/ (NetCrunch 16 features, pricing claims)
- https://www.uvexplorer.com/uvexplorer/
- https://www.paessler.com/press/pressreleases/paessler-acquires-uvnetworks
- https://www.paessler.com/pricing
- https://www.paessler.com/free_network_monitor
- https://www.domotz.com/pricing.php
- https://www.domotz.com/compare/domotz-vs-auvik
- https://www.auvik.com/pricing/
- https://www.manageengine.cn/network-monitoring/free-network-performance-monitoring.html
- https://documentation.solarwinds.com/en/success_center/ntm/content/release_notes/ntm_2-4-4_release_notes.htm
- https://www.netbraintech.com/
- https://www.fortra.com/products/network-monitoring-software/intermapper-pricing-plans (403 to automation)

**Reviews / complaints / third-party pricing**
- https://www.peerspot.com/products/auvik-network-management-anm-room-for-improvement
- https://www.peerspot.com/products/auvik-network-management-anm-reviews
- https://www.capterra.com/p/145245/Auvik/reviews/
- https://www.capterra.com/p/15683/AdRem-NetCrunch/reviews/
- https://www.g2.com/products/lansweeper/reviews
- https://www.vendr.com/marketplace/lansweeper (negotiated Lansweeper pricing benchmarks)
- https://www.trustpilot.com/review/adremsoft.com
- https://community.spiceworks.com/t/advanced-ip-scanner-returns-some-names-but-not-all/942827
- https://www.reddit.com/r/Fing_App/
- https://www.cdwg.com/product/solarwinds-network-topology-mapper-license-1-year-maintenance-1-device/4278047
