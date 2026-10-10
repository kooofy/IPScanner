# IPScanner 1.7.x → next 2–3 releases: technology & scope trends (2024–2026)

*Prepared 2026-10-10. Solo Python/PyQt5 maintainer, Windows-only, IPv4-first LAN/IPAM tool, PyInstaller onedir.*

---

## 1. IPv6 in LAN discovery

**What changed.** Nmap's `targets-ipv6-multicast-echo.nse` sends one ICMPv6 echo to the all-nodes link-local multicast `ff02::1` "to discover responsive hosts on a LAN without needing to individually ping each IPv6 address" ([Nmap NSE](https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-echo.html)). Standalone tooling exists ([ipv6disc](https://github.com/miguelangel-nubla/ipv6disc)) and research continues ([IEEE TrustCom 2025](https://www.computer.org/csdl/proceedings-article/trustcom/2025/653200a578/2dMlpVAIjtK)). RFC 9099 remains the pitfalls reference ([RFC 9099](https://www.rfc-editor.org/rfc/rfc9099.html)).

**Implementable unelevated.** (a) `psutil.net_if_addrs()`/`GetAdaptersAddresses` for your own global/ULA/link-local addresses. (b) The already-populated NDP cache via `GetIpNetTable2(AF_INET6)` or `netsh interface ipv6 show neighbors` — instant, free, and it works where ICMPv6 is filtered; the highest-yield v6 feature by far. (c) One Scapy ICMPv6 echo to `ff02::1` per interface: an ICMPv6 raw socket does not need `IP_HDRINCL`, so unlike IPv4 raw ICMP (admin-only since XP SP2) this is often possible unelevated — test before promising it. (d) mDNS over v6 (join `ff02::fb`; python-zeroconf handles the socket). (e) DHCPv6 has no unprivileged observation path.

**Pitfalls.** Zone IDs are mandatory for link-local (`fe80::1%12`) — propagate the interface index through the data model. `ff02::1` only reaches the on-link segment. Many hosts drop ICMPv6 deliberately. RFC 4941 privacy addresses mean one device = many addresses; collapse on MAC/DUID or asset counts explode. NDP/`netsh` caches hold stale entries, producing false "still present".

**Verdict:** adopt a 1.8 module that *attaches* v6 addresses to existing IPv4 assets, keeping active scanning IPv4-only; full v6 inventory in 2.x. **Risk low, effort 1–2 weeks.** **Skip** DHCPv6 snooping, RA/PD analysis, DAD auditing, /64 sweeps.

---

## 2. Wireless / Wi-Fi layer

**What changed.** Wi-Fi 7 is now the enterprise default: IDC data via Wi-Fi NOW puts Wi-Fi 7 at **53% of enterprise dependent-AP revenue in Q2 2026** (44.5% in Q1 2026, up from 11.8% a year earlier), Wi-Fi 6 down to 29.4% and 6E to 16.9% ([Wi-Fi NOW/IDC](https://wifinowglobal.com/news-blog/wi%E2%80%91fi-7-becomes-enterprise-wlans-biggest-revenue-category-as-market-surges-23-idc-says/)). MLO, 320 MHz and 6 GHz are table stakes for any analyser.

**Realistic on Windows.** The Native Wi-Fi API (`wlanapi.dll` via `ctypes`: `WlanOpenHandle`, `WlanEnumInterfaces`, `WlanGetAvailableNetworkList`, `WlanQueryInterface` with `wlan_intf_opcode_current_connection`) returns SSID, BSSID, channel, band and signal per visible network without admin; `netsh wlan show networks mode=bssid` is the fallback ([netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)); a published ADR documents this choice for a Python Wi-Fi tool ([roamr ADR-0004](https://github.com/sourabh-khot65/roamr/blob/HEAD/docs/adr/0004-windows-native-wifi-api.md)).

**Shippable value:** channel-occupancy histogram, co-/adjacent-channel congestion scoring, a connected-BSSID-to-AP map built over time, roaming-event logging (BSSID change, signal delta, time-to-roam), weak-security detection (open/WEP/TKIP, no WPA3, no PMF), and **SSID/BSSID → subnet correlation** — "which AP is this asset behind?" is genuinely new for a LAN inventory tool.

**Hard limits.** Windows exposes only the *connected* BSSID, never all BSSIDs for an SSID, so a true AP-to-client map needs beacon capture. Monitor mode is the wall: Npcap advertises raw 802.11 with radiotap ([npcap.com](https://npcap.com/)) but depends on the driver exposing `DOT11_OPERATION_MODE_NETWORK_MONITOR`, still a long-open complaint ([npcap#763](https://github.com/nmap/npcap/issues/763)). **Verdict:** adopt the API-only slice. **Risk low–medium, effort 1–2 weeks.** **Skip** spectrum analysis, monitor-mode site surveys, 802.11r/k/v.

---

## 3. Passive / zero-touch discovery

**What changed — the biggest shift in your window.** Microsoft is retiring the two legacy name protocols you lean on. CISA's **CM0053 (March 2025)** recommends disabling LLMNR because it is "exploited by attackers to perform man-in-the-middle (MitM) attacks and credential harvesting via LLMNR poisoning" ([CISA](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0053)). Microsoft's **November 2025** note confirms WINS is removed from all Windows Server releases after Server 2025 (standard support to November 2034), with DNS/DNSSEC as the replacement ([KB5071836](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/11/wins-removal-moving-forward-with-modern-name-resolution)). NetBIOS/LLMNR responders persist for years but are shrinking — so **mDNS becomes your primary name source, and an active LLMNR/NetBIOS responder becomes a security *finding*, not just a data source.**

**State of the art at desktop scale.** The market moved to passive-first classification (Corelight sells asset classification as a by-product of passive sensors — [brief](https://corelight.com/hubfs/resources/joint-solution-briefs/corelight-asset-classification-sb.pdf)). Realisable: ARP/neighbour cache polling every 60–120 s (`arp -a`, `GetIpNetTable2`, `Get-NetNeighbor`); a python-zeroconf mDNS/DNS-SD browser; one periodic SSDP `M-SEARCH` to `239.255.255.250:1900` (the richest low-effort source of model strings, and where UPnP exposure risk hides); `Get-NetTCPConnection` observation to infer who-talks-to-whom with zero packets; and an **optional** Npcap slice (DHCP option 55/60 fingerprints, DNS names).

**Verdict: your #1 bet** — it turns the product from "a scan I run" into "an inventory I trust". **Risk low (polling) / medium (Npcap); effort 1–2 weeks.** **Skip** switch-side DHCP snooping, SPAN/mirror sampling, bundling Zeek/Suricata.

---

## 4. SNMP and modern telemetry

**What changed.** gNMI/OpenConfig ships on current gear ([Cisco MDT](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/prog/mdt/model-driven-telemetry.pdf), [ManageEngine](https://www.manageengine.com/news/manageengine-opm-nexus-streaming-telemetry.html)) but standards-side adoption is slow: an IETF NETCONF/NMOP session states that "YANG Push [RFC8641] was standardized by the IETF in 2019, but market adoption has been rather slow" ([IETF 126](https://datatracker.ietf.org/meeting/126/agenda/netconf-drafts.pdf)). SNMP v2c remains the interoperable floor; v3 is universally supported in principle but USM keys, engine IDs and per-vendor quirks keep v2c dominant in the SMB/edge segment. Treat "v3 is standard now" as a vendor slide, not a field fact.

**Realistic for 2026:** keep SNMP as the topology workhorse and (a) make v3 demonstrably modern — SHA-256/AES-256 preferred with legacy fallback; (b) turn weak SNMP into a *finding* (v2c `public`/`private`, v1 enabled); (c) pin your library hard, because pysnmp is fragmented across 5.x→6.x→7.x under the lextudio fork with an explicit upgrade guide ([pysnmp upgrade docs](https://github.com/lextudio/pysnmp/blob/release-7.1/docs/source/upgrade.rst)). **Verdict: harden, don't chase. Risk low, effort 2–3 days.** **Skip** gNMI/gRPC streaming, NETCONF/RESTCONF, YANG browsing — per-vendor OpenConfig path maps plus TLS/gRPC plumbing is months of work for telemetry you have no UI to display. Revisit only on paid demand.

---

## 5. Security posture / vulnerability adjacency

**What changed, in your favour twice.** Free prioritisation data became API-accessible: **EPSS** publishes a daily 0–1 exploitation probability plus percentile per CVE via CSV and an open API ([FIRST EPSS](https://www.first.org/epss/)), **CISA KEV** is a downloadable JSON catalogue of known-exploited CVEs ([KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)), and FIRST documents combining EPSS with CVSS *and* KEV ([Using EPSS](https://www.first.org/epss/using-epss)). Second, the platform baseline moved: **SMB signing is required by default on all inbound and outbound connections starting Windows 11 24H2 / Windows Server 2025**, guest fallback is off by default on Win11 Pro, SMB1 is removed, NetBIOS ports left the default firewall rules, and a 2-second-per-failure SMB authentication rate limiter is on by default ([Microsoft SMB hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)). "Is SMB signed?" is now a *deviation* signal with high signal-to-noise.

**Realistic and high value, all local, no exploitation:** TLS certificate expiry / self-signed / weak signature (stdlib `ssl`); SMB signing/dialect/guest posture; weak-protocol detection (telnet, FTP, unauthenticated HTTP admin, default SNMP community); and banner/version → CVE ranked by KEV+EPSS against an **embedded offline snapshot**, so no scan data leaves the LAN.

**Guardrails.** Do not build a brute-forcer. Single-attempt, opt-in default-credential checks on printers/routers *will* cause lockouts. Commercial scanners wrap scanning in explicit authorisation language — Tenable's agreement is representative ([Tenable](https://static.tenable.com/prod_docs/Tenable_Scanning_Services_Agreement.pdf)). Your posture: unskippable first-run and per-network acknowledgement ("I own this network or hold written authorisation"), scan-scope allowlist, immutable audit log, and UI copy noting port scanning is regulated in some jurisdictions. **Risk low (TLS/SMB/protocol), medium (CVE accuracy); effort ~2 weeks.**

---

## 6. AI/LLM: real vs hype

**What's real.** 2025–26 research moved from chatbots to constrained classification — LLM-based IoT fingerprinting ([ShadowScan, IEEE](https://xplorestaging.ieee.org/document/11413986)) and parameter-efficient log anomaly detection ([LINEADAPTER, ICPADS 2025](https://ieeexplore.ieee.org/document/11322907)). The four defensible features for a LAN tool: natural-language query over results; auto-summarised change reports from your history diff; **rule/statistics anomaly detection** (new MAC on a known IP, port-set drift, new sysObjectID, first-seen vendor) which needs no model and is the best value/risk item; and device labels from OUI + mDNS + `sysDescr`.

**What's hype here:** autonomous "AI agent scans and fixes your network", cloud inference in the default path, and vector-DB/RAG stacks for a few thousand assets.

**Privacy is the design constraint.** A tool that ships scan results to a cloud LLM is unsellable to the buyers who need LAN inventory. Resolution: **default offline, NL query compiled deterministically** ("Linux devices not seen in 30 days" → parameterised ORM filter), covering ~80% of real queries with no model; then an *optional* local inference endpoint (e.g. `http://127.0.0.1:11434`) that users opt into and that never phones home. Do not bundle a multi-hundred-MB model into a PyInstaller onedir. **Risk low (offline NL→filter, summaries, anomaly rules), high (any default cloud LLM); effort 1 week.**

---

## 7. OT/ICS and IoT scope

**What changed.** Matter/Thread identification became practical without special hardware: commissioning and operational state are advertised over mDNS. Nmap's `matter-identify` NSE (May 2026) queries `_matter._tcp.local` (commissioned), `_matterc._udp.local` (commissioning mode) and `_meshcop._udp.local` (Thread border routers) on 5353/udp, decoding TXT records into Vendor ID, Product ID, device type, fabric/node ID, discriminator and commissioning mode — its sample output resolves an Eve Energy plug-in unit from VID/PID/device type ([nmap-dev, May 2026](https://seclists.org/nmap-dev/2026/q2/5)). Matter 1.5 added device classes including cameras and closures ([Silicon Labs](https://www.silabs.com/blog/matter-1-5-for-next-generation-smart-homes)); Thread 1.4 documentation is public ([Thread Group](https://www.threadgroup.org/Portals/0/Documents/Thread_1.4_Features_White_Paper_September_2024.pdf)). The OT-vendor lesson (Claroty, Dragos) is that identification is **passive and multi-signal** — DPI plus protocol signatures plus behavioural baselines — not one probe ([Dragos](https://www.dragos.com/cybersecurity-platform/network-monitoring)).

**Realistic, strictly read-only:** BACnet `Who-Is`/`I-Am` on UDP 47808 (safe by design); Modbus TCP **Function Code 43 / MEI type 14 "Read Device Identification"**; PROFINET DCP Identify; EtherNet/IP ListIdentity; plus Matter/Thread zeroconf TXT decoding. **Verdict: optional, labelled "OT/IoT identify (read-only)". Risk low if single-shot; effort 2 weeks.** **Skip** any write/enumerate/force function, all of DNP3, and deep fingerprinter taxonomies — a full-time research effort no solo maintainer can hold.

---

## 8. Windows platform realities

**Npcap and licensing.** Npcap is at **1.89**, covering Windows 7→11 on x86/x64/**ARM64**, with raw 802.11 (radiotap), loopback capture and raw sending ([npcap.com](https://npcap.com/)). The trap: the free licence "allows five installs" (narrow exceptions for use solely with Nmap/Wireshark/Defender for Identity) and **"does not allow for any redistribution"**; redistribution needs an OEM licence ([Npcap OEM](https://npcap.com/oem/)). Correct design: **bundle no driver** — detect Npcap at runtime, use it opportunistically (SYN scan, DHCP/DNS enrichment), degrade gracefully to ICMP/ARP/TCP-connect without it. Budget the OEM licence *before* a feature depends on it.

**Raw sockets and secrets.** IPv4 raw ICMP and `IP_HDRINCL` remain Administrator-only, which is why your ARP-table read is more valuable than your ping on locked-down clients. DPAPI (`CryptProtectData`, user scope) is the right home for SNMP communities, v3 keys and webhook/LLM secrets ([Microsoft, Handling Passwords](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords)) — state honestly that user-scope DPAPI stops other users and disk theft, not same-session malware.

**Code signing (2026) — read this before planning releases.** Microsoft's current guidance: **EV certificates no longer bypass SmartScreen — "That behavior was removed in 2024"**, so the EV premium "solely to avoid SmartScreen warnings is no longer justified"; Azure Artifact Signing (formerly Trusted Signing) is ~**$9.99/month** but individuals are limited to **USA and Canada** (organisations US/CA/EU/UK); OV certificates are **$150–300/year** with an HSM/token requirement since the June 2023 CA/Browser Forum rules; and reputation now builds over time from a consistent signing identity, not certificate class ([Microsoft](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)). PyInstaller exes are a known Defender false-positive source ([Microsoft Q&A](https://learn.microsoft.com/en-ie/answers/questions/4078397/where-executables-created-by-pyinstaller-are-being)). Mitigations: stay **onedir** (onefile self-extraction is the bigger FP magnet), avoid UPX, embed version info and a manifest, sign exe + DLLs + installer, publish stable hashes, ship a Defender-exclusion guide, and sign from release one so reputation accrues. A China-based maintainer must verify Azure Artifact Signing eligibility before designing around it.

**Windows on ARM.** The stack is ready: Python ships a **Windows ARM64 installer** (3.15.0, 2026-10-09 — [Python 3.15.0](https://www.python.org/downloads/release/python-3150/)); PyInstaller 6.22.3 ships a `win_arm64` wheel and lists Windows ARM64 as tested for Python 3.8–3.15 ([PyPI](https://pypi.org/project/pyinstaller/)); Npcap has supported ARM64 since 1.50. The one gap is your GUI: **PyQt5 has no official ARM64 wheels** (only a community build, [PyQt5-WinARM64](https://github.com/ViciousSquid/PyQt5-WinARM64)), whereas **PySide6 ships official `win_arm64` wheels** ([Qt downloads](https://download.qt.io/official_releases/QtForPython/pyside6-essentials/)). ARM64 is therefore gated on a PyQt5→PySide6 migration. **Order of work:** Npcap-optional + graceful degradation (1 week) → DPAPI vault (1–2 days) → signing decision (1 day) → ARM64 after the PySide6 migration (1–2 weeks).

---

## A. Top 10 technical bets, ranked by user value ÷ effort

| # | Bet | Implementation sketch |
|---|-----|-----------------------|
| 1 | **Continuous passive discovery mode** | Background thread polls `GetIpNetTable2`/`arp -a` every 60–120 s plus zeroconf mDNS browse and periodic SSDP `M-SEARCH`; first-seen/last-seen written to the existing inventory DB. |
| 2 | **Zero-exploit posture checks** | `ssl` for cert expiry/self-signed/weak-sig; probes for telnet/FTP/HTTP-admin/default SNMP and SMB signing/dialect/guest; per-asset posture score. |
| 3 | **Offline CVE + KEV/EPSS prioritisation** | Bundle KEV JSON + EPSS CSV, match banners/services locally, rank KEV-first then EPSS percentile; refresh on demand, never upload. |
| 4 | **Change-report intelligence** | Turn existing history diffs into a severity-scored digest (new/changed/gone); deterministic templates now, optional LLM polish later. |
| 5 | **IPv6 visibility on IPv4 assets** | Enumerate v6 addresses + NDP cache + one `ff02::1` echo + v6 mDNS/SSDP sightings; store as attributes of the existing asset. |
| 6 | **Wi-Fi channel and roaming insight** | Native Wi-Fi API via `ctypes` for BSSID/channel/signal scans, per-band congestion histogram, roaming-event log, SSID→subnet correlation. |
| 7 | **DPAPI secret vault** | Wrap config secrets with `CryptProtectData`, migrate on first run, note in the UI that secrets are user-scoped. |
| 8 | **OT/IoT read-only identify** | Single-shot BACnet Who-Is, Modbus FC43/MEI 14, PROFINET DCP identify, EtherNet/IP ListIdentity, Matter `_matter`/`_matterc`/`_meshcop` TXT decoding. |
| 9 | **NL query, deterministic first** | Template/grammar compiler mapping natural language → ORM filter; optional localhost-only LLM behind an explicit toggle. |
| 10 | **Authorisation gate + audit log** | Unskippable per-network authorisation acknowledgement, scan-scope allowlist, append-only exportable scan audit log. |

## B. Explicit non-goals (attractive traps)

1. **Full IPv6 inventory / v6 port scanning** — /64 and scope-ID complexity make it a separate product; ship visibility, not parity.
2. **Credential brute-forcing or default-password sweeps at scale** — lockouts, broken devices, real legal exposure.
3. **Bundled capture sensor (Zeek/Suricata + Npcap driver)** — kernel driver, redistribution licence, unmaintainable solo.
4. **gNMI / NETCONF / RESTCONF / YANG push** — RFC 8641 adoption is still slow; per-vendor OpenConfig path maps are an unfunded liability.
5. **802.11 monitor-mode survey / spectrum analysis** — inconsistent Windows driver support; Ekahau et al. win on multi-adapter capture and floor plans.
6. **Active OT writes, DNP3, "ICS vulnerability scanning"** — one malformed frame can stop a process line; read-only identify only.
7. **Onefile builds, UPX packing, unsigned releases** — multiplies Defender/SmartScreen false positives and destroys first-run trust.
8. **Cloud LLM in the default path** — any scan data leaving the LAN disqualifies the tool for the buyers who need it most.
9. **MAC-address-only asset identity** — Wi-Fi MAC randomisation plus IPv6 privacy addresses break it within a year; identity must be composite (MAC + hostname + mDNS instance + `sysName`).

## C. Most authoritative sources used

- [Microsoft — Code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Microsoft — SMB security hardening (Win11 24H2 / Server 2025)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Microsoft KB5071836 — WINS removal, modern name resolution](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/11/wins-removal-moving-forward-with-modern-name-resolution)
- [CISA — CM0053: Disable LLMNR](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0053)
- [Npcap](https://npcap.com/) · [Npcap OEM licensing](https://npcap.com/oem/)
- [PyInstaller 6.22.3](https://pypi.org/project/pyinstaller/) · [Python 3.15.0 (Windows ARM64)](https://www.python.org/downloads/release/python-3150/)
- [FIRST EPSS](https://www.first.org/epss/) · [Using EPSS](https://www.first.org/epss/using-epss) · [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Nmap NSE — targets-ipv6-multicast-echo](https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-echo.html) · [RFC 9099](https://www.rfc-editor.org/rfc/rfc9099.html)
- [Microsoft Learn — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan) · [Native Wi-Fi API choice (ADR)](https://github.com/sourabh-khot65/roamr/blob/HEAD/docs/adr/0004-windows-native-wifi-api.md)
- [IDC via Wi-Fi NOW — Wi-Fi 7 = 53% of enterprise AP revenue, Q2 2026](https://wifinowglobal.com/news-blog/wi%E2%80%91fi-7-becomes-enterprise-wlans-biggest-revenue-category-as-market-surges-23-idc-says/)
- [IETF 126 NETCONF/NMOP — YANG Push adoption "rather slow"](https://datatracker.ietf.org/meeting/126/agenda/netconf-drafts.pdf) · [pysnmp upgrade guide](https://github.com/lextudio/pysnmp/blob/release-7.1/docs/source/upgrade.rst)
- [nmap-dev — matter-identify NSE (Matter/Thread mDNS, May 2026)](https://seclists.org/nmap-dev/2026/q2/5)
- [Silicon Labs — Matter 1.5](https://www.silabs.com/blog/matter-1-5-for-next-generation-smart-homes) · [Thread 1.4 whitepaper](https://www.threadgroup.org/Portals/0/Documents/Thread_1.4_Features_White_Paper_September_2024.pdf)
- [Microsoft — Handling Passwords (DPAPI)](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords)
- [Tenable Scanning Services Agreement (authorisation language)](https://static.tenable.com/prod_docs/Tenable_Scanning_Services_Agreement.pdf)
