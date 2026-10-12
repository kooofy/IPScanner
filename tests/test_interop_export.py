"""v1.9 §1.2 互操作导出包测试。

覆盖：
- 四种格式逐字节 golden file 断言（格式漂移 = 静默破坏，必须钉死）；
- 0 台设备产出**合法的空文档**（可解析的 XML 根 / 带表头的 CSV / `{"data":[]}` /
  空 router.db）；
- **语言切换（zh-CN / en-US）下字节完全一致** —— 同时证明没落 `tr()` 展示串；
- NetBox 表头与官方一致、status 映射正确、nmap 不编 `<os>`（诚实降级）；
- 解析辅助（parse_ports / parse_services）与文件写出往返。
"""

import csv
import io
import json
import os
import xml.etree.ElementTree as ET

import interop_export as ix
import i18n

_HERE = os.path.dirname(__file__)
_FIX = os.path.join(_HERE, "fixtures", "interop")

#: 与生成 golden fixture 时完全一致的样本（改样本要同步重新生成 fixture）。
SAMPLE_ROWS = [
    {
        "identity_key": "aa:bb:cc:dd:ee:ff", "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "10.0.0.1", "status": "online", "hostname": "gw.local",
        "vendor": "MikroTik", "device_class": "路由器", "os_guess": "RouterOS",
        "open_ports": "80,443,22,161",
        "services": '["http","https","ssh"]', "location": "机房A",
        "user": "", "remark": "核心网关",
    },
    {
        "identity_key": "11:22:33:44:55:66", "mac": "11:22:33:44:55:66",
        "ip": "10.0.0.9", "status": "offline", "hostname": "",
        "vendor": "", "device_class": "打印机", "os_guess": "",
        "open_ports": "", "services": "", "location": "",
        "user": "", "remark": "",
    },
]

_GOLDEN = {
    "nmap": "nmap.xml",
    "zabbix": "zabbix_lld.json",
    "netbox": "netbox.csv",
    "oxidized": "router.db",
}


def _golden_bytes(fmt):
    with open(os.path.join(_FIX, _GOLDEN[fmt]), "rb") as f:
        return f.read()


def test_golden_files_match():
    """四种格式逐字节与 checked-in 快照一致。"""
    for fmt in ix.INTEROP_FORMATS:
        got = ix.build_interop(fmt, SAMPLE_ROWS)
        assert got == _golden_bytes(fmt), (
            "格式 %s 与 golden file 不符（%d vs %d 字节）—— 导出格式漂移了！"
            % (fmt, len(got), len(_golden_bytes(fmt)))
        )


def test_empty_documents_valid():
    """0 台设备 → 合法空文档，不是空文件、不是畸形 XML。"""
    # nmap：可解析的 XML，根 nmaprun，0 个 host
    nmap = ix.build_interop("nmap", []).decode("utf-8")
    root = ET.fromstring(nmap)
    assert root.tag == "nmaprun"
    assert root.findall("host") == []

    # netbox：带表头、0 数据行，表头与官方一致
    nb = ix.build_interop("netbox", []).decode("utf-8-sig")
    rdr = list(csv.reader(io.StringIO(nb)))
    assert rdr[0] == ix.NETBOX_HEADER
    assert len(rdr) == 1  # 仅表头

    # zabbix：{"data": []}
    zb = json.loads(ix.build_interop("zabbix", []).decode("utf-8"))
    assert zb == {"data": []}

    # oxidized：空文件即合法空 router.db
    assert ix.build_interop("oxidized", []).decode("utf-8") == ""


def _restore_lang():
    i18n.init("zh-CN")


def test_language_independence():
    """语言切换下导出字节完全一致 = 没落 tr() 展示串的铁证。"""
    try:
        i18n.init("en-US")
        en = {f: ix.build_interop(f, SAMPLE_ROWS) for f in ix.INTEROP_FORMATS}
        i18n.init("zh-CN")
        zh = {f: ix.build_interop(f, SAMPLE_ROWS) for f in ix.INTEROP_FORMATS}
        for f in ix.INTEROP_FORMATS:
            assert en[f] == zh[f], "格式 %s 在 en-US/zh-CN 下字节不一致" % f
        # 规范值（中文设备类型源串）原样保留，没有翻译成展示串
        assert "路由器".encode("utf-8") in zh["netbox"]
        assert "打印机".encode("utf-8") in zh["netbox"]
    finally:
        _restore_lang()


def test_invalid_format_raises():
    import pytest
    with pytest.raises(ValueError):
        ix.build_interop("bogus", SAMPLE_ROWS)
    with pytest.raises(ValueError):
        ix.build_interop(None, SAMPLE_ROWS)


def test_parse_ports():
    assert ix.parse_ports("") == []
    assert ix.parse_ports("80,443, 22") == [80, 443, 22]
    assert ix.parse_ports("80,a,443") == [80, 443]  # 非数字片段丢弃
    assert ix.parse_ports(["22", "23"]) == [22, 23]  # list 输入
    assert ix.parse_ports(None) == []


def test_parse_services():
    assert ix.parse_services("") == []
    assert ix.parse_services('["http","https"]') == ["http", "https"]
    assert ix.parse_services('not-json, but, csv') == ["not-json", "but", "csv"]
    assert ix.parse_services(["snmp", "ssh"]) == ["snmp", "ssh"]
    assert ix.parse_services(None) == []


def test_nmap_omits_os():
    """诚实降级：只有 os_guess，绝不编 <os> 段。"""
    out = ix.build_interop("nmap", SAMPLE_ROWS).decode("utf-8")
    assert "<os" not in out
    # 但端口/服务正常编
    assert "<service name=\"http\"/>" in out
    assert "<status state=\"up\"/>" in out
    assert "<status state=\"down\"/>" in out


def test_nmap_status_mapping():
    rows = [
        {"status": "online", "ip": "1.1.1.1"},
        {"status": "offline", "ip": "2.2.2.2"},
        {"status": "weird", "ip": "3.3.3.3"},
        {"status": "", "ip": "4.4.4.4"},
    ]
    out = ix.build_interop("nmap", rows).decode("utf-8")
    assert out.count('<status state="up"/>') == 1
    assert out.count('<status state="down"/>') == 1
    assert out.count('<status state="unknown"/>') == 2


def test_netbox_header_and_status_mapping():
    """表头与 NetBox 官方一致；status online/offline → Active/Offline。"""
    # 必填列在官方表头最前
    required = ["name", "device_type", "device_role", "site", "status"]
    assert ix.NETBOX_HEADER[:len(required)] == required

    rows = [
        {"status": "online", "hostname": "h", "vendor": "Cisco",
         "device_class": "交换机", "location": "B", "os_guess": "IOS"},
        {"status": "offline", "hostname": "p", "vendor": "",
         "device_class": "打印机", "location": "", "os_guess": ""},
    ]
    rdr = list(csv.reader(io.StringIO(
        ix.build_interop("netbox", rows).decode("utf-8-sig"))))
    assert rdr[0] == ix.NETBOX_HEADER
    # 第一行：device_type = "Cisco 交换机"，status Active
    assert rdr[1][1] == "Cisco 交换机"
    assert rdr[1][2] == "交换机"        # device_role ← device_class
    assert rdr[1][3] == "B"             # site ← location
    assert rdr[1][4] == "Active"
    assert rdr[1][7] == "IOS"           # platform ← os_guess
    # 第二行：offline → Offline，空 vendor → device_type 仅设备类型
    assert rdr[2][1] == "打印机"
    assert rdr[2][4] == "Offline"


def test_oxidized_rows():
    rows = [
        {"hostname": "r1", "device_class": "路由器", "location": "机房A"},
        {"hostname": "", "ip": "10.0.0.5", "device_class": "", "location": ""},
    ]
    out = ix.build_interop("oxidized", rows).decode("utf-8")
    assert out == "r1:路由器:机房A\n10.0.0.5:unknown:default\n"


def test_export_interop_roundtrip(tmp_path):
    """export_interop 落盘内容与 build_interop 完全一致（可回读）。"""
    for fmt in ix.INTEROP_FORMATS:
        p = tmp_path / ("out_" + _GOLDEN[fmt])
        ix.export_interop(fmt, SAMPLE_ROWS, str(p))
        with open(p, "rb") as f:
            assert f.read() == ix.build_interop(fmt, SAMPLE_ROWS)
