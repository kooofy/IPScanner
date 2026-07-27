# -*- coding: utf-8 -*-
"""通用工具函数：网关探测、快照对比、IP 校验。"""
from i18n import tr


def _detect_gateway() -> str:
    """推测默认网关 IP：优先解析系统路由表，失败则按本机网段 .1 推测。"""
    import subprocess as sp
    import socket as sock
    local_ip = ""
    try:
        local_ip = sock.gethostbyname(sock.gethostname())
    except Exception:
        pass
    gw_ip = None
    # Windows 路由表 (0.0.0.0/0 的下一跳)
    try:
        out = sp.run(["route", "print", "-4"], capture_output=True, text=True, timeout=3,
                     creationflags=getattr(sp, "CREATE_NO_WINDOW", 0)).stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                cand = cols[2]
                if _is_valid_ip(cand):
                    gw_ip = cand
                    break
    except Exception:
        pass
    if not gw_ip and local_ip:
        parts = local_ip.split(".")
        if len(parts) == 4:
            gw_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return gw_ip or ""


def _compare_snapshots(base: dict, target: dict) -> list:
    """对比两个快照，返回差异行列表：{ip, change, old, new}。"""
    base_map = {d["ip"]: d for d in base.get("devices", [])}
    target_map = {d["ip"]: d for d in target.get("devices", [])}
    diffs = []

    def _fmt(d):
        parts = [d.get("status", "?"), d.get("hostname") or "—", d.get("mac") or "—"]
        if d.get("device_class"):
            parts.append(d.get("device_class"))
        return " / ".join(str(p) for p in parts)

    for ip, td in target_map.items():
        if ip not in base_map:
            diffs.append({"ip": ip, "change": tr("新增设备"), "old": "—", "new": _fmt(td)})
    for ip, bd in base_map.items():
        if ip not in target_map:
            diffs.append({"ip": ip, "change": tr("消失设备"), "old": _fmt(bd), "new": "—"})
    for ip in base_map:
        if ip in target_map:
            bd, td = base_map[ip], target_map[ip]
            if bd.get("status") != td.get("status"):
                diffs.append({"ip": ip, "change": tr("状态变更"),
                              "old": bd.get("status", "—"), "new": td.get("status", "—")})
            if (bd.get("mac") or "") != (td.get("mac") or ""):
                diffs.append({"ip": ip, "change": tr("MAC 变更"),
                              "old": bd.get("mac") or "—", "new": td.get("mac") or "—"})
            if (bd.get("hostname") or "") != (td.get("hostname") or ""):
                diffs.append({"ip": ip, "change": tr("主机名变更"),
                              "old": bd.get("hostname") or "—", "new": td.get("hostname") or "—"})
            # 设备识别类字段变更（新增字段，旧快照缺省为空，不影响兼容）
            for field, label in (
                ("device_class", tr("设备类型变更")),
                ("open_ports", tr("开放端口变更")),
                ("location", tr("位置变更")),
                ("user", tr("使用者变更")),
            ):
                bv, tv = bd.get(field) or "", td.get(field) or ""
                if bv != tv:
                    diffs.append({"ip": ip, "change": label,
                                  "old": bv or "—", "new": tv or "—"})
    return diffs


def _is_valid_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
