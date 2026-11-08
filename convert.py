"""把节点 URI 转成 mihomo(Clash) 与 sing-box 两种客户端格式。

设计取舍：
  * 只用标准库。YAML 用「JSON 字符串当标量」的方式手写输出，避免为了一行配置引入 pyyaml。
  * 解析失败的节点直接跳过（宁可少一条，也不产出客户端加载不了的行）。
  * 名称统一成 "CF 001" 这种短名，客户端列表里好读。

用法（在 scraper.py 里）：
    from convert import to_clash_provider, to_singbox_config
    write_file(out/"clash.yaml", to_clash_provider(nodes, label))
    write_file(out/"sing-box.json", json.dumps(to_singbox_config(nodes, label), ...))
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

# ---------------------------------------------------------------- 基础工具


def _b64(text: str) -> str:
    """宽松 base64 解码（自动补 padding、兼容 urlsafe）。"""
    s = (text or "").strip().replace("-", "+").replace("_", "/")
    if not s:
        return ""
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return ""


def _query(url) -> dict:
    return {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _split_host_port(url, fallback_port: int) -> tuple[str, int]:
    host = (url.hostname or "").strip("[]").lower()
    port = url.port or fallback_port
    return host, int(port)


def _ws_opts(path: str, host: str) -> dict:
    opts: dict = {"path": path or "/"}
    if host:
        opts["headers"] = {"Host": host}
    return opts


# ---------------------------------------------------------------- 各协议解析


def parse_uri(line: str) -> dict | None:
    """把一行 URI 解析成统一结构；解析不出来返回 None。"""
    if "://" not in line:
        return None
    proto = line.split("://", 1)[0].strip().lower()
    try:
        if proto == "vmess":
            return _parse_vmess(line)
        if proto == "vless":
            return _parse_vless(line)
        if proto == "trojan":
            return _parse_trojan(line)
        if proto == "ss":
            return _parse_ss(line)
        if proto == "hysteria2":
            return _parse_hysteria2(line)
        if proto == "tuic":
            return _parse_tuic(line)
    except Exception:  # noqa: BLE001
        return None
    return None


def _parse_vmess(line: str) -> dict | None:
    body = line[len("vmess://"):].strip()
    j = json.loads(_b64(body.split("#", 1)[0]))
    host = str(j.get("add", "")).strip().strip("[]").lower()
    if not host:
        return None
    net = str(j.get("net", "tcp") or "tcp").lower()
    tls = str(j.get("tls", "")).lower() in ("tls", "reality", "true", "1")
    return {
        "type": "vmess", "server": host, "port": int(str(j.get("port") or 443)),
        "uuid": str(j.get("id", "")), "alter_id": int(str(j.get("aid") or 0)),
        "cipher": str(j.get("scy") or "auto") or "auto",
        "network": net, "tls": tls,
        "sni": str(j.get("sni") or "") or str(j.get("host") or ""),
        "ws_path": str(j.get("path") or "/"), "ws_host": str(j.get("host") or ""),
        "grpc_service": str(j.get("path") or ""), "insecure": _truthy(j.get("allowInsecure", 0)),
    }


def _parse_vless(line: str) -> dict | None:
    url = urlsplit(line)
    host, port = _split_host_port(url, 443)
    if not host or not url.username:
        return None
    q = _query(url)
    security = (q.get("security") or "none").lower()
    net = (q.get("type") or "tcp").lower()
    return {
        "type": "vless", "server": host, "port": port, "uuid": unquote(url.username),
        "flow": q.get("flow") or "",
        "network": net, "tls": security in ("tls", "reality", "xtls"),
        "sni": q.get("sni") or q.get("host") or "",
        "ws_path": q.get("path") or "/", "ws_host": q.get("host") or "",
        "grpc_service": q.get("serviceName") or "",
        "reality_pbk": q.get("pbk") or "", "reality_sid": q.get("sid") or "",
        "fingerprint": q.get("fp") or "", "insecure": _truthy(q.get("allowInsecure")),
    }


def _parse_trojan(line: str) -> dict | None:
    url = urlsplit(line)
    host, port = _split_host_port(url, 443)
    if not host or not url.username:
        return None
    q = _query(url)
    return {
        "type": "trojan", "server": host, "port": port, "password": unquote(url.username),
        "network": (q.get("type") or "tcp").lower(), "tls": True,
        "sni": q.get("sni") or q.get("peer") or "",
        "ws_path": q.get("path") or "/", "ws_host": q.get("host") or "",
        "grpc_service": q.get("serviceName") or "",
        "insecure": _truthy(q.get("allowInsecure")),
    }


def _parse_ss(line: str) -> dict | None:
    body = line[len("ss://"):]
    body, _, _frag = body.partition("#")
    body, _, query = body.partition("?")
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            userinfo = _b64(userinfo)
    else:
        dec = _b64(body)
        if "@" not in dec:
            return None
        userinfo, _, hostport = dec.rpartition("@")
    if ":" not in userinfo:
        return None
    method, _, password = userinfo.partition(":")
    hostport = hostport.strip("/")
    host, _, port = hostport.rpartition(":")
    host = host.strip("[]").lower()
    if not host or not port.isdigit():
        return None
    q = {k: v for k, v in (p.split("=", 1) for p in query.split("&") if "=" in p)}
    plugin = unquote(q.get("plugin", ""))
    return {
        "type": "ss", "server": host, "port": int(port),
        "method": method.strip(), "password": password,
        "plugin": plugin, "tls": False,
    }


def _parse_hysteria2(line: str) -> dict | None:
    url = urlsplit(line)
    host, port = _split_host_port(url, 443)
    if not host:
        return None
    q = _query(url)
    password = unquote(url.username or "") + (":" + unquote(url.password) if url.password else "")
    return {
        "type": "hysteria2", "server": host, "port": port, "password": password or q.get("password", ""),
        "sni": q.get("sni") or "", "tls": True, "insecure": _truthy(q.get("insecure")),
        "obfs": q.get("obfs") or "", "obfs_password": q.get("obfs-password") or "",
    }


def _parse_tuic(line: str) -> dict | None:
    url = urlsplit(line)
    host, port = _split_host_port(url, 443)
    if not host:
        return None
    q = _query(url)
    return {
        "type": "tuic", "server": host, "port": port,
        "uuid": unquote(url.username or ""), "password": unquote(url.password or ""),
        "sni": q.get("sni") or "", "tls": True, "insecure": _truthy(q.get("insecure")),
        "congestion_control": q.get("congestion_control") or "bbr",
        "alpn": [a for a in (q.get("alpn") or "").split(",") if a],
    }


# ---------------------------------------------------------------- mihomo / Clash


def to_clash_proxy(n: dict, name: str) -> dict | None:
    t = n["type"]
    base: dict = {"name": name, "server": n["server"], "port": n["port"]}

    if t == "vmess":
        p = dict(base, type="vmess", uuid=n["uuid"], alterId=n["alter_id"],
                 cipher=n.get("cipher") or "auto", udp=True)
        if n["tls"]:
            p.update(tls=True, servername=n.get("sni") or n["server"],
                     **({"skip-cert-verify": True} if n.get("insecure") else {}))
        if n["network"] == "ws":
            p.update(network="ws", **{"ws-opts": _ws_opts(n["ws_path"], n["ws_host"])})
        elif n["network"] == "grpc":
            p.update(network="grpc", **{"grpc-opts": {"grpc-service-name": n["grpc_service"]}})
        return p

    if t == "vless":
        p = dict(base, type="vless", uuid=n["uuid"], udp=True)
        if n.get("flow"):
            p["flow"] = n["flow"]
        if n["tls"]:
            p.update(tls=True, servername=n.get("sni") or n["server"])
            if n.get("reality_pbk"):
                p["reality-opts"] = {"public-key": n["reality_pbk"], "short-id": n.get("reality_sid") or ""}
            if n.get("fingerprint"):
                p["client-fingerprint"] = n["fingerprint"]
            if n.get("insecure"):
                p["skip-cert-verify"] = True
        if n["network"] == "ws":
            p.update(network="ws", **{"ws-opts": _ws_opts(n["ws_path"], n["ws_host"])})
        elif n["network"] == "grpc":
            p.update(network="grpc", **{"grpc-opts": {"grpc-service-name": n["grpc_service"]}})
        return p

    if t == "trojan":
        p = dict(base, type="trojan", password=n["password"], udp=True,
                 sni=n.get("sni") or n["server"])
        if n.get("insecure"):
            p["skip-cert-verify"] = True
        if n["network"] == "ws":
            p.update(network="ws", **{"ws-opts": _ws_opts(n["ws_path"], n["ws_host"])})
        elif n["network"] == "grpc":
            p.update(network="grpc", **{"grpc-opts": {"grpc-service-name": n["grpc_service"]}})
        return p

    if t == "ss":
        p = dict(base, type="ss", cipher=n["method"], password=n["password"], udp=True)
        plugin = (n.get("plugin") or "").lower()
        if plugin.startswith("obfs"):
            p["plugin"] = "obfs"
            p["plugin-opts"] = {"mode": "http"}
        return p

    if t == "hysteria2":
        p = dict(base, type="hysteria2", password=n["password"], udp=True,
                 sni=n.get("sni") or n["server"])
        if n.get("insecure"):
            p["skip-cert-verify"] = True
        if n.get("obfs"):
            p["obfs"] = n["obfs"]
            p["obfs-password"] = n.get("obfs_password") or ""
        return p

    if t == "tuic":
        p = dict(base, type="tuic", uuid=n["uuid"], password=n["password"], udp=True,
                 sni=n.get("sni") or n["server"],
                 **{"congestion-controller": n.get("congestion_control") or "bbr"})
        if n.get("insecure"):
            p["skip-cert-verify"] = True
        if n.get("alpn"):
            p["alpn"] = n["alpn"]
        return p

    return None


# ---------------------------------------------------------------- sing-box


def to_singbox_outbound(n: dict, tag: str) -> dict | None:
    t = n["type"]
    o: dict = {"type": t, "tag": tag, "server": n["server"], "server_port": n["port"]}

    tls = None
    if n.get("tls"):
        tls = {"enabled": True, "server_name": n.get("sni") or n["server"], "insecure": bool(n.get("insecure"))}
        if n.get("reality_pbk"):
            tls["reality"] = {"enabled": True, "public_key": n["reality_pbk"], "short_id": n.get("reality_sid") or ""}
            if n.get("fingerprint"):
                tls["utls"] = {"enabled": True, "fingerprint": n["fingerprint"]}
    transport = None
    if n.get("network") == "ws":
        transport = {"type": "ws", "path": n["ws_path"] or "/"}
        if n.get("ws_host"):
            transport["headers"] = {"Host": n["ws_host"]}
    elif n.get("network") == "grpc":
        transport = {"type": "grpc", "service_name": n.get("grpc_service") or ""}

    if t == "vmess":
        o.update(uuid=n["uuid"], alter_id=n["alter_id"], security=n.get("cipher") or "auto")
    elif t == "vless":
        o.update(uuid=n["uuid"], packet_encoding="xudp")
        if n.get("flow"):
            o["flow"] = n["flow"]
    elif t == "trojan":
        o.update(password=n["password"])
    elif t == "ss":
        o = {"type": "shadowsocks", "tag": tag, "server": n["server"],
             "server_port": n["port"], "method": n["method"], "password": n["password"]}
        return o
    elif t == "hysteria2":
        o.update(password=n["password"])
        if n.get("obfs"):
            o["obfs"] = {"type": n["obfs"], "password": n.get("obfs_password") or ""}
    elif t == "tuic":
        o.update(uuid=n["uuid"], password=n["password"],
                 congestion_control=n.get("congestion_control") or "bbr")
        if n.get("alpn"):
            o["alpn"] = n["alpn"]
    else:
        return None

    if tls:
        o["tls"] = tls
    if transport:
        o["transport"] = transport
    return o


# ---------------------------------------------------------------- YAML 输出


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]*$")


def _key(k: str) -> str:
    return k if _KEY_RE.match(k) else json.dumps(str(k), ensure_ascii=False)


def _is_container(v) -> bool:
    return isinstance(v, (dict, list))


def _dump_yaml(obj, indent: int = 0) -> list[str]:
    pad = "  " * indent
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = _key(k)
            if _is_container(v):
                if not v:
                    out.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}")
                else:
                    out.append(f"{pad}{key}:")
                    out.extend(_dump_yaml(v, indent + 1))
            else:
                out.append(f"{pad}{key}: {_scalar(v)}")
        return out
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and item:
                sub = _dump_yaml(item, indent + 1)
                sub[0] = f"{pad}- {sub[0].lstrip()}"
                out.extend(sub)
            elif _is_container(item) and item:
                out.append(f"{pad}-")
                out.extend(_dump_yaml(item, indent + 1))
            else:
                out.append(f"{pad}- {_scalar(item)}")
        return out
    return [f"{pad}{_scalar(obj)}"]


def to_clash_provider(nodes: list[dict], namer) -> str:
    """mihomo / Clash Verge 的 proxy-provider 文件（只有 proxies:，可直接当订阅用）。"""
    proxies = []
    for i, n in enumerate(nodes, 1):
        try:
            p = to_clash_proxy(parse_uri(n["line"]), namer(i))
        except Exception:  # noqa: BLE001
            p = None
        if p:
            proxies.append(p)
    head = ["# 由 CFnodes 自动生成：mihomo / Clash Verge / Clash Meta 的 proxy-provider 文件",
            f"# 节点数：{len(proxies)}", "proxies:"]
    return "\n".join(head + _dump_yaml(proxies, 1)) + "\n"


def to_singbox_config(nodes: list[dict], namer) -> dict:
    """sing-box 1.10+ 的完整最小配置：selector 默认第一组、direct 兜底。"""
    outs = []
    for i, n in enumerate(nodes, 1):
        try:
            o = to_singbox_outbound(parse_uri(n["line"]), namer(i))
        except Exception:  # noqa: BLE001
            o = None
        if o:
            outs.append(o)
    tags = [o["tag"] for o in outs]
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"tag": "google", "address": "tls://8.8.8.8"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                      "listen_port": 2080}],
        "outbounds": [{"type": "selector", "tag": "proxy", "outbounds": tags or ["direct"],
                       "default": tags[0] if tags else "direct"},
                      {"type": "direct", "tag": "direct"}]
        + outs,
        "route": {"final": "proxy", "auto_detect_interface": True},
    }
