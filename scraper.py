#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFnodes 强化版抓取脚本（替换原 scraper.py）

相对原版的改动：
  1. 端点级去重：以 (协议, host, port) 为主键，重复只留一条并统计（原版按整行去重，实测 29% 冗余）
  2. 并发探活：TCP 类协议做并发 TCP 连通性 + 延迟测量，死节点剔除；
     UDP 类协议（tuic / hysteria2）无法 TCP 探测，标记为 unverified 排在末尾
  3. 黑名单改为「只匹配 host 与备注名」，不再对整行子串匹配（原版 '-1' / 'err' 会误杀合法节点）
  4. 密码走环境变量 SUB_PASSWORD；未配置时跳过加密输出并告警，避免公共仓库里的「假加密」
  5. 抓取层并发 + 重试，并输出「每个源贡献多少条」，便于定位失效源
  6. 输出 output/stats.json，便于 Actions 日志排障

用法：
  python scraper.py                 # 抓取 + 去重 + 探活 + 输出
  python scraper.py --no-probe      # 只做格式清洗与去重
  python scraper.py --limit 300     # 探活后按延迟排序，保留前 300 条
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit

try:  # requests 优先，缺失时退回标准库，保证脚本在裸环境也能跑
    import requests  # type: ignore

    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAS_REQUESTS = False

try:
    from Crypto.Cipher import AES  # type: ignore
    from Crypto.Util.Padding import pad  # type: ignore

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

# ---------------------------------------------------------------- 配置区

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

_DEFAULT_REMARK_B64 = "56eR5oqA5YWx5LqrLeW8gOa6kOiKgueCuQ=="


def _default_remark() -> str:
    try:
        return base64.b64decode(_DEFAULT_REMARK_B64).decode("utf-8")
    except Exception:
        return "Node"


CUSTOM_REMARK = os.environ.get("CUSTOM_REMARK") or _default_remark()

# 订阅源（可继续追加；单个源失败不影响整体）
SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://gcore.jsdelivr.net/gh/aews/jd2/v20528.txt",
]

# host 黑名单：只做「等于 / 后缀」匹配，避免子串误杀
HOST_BLOCKLIST = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}

# 备注名黑名单：只匹配名字（广告词），不碰 URI 其余部分
NAME_BLOCKLIST = ["剩余", "到期", "官网", "别买", "错误", "timeout", "过期", "推广"]

SUPPORTED = ("vmess", "vless", "ss", "ssr", "trojan", "tuic", "hysteria2")
UDP_PROTOCOLS = {"tuic", "hysteria2"}
DEFAULT_PORTS = {"vmess": 443, "vless": 443, "trojan": 443, "tuic": 443, "hysteria2": 443, "ss": 8388}

PROBE = os.environ.get("PROBE", "true").strip().lower() not in ("0", "false", "no", "off")
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3"))
PROBE_WORKERS = int(os.environ.get("PROBE_WORKERS", "96"))
PROBE_MIN_ALIVE_RATIO = float(os.environ.get("PROBE_MIN_ALIVE_RATIO", "0.05"))
FETCH_WORKERS = int(os.environ.get("FETCH_WORKERS", "8"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "20"))
MAX_NODES = int(os.environ.get("MAX_NODES", "2000"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")

SUB_PASSWORD = os.environ.get("SUB_PASSWORD", "").strip()
_PLACEHOLDER_PASSWORDS = {"", "cfpassword3114", "change-me", "change-me-please", "password"}


# ---------------------------------------------------------------- 基础工具

def b64decode_loose(s: str) -> str | None:
    """宽松 base64 解码：自动补 padding，兼容 url-safe 变体。"""
    s = (s or "").strip().replace("\r", "").replace("\n", "")
    if not s:
        return None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return None


def looks_like_base64(s: str) -> bool:
    s = (s or "").strip().replace("\r", "").replace("\n", "")
    if len(s) < 16:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=\-_]+", s) is not None


def split_host_port(hostport: str) -> tuple[str | None, int]:
    """解析 'host:port' / '[v6]:port' / 'host'；失败时端口为 0。"""
    hostport = (hostport or "").strip().rstrip("/")
    if not hostport:
        return None, 0
    if hostport.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostport)
        if not m:
            return None, 0
        return m.group(1).lower(), int(m.group(2) or 0)
    if hostport.count(":") == 1:
        host, _, port = hostport.partition(":")
        try:
            return host.lower(), int(port)
        except ValueError:
            return host.lower(), 0
    if hostport.count(":") > 1:  # 裸 IPv6
        return hostport.lower(), 0
    return hostport.lower(), 0


def http_get(url: str, timeout: float = FETCH_TIMEOUT, retries: int = 2) -> str | None:
    last_err = ""
    for attempt in range(retries + 1):
        try:
            if _HAS_REQUESTS:
                r = requests.get(url, headers=UA, timeout=timeout)
                r.raise_for_status()
                return r.text
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    print(f"[!] 抓取失败 {url} -> {last_err}")
    return None


def parse_subscription(raw: str) -> list[str]:
    """订阅体可能是 base64 也可能是明文，两种都试。"""
    raw = (raw or "").lstrip("\ufeff").strip()
    if not raw:
        return []
    if looks_like_base64(raw):
        dec = b64decode_loose(raw)
        if dec and "://" in dec:
            return [ln.strip() for ln in dec.splitlines() if ln.strip()]
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


# ---------------------------------------------------------------- 节点解析

def parse_node(line: str) -> dict | None:
    """把一行解析成 {proto, host, port, name, line}；失败返回 None。"""
    if "://" not in line:
        return None
    proto = line.split("://", 1)[0].strip().lower()
    if proto not in SUPPORTED:
        return None
    try:
        if proto == "vmess":
            body = line[len("vmess://"):].strip()
            dec = b64decode_loose(body.split("#", 1)[0])
            if not dec:
                return None
            j = json.loads(dec)
            host = str(j.get("add", "")).strip().strip("[]").lower()
            if not host:
                return None
            try:
                port = int(str(j.get("port", "0")).strip() or 0)
            except ValueError:
                port = 0
            return {"proto": proto, "host": host, "port": port or DEFAULT_PORTS[proto],
                    "name": str(j.get("ps", "") or ""), "line": line}

        if proto == "ssr":
            body = line[len("ssr://"):].split("#", 1)[0]
            dec = b64decode_loose(body)
            if not dec or ":" not in dec:
                return None
            parts = dec.split("/", 1)[0].split(":")
            if len(parts) < 6:
                return None
            host = parts[0].strip().strip("[]").lower()
            try:
                port = int(parts[1])
            except ValueError:
                port = 0
            if not host:
                return None
            return {"proto": proto, "host": host, "port": port, "name": "", "line": line}

        if proto == "ss":
            body = line[len("ss://"):]
            body, _, frag = body.partition("#")
            name = unquote(frag)
            body = body.split("?", 1)[0]
            if "@" in body:
                _, _, hostport = body.rpartition("@")
            else:
                dec = b64decode_loose(body)
                if not dec or "@" not in dec:
                    return None
                _, _, hostport = dec.rpartition("@")
            host, port = split_host_port(hostport)
            if not host:
                return None
            return {"proto": proto, "host": host, "port": port or DEFAULT_PORTS[proto],
                    "name": name, "line": line}

        # vless / trojan / tuic / hysteria2
        body, _, frag = line.partition("#")
        name = unquote(frag)
        host, port = "", 0
        try:
            u = urlsplit(body)
            host = (u.hostname or "").strip("[]").lower()
            port = u.port or 0
        except ValueError:
            m = re.search(r"@(\[[^\]]+\]|[^:/?#]+):(\d+)", body)
            if m:
                host, port = split_host_port(f"{m.group(1)}:{m.group(2)}")
        if not host:
            return None
        return {"proto": proto, "host": host, "port": port or DEFAULT_PORTS.get(proto, 443),
                "name": name, "line": line}
    except Exception:  # noqa: BLE001
        return None


def block_reason(node: dict) -> str | None:
    host = node["host"]
    if host in HOST_BLOCKLIST or any(host.endswith("." + b) for b in HOST_BLOCKLIST):
        return "host"
    name_l = (node["name"] or "").lower()
    for kw in NAME_BLOCKLIST:
        if kw.lower() in name_l:
            return "name"
    return None


# ---------------------------------------------------------------- 探活

def tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> float | None:
    if not port:
        return None
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000, 1)
    except Exception:  # noqa: BLE001
        return None


def probe_nodes(nodes: list[dict]) -> tuple[list[dict], dict]:
    tcp_targets = [n for n in nodes if n["proto"] not in UDP_PROTOCOLS]
    udp_nodes = [n for n in nodes if n["proto"] in UDP_PROTOCOLS]
    print(f"[*] 探活：TCP {len(tcp_targets)} 个（并发 {PROBE_WORKERS}，超时 {PROBE_TIMEOUT}s），"
          f"UDP {len(udp_nodes)} 个跳过")

    alive: list[dict] = []
    latencies: dict[int, float] = {}
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        futs = {ex.submit(tcp_probe, n["host"], n["port"]): i for i, n in enumerate(tcp_targets)}
        done = 0
        for fut in as_completed(futs):
            idx = futs[fut]
            lat = fut.result()
            done += 1
            if lat is not None:
                latencies[idx] = lat
            if done % 250 == 0:
                print(f"    进度 {done}/{len(tcp_targets)}，存活 {len(latencies)}")

    for i, n in enumerate(tcp_targets):
        if i in latencies:
            n["latency_ms"] = latencies[i]
            alive.append(n)
    alive.sort(key=lambda x: x["latency_ms"])
    for n in udp_nodes:
        n["latency_ms"] = None
    udp_nodes.sort(key=lambda x: x["host"])

    ratio = (len(alive) / len(tcp_targets)) if tcp_targets else 0.0
    stats = {
        "tcp_total": len(tcp_targets),
        "tcp_alive": len(alive),
        "udp_unverified": len(udp_nodes),
        "alive_ratio": round(ratio, 4),
    }
    print(f"[*] 探活完成：TCP 存活 {len(alive)}/{len(tcp_targets)}（{ratio * 100:.1f}%）")

    # 自我保护：存活率异常低通常意味着探测环境受限（CI 出口被封），此时回退为不剔除
    if tcp_targets and ratio < PROBE_MIN_ALIVE_RATIO:
        print(f"[!] 存活率低于 {PROBE_MIN_ALIVE_RATIO:.0%}，疑似探测环境受限，本轮回退为保留全部节点")
        stats["fallback_no_prune"] = True
        return tcp_targets + udp_nodes, stats

    return alive + udp_nodes, stats


# ---------------------------------------------------------------- 重命名 & 输出

def rename_node(node: dict, index: int) -> str:
    new_name = f"{CUSTOM_REMARK} {index:03d}"
    line = node["line"]
    if node["proto"] == "vmess":
        try:
            dec = b64decode_loose(line[len("vmess://"):].strip().split("#", 1)[0])
            if not dec:
                return line
            j = json.loads(dec)
            j["ps"] = new_name
            payload = base64.b64encode(
                json.dumps(j, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            return "vmess://" + payload
        except Exception:  # noqa: BLE001
            return line
    return f"{line.split('#', 1)[0]}#{quote(new_name)}"


def encrypt_aes(content: str, password: str) -> str | None:
    """AES-128-CBC，key = md5(password)，iv = key —— 兼容小火箭等客户端。

    安全性完全依赖密码保密；密码进公共仓库等于没加密，因此未通过 Secret 提供密码时跳过输出。
    """
    if not _HAS_CRYPTO:
        return None
    key = hashlib.md5(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, key)
    return base64.b64encode(cipher.encrypt(pad(content.encode("utf-8"), AES.block_size))).decode("utf-8")


def write_file(path: str, content: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(tmp, path)


def render_summary(stats: dict) -> str:
    """生成 GitHub Actions 运行摘要（Markdown），供 workflow 直接 cat 到 $GITHUB_STEP_SUMMARY。"""
    out = ["### 抓取结果", ""]
    out.append(f"- 最终节点: **{stats['final']}**，协议: `{stats['by_protocol']}`")
    out.append(f"- 解析 {stats['parsed']} 条，整行重复 {stats['duplicate_lines']}，"
               f"端点重复 {stats['duplicate_endpoints']}")
    probe = stats.get("probe", {})
    if probe.get("enabled"):
        note = "（存活率过低，已回退为不剔除）" if probe.get("fallback_no_prune") else ""
        out.append(f"- 探活: TCP 存活 {probe.get('tcp_alive')}/{probe.get('tcp_total')} "
                   f"({probe.get('alive_ratio', 0) * 100:.1f}%)，"
                   f"UDP 未验证 {probe.get('udp_unverified')}{note}")
    else:
        out.append("- 探活: 未启用")
    failed = [u for u, v in stats.get("sources", {}).items() if not v.get("ok")]
    if failed:
        listed = ", ".join(f"`{u}`" for u in failed[:5])
        more = " …" if len(failed) > 5 else ""
        out.append(f"- 失效源 {len(failed)} 个: {listed}{more}")
    out.append(f"- 加密输出: {stats['encrypted_output']}，耗时 {stats['duration_s']}s")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 主流程

def main() -> int:
    ap = argparse.ArgumentParser(description="CFnodes 强化版抓取脚本")
    ap.add_argument("--no-probe", action="store_true", help="跳过连通性探测")
    ap.add_argument("--limit", type=int, default=MAX_NODES, help="最终保留上限（按延迟排序后截断）")
    ap.add_argument("--output-dir", default=OUTPUT_DIR)
    args = ap.parse_args()

    do_probe = PROBE and not args.no_probe
    started = datetime.now(timezone.utc)
    print(f"=== 开始抓取 {started:%Y-%m-%d %H:%M:%S} UTC | 探活={'开' if do_probe else '关'} "
          f"| requests={'有' if _HAS_REQUESTS else '无(urllib)'} ===")

    # 1) 并发抓取
    fetched: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(http_get, url): url for url in SOURCE_URLS}
        for fut in as_completed(futs):
            url = futs[fut]
            try:
                fetched[url] = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"[!] 源异常 {url}: {e}")
                fetched[url] = None

    # 2) 解析 + 过滤（按源顺序，便于统计与复现）
    rejected = {"parse_fail": 0, "blocked_host": 0, "blocked_name": 0}
    per_source: dict[str, dict] = {}
    parsed: list[dict] = []
    for url in SOURCE_URLS:
        raw = fetched.get(url)
        lines = parse_subscription(raw) if raw else []
        ok = 0
        for line in lines:
            node = parse_node(line)
            if node is None:
                if "://" in line:
                    rejected["parse_fail"] += 1
                continue
            reason = block_reason(node)
            if reason:
                rejected["blocked_" + reason] += 1
                continue
            parsed.append(node)
            ok += 1
        per_source[url] = {"ok": raw is not None, "lines": len(lines), "parsed": ok}
        print(f"    {'OK ' if raw is not None else 'ERR'} 解析 {ok:5d} 条 <- {url[:88]}")

    print(f"[*] 解析合计 {len(parsed)} 条 | 解析失败 {rejected['parse_fail']} | "
          f"host 拦截 {rejected['blocked_host']} | 名称拦截 {rejected['blocked_name']}")

    # 3) 去重：先整行，再端点
    uniq_lines: dict[str, dict] = {}
    for n in parsed:
        uniq_lines.setdefault(n["line"], n)
    after_line = list(uniq_lines.values())

    seen_ep: dict[str, dict] = {}
    dup_endpoints = 0
    for n in after_line:
        key = f"{n['proto']}|{n['host']}|{n['port']}"
        if key in seen_ep:
            dup_endpoints += 1
            continue
        seen_ep[key] = n
    nodes = list(seen_ep.values())
    print(f"[*] 去重：整行重复 {len(parsed) - len(after_line)} 条，"
          f"端点重复 {dup_endpoints} 条，剩余 {len(nodes)} 条唯一端点")

    # 4) 探活
    probe_stats = {"enabled": False}
    if do_probe and nodes:
        nodes, probe_stats = probe_nodes(nodes)
        probe_stats["enabled"] = True
    elif nodes:
        for n in nodes:
            n["latency_ms"] = None

    # 5) 截断 + 重命名
    if args.limit and len(nodes) > args.limit:
        print(f"[*] 按上限截断：{len(nodes)} -> {args.limit}")
        nodes = nodes[: args.limit]

    final_lines = [rename_node(n, i) for i, n in enumerate(nodes, 1)]
    raw_text = "\n".join(final_lines)
    sub_b64 = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

    os.makedirs(args.output_dir, exist_ok=True)
    write_file(os.path.join(args.output_dir, "nodes.txt"), raw_text)
    write_file(os.path.join(args.output_dir, "sub.txt"), sub_b64)

    enc_status = "skipped"
    if SUB_PASSWORD and SUB_PASSWORD.lower() not in _PLACEHOLDER_PASSWORDS:
        encrypted = encrypt_aes(sub_b64, SUB_PASSWORD)
        if encrypted:
            write_file(os.path.join(args.output_dir, "encrypted_sub.txt"), encrypted)
            enc_status = "written"
            print("[*] 已生成加密订阅（密码来自 SUB_PASSWORD 环境变量/Secret）")
        else:
            enc_status = "no_pycryptodome"
            print("[!] pycryptodome 未安装，跳过加密输出")
    else:
        print("[!] 未提供 SUB_PASSWORD（或为占位值），跳过加密输出——"
              "把密码写进公共仓库等于没有加密，请改用 GitHub Secrets")

    proto_count: dict[str, int] = {}
    for n in nodes:
        proto_count[n["proto"]] = proto_count.get(n["proto"], 0) + 1

    stats = {
        "generated_at_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": round((datetime.now(timezone.utc) - started).total_seconds(), 1),
        "sources": per_source,
        "parsed": len(parsed),
        "rejected": rejected,
        "duplicate_lines": len(parsed) - len(after_line),
        "duplicate_endpoints": dup_endpoints,
        "probe": probe_stats,
        "final": len(nodes),
        "by_protocol": proto_count,
        "encrypted_output": enc_status,
        "remark_prefix": CUSTOM_REMARK,
    }
    write_file(os.path.join(args.output_dir, "stats.json"),
               json.dumps(stats, ensure_ascii=False, indent=2))
    write_file(os.path.join(args.output_dir, "summary.md"), render_summary(stats))

    print(f"[*] 完成：{len(nodes)} 条节点，协议分布 {proto_count}，"
          f"耗时 {stats['duration_s']}s -> {args.output_dir}/{{nodes.txt,sub.txt,stats.json,summary.md}}")

    if not nodes:
        print("[!] 结果为空，请检查订阅源与网络")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
