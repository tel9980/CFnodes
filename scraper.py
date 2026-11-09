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
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, unquote, urlsplit

from convert import to_clash_provider, to_singbox_config

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
STABLE_ROUNDS = int(os.environ.get("STABLE_ROUNDS", "2"))   # 连续几轮探活都活才进订阅
ALIVE_STATE = os.environ.get("ALIVE_STATE", "alive.json")
ALIVE_TTL_DAYS = float(os.environ.get("ALIVE_TTL_DAYS", "3"))   # 跨轮存活状态（放在 output/ 里随仓库滚动）
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


def apply_stability_filter(nodes: list[dict], output_dir: str) -> tuple[list[dict], dict]:
    """连续 STABLE_ROUNDS 轮探活都活着才发布。

    为什么：TCP 能连 ≠ 能正常代理，很多节点是"刚死但端口还开着"。用跨轮状态过滤掉抖动节点，
    订阅里剩下的稳定性明显更好。UDP 类（hysteria2 等）无法 TCP 探活，不做过滤直接保留。

    状态文件 <output_dir>/alive.json = {"streak": {端点: 连续存活轮数}}。
    首次运行没有状态文件 → 全部放行（streak 记 1），避免第一天把订阅清空。
    """
    state_path = os.path.join(output_dir, ALIVE_STATE)
    prev: dict[str, int] = {}
    prev_seen: dict[str, str] = {}
    fresh = True
    try:
        with open(state_path, encoding="utf-8") as f:
            data = json.load(f)
        prev = {str(k): int(v) for k, v in (data.get("streak") or {}).items()}
        prev_seen = {str(k): str(v) for k, v in (data.get("seen") or {}).items()}
        fresh = False
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 读取 {state_path} 失败（{exc}），按首次运行处理")

    keep: list[dict] = []
    held = 0
    streak: dict[str, int] = {}
    seen: dict[str, str] = {}
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    present: set[str] = set()
    for n in nodes:
        if n.get("latency_ms") is None:          # UDP 类：无法探活，直接保留
            keep.append(n)
            continue
        key = f"{n['proto']}|{n['host']}|{n['port']}"
        present.add(key)
        s = prev.get(key, 0) + 1
        streak[key] = s
        seen[key] = now_iso
        if fresh or s >= STABLE_ROUNDS:
            keep.append(n)
        else:
            held += 1

    # 本轮没出现的端点：保留它的历史轮数（免费源每隔几小时就换一批，
    # 若把"这次没出现"当成"重新从 1 开始"，节点永远攒不到 2 轮，订阅会越跑越少）。
    # 只保留 ALIVE_TTL_DAYS 天内见过的，避免状态文件无限变大。
    horizon = (datetime.now(timezone.utc) - timedelta(days=ALIVE_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for key, s in prev.items():
        if key in present:
            continue
        last = prev_seen.get(key, now_iso)
        if last >= horizon:
            streak[key] = s
            seen[key] = last

    try:
        os.makedirs(output_dir, exist_ok=True)
        write_file(state_path, json.dumps(
            {"updated": now_iso, "ttl_days": ALIVE_TTL_DAYS, "streak": streak, "seen": seen},
            ensure_ascii=False, indent=0))
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 写 {state_path} 失败：{exc}")

    print(f"[*] 连续存活过滤：保留 {len(keep)} 条，暂缓 {held} 条"
          f"（首次运行则全部放行，阈值 {STABLE_ROUNDS} 轮）")
    return keep, {"stable_rounds": STABLE_ROUNDS, "stable_kept": len(keep),
                  "stable_held_back": held, "stable_state": state_path}

# ---------------------------------------------------------------- 重命名 & 输出

PROTO_ORDER = {"vless": 0, "vmess": 1, "trojan": 2, "ss": 3, "hysteria2": 4, "tuic": 5, "ssr": 6}


def sort_nodes(nodes: list[dict]) -> list[dict]:
    """按协议分组、组内按延迟从快到慢排。

    好处：客户端导入后同一协议的节点挨在一起；订阅列表里最快的节点永远在前排，
    而不是每次运行都按抓到顺序乱跳。
    """
    return sorted(nodes, key=lambda n: (
        PROTO_ORDER.get(n["proto"], 9),
        n.get("latency_ms") if n.get("latency_ms") is not None else float("inf"),
        n["host"], n["port"],
    ))


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
        # 4.5) 连续存活过滤：只有连续 N 轮都活的节点才进订阅（UDP 类不过滤）
        nodes, stable_stats = apply_stability_filter(nodes, args.output_dir)
        probe_stats.update(stable_stats)
    elif nodes:
        for n in nodes:
            n["latency_ms"] = None

    # 5) 截断 + 重命名
    if args.limit and len(nodes) > args.limit:
        print(f"[*] 按上限截断：{len(nodes)} -> {args.limit}")
        nodes = nodes[: args.limit]

    nodes = sort_nodes(nodes)
    final_lines = [rename_node(n, i) for i, n in enumerate(nodes, 1)]
    raw_text = "\n".join(final_lines)
    sub_b64 = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

    os.makedirs(args.output_dir, exist_ok=True)
    write_file(os.path.join(args.output_dir, "nodes.txt"), raw_text)
    write_file(os.path.join(args.output_dir, "sub.txt"), sub_b64)

    # 客户端格式：mihomo/Clash 的 provider 文件 + sing-box 完整配置（解析失败的节点自动跳过）
    def _namer(i: int) -> str:
        return f"{CUSTOM_REMARK} {i:03d}"

    client_stats: dict[str, object] = {}
    try:
        clash_text = to_clash_provider(nodes, _namer)
        write_file(os.path.join(args.output_dir, "clash.yaml"), clash_text)
        client_stats["clash_nodes"] = clash_text.count("\n  - name:") + clash_text.count("\n  - \"name\":")
        client_stats["clash_kb"] = round(len(clash_text.encode("utf-8")) / 1024, 1)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 生成 clash.yaml 失败：{type(exc).__name__}: {exc}")
    try:
        sb_cfg = to_singbox_config(nodes, _namer)
        sb_text = json.dumps(sb_cfg, ensure_ascii=False, indent=1)
        write_file(os.path.join(args.output_dir, "sing-box.json"), sb_text)
        client_stats["singbox_nodes"] = max(0, len(sb_cfg["outbounds"]) - 2)
        client_stats["singbox_kb"] = round(len(sb_text.encode("utf-8")) / 1024, 1)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 生成 sing-box.json 失败：{type(exc).__name__}: {exc}")
    if client_stats:
        print(f"[*] 客户端格式：clash {client_stats.get('clash_nodes')} 条 / "
              f"sing-box {client_stats.get('singbox_nodes')} 条")

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
        "clients": client_stats,
    }
    write_file(os.path.join(args.output_dir, "stats.json"),
               json.dumps(stats, ensure_ascii=False, indent=2))
    write_file(os.path.join(args.output_dir, "summary.md"), render_summary(stats))

    print(f"[*] 完成：{len(nodes)} 条节点，协议分布 {proto_count}，"
          f"耗时 {stats['duration_s']}s -> {args.output_dir}/{{nodes.txt,sub.txt,clash.yaml,sing-box.json,stats.json,summary.md}}")

    if not nodes:
        print("[!] 结果为空，请检查订阅源与网络")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
