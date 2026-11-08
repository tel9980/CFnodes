# CFnodes · 免费节点订阅（自动清洗 + 自动更新）

每 **12 小时**自动抓取公开节点源 → 去重 → 逐个测通 → 只留下能连的，输出成订阅链接。

> 更新时间：每天 **北京时间 08:00 和 20:00** 各跑一次（GitHub 免费额度有限，实际可能有几分钟到十几分钟延迟）。

## 一、订阅地址

```
https://raw.githubusercontent.com/tel9980/CFnodes/main/output/sub.txt
```

复制这一行，粘到客户端里就行。**地址永久不变**，节点会自动更新。

## 二、客户端怎么用

**安卓 · v2rayNG**
「+」→「订阅分组设置」→ 添加 → 粘贴地址 → 保存 → 右上角「更新订阅」→ 全选节点 →「测试延迟」→ 选延迟低的 → 连接。

**Windows · v2rayN**
「订阅」→「订阅设置」→ 添加 → 粘贴地址 → 确定 →「订阅」→「更新订阅」→ 全选 →「测试延迟」→ 双击延迟低的节点。

**iPhone · Shadowrocket**
右上角「+」→ 类型选 **Subscribe** → URL 粘贴地址 → 完成 → 左滑「更新」→ 点节点连接。

## 三、节点怎么挑

1. 先「更新订阅」，再「测试延迟」——**顺序不能反**，否则测的是旧节点
2. 选延迟数字最小、且不是「超时」的
3. 连不上就换下一个，连试 3~5 个是正常操作

建议在客户端里开启「自动更新订阅」，间隔 **6 小时**，之后基本不用管。

## 四、这个仓库做了什么

| 环节 | 做法 |
|---|---|
| 抓取 | 并发抓取全部订阅源，单源失败自动重试，不拖慢整体 |
| 清洗 | 只保留 vmess / vless / ss / ssr / trojan / tuic / hysteria2 协议 |
| 去重 | 按「协议 + 域名/ IP + 端口」合并，同一台机器只留一条 |
| 探活 | 并发 TCP 探测（96 线程），死节点直接剔除；UDP 协议（tuic / hysteria2）无法探测，标记为未验证 |
| 连续存活 | 只有**连续两轮**探活都通过的节点才进订阅（状态记在 `output/alive.json`），过滤掉「端口开着但用不了」的抖动节点；想关掉就设 `STABLE_ROUNDS=1` |
| 排序 | 按实测延迟从快到慢 |
| 加密 | 可选：配置 `SUB_PASSWORD` 后额外产出 `output/encrypted_sub.txt`（AES-128-CBC） |

**每次运行的明细**都在 Actions 页面的 Summary 里，也保存在 `output/stats.json`：

- `sources`：每个源抓到多少条、是否失效
- `probe`：探测了多少个、存活多少
- `final`：最终保留多少条、协议分布

## 五、常见问题

**全部节点都超时？**
先用手机流量试一次（部分宽带会阻断这类流量）；还不行就等下一轮自动更新，或去 Actions 页面手动点 `Run workflow`。

**节点数变少了？**
正常。探测失败或源不可用的节点会被剔除，留下来的都是当场能连通的。

**想自己改源 / 改名字？**
编辑 `scraper.py` 顶部的 `SOURCE_URLS` 与 `CUSTOM_REMARK` 即可。

## 六、可选：用 Cloudflare Worker 加速

raw.githubusercontent.com 在国内偶尔不可达，可以在 Cloudflare Workers 里建一个反代（**注意地址要指向本仓库，不要指向别人的仓库**）：

```js
export default {
  async fetch(request) {
    const upstream = "https://raw.githubusercontent.com/tel9980/CFnodes/main/output/sub.txt";
    const resp = await fetch(upstream, { cf: { cacheTtl: 300 } });
    return new Response(resp.body, {
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "max-age=300" },
    });
  },
};
```

部署后把 `https://你的worker名.workers.dev` 填进客户端即可。

## 七、安全提醒

节点由互联网上的陌生人提供，服务端可以看到你的 DNS 与未加密流量。**请勿在此类代理上登录网银、支付、公司邮箱等敏感账号**，仅用于浏览公开信息。请遵守你所在地区的法律法规。

## 八、许可

仅供学习与技术研究使用，请勿用于商业用途。
