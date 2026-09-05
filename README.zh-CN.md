<p align="center">
  <img src="assets/hako-logo-256.png" width="128" height="128" alt="Hako">
</p>

<h1 align="center">Hako</h1>

<p align="center"><strong>H</strong>igh-performance <strong>A</strong>daptive <strong>K</strong>ernel — <strong>O</strong>pen-source</p>

<p align="center">高性能 · 自适应 · 开源内核</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License: GPL-3.0">
  <img src="https://img.shields.io/badge/core-mihomo%201.19.29-00b4f0?style=flat-square" alt="Core: mihomo 1.19.29">
  <img src="https://img.shields.io/badge/platforms-iOS%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms: iOS | macOS">
  <img src="https://img.shields.io/badge/status-pre--release-orange?style=flat-square" alt="Status: pre-release">
</p>

<p align="center"><a href="README.md">English</a> · <strong>简体中文</strong></p>

**把一个真正的代理内核，装进你的 iOS 或 macOS App。**

Hako 把成熟的 **mihomo**（Clash.Meta）代理引擎打包成 `Hako.xcframework` —— 一个小巧的 Swift / Objective-C 框架，加进你的 App 就能用。它跑在 Apple 官方的 **NetworkExtension** API 上，天生为过 App 审核而设计：不用塞一堆内核源码，也不用任何私有黑魔法。App 你来做，流量交给 Hako。

用它就能做出一个**兼容 Clash / mihomo 的 VPN App**，覆盖 iPhone、iPad 和 Mac。Hako 基于 mihomo 稳定版分叉，专门调校过，能在 Apple 严苛的 Network Extension 内存和耗电限制里稳稳运行。

## 官网与客户端

- [官方网站](https://clash.md/)
- [在 App Store 下载官方客户端](https://apps.apple.com/app/id6794257189)

## 快，而且不崩

iOS 只给一个 VPN App 大约 **50 MiB 内存**，超过这条线，系统就直接把它杀掉（Apple 把这叫 *jetsam*）。真流量一上来，写得糙的代理就会冲破这条线然后崩溃 —— 这是 iPhone、iPad 上代理类 App 人尽皆知的老大难。Hako 从设计上就稳稳压在线以下。下面全是在真机 **iPad Pro（M2）** 上实测的数字：

```
  Hako 实际用掉了 Apple 50 MiB 内存上限的多少：

  50.0 MiB  |####################|  Apple 硬上限（越线即被系统杀掉）
  --------------------------------------------------------------
  38.5 MiB  |###############.....|  30 分钟压力测试 · 余量 22%
  39.6 MiB  |################....|  重载上传 + 慢速接收端 · 余量 21%
                                    （400 条并发连接，仍然不越线）
```

```
  经隧道实测速度（iPad Pro M2，公网环境）：

    Speedtest（Ookla）    924 Mbps 下行 / 545 Mbps 上行   延迟 5 ms
       ……与此同时，内核只用了 18.7 MiB 内存（上限 50）。
       瓶颈在 WiFi / 宽带线路，不在 Hako。

  30 分钟不间断压力测试 —— 这是发布卡口，不是演示：

    搬运 16.49 GB   0 掉线   0 丢包   0 崩溃   0 内存击杀
```

对端读得慢的时候还拼命上传，是把 iOS VPN 撑爆内存、直接搞崩的经典操作。Hako 的做法是给自己降速、把连接稳住，而不是崩。*（原理很简单：接收缓冲有上限，遇到「缓冲不够」就当成该减速的信号，而不是当成致命错误。）*

> 这些数字全部来自真实 Apple 设备上的受控测试。速度的天花板是你的 WiFi 和宽带，不是内核。SDK 会实时上报自己的状态 —— 吞吐、连接数、内存、健康度 —— 你可以在自己的设备上测自己的构建。

## 盒子里有什么 —— 以及哪些要你自己做

**Hako 给你：** 代理引擎（mihomo 分叉）、把它变成 SDK 的 `bind/hako` 绑定、以及构建工具，打包成 `Hako.xcframework`，附 API 文档。最难啃的那块骨头，已经啃完了。

**你来做：** App 本体、界面、把数据包递给 Hako 的 `NEPacketTunnelProvider` 胶水层、配置与凭据的存储、以及代码签名。Hako **不带** App、**不带**界面、**不带**证书。你把框架链接进去，发布你自己的产品。

## 快速上手

你需要 [Go 1.20+](https://go.dev/dl/)，构建 Apple 框架还需要装了 `gomobile` 的 Xcode。

```sh
# 构建内核
go build ./...

# 构建三切片的 Hako.xcframework（真机 + 模拟器 + macOS）
make lib_apple
```

然后，在你的 App 里：

1. 把 `Hako.xcframework` **同时**链接进 App 和 Packet Tunnel 扩展（它是静态框架，*Embed* 选 **Do Not Embed**）。
2. 给每个链接 Hako 的 target 都加上 `-lresolv`（它要用 C 解析库，这个 flag 不会自动带过去）。
3. 在 `NEPacketTunnelProvider` 里，用生成好的 Objective-C API 驱动内核，用 Apple 公开的 `NEPacketTunnelFlow` 收发数据包。
4. 配置、订阅 URL、凭据都握在你自己手里。内核只读一份做好的配置；它不是订阅管理器，不会替你拉取或保存任何东西。
5. 签名，发布。

三个切片的公开头文件完全一致，SHA-256 写在 SDK 清单里，方便你精确锁定发布的那一版。

## 内核能做什么

你拿到的是完整的 mihomo 数据面，跑在 Packet Tunnel 里，通过 SDK 控制。下面这些在 iOS 上都能用：

- **协议：** Shadowsocks、VMess、VLESS、Trojan、Snell、Hysteria / Hysteria2、TUIC、WireGuard、AnyTLS、SSH 等等。每种协议都能构建、能解析 —— 你要上线的那几种，先拿自己的服务器测一遍。
- **DNS：** 隧道内解析器，支持 DoH / DoT / DoQ、fake-IP、流量嗅探、按域名的 nameserver 规则。
- **路由：** 按 domain、IP-CIDR、GEOIP / GEOSITE、RULE-SET 匹配，还有逻辑规则（`AND` / `OR` / `NOT`）和 sub-rule。*（按 App、按进程的规则在 iOS 上用不了 —— Apple 不提供「这个包是哪个 App 发的」这种接口，所以 Hako 直接跳过，而不是假装能做。）*
- **代理组：** `select`、`url-test`、`fallback`、`load-balance`，都带健康检查；还有远程 rule-provider 和 proxy-provider。
- **运行时控制：** 实时的状态、流量、连接、代理、日志，加上切换代理、测延迟、断开连接这些动作 —— 全走本机的、App 私有的通道，绝不开一个暴露在网络上的控制器。
- **为上架而生：** Hako 只通过 Apple 公开的 `NEPacketTunnelFlow` 跟 iOS 打交道。没有私有文件描述符的偏门手法，没有未公开的 API。

行为跟随上游 mihomo —— 见 [mihomo 文档](https://wiki.metacubex.one/) 和 [`docs/config.yaml`](docs/config.yaml)。

## 上线之前

**这是 pre-1.0。** API 和互通测试都已就位。协议通过解析和参照测试验证过；在签名真机上的测试要你自己来。在正式的 `v*-hako.*` 发行 tag 出现之前，请把你切出的任何构建都当作开发版。版本以仓库的发行 tag 为准。

## 源码、致谢与许可

Hako 是 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 的**硬分叉**，钉在某个特定的**稳定**上游 tag 上（当前是 `v1.19.29`），绝不用 `Alpha`。它与 MetaCubeX、SagerNet **没有**任何隶属或背书关系。按 mihomo 的许可，无隶属关系的分叉不能用 *mihomo* 这个名字，所以它叫 **Hako**；上游名字只在 GPLv3 署名需要的地方保留。

**许可证：GPL-3.0。** 因为 `Hako.xcframework` 静态链接了整个内核，这个框架在 GPLv3 下属于衍生作品，它的源码就是本仓库在发行 tag 上的状态。完整署名见 [`NOTICE`](NOTICE)，第三方许可见 [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)，许可全文见 [`LICENSE`](LICENSE)。

站在这些项目的肩膀上：[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)、[Dreamacro/clash](https://github.com/Dreamacro/clash)、[SagerNet/sing-box](https://github.com/SagerNet/sing-box)、[riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)、[v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)、[WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)。

## 安全

请**私下**报告漏洞 —— 见 [`SECURITY.md`](SECURITY.md)。不要为安全问题开公开 issue，也**永远不要**把真实凭据或订阅 URL 贴进报告。
