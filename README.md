<p align="center">
  <img src="assets/hako-logo-256.png" width="128" height="128" alt="Hako">
</p>

<h1 align="center">Hako</h1>

<p align="center"><strong>H</strong>igh-performance <strong>A</strong>daptive <strong>K</strong>ernel — <strong>O</strong>pen-source</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License: GPL-3.0">
  <img src="https://img.shields.io/badge/core-mihomo%201.19.29-00b4f0?style=flat-square" alt="Core: mihomo 1.19.29">
  <img src="https://img.shields.io/badge/platforms-iOS%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms: iOS | macOS">
  <img src="https://img.shields.io/badge/status-pre--release-orange?style=flat-square" alt="Status: pre-release">
</p>

<p align="center"><strong>English</strong> · <a href="README.zh-CN.md">简体中文</a></p>

**Put a real proxy kernel inside your iOS or macOS app.**

Hako packages the proven **mihomo** (Clash.Meta) proxy engine as `Hako.xcframework` — a small Swift / Objective-C framework you add to your app. It runs on Apple's official **NetworkExtension** API, so it's built to pass App Review: no vendored kernel sources, no private hacks. You build the app; Hako moves the traffic.

Use it to ship a **Clash / mihomo-compatible VPN app** for iPhone, iPad, and Mac. Hako is a fork of a stable mihomo release, tuned to live inside Apple's strict Network Extension limits on memory and battery.

## Official website and client

- [Official website](https://clash.md/)
- [Download the official client on the App Store](https://apps.apple.com/app/id6794257189)

## Fast, and it doesn't fall over

iOS only lets a VPN app use about **50 MiB of memory** before the system force-quits it (Apple calls this *jetsam*). Push real traffic through a careless proxy and it blows past that and crashes — a well-known pain point for proxy apps on iPhone and iPad. Hako is built to stay well under the line. Real numbers, all measured on a physical **iPad Pro (M2)**:

```
  How much of Apple's 50 MiB memory limit Hako actually uses:

  Apple's hard limit (crash)     50.0 MiB  |####################|
  --------------------------------------------------------------
  Hako, 30-min stress test       38.5 MiB  |###############.....|  22% to spare
  Hako, heavy upload + slow peer 39.6 MiB  |################....|  21% to spare
                                           400 connections at once, still never crosses the line
```

```
  Real speed, through the tunnel  (iPad Pro M2, on the open internet):

    Speedtest (Ookla)        924 Mbps down  /  545 Mbps up   ping 5 ms
       ...and while doing that, the kernel used just 18.7 MiB of memory
       (of the 50 available). The WiFi / broadband line is the limit here,
       not Hako.

  A 30-minute non-stop stress run -- this is a release gate, not a demo:

    16.49 GB moved   0 disconnects   0 dropped packets   0 crashes   0 memory kills
```

Uploading hard while the other end reads slowly is the classic way to make an iOS VPN run out of memory and die. Hako slows itself down and keeps the connection alive instead. *(Under the hood: a capped receive buffer, and it treats "out of buffer space" as a reason to slow down, not a reason to crash.)*

> All numbers come from controlled runs on real Apple hardware. Your WiFi and ISP set the top speed, not the kernel. The SDK reports its own live stats — throughput, connections, memory, health — so you can measure your build on your own device.

## What's in the box — and what you build

**Hako gives you:** the proxy engine (the mihomo fork), the `bind/hako` binding that turns it into an SDK, and the build tooling — shipped as `Hako.xcframework` with API docs. That's the hard part, and it's done.

**You build:** the app, its UI, the `NEPacketTunnelProvider` glue that hands packets to Hako, config and credential storage, and code signing. Hako ships **no** app, **no** UI, and **no** certificates. You link the framework and ship your own product.

## Quick start

You'll need [Go 1.20+](https://go.dev/dl/), plus Xcode with `gomobile` for the Apple framework.

```sh
# build the kernel
go build ./...

# build the 3-slice Hako.xcframework (device + simulator + macOS)
make lib_apple
```

Then, in your app:

1. Link `Hako.xcframework` into **both** the app and the Packet Tunnel extension (it's a static framework — set *Embed* to **Do Not Embed**).
2. Add `-lresolv` to every target that links Hako (it needs the C resolver, and the flag doesn't carry over on its own).
3. From your `NEPacketTunnelProvider`, drive the kernel through the generated Objective-C API and move packets over Apple's public `NEPacketTunnelFlow`.
4. Keep your configs, subscription URLs, and credentials on your side. The kernel reads a finished config; it is not a subscription manager and won't fetch or store anything for you.
5. Sign and ship it.

The public header is identical across all three slices, and its SHA-256 is in the SDK manifest, so you can pin exactly what you shipped.

## What the kernel can do

You get the full mihomo data plane, running inside the Packet Tunnel and controlled through the SDK. Here's what works on iOS:

- **Protocols:** Shadowsocks, VMess, VLESS, Trojan, Snell, Hysteria / Hysteria2, TUIC, WireGuard, AnyTLS, SSH, and more. Every protocol builds and parses — test the ones you ship against your own servers first.
- **DNS:** an in-tunnel resolver with DoH / DoT / DoQ, fake-IP, traffic sniffing, and per-domain nameserver rules.
- **Routing:** rules by domain, IP-CIDR, GEOIP / GEOSITE, and RULE-SET, plus logical (`AND` / `OR` / `NOT`) and sub-rules. *(Per-app and process rules don't work on iOS — Apple gives no way to tell which app a packet came from, so Hako skips them instead of faking it.)*
- **Proxy groups:** `select`, `url-test`, `fallback`, and `load-balance` with health checks, plus remote rule and proxy providers.
- **Runtime control:** live status, traffic, connections, proxies, and logs, plus actions like switch proxy, latency test, and close connection — all over a local, app-private channel, never a network-exposed controller.
- **Built for the App Store:** Hako talks to iOS only through Apple's public `NEPacketTunnelFlow`. No private file-descriptor tricks, no undocumented APIs.

Behavior follows upstream mihomo — see the [mihomo docs](https://wiki.metacubex.one/) and [`docs/config.yaml`](docs/config.yaml).

## Before you ship

**This is pre-1.0.** The API and interoperability tests are in place. Protocols are verified by parsing and reference tests; testing on a signed device is up to you. Treat any build you cut as a development build until there's a formal `v*-hako.*` release tag — the repository's release tags are the source of truth for versioning.

## Source, credits & license

Hako is a **hard fork** of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo), pinned to a specific **stable** upstream tag (currently `v1.19.29`) — never an `Alpha`. It is **not** affiliated with or endorsed by MetaCubeX or SagerNet. Per mihomo's license, unaffiliated forks can't use the *mihomo* name, so this one is **Hako**; the upstream name stays only where GPLv3 attribution needs it.

**License: GPL-3.0.** Because `Hako.xcframework` statically links the whole kernel, the framework is a derivative work under GPLv3, and its source is this repository at the released tag. Full attribution is in [`NOTICE`](NOTICE), third-party licenses in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md), and the full text in [`LICENSE`](LICENSE).

Built on the work of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo), [Dreamacro/clash](https://github.com/Dreamacro/clash), [SagerNet/sing-box](https://github.com/SagerNet/sing-box), [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2), [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core), and [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go).

## Security

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Don't open public issues for security problems, and never paste real credentials or subscription URLs into a report.
