<p align="center">
  <img src="assets/hako-logo-256.png" width="128" height="128" alt="Hako">
</p>

# Hako

English · [简体中文](README.zh-CN.md)

Hako is a proxy kernel based on **mihomo v1.19.30**, with Go bindings and build tooling for Apple applications. It produces `Hako.xcframework` for iOS, macOS and tvOS.

## Official website and client

- [Official website](https://clash.md/)
- [Download Clash on the App Store](https://apps.apple.com/app/id6794257189)

If you want to use the app, start with the download above. This repository is for developers building or integrating the kernel.

## Project repositories

| Repository | Contents |
| --- | --- |
| [Hako](https://github.com/TokenPLS/Hako) | Proxy kernel, Go bindings and Apple SDK build tools |
| [Hako-Adapter](https://github.com/TokenPLS/Hako-Adapter) | Swift packet-flow bridge and provider lifecycle components |
| [Hako-Client](https://github.com/TokenPLS/Hako-Client) | Native iOS, iPadOS, macOS and tvOS applications and extensions |

The upstream baseline version describes the proxy engine. It is separate from the App Store app version and the SDK release tag. This source distribution is pre-release; pin a specific revision when integrating it.

## What is included

- The mihomo-based proxy engine: protocol implementations, DNS, routing rules, proxy groups and providers.
- `bind/hako`: the API exposed to Apple applications through gomobile.
- `cmd/build_libbox`: SDK generation and platform packaging.
- [`docs/config.yaml`](docs/config.yaml): configuration reference included with the source.

An application supplies configuration, storage, the Network Extension integration and signing. Platform capabilities differ; a configuration accepted by the parser does not establish end-to-end support for every protocol or rule on every platform.

## Build the Apple SDK

Use macOS with the full Xcode installation and the iOS, macOS and tvOS SDKs. The current build was checked with Xcode 26.6. The binding module declares Go 1.25.0 and selects toolchain Go 1.26.6 in [`bind/hako/go.mod`](bind/hako/go.mod); allow Go to obtain that toolchain, or install it explicitly.

Clone the repository with its history and tags, then install the pinned gomobile tools:

```sh
git clone https://github.com/TokenPLS/Hako.git
cd Hako
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
make lib_apple
```

The build reads version information from Git tags. Keep the tags available when checking out a pinned revision.

The output is `Hako.xcframework`, containing five platform slices:

| Platform | Architectures |
| --- | --- |
| iOS device | arm64 |
| iOS Simulator | arm64, x86_64 |
| macOS | arm64, x86_64 |
| tvOS device | arm64 |
| tvOS Simulator | arm64, x86_64 |

Link the framework into each target that uses the API, including the Packet Tunnel extension. The framework is static: choose **Do Not Embed** and link `libresolv`. Use the generated headers for the API of your pinned revision. For a working application integration, see [Hako-Client](https://github.com/TokenPLS/Hako-Client).

## Development and feedback

For the root Go module:

```sh
go build ./...
go test ./...
```

The Apple binding has its own module and tests under `bind/hako`. An SDK build alone does not establish runtime behavior on a signed device.

Report kernel problems in this repository's [Issues](https://github.com/TokenPLS/Hako/issues). Include the source revision, platform, reproduction steps, expected behavior and observed result. Use a minimal sample configuration with secrets removed. For app interface or installation problems, use [Hako-Client Issues](https://github.com/TokenPLS/Hako-Client/issues).

For security reports, follow [SECURITY.md](SECURITY.md).

## License and credits

Hako is based on [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) and the work of its contributors. Hako is an independent project and is not affiliated with or endorsed by MetaCubeX.

The project is licensed under [GPL-3.0](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for attribution and dependency licenses.
