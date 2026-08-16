# Security Policy

Hako is a proxy **kernel + SDK** that moves user network traffic. We take security seriously and appreciate coordinated disclosure.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security problem.**

Report privately via **GitHub Private Vulnerability Reporting**: the repository's **Security** tab → **Report a vulnerability**. (Maintainers: enable this under Settings → Code security.)

Please include: affected version / commit, platform (iOS/macOS + OS version), a minimal reproduction, and the impact you believe it has. **Redact real secrets** — never include real subscription URLs, proxy passwords, private keys, tokens, or personal device identifiers. Use placeholder or self-hosted test endpoints.

We aim to acknowledge within **3 business days** and to coordinate public disclosure within about **90 days** of the report. We will credit you in the advisory unless you prefer to remain anonymous.

## Scope

Hako is the **kernel and gomobile SDK only**.

**In scope** — issues in this repository:

- Memory-safety, crash, or DoS defects in the Go kernel or the `bind/hako` gomobile binding.
- Traffic-handling defects that cause **leakage or bypass** originating in the kernel: packets escaping the tunnel, DNS leaking outside the configured resolver, routing/admission bypass at the data plane.
- Exposure of the control surface: the embedded control socket, config/rule mutation, or the self-update path being reachable/writable when it should be locked down.
- The Core writing credentials, proxy passwords, or subscription URLs to logs in the clear.

**Out of scope** — report elsewhere:

- Vulnerabilities in **upstream mihomo** that also affect stock mihomo — report to [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo).
- The **consuming application**: its Network Extension adapter, credential storage, UI, background scheduling, code signing, or provisioning. Hako ships none of these — they are the downstream integrator's responsibility.
- User misconfiguration, or issues requiring a jailbroken device.

## Supported versions

Hako is pre-1.0; only the most recent release line and `main` receive security fixes. Because Hako embeds a pinned mihomo core, some fixes arrive by syncing a newer stable upstream tag.
