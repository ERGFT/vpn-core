# Documentation

[Русский](README.md) | **English**

Where to start — the [README](../README.en.md): what the project is, building
and first run. This is the detailed reference.

## Using

| Page | About |
|---|---|
| [FEATURES.en.md](FEATURES.en.md) | all features, their status and how each was tested; known limitations |
| [CLI.en.md](CLI.en.md) | command-line options, autostart (Windows service, systemd) |
| [CONFIG.en.md](CONFIG.en.md) | sing-box/Xray config file: inbounds, outbounds, rules, rule sets, server groups, subscriptions, `fragment` and `noises` |
| [DNS.en.md](DNS.en.md) | own DNS: DoH/DoT/DoQ servers, rules, cache, fake-IP |
| [TUN.en.md](TUN.en.md) | system routing for TCP/UDP through a virtual interface, kill switch, and protocol limits |
| [API.en.md](API.en.md) | local API (Clash API), web dashboards, config reload |
| [LINK.en.md](LINK.en.md) | `vless://` link parameters |
| [WINDOWS.en.md](WINDOWS.en.md) | building and running on Windows |
| [SECURITY-MODEL.en.md](SECURITY-MODEL.en.md) | assumptions, security boundaries, and threats on shared Wi-Fi |
| [Internal REALITY review](reviews/2026-11-04-reality-internal-review.en.md) | scope and findings of an internal review; not an independent external audit |

## Embedding and development

| Page | About |
|---|---|
| [LIBRARY.en.md](LIBRARY.en.md) | the core as a library (C ABI): Android, iOS, desktop |
| [APPLICATION_ROUTING.en.md](APPLICATION_ROUTING.en.md) | binding connections to apps and sites; platform limitations |
| [ARCHITECTURE.en.md](ARCHITECTURE.en.md) | how the core works inside |
| [REPOSITORY.en.md](REPOSITORY.en.md) | where things are in the repository |
| [TESTING.en.md](TESTING.en.md) | how the project is tested, comparison with Xray-core, performance |
| [RUSTLS_PATCH.en.md](RUSTLS_PATCH.en.md) | what was changed in rustls and why |
| [stage5-crypto-review-and-interop.en.md](stage5-crypto-review-and-interop.en.md) | checklist for a future independent REALITY cryptographic review |
| [RELEASING.en.md](RELEASING.en.md) | preflight builds, artifact verification, and tag publishing |

## Documentation rules

| Page | About |
|---|---|
| [STYLE_GUIDE.en.md](STYLE_GUIDE.en.md) | VCTWS 1.0 editorial rules for technical documentation |
| [GLOSSARY.en.md](GLOSSARY.en.md) | agreed Russian and English technical terms |

Decision history by stage — [PLAN.en.md](../PLAN.en.md), what changed —
[CHANGELOG.md](../CHANGELOG.md#changelog).
