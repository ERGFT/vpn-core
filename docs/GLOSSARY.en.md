# vpn-core Glossary

[Русский](GLOSSARY.md) | [English](GLOSSARY.en.md) · [Documentation standard](STYLE_GUIDE.en.md)

The terms below define editorial usage in project documentation. Definitions set boundaries; they are not behavior guarantees. Before making a technical change, verify the primary source in the link.

| RU | EN | Definition and source |
|---|---|---|
| Ядро | Core | The `reality-core` library component that implements the project's network logic [Architecture](ARCHITECTURE.en.md). |
| CLI-клиент | CLI client | The `reality-client` executable that uses the core and provides a command-line interface [CLI](CLI.en.md). |
| Встраивающее приложение | Host application | An application that links the library through its public interface and owns its UI and system integration [Library](LIBRARY.en.md). |
| SDK | SDK | A set of artifacts published or built for integration, such as a library and C ABI header. Exact contents depend on the workflow and release [Library](LIBRARY.en.md), [releasing](RELEASING.en.md). |
| C ABI | C ABI | The public binary interface declared in a C header and callable from compatible languages [`reality.h`](../ffi/include/reality.h), [library](LIBRARY.en.md). |
| Вход | Inbound | A configuration endpoint through which a component accepts client traffic [Configuration](CONFIG.en.md). |
| Выход | Outbound | A configuration path through which the core forwards traffic, for example to a proxy server or directly [Configuration](CONFIG.en.md). |
| Транспорт | Transport | A mechanism that carries protocol traffic, such as TCP, WebSocket, or gRPC, when implemented [Features](FEATURES.en.md). |
| Протокол | Protocol | A set of data-exchange rules between peers, such as VLESS [Architecture](ARCHITECTURE.en.md). |
| Правило маршрутизации | Routing rule | A configuration condition that matches traffic to an action or outbound according to the actual evaluation order [Configuration](CONFIG.en.md). |
| Цепочка `detour` | `detour` chain | A sequence of outbounds in which one outbound uses another as its next transport path, when allowed by the configuration [Configuration](CONFIG.en.md). |
| Разрешение имени | Name resolution | Mapping a domain name to a network address using a selected mechanism and execution location [DNS](DNS.en.md). |
| Bootstrap DNS | Bootstrap DNS | A DNS mechanism that resolves the DNS server's name before a request can be sent to that server [DNS](DNS.en.md). |
| Fake IP | Fake IP | A synthetic address used by the DNS subsystem to retain the relationship between a DNS answer and a domain name; implementation defines when it applies [DNS](DNS.en.md). |
| Внешний TUN | External TUN | A TUN resource provided to the core by the host application under the platform contract [TUN](TUN.en.md), [library](LIBRARY.en.md). |
| Предварительная проверка | Validation | A check of configuration or input before normal network operation. Its scope depends on the specific command or API [CLI](CLI.en.md), [library](LIBRARY.en.md). |
| Проверка совместимости | Interoperability test | A check of data exchange with a named external implementation in a specific scenario [Testing](TESTING.en.md). |
| Кросс-компиляция | Cross-compilation | Building for a target platform that differs from the platform on which the build runs [Library](LIBRARY.en.md), [releasing](RELEASING.en.md). |
| Отказ без обходного пути | Fail-closed | Behavior in which a specific flow or operation fails under stated conditions instead of using a stated fallback [Security model](SECURITY-MODEL.en.md). |
| Проверка подлинности | Authentication | Checking that a peer or credentials match an expected identity [API](API.en.md), [architecture](ARCHITECTURE.en.md). |
| Отпечаток TLS | TLS fingerprint | A set of observable TLS-client parameters used to describe or select a ClientHello profile [Features](FEATURES.en.md), [architecture](ARCHITECTURE.en.md). |
| Внутреннее ревью | Internal review | A scoped check performed by project participants or automatically within the repository [REALITY reviews](reviews/2026-11-04-reality-internal-review.en.md). |
| Независимый аудит | Independent audit | A separate external assessment with a named assessor, scope, and method [REALITY reviews](reviews/2026-11-04-reality-internal-review.en.md). |
| Стабильный релиз | Stable release | A project release without a prerelease status, identified by a specific tag and artifact set [Releasing](RELEASING.en.md), [Releases](https://github.com/ERGFT/vpn-core/releases). |

## Term and synonym boundaries

Use a synonym only when it preserves the meaning in the specific context; name the concrete object when the context is narrower. “External TUN” describes a host-provided interface or integration object. “TUN descriptor” applies only when discussing the descriptor passed to an API. The terms are not interchangeable in every section. “FFI” is broader than “C ABI,” and “SDK” refers to an artifact set whose contents must be checked for the relevant release.

## Exact names that are not translated

Preserve the spelling of protocol names, APIs, and identifiers: `VLESS`, `REALITY`, `XTLS Vision`, `XUDP`, `TUN`, `SOCKS5`, `C ABI`, `FFI`, `SDK`, `DoH`, `DoT`, `DoQ`, `Xray-core`, `sing-box`, `rc_validate`, `rc_is_alive`, `dns.bootstrap`, `route.final`, `user_id`. Check source code and public headers for additional names.

Use “VPN” only for a scenario that actually handles VPN traffic, such as TUN. For a local SOCKS/HTTP proxy and a library, name the component or mode precisely.
