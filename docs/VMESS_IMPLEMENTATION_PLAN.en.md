<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# VMess implementation plan

## Status

The VMess stage has started, but outbound connections are not implemented yet. `core::vmess` parses modern `vmess://` share links: base64 JSON, UUID, `aid=0`, modern AEAD choices, and shared transport parameters. Non-zero `alterId` and non-AEAD ciphers are rejected explicitly. `core::vmess::aead` now contains the nested-HMAC KDF, derived command key, AuthID creation, and two-layer AES-128-GCM header sealing; complete request-header serialization and network exchange are not connected yet.

The parser reuses `TransportConfig` and its validation. It does **not** establish a connection, perform VMess authentication, or imply VMess support in configuration files or subscriptions. Do not register the protocol in the outbound factory or importers until the protocol client works.

## Remaining work

1. Finish and verify AuthID and AEAD request headers against independent current Xray/V2Ray vectors, implement address/command serialization and the response header/body key derivation. The current KDF/AuthID test values do not replace independent interoperability vectors.
2. Implement authenticated AES-128-GCM and ChaCha20-Poly1305 chunks with length bounds and correct EOF/error handling.
3. Add TCP and UDP semantics while reusing the project's shared TCP/TLS/REALITY and supported transports without duplicating the transport layer.
4. Integrate typed configuration with the outbound factory, Xray/sing-box importers, URI/subscription flow, and negative tests for unsupported parameters.
5. Verify interoperability with Xray and V2Ray in a reproducible interop suite; update capability tables, examples, and RU/EN translations.

## Completion criteria

- TCP and UDP pass bidirectional checks against current Xray and V2Ray.
- Supported ciphers, transports, and import formats are documented; legacy alterId and unsupported ciphers fail with clear errors.
- Reference tests for headers/AEAD, network integration tests, negative tests, and required CI checks are present.
- Russian and English documentation report the same verified status and do not claim unproven support.
