<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# VMess implementation plan

## Status

The VMess stage has started, but outbound connections are not implemented yet. `core::vmess` parses modern `vmess://` share links: base64 JSON, UUID, `aid=0`, modern authenticated encryption with associated data (AEAD) choices, and shared transport parameters. Non-zero `alterId` and non-AEAD ciphers are rejected explicitly. `core::vmess::aead` now contains the nested-HMAC KDF, derived command key, AuthID creation, and two-layer AES-128-GCM header sealing. `core::vmess::header` encodes/decodes the plaintext request header, addresses, padding, and FNV-1a checksum; CI passed for these modules, but independent Xray/V2Ray wire vectors have not yet been added.

The module now opens an incoming AEAD request-header payload, derives response keys from the random request-body key/IV, and authenticates/opens the two-layer AEAD response header while returning the exact number of consumed bytes. These helpers are not yet connected to a network session and do not replace independent interoperability vectors.

`core::vmess::response` now parses plaintext response-header payload framing: it checks the expected response marker, preserves the option byte, bounds the command frame, and returns the exact parsed length. Command data remains opaque; this module does not implement dynamic-port or connection-control behavior.

`core::vmess::body` provides a directional AEAD chunk codec for AES-128-GCM and ChaCha20-Poly1305, two-byte sizes, optional authenticated lengths using `auth_len`, bounds checks (encrypted chunks are limited to 2^14 bytes per the Project X specification), and a sequential nonce. The nonce counter stops after 65,536 chunks and returns an error instead of reusing a nonce; a safe rollover strategy must be defined before integration with long-lived TCP sessions. This is a low-level codec; it is not yet connected to asynchronous streams or UDP sessions and has no independent wire vectors.

Framing and `auth_len` key derivation were checked against [Xray `EncodeRequestBody`](https://github.com/XTLS/Xray-core/blob/main/proxy/vmess/encoding/client.go), the [Xray chunk parser](https://github.com/XTLS/Xray-core/blob/main/common/crypto/chunk.go), and [V2Ray `EncodeRequestBody`](https://github.com/v2fly/v2ray-core/blob/master/proxy/vmess/encoding/client.go). Source inspection does not replace an independent golden vector or network interoperability test.

The field layout follows the [Project X VMess specification](https://xtls.github.io/en/development/protocols/vmess.html) and [Xray `DecodeResponseHeader`](https://github.com/XTLS/Xray-core/blob/main/proxy/vmess/encoding/client.go#L1061-L1169). This is a source-level structure check, not a network interoperability test.

The parser reuses `TransportConfig` and its validation. It does **not** establish a connection, perform VMess authentication, or imply VMess support in configuration files or subscriptions. Do not register the protocol in the outbound factory or importers until the protocol client works.

## Remaining work

1. Verify AuthID/request/response headers against independent current Xray/V2Ray interoperability vectors. Request-header serialization/decoding and plaintext response-header framing are implemented; compatibility remains unconfirmed until reference interoperability checks pass.
2. Connect AEAD chunks to TCP streams and UDP packet semantics; verify chunk masking, global padding, EOF/errors, and nonce exhaustion against independent wire vectors.
3. Add TCP and UDP semantics while reusing the project's shared TCP/TLS/REALITY and supported transports without duplicating the transport layer.
4. Integrate typed configuration with the outbound factory, Xray/sing-box importers, URI/subscription flow, and negative tests for unsupported parameters.
5. Verify interoperability with Xray and V2Ray in a reproducible interop suite; update capability tables, examples, and RU/EN translations.

## Completion criteria

- TCP and UDP pass bidirectional checks against current Xray and V2Ray.
- Supported ciphers, transports, and import formats are documented; legacy alterId and unsupported ciphers fail with clear errors.
- Reference tests for headers/AEAD, network integration tests, negative tests, and required CI checks are present.
- Russian and English documentation report the same verified status and do not claim unproven support.
