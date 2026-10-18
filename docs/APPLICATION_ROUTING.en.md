[Русский](APPLICATION_ROUTING.md) | [English](APPLICATION_ROUTING.en.md)

# Applications and sites in one TUN

Status: **experimental**, core API and C ABI. This change does not implement
a particular Android client's integration or physical-device verification.

`route.rules` supports `user_id` (OS UID: a number or array) and `invert`
(negation of the complete predicate). First match wins: UID entries are ORed;
UID and domain/port/network/inbound conditions are ANDed. For example:

```json
{
  "route": {
    "rules": [
      {"domain_suffix": ["bypass.example"], "outbound": "direct"},
      {"user_id": [10001], "outbound": "proxy"},
      {"user_id": [10001], "invert": true, "outbound": "direct"}
    ],
    "final": "proxy"
  }
}
```

UID 10001 uses proxy, other known UIDs use direct, and the site/subdomains use
direct regardless of the app. Referenced outbounds must exist. The client sets
rule order: an application rule before a site rule takes precedence. Fake-IP
recovery happens before routing.

## Trusted metadata

Before starting, install `rc_set_connection_owner(callback, user)` or Rust
`connection_owner::set_callback`. The callback receives IP protocol 6/17 and
original numeric `SocketAddr` endpoints before fake-IP/sniffing; IPv6 is bracketed.
Return UID 0..UINT32_MAX, or -1/None for unknown. C strings are borrowed only for
the callback duration. Negative and out-of-range UIDs are rejected.

The callback runs once per new TUN TCP/UDP flow, only when UID rules exist.
It is not per-packet, does not cache ownership indefinitely by port, and is not
used for SOCKS/HTTP or internal DNS/health flows. This is process-global:
install before startup and remove after all cores and callbacks have stopped.
Keep user data alive and thread-safe. Calls are synchronous: do not block, make
network requests or unwind exceptions through the C ABI. Existing C ABI signatures
are unchanged; this adds a symbol. Rust `Metadata` gains `user_id: Option<u32>`.

When a relevant UID rule cannot identify its owner, routing selects the block
outbound `connection-owner-unavailable`, not final/direct. Inversion does not
turn unknown into an unselected app. Earlier self-contained site/inbound rules
can still match without a UID. Explicit global/direct modes continue bypassing
ordinary rules; this guarantee applies to rule mode. DNS hijacking still happens
before application routing.

## Android client integration requirements

1. Bridge the callback through JNI to `ConnectivityManager.getConnectionOwnerUid`
   (API 29+), with original TCP/UDP endpoints. Return -1 on failure/unknown,
   not the VPN application's UID.
2. Translate package_name through `ApplicationInfo.uid`. The core neither reads
   Android package lists nor trusts a package name as ownership evidence. Apps
   sharing a UID cannot be separated this way; inform the user.
3. Capture the required apps in TUN for mixed rules: old addAllowedApplication/
   addDisallowedApplication filters must not bypass site overrides. Protect the
   VPN's own sockets as before.
4. Put site rules before UID rules according to client policy. Do not drop extra
   rules or remove a client's existing guard before its resolver, adapter and
   DNS/fake-IP/TCP/UDP device verification are implemented.
5. On API 24–28 without a reliable resolver, do not enable mixed routing. Never
   invent an owner or route unknown owners directly.

Existing NOVA APKs are not automatically repaired: new native binaries and
JNI/adapter changes are required. Real applications, shared UIDs, network changes,
application DNS/DoH and battery use require physical-device testing.
