# smoltcp 0.12.0 with TCP backports

[Русский](smoltcp-window-patch.md) | **English**

The TUN inbound stack uses smoltcp through netstack-smoltcp 0.2.4, which
requires smoltcp 0.12. In 0.12, a TCP segment was accepted if it fit in the
entire receive buffer, rather than the window advertised to the peer. If the
scaled window was advertised as zero while a few bytes remained in the buffer,
those bytes were accepted and the next window calculation (`last_scaled_window`)
panicked with "attempt to subtract sequence numbers with underflow". The TUN
stack stopped; this happened in `scripts/tun_netns.sh` in CI while transferring
2 MiB.

The first fix matches smoltcp 0.13 ([#1079], "Reject bytes outside the receive
window"): the right edge is `remote_last_ack + advertised window`. It also adds
`test_established_rejects_data_beyond_advertised_window`, which reproduces the
panic without the fix.

The second fix backports zero-window probes from smoltcp 0.13 ([#1026], "Add
zero window probe support"). In 0.12, when the peer's window is zero and there
is no unacknowledged data, the sender sends nothing. If the ACK that reopens the
window is lost (for example, because the TUN queue overflowed), the connection
stalls forever; this hung a 32 MiB transfer in `scripts/tun_netns.sh` in CI.
Now, when the window is zero and data is pending, a one-byte probe is sent on
each RTO, with exponential backoff up to 10 seconds. Differences from 0.13:

- In 0.12, almost every incoming packet moves the timer to Idle. The probe
  timer is therefore saved and restored if the packet acknowledged nothing;
  otherwise the delay would not back off exponentially.
- The initial RTO in 0.12 is 700 ms, not 1 s (the RTO rewrite from [#1023] was
  not backported). Three tests from 0.13 have their timings adjusted
  (700 → 1400 → 2800 ms).

The `test_zero_window_probe_*` tests come from 0.13; seven fail without the
fix. The full patch is `smoltcp-window-patch.diff` (`scripts/vendor_patch.sh
smoltcp`; `scripts/ci.sh` runs it with `--check`).

The third fix from upstream [#1162] confirms repeated data segments and
zero-window probes without limiting protective ACKs. Otherwise, a lost ACK can
put the peer into retransmission/persist backoff. Empty ACKs remain rate-limited
to prevent an ACK loop. The upstream tests `test_old_data_ack_not_rate_limited`
and `test_zero_window_ack_not_rate_limited` both fail without this fix. CI runs
five separate 32 MiB transfers and checks their SHA-256, with a 60-second limit
for each.

The fourth fix preserves the furthest previously advertised right edge of the
receive window. Window-scale rounding can reduce the last edge by a few bytes,
but the peer may already have sent them under the earlier advertisement.
Discarding those bytes blocked full-duplex TUN in Linux CI: receive window 0,
incoming ACK four bytes ahead, reverse buffer full. Receiving is bounded by
both the previously allowed edge and the actual buffer capacity. The remaining
length of the last rounded window saturates at zero instead of underflowing.
SYN is counted without scaling, and state is reset with the socket.
`test_scaled_window_preserves_in_flight_bytes_and_reverse_ack` checks the
remaining bytes, reverse-flow ACK, and window reopening after a read together.
The check that rejects bytes never allowed by the window remains, with an
explicit initial 60-byte window.

Updating to smoltcp ≥ 0.13 is not possible yet: it requires Rust 1.91 (the
project MSRV is 1.89), and netstack-smoltcp still requires 0.12. Remove this
patch when netstack-smoltcp moves to a newer version (see `[patch.crates-io]`
in `Cargo.toml`).

`cargo audit` and `cargo deny` do not see crates under `vendor/`; check RustSec
manually for vulnerabilities in smoltcp 0.12.

[#1079]: https://github.com/smoltcp-rs/smoltcp/pull/1079
[#1026]: https://github.com/smoltcp-rs/smoltcp/pull/1026
[#1023]: https://github.com/smoltcp-rs/smoltcp/pull/1023
[#1162]: https://github.com/smoltcp-rs/smoltcp/pull/1162
