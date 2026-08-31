# 1. ESP framing via librte_ipsec transport mode

Status: accepted

## Context

dp-service tunnels overlay traffic in IPinIPv6 and, with `--enable-ipsec`, protects that tunnel
with ESP. The outer header is not built by the IPsec code: `ipip_encap` builds it, per packet,
from the route and the interface the packet came in on. Its source is the sending VF's own
underlay address and its destination is the full 128-bit underlay address of the target VF, which
is what the receiving instance's VNF lookup resolves to a port. Neither is a property of the
Security Association.

The first proof of concept therefore wrote the ESP header, padding, trailer and ICV by hand, and
built the crypto operations directly on `rte_cryptodev`. `librte_ipsec` was linked only for its
Security Association Database. The reason recorded at the time was that `librte_ipsec`'s
tunnel-mode outbound copies a fixed per-Security-Association outer header template
(`lib/ipsec/esp_outb.c`), which cannot express a header that differs per packet.

That reasoning is correct, and it is why the hand-rolled framing lasted two iterations. What it
misses is that it only rules out **tunnel** mode.

## Decision

Use `librte_ipsec` in **transport** mode, over the outer header `ipip_encap` has already built.

Transport mode has no header template. `outb_trs_pkt_prepare()` inserts ESP into whatever header
the packet already carries, moves that header forward, writes the old next-protocol value into the
ESP trailer and fixes up the length - which is, byte for byte, what the hand-rolled code did.
Composed with the existing `ipip_encap` / `ipip_decap` pair, transport-mode ESP over the tunnel
header produces and consumes exactly the wire format tunnel mode would.

Two consequences of the model are worth stating, because both are easy to read backwards:

- `prm.trs.proto` names the protocol of the header **being protected**, not of what that header
  carries. `fill_sa_type()` turns it into `RTE_IPSEC_SATP_IPV4` or `RTE_IPSEC_SATP_IPV6`, and
  `update_trs_l3hdr()` uses that bit to decide how to parse the header. Ours is the outer IPv6
  header, so the value is always `IPPROTO_IPV6`. It does not pin the tunneled protocol: that is
  read from the header on the way out and from the ESP trailer on the way in, so one association
  still carries both IPv4 and IPv6 packets.
- The mode is transport, but the *behaviour* is tunnelling, because `ipip_decap` still strips the
  outer header afterwards. `docs/concepts/ipsec.md` describes the wire format; this file explains
  why the code says `RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT`.

## Consequences

- The ESP header, sequence number, explicit IV, padding, trailer and ICV placement all come from
  DPDK. About 150 lines of header surgery across the two graph nodes are gone.
- An anti-replay window becomes one configuration field (`replay_win_sz`) rather than a sliding
  bitmap we would have had to write. It is set per association over gRPC; ADR 0002 records why
  it defaults to off.
- The wire format does not change. `gen_iv()` is `iv[0] = sqn` and `IPSEC_PAD_AES_GCM` is 4, both
  matching what the hand-rolled code produced, and the test suite's independent scapy
  implementation authenticates the result in both directions.
- **Switching `mode` to `RTE_SECURITY_IPSEC_SA_MODE_TUNNEL` would look like a simplification and
  would silently break the tunnel.** The outer header would come from a per-association template
  and the per-VF destination the peer's VNF lookup depends on would be lost. This is the reason
  this file exists.
- The mbuf needs 8 bytes more tailroom than it ends up using: `outb_trs_pkt_prepare()` writes the
  additional authenticated data into the tailroom past the ICV. The largest packet that survives
  encryption shrinks accordingly.
- Both graph nodes must set `mb->l2_len` and `mb->l3_len` to the outer header's sizes, which on
  egress overwrites what `ipip_encap` left there for inner checksum offload. That offload was
  already meaningless under IPsec - a NIC cannot checksum ciphertext - so `dp_nat.c` now computes
  those checksums in software whenever the mode is on.
