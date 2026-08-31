# 2. The anti-replay window is disabled by default

Status: accepted

## Context

`replay_window` became a per-association field on `CreateSecurityAssociation`, replacing the
compiled-in 64 that every ingress association used to get. A field needs a value when the client
omits it, and proto3 decides more of that question than it first appears.

RFC 4303 section 3.4.3 makes anti-replay the receiver's default: the sender must always increment
its sequence number, and the receiver checks unless the two ends agreed otherwise. Sixty-four is
the window the RFC recommends as a minimum, and it is what dpservice did before this change. On
the merits, 64 is the right default.

It was rejected anyway, because of what it costs on the wire.

A proto3 scalar has no presence. With a default of 64, `replay_window = 0` carries two different
intents that arrive at the server identically: "I omitted the field, give me the default" and "I
want replay checking off". Separating them means `optional uint32` in a protocol file that has
never used field presence, a `bool has_replay_window` travelling next to the value through
`struct dpgrpc_ipsec_sa` and `struct dp_ipsec_sa`, and a Go CLI that has to decide presence from
`fs.Changed("replay-window")` rather than from the value it just parsed. Three surfaces carrying
a flag whose only purpose is to disambiguate a number.

With a default of 0, none of that exists. Unset and disabled are the same state because they mean
the same thing, and the field is a plain `uint32` everywhere.

## Decision

`replay_window` defaults to 0, and 0 means anti-replay is disabled.

An association created without the field accepts replayed frames. This is total rather than
partial: in `librte_ipsec` both `esn_inb_check_sqn()` and `esp_inb_rsn_update()` return early when
`win_sz == 0`, so neither the pre-crypto sequence check nor the post-crypto bitmap update runs. It
is not a one-packet window; a duplicate is decrypted and delivered.

Two values are refused rather than accepted quietly, both with `DP_GRPC_ERR_SA_REPLAY_WINDOW`:
a non-zero window on an egress association, which `librte_ipsec` would ignore because it only
sizes a replay bitmap for the inbound direction, and anything above
`DP_IPSEC_REPLAY_WINDOW_MAX`. The cap exists because the field is otherwise an unbounded `uint32`
reaching an allocator - `rte_ipsec_sa_size()` itself only objects above two million, where one
association's bitmap costs about a quarter of a megabyte.

## Consequences

- **A control plane that wants anti-replay has to ask for it, on every ingress association.** A
  client written against the old dpservice, which had no such field, gets a weaker tunnel after
  upgrading without any error to tell it so. This is the real cost of this decision and it is not
  mitigated anywhere in the code; it is documented here and in `docs/concepts/ipsec.md`.
- The test suite asks for 64 explicitly in `test/local/dp_service.py`, so what it exercises did
  not change when the default did.
- Both behaviours are asserted. `xtratest_ipsec_dataplane.py` replays one frame under a 64-packet
  window and expects it dropped, and replays another under a window of 0 and expects it delivered
  twice. The windowed case also asserts that an in-window, never-seen sequence number is still
  accepted, which is what distinguishes a window from a requirement that sequence numbers only
  increase.
- Should the default ever be reconsidered, the work is the `optional uint32` migration described
  above, not a one-line change.
