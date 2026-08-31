# IPsec

dp-service can encrypt the traffic it sends over the underlay, so that the tunnel between two
instances is not readable by anyone with access to the fabric in-between. This is enabled by
starting dp-service with `--enable-ipsec` and is off by default.

This is a **proof of concept**. It proves the dataplane can carry ESP and that its Security
Associations can be managed at runtime; it is not yet a usable IPsec deployment. The limits below
are deliberate, not oversights.


## Wire format

The mode adds ESP on top of the encapsulation that already happens, rather than replacing it.
`ipip_encap` builds the outer header as it always does, and `ipsec_encap` then inserts an ESP
header between that outer IPv6 header and the packet it tunnels:

```
| Ethernet | IPv6 (proto=50) | SPI | Seq | IV |<-- encrypted -->| ICV |
                                              | tunneled packet | padding | pad len | next proto |
```

The outer IPv6 `proto` becomes 50 (ESP) and the value it used to carry (4 for IPv4, 41 for IPv6)
moves into the ESP trailer's next-header byte. Everything from the tunneled packet to the end of
the trailer is encrypted; the ICV authenticates the ESP header and the ciphertext, but **not** the
outer IP header, exactly as RFC 4303 specifies.

On the wire this is indistinguishable from ESP in tunnel mode, and interoperates with a
tunnel-mode peer, so a capture can be read with ordinary tooling.

Inside dp-service it is not tunnel mode, though. The framing is done by `librte_ipsec` in
**transport** mode, applied to the outer header `ipip_encap` has already built; the tunnelling
comes from `ipip_decap` stripping that header afterwards. Tunnel mode would build the outer header
itself, from a fixed per-association template, which cannot express a source that varies per VF
and a full 128-bit destination the peer resolves to a port. See
[the ADR](../adr/0001-esp-framing-via-librte-ipsec-transport-mode.md).

On the way in, `cls` sends ESP packets to `ipsec_decap`, which decrypts and strips ESP, leaving
precisely what `ipip_decap` would otherwise have received. Neither `ipip_encap` nor `ipip_decap`
is modified by this feature.


## Security Associations

Associations are provisioned over gRPC and looked up per packet; nothing is compiled in.
Each one is **unidirectional**, as RFC 4301 defines it, and carries AES-128-GCM (RFC 4106)
key material, so a peer needs one association for each direction.

```
dpservice-cli create securityassociation --spi=100 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2:: \
    --key=<32 hex digits> --salt=<8 hex digits>
```

`src` and `dst` are the underlay addresses as they appear on the wire **in that association's
direction**, so an ingress association for the same peer swaps them. dp-service refuses an
association whose local side is not its own underlay prefix, since such an association could
never match a packet.


### How an association is found

The database is keyed on `SPI + destination + source`, with the underlay addresses matched on
their **first 64 bits only**. dp-service derives every underlay address it hands out from the
configured underlay address's /64, so one association covers a whole peer host rather than each
of its individual addresses.

On ingress the SPI is read from the packet. On egress there is nothing to read it from - a real
implementation would consult a security policy database, which does not exist here - so the SPI
is derived: **it is the VNI**, and the caller is responsible for creating associations whose
`spi` equals the VNI they serve. This is an egress-side rule only; ingress matches whatever SPI
arrives against the address pair, and cannot check it, since the VNI is not known until after
decapsulation.

A packet with no matching association is **dropped**, in both directions, without a log line.
Before the control plane has provisioned anything that is the expected state, and one line per
packet would bury the failures that do matter. Egress never falls back to cleartext.


### Sequence numbers

Each association owns its sequence number, as RFC 4303 requires. It starts at 1 and doubles as
the 8-byte explicit nonce, which makes the one thing AES-GCM cannot survive - the same nonce
twice under one key - impossible by construction rather than merely unlikely. The salt is never
on the wire; both ends must already have it.

Ingress associations may carry an **anti-replay window**, sized per association by the
`replay_window` field on `CreateSecurityAssociation`. A frame whose sequence number has already
been seen, or which has fallen further behind than the window is wide, is rejected before it is
decrypted; reordering on the underlay is tolerated up to that depth. The rejection happens in
`ipsec_decap` before any crypto runs, so a replayed frame costs nothing to refuse.

**The window is off unless an association asks for one.** `replay_window` defaults to zero, and
zero disables replay checking altogether rather than narrowing it to a single packet - a
duplicated frame is decrypted and delivered. This is a deliberate departure from RFC 4303
section 3.4.3, where anti-replay is the receiver's default; see ADR 0002 for why. An association
that wants the protection has to say so, and 64 is the value RFC 4303 recommends as a minimum.

An egress association has nothing to check, so any non-zero `replay_window` is refused there
rather than silently ignored. The upper bound is 4096.


## Deliberate limits

- **No security policy database.** What gets protected is not selectable: with the mode on,
  everything leaving through the tunnel is encrypted, and unencrypted tunnel traffic arriving on
  a PF is dropped rather than accepted. The association database doubles as outbound policy,
  keyed on the address pair, and a missing association stands in for the "no matching policy" a
  real SPD would provide. It also prevents a receiver that silently accepts a downgrade.
- **No SA negotiation or rekeying.** Associations are created and deleted over gRPC, but keys
  arrive fully formed: there is no IKE, no distribution, no lifetime or byte counters, and no
  automatic rotation. Rekeying is delete-then-create by the control plane, and the gap between
  the two drops traffic rather than sending it in the clear. `ListSecurityAssociations` does not
  exist yet.
- **Anti-replay is off by default.** `replay_window` is configurable per association, but an
  association created without it accepts replayed frames. A control plane that wants the
  protection must ask for it on every ingress association it creates. See ADR 0002.
- **The management API is trusted.** It has no TLS and it is assumed to be reachable only from
  the host it runs on. `GetSecurityAssociation` returns the key and salt.
- **A peer sharing our /64 cannot have both directions.** Because only the first 64 bits are
  matched, an egress association `(spi, dst=peer, src=local)` and its ingress mirror become the
  same database key when the peer's underlay prefix is our own. The second create is then refused
  as a duplicate. Peers are expected to sit in distinct /64s.
- **The direction is not re-checked on lookup.** Both directions share one database, and an entry
  is found purely by its key; nothing verifies afterwards that an association handed to the
  decrypting node is an ingress one. The address layout makes that unreachable, but by arithmetic
  rather than by construction.
- **One cipher.** The API carries an `algorithm` field so a second one does not need a breaking
  change, but AES-128-GCM is the only accepted value.
- **Reduced MTU.** ESP adds up to 37 bytes, and the mbuf data room leaves no space for that on a
  full-size frame. Tunneled packets above roughly 1480 bytes are dropped with a warning naming
  the node. The advertised DHCP MTU is *not* adjusted automatically. A further 8 bytes of
  tailroom are needed but never used: `librte_ipsec` writes the additional authenticated data
  past the ICV, outside the packet.
- **Checksums are computed in software.** Asking a NIC to compute an inner checksum cannot work
  once the packet is encrypted, so `dp_nat.c` takes the software path whenever the mode is on.
  This is not covered by a test - the suite runs on TAPs, where that path is taken anyway.
- **Hardware offloading is refused.** dp-service will not start with both `--enable-ipsec` and
  offloading. Offloaded flows bypass the graph entirely, so they would leave the PF in cleartext.
- **Virtual services stay in cleartext.** `virtsvc` transmits to a PF directly rather than through
  `ipip_encap`, so its traffic is not covered by this mode.
- **Software crypto only.** The `crypto_openssl` PMD is created by dp-service itself when the mode
  is enabled; hardware crypto devices are not used. The PMD requires DPDK to have been built with
  libcrypto available, and the production container image does not yet ship the runtime library,
  so `--enable-ipsec` there aborts at startup.


## Testing

The pytest suite runs `test_vf_to_vf_encap.py` twice: once normally, and once as the `ipsec`
suite with the mode enabled. The test body is identical; only what it observes on the PF differs.
The `ipsec` suite also runs `xtratest_ipsec_grpc.py`, which exercises create, get and delete
without sending a packet, so that an API failure and a dataplane failure are distinguishable.

In IPsec mode the loopback responder plays the peer for real. The two directions carry different
keys, so it decrypts the captured frame with one association and builds the answer with the
other, using scapy's own ESP implementation. That matters for what the suite proves: a responder
that reflects ciphertext only shows dp-service can be *read*, while one that builds the frame
shows dp-service accepts ESP it did not produce. Both halves of interoperability are covered only
by the second.

The harness therefore holds both keys, which the suite is entitled to since it provisions the
associations itself. It shares no code with dp-service, so it cannot pass by reimplementing a bug
in the code under test - GCM authentication fails unless the additional authenticated data, the
nonce construction and the trailer all match what a second implementation expects. It also asserts
that the payload is *not* readable on the PF, which fails loudly if the cipher ever degrades to
doing nothing, and it checks the parts of the framing that a successful decrypt would silently
accept: that the explicit IV really is the sequence number, and that the padding is minimal and
4-byte aligned. Those assertions are what holds the wire format still: they were written against
the hand-rolled framing this mode started with, and had to keep passing once `librte_ipsec` took
it over.

`xtratest_ipsec_dataplane.py` covers the failing path, which the round trip cannot: it runs the
same exchange twice, differing only in which key the peer authenticates its answer with, and
requires the second one not to arrive.

**Both associations still share one SPI, and that is a property of the test rather than of the
design.** dp-service derives the egress SPI from the VNI, so the egress association's SPI is
fixed; the ingress one is free, and is kept equal to it. Between two real hosts each side picks
its own. Nothing in dp-service depends on them matching - ingress resolves the association from
the SPI on the wire - but the suite would not notice if something started to.
