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

The result is standard ESP in tunnel mode, so a capture can be read with ordinary tooling.

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
- **No anti-replay window.** A replayed frame is decrypted and delivered like any other. Nothing
  in the design prevents one - the test peer now counts its own sequence numbers, so a window
  would no longer reject legitimate traffic - it is simply not implemented yet.
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
  the node. The advertised DHCP MTU is *not* adjusted automatically.
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
4-byte aligned.

**Both associations still share one SPI, and that is a property of the test rather than of the
design.** dp-service derives the egress SPI from the VNI, so the egress association's SPI is
fixed; the ingress one is free, and is kept equal to it. Between two real hosts each side picks
its own. Nothing in dp-service depends on them matching - ingress resolves the association from
the SPI on the wire - but the suite would not notice if something started to.
