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

The three RPCs behind this, and what they reject, are in [the gRPC interface](#the-grpc-interface).


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

**Extended sequence numbers** widen that counter from 32 bits to 64, per RFC 4304, and are asked
for with the `esn` field. Only the lower half travels in the packet; the upper half is
authenticated along with it and reconstructed by the peer. This matters because a 32-bit counter
is not a large budget at line rate - an association sending 1.5 Mpps exhausts it in under an
hour, and it may not wrap, since a repeated sequence number is a repeated nonce.

`esn` is off unless asked for, and unlike the window it is **not** a local decision: it changes
what the ICV covers, so two ends that disagree fail every frame rather than merely counting
differently. Both associations of a tunnel have to be created with the same value, and dpservice
cannot check that - it only ever sees its own end. See ADR 0003.


## The gRPC interface

Three RPCs were added to the `DPDKironcore` service in `proto/dpdk.proto`, and they exist only
when dpservice was started with `--enable-ipsec`; without it every one of them fails with
`SA_DISABLED` rather than being absent from the service.

| RPC | Purpose |
| --- | --- |
| `CreateSecurityAssociation` | Install one unidirectional association, with its key material |
| `GetSecurityAssociation` | Read one back, including its key and salt |
| `DeleteSecurityAssociation` | Remove one |

There is no `ListSecurityAssociations`. A caller that wants to enumerate what it installed has to
remember it, which is acceptable only because the control plane is the sole writer.

### The identity of an association

`Get` and `Delete` name an association by the same three fields the database is keyed on, and
nothing else:

```protobuf
message GetSecurityAssociationRequest {
	uint32 spi = 1;
	bytes src_underlay = 2;
	bytes dst_underlay = 3;
}
```

`DeleteSecurityAssociationRequest` carries exactly those fields too. The addresses are matched on
their first 64 bits, so an address anywhere inside the peer's `/64` names the same entry as the
one that created it; `GetSecurityAssociationResponse` returns them masked to that length, which is
how a caller can see what was actually stored rather than what it happened to send. The direction
is deliberately not part of the identity - it is a property of the association, not of its name -
which is why two associations that differ only in direction collide when a peer shares our `/64`.

### Creating one

```protobuf
message CreateSecurityAssociationRequest {
	uint32 spi = 1;
	TrafficDirection direction = 2;    // INGRESS or EGRESS
	IpsecAlgorithm algorithm = 3;      // AES_128_GCM or AES_256_GCM
	bytes src_underlay = 4;            // source underlay address, as seen on the wire in this direction
	bytes dst_underlay = 5;            // destination underlay address, likewise
	bytes key = 6;                     // hex-encoded, 32 digits for AES-128-GCM, 64 for AES-256-GCM
	bytes salt = 7;                    // hex-encoded, 8 digits for both
	uint32 replay_window = 8;          // ingress only, 0 disables replay checking
	bool esn = 9;                      // extended (64-bit) sequence numbers, both ends must agree
}
```

`TrafficDirection` and `IpsecAlgorithm` are enums rather than free-form strings, so an unknown
cipher is a decode-time failure at the caller instead of a runtime one here. `AES_128_GCM` is
value 0, which makes it what an omitted field means.

The key length is a property of the algorithm rather than of the request: a 32-digit key with
`AES_256_GCM`, or a 64-digit one with `AES_128_GCM`, is refused rather than padded or truncated.

Every `bytes` field here carries text, not octets: `src_underlay` and `dst_underlay` are IPv6
addresses in their printed form, and `key` and `salt` are hex. That follows the convention the
rest of the API already uses, and it leaves the key material readable in a capture of the
management channel - which is a statement about how little this interface is trusted, not a
feature.

`GetSecurityAssociationResponse` mirrors this message field for field, with `status` prepended,
and it does return the key and the salt.

### What it rejects

Failures arrive on two layers. Anything malformed enough that the request cannot be built - an
unparseable address, hex that is not the length the cipher needs, an unknown direction - is
refused at the gRPC layer with `INVALID_ARGUMENT` and a naming message, before the dataplane sees
it. Everything the dataplane itself rejects arrives as the `Status` embedded in an otherwise
successful response:

| Code | Name | Raised when |
| --- | --- | --- |
| 461 | `SA_EXISTS` | The `spi`+`dst`+`src` key is already in the database |
| 462 | `SA_NOT_FOUND` | `Get` or `Delete` named an association that is not there |
| 463 | `SA_CREATE` | The crypto session or the database insert failed |
| 464 | `SA_ALGO` | `algorithm` is not one dpservice implements |
| 465 | `SA_BAD_ADDR` | The local side of the association is not our own underlay `/64` |
| 466 | `SA_DISABLED` | dpservice was not started with `--enable-ipsec` |
| 467 | `SA_REPLAY_WINDOW` | Non-zero on an egress association, or above 4096 |

`SA_EXISTS` is checked explicitly rather than left to the database, because
`rte_ipsec_sad_add()` overwrites a duplicate key and reports success, leaking the association it
used to point at. A create beyond the 64-association limit returns the generic `LIMIT_REACHED`,
and an allocation failure `OUT_OF_MEMORY`.

### From the CLI

`dpservice-cli` wraps all three, under `securityassociation`:

```bash
dpservice-cli create securityassociation --spi=100 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2:: \
    --key=<32 hex digits> --salt=<8 hex digits> [--replay-window=64]

dpservice-cli get    securityassociation --spi=100 --src-underlay=fc00:1:: --dst-underlay=fc00:2::
dpservice-cli delete securityassociation --spi=100 --src-underlay=fc00:1:: --dst-underlay=fc00:2::
```

`--algorithm` defaults to `aes-128-gcm`, `--replay-window` to zero and `--esn` to off, so none of
the three has to be given. `--algorithm=aes-256-gcm` takes a 64-digit key; `--esn` has to be
passed to both ends of a tunnel or neither.


## Deliberate limits of the PoC

- **No security policy database.** What gets protected is not selectable: with the mode on,
  everything leaving through the tunnel is encrypted, and unencrypted tunnel traffic arriving on
  a PF is dropped rather than accepted. The association database doubles as outbound policy,
  keyed on the address pair, and a missing association stands in for the "no matching policy" a
  real SPD would provide. It also prevents a receiver that silently accepts a downgrade.
- **No SA negotiation or rekeying.** Associations are created and deleted over gRPC, but keys
  arrive fully formed: there is no IKE, no distribution, no lifetime or byte counters, and no
  automatic rotation. Rekeying is delete-then-create by the control plane, and the gap between
  the two drops traffic rather than sending it in the clear. `ListSecurityAssociations` does not
  exist yet; see [the gRPC interface](#the-grpc-interface) for what does.
- **Anti-replay is off by default.** `replay_window` is configurable per association, but an
  association created without it accepts replayed frames. A control plane that wants the
  protection must ask for it on every ingress association it creates. See ADR 0002.
- **Extended sequence numbers are off by default.** `esn` is configurable per association. Without
  it the association counts in 32 bits, and the sender must be torn down and rebuilt with fresh
  keys before 2^32 packets - reusing a sequence number reuses the AES-GCM nonce, which forfeits
  authentication for that key. With it the counter is 64 bits, of which the lower half is sent and
  the upper half authenticated. Both ends must agree: unlike the replay window this changes what
  the ICV covers, so a mismatch fails every frame rather than degrading. See ADR 0003.
- **The management API is trusted.** It has no TLS and it is assumed to be reachable only from
  the host it runs on. [`GetSecurityAssociation`](#the-grpc-interface) returns the key and salt.
- **A peer sharing our /64 cannot have both directions.** Because only the first 64 bits are
  matched, an egress association `(spi, dst=peer, src=local)` and its ingress mirror become the
  same database key when the peer's underlay prefix is our own. The second create is then refused
  as a duplicate. Peers are expected to sit in distinct /64s.
- **Two ciphers.** `algorithm` accepts `aes-128-gcm` (the default) and `aes-256-gcm`. They differ
  only in key length - the nonce construction, the 16-byte ICV and the framing are identical, and
  nothing on the wire says which one an association uses, so both ends have to be configured
  alike. Anything else is refused, as is a key whose length does not match the algorithm named.
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
  libcrypto, which is why the builder stage installs `libssl-dev`; the runtime library it then
  needs is already in the `debian:13-slim` base both container images start from.


## Testing

The pytest suite runs `test_vf_to_vf_encap.py` twice: once normally, and once as the `ipsec`
suite with the mode enabled. The test body is identical; only what it observes on the PF differs.
The `ipsec` suite also runs `xtratest_ipsec_grpc.py`, which exercises create, get and delete
without sending a packet, so that an API failure and a dataplane failure are distinguishable.

`xtratest_ipsec_esn.py` covers the two per-association options that change what the cipher does
rather than which packets it covers - extended sequence numbers and the 256-bit key - in *both*
directions, and one test runs them together. It has to get at the encrypting side by deleting the
session's own pair of associations and creating it again with the parameters under test, because
the egress SPI is derived from the VNI and there is therefore no way to hold a second outbound
association for one peer. `xtratest_ipsec_dataplane.py` covers the same two options on the way in,
where an extra association *can* simply be added, and adds the negative both files rest on: a
frame framed without extended sequence numbers, on an association that has them, is refused - the
same key, the same SPI and a sequence number never seen, differing only in what the ICV covers.

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


### The second peer

Everything above happens inside the test process: scapy holds the keys and builds the answers.
`xtratest_ipsec_xfrm.py` runs the same round trip against the Linux kernel instead. The peer is a
network namespace holding an XFRM interface, one state and one policy per direction written with
`iproute2` the way a deployment would write them, and an ordinary UDP echo server that has never
heard of IPsec. Nothing in the test participates in the crypto: what the echo server receives has
already been decrypted by the kernel, and what it answers is encrypted on the way out.

That is a different claim from the one scapy supports. scapy is *a* second implementation; the
kernel is *the* implementation dp-service meets in production, and it refuses what the RFC forbids
where scapy would shrug. It is also the only place the suite tests the sentence this document
opens with: dp-service frames ESP in **transport** mode over an outer header `ipip_encap` has
already written, and the peer at the other end believes it is speaking tunnel mode. That the two
agree on the wire is what makes the mode interoperable at all, and it is now asserted rather than
argued.

The peer is a second neighbour, with its own underlay `/64` and its own key material, so nothing
it does can disturb the associations the scapy peer runs on. Getting the frames to it takes a
relay: what leaves the PF is addressed to the MAC of a neighbouring router, and on a TAP netlink
never finds one, so the destination is all zeroes. No bridge can deliver such a frame to a kernel
stack - it arrives as `PACKET_OTHERHOST` and is dropped before xfrm sees it - so two sniffer
threads carry the frames across, rewriting the ethernet header and nothing past it.

Because both implementations can drop a packet without saying anything, the test reads the
namespace's `/proc/net/xfrm_stat` and requires every counter to be zero. That is what turns a
silent kernel-side drop into `XfrmInStateProtoError` or `XfrmOutNoStates` rather than into five
packets that never arrived.

**Both associations still share one SPI, and that is a property of the test rather than of the
design.** dp-service derives the egress SPI from the VNI, so the egress association's SPI is
fixed; the ingress one is free, and is kept equal to it. Between two real hosts each side picks
its own. Nothing in dp-service depends on them matching - ingress resolves the association from
the SPI on the wire - but the suite would not notice if something started to.


### The full path

![The xfrm peer round trip](xfrm_round_trip.svg)

One burst of five packets, out along the top lane and back along the bottom. The three dashed
boundaries are the interfaces the frames actually cross; the boxed annotations show what is on the
wire at each crossing. Both dpservice and the kernel advance their own sequence numbers per burst,
which is why the peer fixture is module-scoped.
