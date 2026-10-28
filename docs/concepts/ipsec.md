# IPsec

dp-service can encrypt the traffic it sends over the underlay, so that the tunnel between two
instances is not readable by anyone with access to the fabric in-between.

Two things have to be true for a packet to be protected. dp-service has to have been started with
`--enable-ipsec`, which brings up the crypto subsystem and is off by default; and the interface
the packet belongs to has to be **encrypting**, which is a per-interface flag that is also off by
default. The first is a capability - it says an interface *may* encrypt, never that one does -
and the second is the policy. See [encryption is a property of the interface](#encryption-is-a-property-of-the-interface).

This is the **initial implementation**. The dataplane carries ESP and its Security Associations
are managed at runtime, but it is not yet a complete IPsec deployment. Its
[limitations](#deliberate-limitations-of-the-initial-implementation) are deliberate, not
oversights.


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
[ESP framing uses transport mode](#esp-framing-uses-transport-mode).

On the way in, `cls` sends ESP packets to `ipsec_decap`, which decrypts and strips ESP, leaving
precisely what `ipip_decap` would otherwise have received. Neither `ipip_encap` nor `ipip_decap`
is modified by this feature.


## Security Associations

Associations are provisioned over gRPC and looked up per packet; nothing is compiled in.
Each one is **unidirectional**, as RFC 4301 defines it, and carries AES-128-GCM (RFC 4106)
key material, so a peer needs one association for each direction.

```
dpservice-cli create securityassociation --vni=100 --spi=43794 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2:: \
    --key=<32 hex digits> --salt=<8 hex digits>
```

`src` and `dst` are the underlay addresses as they appear on the wire **in that association's
direction**, so an ingress association for the same peer swaps them. dp-service refuses an
association whose local side is not its own underlay prefix, since such an association could
never match a packet.

`vni` is the tenant network whose traffic the association protects, and `spi` is what goes in the
ESP header. The two are independent: an egress association is *found* under its VNI and *writes*
its SPI, so the number on the wire is whatever the two ends agreed on. See
[the lookup SPI is not the wire SPI](#the-lookup-spi-is-not-the-wire-spi).

The RPCs behind this, and what they reject, are in [the gRPC interface](#the-grpc-interface).


### How an association is found

The database is keyed on a 32-bit value plus the destination and source underlay addresses, with
the addresses matched on their **first 64 bits only**. dp-service derives every underlay address
it hands out from the configured underlay address's /64, so one association covers a whole peer
host rather than each of its individual addresses.

That 32-bit value is the **lookup SPI**, and which field it comes from depends on the direction.
On ingress it is the SPI the frame carries, because that is all `ipsec_decap` has to go on. On
egress there is nothing to read it from - the packet is not ESP yet - so it is the **VNI** of the
interface the packet came in on. An outbound association is therefore named by the tenant whose
traffic it protects, which leaves the SPI it writes into the ESP header free.

A caller never has to know which of the two it is. `Create`, `Get` and `Delete` all take the same
five fields - and `Update` names its association by them too - and dp-service resolves the lookup
SPI itself and then checks the rest of what it was given against what it found; see [the identity
of an association](#the-identity-of-an-association).

A packet with no matching association is **dropped**, in both directions, without a log line.
Before the control plane has provisioned anything that is the expected state, and one line per
packet would bury the failures that do matter. Egress never falls back to cleartext.


### The inbound VNI check

Matching only the first 64 bits is deliberate on the peer's side of an association. On the local
side it would be a hole, because every underlay address dp-service hands out carries this host's
own prefix in that half: masked, the local side of *every* ingress association on a host is the
same value.

Left alone, that means a peer holding one valid ingress association can address its ESP at any
endpoint on this host. The database matches, the ICV verifies - the peer does hold the key - and
`ipip_decap` then resolves the destination from the outer address the peer chose, delivering the
traffic into a tenant the association was never provisioned for.

So `ipsec_decap` resolves that endpoint itself, from the outer destination address, and drops any
frame whose VNI is not the one its association records. The check runs **before** the frame is
decrypted and logs nothing: reaching it costs no key at all, only a guessed SPI and a spoofed
source prefix, so anything written there would be forgeable at line rate. This is the one place
dp-service makes a policy decision on unauthenticated data, and it is safe only because the
outcome is always a drop - a forged frame cannot cause a legitimate one to be discarded. See
[ingress associations are bound to their VNI](#ingress-associations-are-bound-to-their-vni).


### Encryption is a property of the interface

`encrypt` is a flag on an interface, set when it is created or toggled afterwards, and it decides
one thing in both directions:

> **Cleartext leaves an interface if and only if it is not encrypting, and cleartext is accepted
> for an interface if and only if it is not encrypting.**

Both halves are enforced, and the second is the one that carries the weight. Refusing ESP at a
cleartext interface is the lesser half - a peer holding no association is refused by the database
anyway. Refusing *cleartext* at an encrypting one is what stops an attacker on the fabric from
injecting into a protected tenant with no key, no ICV and no guessed SPI, using nothing but an
ordinary IPinIP frame addressed at the endpoint.

There is no fallback. An encrypting interface with no matching egress association **drops**, and
never sends in the clear instead: an interface is created before its association is provisioned,
and a fallback would leak during exactly that window, silently. The cost is that such an interface
is a black hole until its association arrives.

Both ends of a tunnel must agree. Turning the flag on at one endpoint severs it from every peer
that has not turned it on, in both directions and at once, so encryption is a property of an
endpoint *pair* and rolling it out is a coordinated change rather than an incremental one.

Nothing checks that a VNI is uniform. Associations are per VNI and interfaces are not, so a VNI
may hold interfaces of both kinds; that is what makes a permanent exemption possible, and the
coherence of the result is the control plane's to get right. Why the checks sit where they do is
in [why encryption is per interface](#why-encryption-is-per-interface).

### Why the policy database is one selector wide

A real implementation consults a security policy database per packet, matching traffic selectors -
addresses, protocol, ports - to decide whether to protect, bypass or discard it, and only then
looks for an association. dp-service has exactly one selector: the endpoint.

In RFC 4301 terms that is an SPD with a PROTECT rule for encrypting interfaces, a BYPASS rule for
the rest, and a default of DISCARD. What makes BYPASS safe here - it is the entry that can leak -
is that the two rules **partition** the traffic rather than overlapping: a bypassing endpoint
cannot receive protected traffic and a protecting endpoint cannot receive bypassed traffic, so
there is no configuration under which traffic that should have been protected is accepted, or
sent, unprotected instead.

The whole of it is one comparison in `cls`, made on the port the outer destination address
resolves to:

```c
if (unlikely(dst_port->iface.encrypt != (ipv6_hdr->proto == IPPROTO_ESP)))
    return CLS_NEXT_DROP;
```

`cls` is the only node that can make it. The endpoint is not resolved before it, and after it the
distinction is gone: `ipsec_decap` deliberately leaves a decrypted frame indistinguishable from
one that arrived in the clear, so that `ipip_decap` sees one kind of packet. Egress is the mirror,
in `ipip_encap`, which holds both edges per PF port and picks between Tx and `ipsec_encap` on the
flag of the interface the packet came from. `ipsec_encap` therefore only ever receives packets
that must be encrypted, and keeps its contract unqualified.

Like [the inbound VNI check](#the-inbound-vni-check), the ingress comparison decides on
unauthenticated data, and is safe for the same reason: its outcome is always a drop, so a forged
frame cannot cause a legitimate one to be discarded.

What is still genuinely missing is the *other* use of an SPD, the inbound policy check of RFC 4301
section 5.2 - confirming that what a decrypted packet turned out to be is what its association was
allowed to carry. The VNI check is that check narrowed to the one selector dp-service has, and
nothing inspects the inner packet.


### Sequence numbers

Each association owns its sequence number, as RFC 4303 requires. It starts at 1 and doubles as
the 8-byte explicit nonce, which makes the one thing AES-GCM cannot survive - the same nonce
twice under one key - impossible by construction within one association. The salt is never
on the wire; both ends must already have it.

Across associations it is the control plane's to avoid, and [`Update`](#replacing-one) is where
that matters: it installs a *new* association under an existing name, so its counter starts over
from 1. It therefore has to be given key material that association has not used before - the
nonce is `salt || sequence number`, and reusing both under one key repeats it. This is the same
obligation a delete followed by a create has always carried, and dpservice checks neither.

Ingress associations may carry an **anti-replay window**, sized per association by the
`replay_window` field on `CreateSecurityAssociation`. A frame whose sequence number has already
been seen, or which has fallen further behind than the window is wide, is rejected before it is
decrypted; reordering on the underlay is tolerated up to that depth. The rejection happens in
`ipsec_decap` before any crypto runs, so a replayed frame costs nothing to refuse.

**The window is off unless an association asks for one.** `replay_window` defaults to zero, and
zero disables replay checking altogether rather than narrowing it to a single packet - a
duplicated frame is decrypted and delivered. This is a deliberate departure from RFC 4303
section 3.4.3, where anti-replay is the receiver's default; see
[anti-replay is off by default](#anti-replay-is-off-by-default) for why. An association
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
cannot check that - it only ever sees its own end. See
[extended sequence numbers are opt-in](#extended-sequence-numbers-are-opt-in).


## The gRPC interface

Seven RPCs were added to the `DPDKironcore` service in `proto/dpdk.proto`. Four manage the
associations, and they exist only when dpservice was started with `--enable-ipsec`; without it
every one of them fails with `IPSEC_DISABLED` rather than being absent from the service.

| RPC | Purpose |
| --- | --- |
| `CreateSecurityAssociation` | Install one unidirectional association, with its key material |
| `GetSecurityAssociation` | Read one back, including its key and salt |
| `UpdateSecurityAssociation` | Replace an egress association in place, with no gap in what it protects |
| `DeleteSecurityAssociation` | Remove one |

There is no `ListSecurityAssociations`. A caller that wants to enumerate what it installed has to
remember it, which is acceptable only because the control plane is the sole writer.

The other three carry the per-interface policy:

| RPC | Purpose |
| --- | --- |
| `EnableInterfaceEncryption` | Start protecting an interface's underlay traffic |
| `DisableInterfaceEncryption` | Stop protecting it |
| `GetInterfaceEncryption` | Read the flag back |

All three take nothing but `interface_id`. The same flag can be set when the interface is created
- `CreateInterfaceRequest.encrypt`, defaulting to false - and is reported by `GetInterface` and
`ListInterfaces` on `Interface.encrypt`, always, including when it is false.

There is deliberately no single setter taking a `bool`. A proto3 scalar has no presence, so an
omitted field would be indistinguishable from an explicit request to stop encrypting - which is
the one transition here that turns a protected endpoint into a cleartext one. The verb goes in
the method name, where omission cannot forge it.

`Enable` on an interface that is already encrypting is `ALREADY_ACTIVE` (210), and `Disable` on
one that is not is `NOT_ACTIVE` (211), which is what `CaptureStart` and `CaptureStop` already do.
A reconciling caller that re-applies desired state should treat both as success. Only `Enable`
needs the capability; reading is always allowed and answers false, and turning protection off is
never refused for want of a subsystem.

### The identity of an association

An association is named by five fields, which travel together as one message. Four of them are
fixed for its whole life; the wire SPI is not, since [replacing an association](#replacing-one)
is how it changes:

```protobuf
message SecurityAssociationId {
	uint32 vni = 1;                    // the VNI whose traffic this association protects
	uint32 spi = 2;                    // Security Parameter Index, as carried in the ESP header
	TrafficDirection direction = 3;
	bytes src_underlay = 4;            // source underlay address, as seen on the wire in this direction
	bytes dst_underlay = 5;            // destination underlay address, likewise
}
```

`GetSecurityAssociationRequest` and `DeleteSecurityAssociationRequest` are that message and
nothing else; `Create` and the `Get` response embed it beside the key material, and
[`Update`](#replacing-one) embeds it as the name of the association it replaces.

Only three of the five are what the database is keyed on - the lookup SPI plus the address pair -
but all five are matched. dp-service resolves the entry, then compares the fields it did not key
on against what it was given, and answers `SA_NOT_FOUND` if they differ. The point is that a
caller working from stale state gets an error instead of silently operating on a different
association: naming an egress association by a wire SPI it no longer has finds nothing, rather
than finding the one that replaced it.

The addresses are matched on their first 64 bits, so an address anywhere inside the peer's `/64`
names the same entry as the one that created it; `GetSecurityAssociationResponse` returns them
masked to that length, which is how a caller can see what was actually stored rather than what it
happened to send.

### Creating one

```protobuf
message CreateSecurityAssociationRequest {
	SecurityAssociationId id = 1;
	IpsecAlgorithm algorithm = 2;      // AES_128_GCM or AES_256_GCM
	bytes key = 3;                     // hex-encoded, 32 digits for AES-128-GCM, 64 for AES-256-GCM
	bytes salt = 4;                    // hex-encoded, 8 digits for both
	uint32 replay_window = 5;          // ingress only, 0 disables replay checking
	bool esn = 6;                      // extended (64-bit) sequence numbers, both ends must agree
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

### Replacing one

An egress association can be replaced without ever leaving the traffic it protects unprotected:

```protobuf
message UpdateSecurityAssociationRequest {
	SecurityAssociationId id = 1;      // the association as it stands now, current wire SPI and all
	uint32 new_spi = 2;                // what its ESP headers carry from here on
	IpsecAlgorithm algorithm = 3;
	bytes key = 4;
	bytes salt = 5;
	uint32 replay_window = 6;          // egress, so anything but zero is refused
	bool esn = 7;
}
```

dpservice builds the replacement whole - its own crypto session, its own `librte_ipsec` state -
while the old association is still encrypting, and only then swaps it in. Requests are processed
by a source node of the one graph, so no packet is handled in between: packet *N* leaves under the
old key and packet *N+1* under the new one. Anything that fails leaves the association that is
there still serving traffic, so a failed `Update` is indistinguishable from one that was never
sent.

`id` names the association **as it stands**, so it carries the wire SPI the association has now,
not the one it is about to get; that goes in `new_spi`. Everything after it is what the
association becomes, with the same defaulting rules as a create - nothing is carried over from
what is being replaced, so an omitted `algorithm` means AES-128-GCM rather than whatever the old
association used.

It is **egress only**; an ingress `Update` is refused with `SA_DIRECTION`. An inbound association
does not need one: it is found under the SPI its frames carry, so a second one is simply added
beside the live one and the old one deleted once the peer has switched. Rotating an inbound key in
place would be worse than that, not better, since it would drop whatever is still in flight under
the old SPI. See
[egress associations are rekeyed by replacement](#egress-associations-are-rekeyed-by-replacement).

Rekeying a whole tunnel is therefore three steps, in this order, and the order is the control
plane's to get right - dpservice cannot see whether the far end is ready:

1. the peer installs its new **ingress** association, alongside the one it already has;
2. this side **replaces** its egress association, which switches the wire SPI and the key at once;
3. the peer deletes its old ingress association.

### What it rejects

Failures arrive on two layers. Anything malformed enough that the request cannot be built - an
unparseable address, hex that is not the length the cipher needs, an unknown direction - is
refused at the gRPC layer with `INVALID_ARGUMENT` and a naming message, before the dataplane sees
it. Everything the dataplane itself rejects arrives as the `Status` embedded in an otherwise
successful response:

| Code | Name | Raised when |
| --- | --- | --- |
| 461 | `SA_EXISTS` | The lookup SPI + `dst` + `src` key is already in the database |
| 462 | `SA_NOT_FOUND` | `Get` or `Delete` named an association that is not there, or named one by a field that does not match what is |
| 463 | `SA_CREATE` | The crypto session or the database insert failed |
| 464 | `SA_ALGO` | `algorithm` is not one dpservice implements |
| 465 | `SA_BAD_ADDR` | The local side of the association is not our own underlay `/64` |
| 466 | `IPSEC_DISABLED` | dpservice was not started with `--enable-ipsec` |
| 467 | `SA_REPLAY_WINDOW` | Non-zero on an egress association, or above 4096 |
| 468 | `SA_DIRECTION` | `Update` named an ingress association, which cannot be replaced in place |

`SA_EXISTS` is checked explicitly rather than left to the database, because
`rte_ipsec_sad_add()` overwrites a duplicate key and reports success, leaking the association it
used to point at. It is raised on the *lookup* SPI, so a second egress association for a VNI and
peer collides with the first however different the rest of its identity is - freeing the wire SPI
does not create a second outbound slot. A create beyond the 64-association limit returns the generic `LIMIT_REACHED`,
and an allocation failure `OUT_OF_MEMORY`.

### From the CLI

`dpservice-cli` wraps all four, under `securityassociation`:

```bash
dpservice-cli create securityassociation --vni=100 --spi=43794 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2:: \
    --key=<32 hex digits> --salt=<8 hex digits> [--replay-window=64]

dpservice-cli get    securityassociation --vni=100 --spi=43794 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2::
dpservice-cli delete securityassociation --vni=100 --spi=43794 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2::

dpservice-cli update securityassociation --vni=100 --spi=43794 --direction=egress \
    --src-underlay=fc00:1:: --dst-underlay=fc00:2:: \
    --new-spi=43795 --key=<32 hex digits> --salt=<8 hex digits>
```

The same five flags name the association in every one of them. `update` adds `--new-spi` and a
full set of the create's flags, because it replaces the association rather than editing it.

The per-interface policy is its own command group, since it is not CRUD:

```bash
dpservice-cli create interface --id=vm1 --vni=100 --device=... --ipv4=... --ipv6=... --encrypt

dpservice-cli encryption enable  --interface-id=vm1
dpservice-cli encryption disable --interface-id=vm1
dpservice-cli encryption get     --interface-id=vm1
```

`get interface` and `list interfaces` show the flag in an `Encrypt` column.

`--algorithm` defaults to `aes-128-gcm`, `--replay-window` to zero and `--esn` to off, so none of
them has to be given - on an `update` too, where an omitted flag means its default rather than
what the association held a moment ago. `--algorithm=aes-256-gcm` takes a 64-digit key; `--esn`
has to be passed to both ends of a tunnel or neither.


## Deliberate limitations of the initial implementation

- **A security policy database one selector wide.** What gets protected is selectable, but only
  per interface: there are no traffic selectors on addresses, protocol or ports, and nothing
  inspects the inner packet. See
  [why the policy database is one selector wide](#why-the-policy-database-is-one-selector-wide).
  What *is* missing is the inbound policy check of RFC 4301 section 5.2 in its full form; the one
  selector dp-service can check is covered by [the inbound VNI check](#the-inbound-vni-check).
- **No SA negotiation, though rekeying is gapless.** Associations are managed over gRPC, but keys
  arrive fully formed: there is no IKE, no distribution, no lifetime or byte counters, and no
  automatic rotation. Rotating them by hand loses nothing - inbound by holding two associations
  at once, outbound by [replacing one](#replacing-one) - but the *ordering* of those steps is the
  control plane's obligation, because dpservice cannot see whether the far end is ready and the
  switch is instantaneous. An `Update` issued before the peer has installed its new ingress
  association loses exactly as much traffic as the gap it replaces.
  `ListSecurityAssociations` does not exist; see
  [the gRPC interface](#the-grpc-interface) for what does.
- **Anti-replay is off by default.** `replay_window` is configurable per association, but an
  association created without it accepts replayed frames. A control plane that wants the
  protection must ask for it on every ingress association it creates. See
  [anti-replay is off by default](#anti-replay-is-off-by-default).
- **Extended sequence numbers are off by default.** `esn` is configurable per association. Without
  it the association counts in 32 bits, and the sender must be torn down and rebuilt with fresh
  keys before 2^32 packets - reusing a sequence number reuses the AES-GCM nonce, which forfeits
  authentication for that key. With it the counter is 64 bits, of which the lower half is sent and
  the upper half authenticated. Both ends must agree: unlike the replay window this changes what
  the ICV covers, so a mismatch fails every frame rather than degrading. See
  [extended sequence numbers are opt-in](#extended-sequence-numbers-are-opt-in).
- **The management API is trusted.** It has no TLS and it is assumed to be reachable only from
  the host it runs on. [`GetSecurityAssociation`](#the-grpc-interface) returns the key and salt.
- **A peer sharing our /64 can collide with itself.** Because only the first 64 bits are matched,
  an egress association and its ingress mirror see the same address pair when the peer's underlay
  prefix is our own, and then only the lookup SPI tells them apart - the VNI on one side, the wire
  SPI on the other. Picking a wire SPI numerically equal to the VNI it serves makes the second
  create fail as a duplicate. This used to be unavoidable, since the two were required to be equal;
  now it is merely a number to avoid. Peers are still expected to sit in distinct /64s.
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
- **Virtual services stay in cleartext, and are the one exception to the invariant.** `virtsvc`
  transmits to a PF directly rather than through `ipip_encap`, and inbound it is matched in `cls`
  before the encryption comparison. So in a build with `enable_virtual_services` an encrypting
  interface both sends and accepts virtsvc traffic in the clear. The option is off by default.
- **An upgraded instance stops encrypting.** `encrypt` defaults to false, so an instance that ran
  with `--enable-ipsec` on an earlier release and had its associations provisioned carries its
  traffic in the clear after the upgrade, until the control plane sets the flag on each interface.
  There is no error to say so. This is the cost of defaulting to false and it is not mitigated
  anywhere in the code.
- **Software crypto only.** The `crypto_openssl` PMD is created by dp-service itself when the mode
  is enabled; hardware crypto devices are not used. The PMD requires DPDK to have been built with
  libcrypto, which is why the builder stage installs `libssl-dev`; the runtime library it then
  needs is already in the `debian:13-slim` base both container images start from.


## Design decisions

Each of the choices below had a plausible alternative. They are recorded with the reason it was
not taken, so that a later change which looks like a simplification can be checked against them.

### ESP framing uses transport mode

The outer header is not a property of a Security Association. `ipip_encap` builds it per packet:
its source is the sending VF's own underlay address and its destination the full 128-bit underlay
address of the target VF, which the receiving instance's VNF lookup resolves to a port.
`librte_ipsec`'s tunnel-mode outbound copies a fixed per-association outer header template
(`lib/ipsec/esp_outb.c`), which cannot express that.

Transport mode has no template. `outb_trs_pkt_prepare()` inserts ESP into whatever header the
packet already carries, moves that header forward, writes the old next-protocol value into the ESP
trailer and fixes up the length. Composed with `ipip_encap` and `ipip_decap`, transport-mode ESP
over the tunnel header produces and consumes exactly the wire format tunnel mode would, and the ESP
header, sequence number, explicit IV, padding, trailer, ICV placement and anti-replay window all
come from DPDK.

Two consequences are easy to read backwards:

- `prm.trs.proto` names the protocol of the header **being protected**, not of what that header
  carries. Ours is the outer IPv6 header, so the value is always `IPPROTO_IPV6`. It does not pin
  the tunneled protocol: that is read from the header on the way out and from the ESP trailer on
  the way in, so one association carries both IPv4 and IPv6 packets.
- **Switching `mode` to `RTE_SECURITY_IPSEC_SA_MODE_TUNNEL` would look like a simplification and
  would silently break the tunnel.** The outer header would come from the per-association
  template, and the per-VF destination the peer's VNF lookup depends on would be lost.

Both graph nodes set `mb->l2_len` and `mb->l3_len` to the outer header's sizes, which on egress
overwrites what `ipip_encap` left there for inner checksum offload. That offload is meaningless
under IPsec anyway - a NIC cannot checksum ciphertext - which is why `dp_nat.c` computes those
checksums in software when the mode is on.

### Anti-replay is off by default

RFC 4303 section 3.4.3 makes anti-replay the receiver's default, and 64 is the window it
recommends as a minimum. On the merits 64 would be the right default for `replay_window`; it was
rejected because of what it costs in the API.

A proto3 scalar has no presence. With a default of 64, `replay_window = 0` would carry two intents
that arrive at the server identically - "I omitted the field" and "I want replay checking off".
Separating them would take an `optional uint32` in a protocol file that uses field presence nowhere
else, a presence flag travelling beside the value through `struct dpgrpc_ipsec_sa` and
`struct dp_ipsec_sa`, and a CLI deciding presence from `fs.Changed("replay-window")` rather than
from the value it parsed. With a default of 0, unset and disabled are the same state because they
mean the same thing, and the field is a plain `uint32` everywhere.

Zero disables the check totally rather than narrowing it to one packet: in `librte_ipsec` both
`esn_inb_check_sqn()` and `esp_inb_rsn_update()` return early when `win_sz == 0`. The cap of 4096
exists because the field would otherwise be an unbounded `uint32` reaching an allocator;
`rte_ipsec_sa_size()` itself only objects above two million, where one association's bitmap costs
about a quarter of a megabyte.

The cost is that a control plane that wants anti-replay has to ask for it on every ingress
association, which is why the test suite asks for 64 explicitly in `test/local/dp_service.py`.
Should the default ever be reconsidered, the work is the `optional uint32` migration above, not a
one-line change.

### Extended sequence numbers are opt-in

`esn` defaults to off for the same presence reason as the replay window - a proto3 `bool` cannot
tell `false` from omitted - and for a second, stronger one. Anti-replay is a local decision: a
receiver that checks and a sender that does not still interoperate. ESN is not. It changes what
the ICV covers, so two ends that disagree fail *every* frame, with an authentication error that
names nothing about the cause. Defaulting it on would silently break interoperability with any peer
configured without it, including a Linux XFRM peer configured without `flag esn`. A field whose
wrong value produces a total, undiagnosable outage should be one the operator typed.

Nothing else about an association depends on it: the window and the cipher stay independent, which
`xtratest_ipsec_esn.py` asserts by running one combination of all three.

### The lookup SPI is not the wire SPI

What an association is keyed on and what its ESP header carries are two fields. `ipsec_encap`
cannot read an SPI off a packet that is not ESP yet, so if one value did both jobs, an egress
association would have to be created with its SPI equal to its VNI. That costs two things: every
ESP packet leaving the host would advertise the tenant's VNI in a header field anyone on the
underlay can read without a key, and the wire SPI could never change without moving the entry, so
rekeying could only be a delete followed by a create.

So `spi` is the wire SPI, `vni` records the tenant, and the database key - the lookup SPI - is
derived from the two by `dp_ipsec_get_lookup_spi()`: the VNI for an egress association, the wire
SPI for an ingress one.

The API hides that rule by naming every association by its full identity, as
[described above](#the-identity-of-an-association). Two alternatives were rejected. Shaping the
requests by direction - a wire SPI for ingress, a VNI for egress - is honest, but pushes the
internal keying rule into the API and makes the caller learn it. Keying on the lookup SPI alone and
ignoring the other field is simpler still, but then a caller working from a stale wire SPI silently
deletes the association that is currently in place, which is the one outcome worth spending a
comparison to prevent.

Egress uniqueness is therefore `(VNI, src, dst)`: decoupling frees the wire SPI to change, it does
not create a second outbound slot. And because the wire SPI is unconstrained, an ingress and an
egress association cannot be assumed to share a number; the test suite deliberately gives the two
directions different ones.

### Ingress associations are bound to their VNI

[The inbound VNI check](#the-inbound-vni-check) describes what is enforced. The endpoint lookup it
needs is shared: `ipsec_decap` calls `dp_vnf_resolve_tunnel_dst()` on the outer destination `cls`
has already extracted and marks the packet, so `ipip_decap` does not repeat it, while cleartext
traffic is resolved in `ipip_decap` as before.

Matching the local underlay address in full, 128 bits rather than 64, was the alternative. It
closes the same hole more strongly - the database itself refuses the frame, with no field anyone can
provision wrongly - but it changes what an association is. Cardinality would become one per local
interface instead of one per VNI, so every interface added to a host would need its own ingress
association created and deleted alongside it, and the two directions of a tunnel would stop being
mirror images, since egress stays keyed on the VNI.

Placing the check after the ICV, where RFC 4301 section 5.2 puts the inbound policy check, was
considered: there only a key holder can reach it, so a mismatch would mean one specific thing - a
legitimate peer provisioned with the wrong VNI - and would be worth logging. It was not chosen. The
drop is the point, the check reads nothing the association lookup did not already read
unauthenticated, and refusing before the crypto is spent is strictly cheaper. The price is a policy
decision made on unauthenticated data, which deviates from RFC 4301 and has to stay deliberate.

### Egress associations are rekeyed by replacement

[Replacing one](#replacing-one) describes the operation. The alternative was make-before-break on
egress too: two outbound associations for one VNI and peer, a selector in `ipsec_encap`, and
something to retire the loser. It solves a problem that does not exist. Make-before-break is for
the case where the far end might not be ready; here the far end is the receiver, and the receiver
can already hold both keys. A selector on the sending side would add a second live association, a
state machine to retire it, and a decision with exactly one right answer.

The replacement is filed under the key the old association already occupies, so
`rte_ipsec_sad_add()` overwrites the entry - the very behaviour `Create` guards against with
`SA_EXISTS` is what a replacement wants. It also takes over the old association's slot in
`dp_ipsec_sas[]` rather than asking for a free one, so a host at the association limit can still
rekey every one of them; `Update` never fails on capacity. It is not an upsert: naming an
association that is not there is `SA_NOT_FOUND`.

An ingress `Update` is refused with `SA_DIRECTION`. `SA_NOT_FOUND` would have been cheaper and
untrue - the association is right there. Changing an ingress SPI would *move* the entry rather than
replace it, with its own collision case against whatever sits under the new SPI; and an `Update`
that cannot change the SPI is a key rotation in place, which destroys the old key while frames under
it are still in flight. Replacement is meaningful exactly where the name is stable.

The request names the association as it stands, current wire SPI and all, with `new_spi` beside the
rest. Shaping it the other way - `id` being what the association becomes, resolved by VNI alone -
would make the message identical to `Create`'s, but give up the comparison that stops a caller
working from stale state. A rekey is precisely when two controllers can disagree about which SPI is
current, so it is the last place to stop checking.

The replacement counts from 1. `struct rte_ipsec_sa` is opaque in the installed DPDK headers, so
the old sequence number cannot be read, and shadowing it with a counter of dpservice's own would
drift the moment a packet failed crypto after being prepared. dpservice could refuse key material
the old association used, since this is the only rekey where the previous key is still in the
database when the new one arrives; it does not, because a rule that fires here and nowhere else
would read as a guarantee dpservice is not making.

### Why encryption is per interface

[Encryption is a property of the interface](#encryption-is-a-property-of-the-interface) describes
the invariant. `--enable-ipsec` stays, as a capability gate, rather than being removed: an
unconditional `dp_ipsec_init()` would make the `crypto_openssl` PMD, and the libcrypto it needs at
runtime, a requirement of every deployment, and one without it would fail the vdev hotplug and not
start. The gate also keeps the startup conflict with hardware offloading where it is, instead of
turning it into a per-`CreateInterface` rejection.

The checks sit where they do for reasons that are easy to undo by accident:

- Splitting the ingress comparison across the two decap nodes would mean reintroducing, as a new
  per-packet mark bit, the ESP-or-cleartext distinction `ipsec_decap_restore_flow()` deliberately
  erases.
- Branching on egress inside `ipsec_encap` instead of `ipip_encap` would have kept the graph wiring
  unchanged, but that node opens by marking every packet `crypto_failed` and dropping on a lookup
  miss. A pass-through path would make that fail-closed default conditional.
- Enforcing a uniform flag across a VNI would need a scan per call, would let the first interface
  in a VNI silently decide policy for every later one, and would forbid the one configuration
  per-interface granularity is genuinely good for: a permanent exemption for a workload that must
  stay in the clear.
- Refusing `--enable-ipsec` in a build with virtual services, as the offload check does, was
  considered and not taken.


## Testing

The pytest suite runs `test_vf_to_vf_encap.py` twice: once normally, and once as the `ipsec`
suite with the mode enabled. The test body is identical; only what it observes on the PF differs.
The `ipsec` suite also runs `xtratest_ipsec_grpc.py`, which exercises the four calls without
sending a packet, so that an API failure and a dataplane failure are distinguishable.

`xtratest_ipsec_esn.py` covers the two per-association options that change what the cipher does
rather than which packets it covers - extended sequence numbers and the 256-bit key - in *both*
directions, and one test runs them together. It has to get at the encrypting side by deleting the
session's own pair of associations and creating it again with the parameters under test, because
an egress association is found under its VNI and there is therefore no way to hold a second
outbound association for one peer - deliberately not through `Update`, so that a regression in
the replace path cannot report itself as a cipher failure. `xtratest_ipsec_dataplane.py` covers the same two options on the way in,
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
requires the second one not to arrive. Its test of [the inbound VNI check](#the-inbound-vni-check)
relies on the fixture making every interface encrypting: a frame encrypted under one VNI's
association and aimed at a cleartext interface in another would be dropped by the `cls` comparison
first, and the assertion would still pass without the VNI check being covered.

`xtratest_ipsec_rekey.py` rotates both directions of the session's tunnel, in the order
[the replace path](#replacing-one) prescribes: the peer registers the new egress key, the egress
association is replaced, the new ingress association is added beside the live one, and only then
is the old one deleted. Three bursts of three packets, all nine delivered. The peer holds every
egress association dpservice might be sending under and picks by the SPI it reads off the frame,
rather than being told which key to use - a harness that switched keys on cue would pass without
ever showing that the SPI on the wire changed. The replacement's first frame is required to carry
sequence 1, which is what a new association starting a counter of its own looks like from
outside, and why it has to be given key material the old one never used.

Nothing here is concurrent, and nothing needs to be: gRPC requests are handled by a source node
of the one graph, so no packet is processed while a replacement is swapped in. The bursts either
side of it show that the transition costs nothing, which is a different claim from winning a race
and the only one there is to make.


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

The two directions carry **different SPIs**, here as everywhere else in the suite: each end picks
the number its peer will send under, and a harness reusing one number for both would keep passing
if dp-service ever started to derive one direction's SPI from the other's. What the peer sends
under is, on the other hand, deliberately the very number the scapy peer sends under. Two ingress
associations then sit in the database under one lookup SPI, told apart by the source `/64` alone,
which is what the `(SPI, dst, src)` key exists for and what two neighbours picking the same number
by chance look like. The wire SPI dp-service sends this peer *is* its own, and has to be: the
kernel finds its inbound state by that number, so an SPI taken from anywhere but the association
that encrypted the frame surfaces as `XfrmInNoStates` in the counters read above.


### The full path

![The xfrm peer round trip](xfrm_round_trip.svg)

One burst of five packets, out along the top lane and back along the bottom. The three dashed
boundaries are the interfaces the frames actually cross; the boxed annotations show what is on the
wire at each crossing. Both dpservice and the kernel advance their own sequence numbers per burst,
which is why the peer fixture is module-scoped.
