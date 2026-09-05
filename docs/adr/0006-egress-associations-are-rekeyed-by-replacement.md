# 6. An egress association is rekeyed by replacement

Status: accepted

## Context

[ADR 4](0004-the-lookup-spi-is-not-the-wire-spi.md) freed the wire SPI from the VNI, and said in
its consequences that this was not enough: "the decoupling frees the wire SPI to change, it does
not create a second slot - so gapless rekeying additionally needs a replace path, which is
deliberately left to a later change." This is that change.

Rekeying the sending side was `Delete` followed by `Create`. Between the two requests the VNI has
no egress association, and a VNI with no egress association is dropped rather than sent in the
clear (`docs/concepts/ipsec.md`), so every packet in the gap was lost. How long the gap is
depends on how fast the control plane issues its second request, which is not a property anyone
wants traffic loss to depend on.

The receiving side has no such problem and never did. An ingress association is found under the
SPI its frames carry, so several of them serve one VNI and peer at once: the new key can be
installed while the old one is still accepting frames, and the old one deleted once the peer has
switched. That is make-before-break, and the inbound half of it has worked since ADR 4.

## Decision

`UpdateSecurityAssociation` replaces an egress association in place. The replacement is built
whole - its own crypto session, its own `rte_ipsec_sa` - while the old association is still
encrypting, and only then filed under the key the old one already occupies. The lookup key does
not change, because an egress association is filed under its VNI and the addresses are matched on
their prefix, so `rte_ipsec_sad_add()` overwrites the entry: the behaviour `dp_ipsec_create_sa()`
has to guard against with `SA_EXISTS` is exactly what a replacement wants.

There is no gap because there is no window to have one in. gRPC requests are processed by
`rx_periodic`, a source node of the one graph `dp_graph_init()` allows, so no packet is handled
between the two statements that swap the pointer: packet *N* leaves under the old key and packet
*N+1* under the new one.

The alternative was make-before-break on egress too - two outbound associations for one VNI and
peer, with something to say which one `ipsec_encap` selects and something else to retire the
loser. It was rejected because it solves a problem that does not exist. Make-before-break is for
the case where the far end might not be ready yet; here the far end is the receiver, and the
receiver can already hold both. The correct rekey is therefore: the peer adds its new ingress
association, we replace ours, the peer deletes the old one. A selector on the sending side would
add a second live association, a state machine to retire it, and a decision with exactly one right
answer.

**Egress only.** An ingress `Update` is refused with `SA_DIRECTION`. An ingress association is
found under the SPI its frames carry, so changing that SPI would *move* the entry rather than
replace its contents - a different operation, with its own collision case against whatever sits
under the new SPI. And an `Update` that cannot change the SPI is a key rotation in place, which
for ingress is strictly worse than what already exists: it destroys the old key at the instant of
the swap, dropping every frame still in flight under it. The asymmetry is the same one ADR 4
records - an outbound association is found under a name that does not change, an inbound one under
a name that does - and replacement is meaningful exactly where the name is stable. `SA_NOT_FOUND`
would have been the cheaper answer and is a lie: the association is right there.

**Named by its current identity.** The request carries the full `SecurityAssociationId` as the
association stands, current wire SPI and all, plus a `new_spi` beside the rest of the body. The
same comparison `Get` and `Delete` run applies, so a caller working from a stale wire SPI replaces
nothing rather than replacing whatever took its place. Shaping the request the other way - `id`
being what the association *becomes*, resolved by VNI alone - would have made the message
identical to `Create`'s, at the cost of the one check ADR 4 spent a comparison to keep. A rekey is
precisely the operation during which two controllers can disagree about which SPI is current, so
it is the last place to stop checking.

**All or nothing.** Anything that fails - the session, the `rte_ipsec_sa`, the database write -
leaves the association that is there still filed, still encrypting, with its sequence number
untouched. A failed `Update` is indistinguishable from one that was never sent, which is what
makes it safe to retry. The replacement takes over the old association's slot in
`dp_ipsec_sas[]` rather than asking for a free one, so a host holding the maximum number of
associations can still rekey every one of them; `Update` never fails on capacity. It is not an
upsert either: naming an association that is not there is `SA_NOT_FOUND`, not a silent `Create`.

## Consequences

The replacement counts from 1. `struct rte_ipsec_sa` is opaque in the installed DPDK headers, so
the sequence number of the association being replaced cannot be read, and shadowing it with a
counter of dpservice's own would drift the moment a packet failed crypto after being prepared. An
`Update` therefore needs key material the association has not used before: the AES-GCM nonce is
`salt || sequence number`, and reusing both under one key repeats it. This is not a new hazard -
`Delete` followed by `Create` with the same key has always done the same thing - and dpservice
does not check for it. It could, on this one path, since it is the only rekey where the previous
key is still in the database when the new one arrives; it does not, because a rule that fires here
and nowhere else would read as a guarantee dpservice is not making. Key lifecycle belongs to
whoever manages keys, which for this proof of concept is the control plane.

The ordering is the control plane's obligation. dpservice cannot see whether the peer has
installed its new ingress association, and the switch is instantaneous, so an `Update` issued too
early loses traffic just as surely as the gap it replaces. The sequence - receiver first, sender
second, retire third - is a contract, documented rather than enforced.

An egress association can now outlive every field of its identity except its name. What
`GetSecurityAssociation` reports for a given VNI and peer is whatever the last `Update` installed,
and a caller that has not been told about that `Update` will not find the association it thinks it
has.
