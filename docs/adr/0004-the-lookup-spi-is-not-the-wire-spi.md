# 4. The lookup SPI is not the wire SPI

Status: accepted

## Context

`struct dp_ipsec_sa` carried a single `spi`, and that one field did two unrelated jobs. It is
written into the transform at `dp_ipsec.c:180`, so it becomes the Security Parameter Index every
ESP header on the wire carries. It is also what `dp_ipsec_build_key()` files the association
under at `dp_ipsec.c:470`, so it is what the Security Association Database is keyed on.

Those two roles only met because of a convention. `ipsec_encap` cannot read an SPI off a packet
that is not ESP yet, so it looks its association up under the VNI the packet came in on
(`ipsec_encap_node.c:37`). For that lookup to find anything, the association had to have been
created with its SPI set equal to that VNI, and the API said so in as many words.

The convention cost two things. Every ESP packet leaving the host advertised the tenant's VNI in
cleartext, in a header field an observer on the underlay reads without any key at all. And one
VNI towards one peer admitted exactly one egress association, because a second one was the same
database key and was refused - so rekeying could only ever be delete-then-create, dropping every
packet in the gap.

Neither cost buys anything. The database's key field is thirty-two bits of key material; nothing
about it requires it to be the value that goes on the wire.

## Decision

The two roles get two fields. `spi` stays what the ESP header carries - the **wire SPI**. A new
`vni` records which tenant's traffic the association protects. What the database is keyed on is
the **lookup SPI**, derived from the two by `dp_ipsec_get_lookup_spi()`: the VNI for an egress
association, the wire SPI for an ingress one. An inbound association is named by what the packet
carries; an outbound one is named by the VNI whose traffic it protects, which leaves its wire SPI
free to change without moving the entry.

The datapath does not change. Both graph nodes already pass the correct value; only the control
plane filed them wrongly.

That raises a question the API has to answer, because the caller would otherwise have to know
which of its fields keys which direction. It does not: an association is named by its full
**SA identity** - VNI, wire SPI, direction, and the two underlay addresses. Create, Get and
Delete all take all five. The server resolves the lookup SPI itself, finds the entry, and then
verifies that the fields it did not key on match what was asked for; a mismatch is
`SA_NOT_FOUND`.

Two alternatives were rejected. Shaping the requests by direction - a wire SPI for ingress, a VNI
for egress - is honest, but it pushes the internal keying rule into the API and makes the caller
learn it. Keying on the lookup SPI alone and ignoring the other field is simpler still, but then
a caller working from a stale wire SPI silently deletes the association that is currently in
place, which is the one outcome worth spending a comparison to prevent.

## Consequences

Egress uniqueness moves from `(wire SPI, src, dst)` to `(VNI, src, dst)`. Two egress associations
for one VNI and one peer still cannot coexist - the decoupling frees the wire SPI to change, it
does not create a second slot - so gapless rekeying additionally needs a replace path, which is
deliberately left to a later change.

After a wire SPI is rotated, a Delete carrying the old one returns `SA_NOT_FOUND` even though the
lookup SPI still resolves. That is the intended reading: the caller is naming an association that
no longer exists.

The wire SPI is now unconstrained, which means an ingress and an egress association can no longer
be assumed to share a number, and test material that leaned on that has to say what it means.
