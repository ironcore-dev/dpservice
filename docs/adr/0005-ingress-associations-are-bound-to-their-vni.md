# 5. An ingress association is bound to its VNI

Status: accepted

## Context

Associations are matched on the first 64 bits of the underlay addresses only, so that one of them
covers a peer host rather than each of its individual addresses (`DP_IPSEC_ADDR_PREFIX_LEN`). The
peer's side of that is deliberate and unchanged. The local side is not so harmless: every
underlay address dpservice hands out is built with the host's own prefix in its upper half and
varies only below it (`dp_ipaddr.c:77`). Masked to 64 bits, the local side of every ingress
association on a host is therefore the same value.

A peer holding one valid ingress association can exploit that. It addresses an ESP frame to the
underlay address of any endpoint on this host, not just the one the association was provisioned
for. The database matches, because the local side masks to the same prefix either way. The ICV
verifies, because the peer does hold the key. `ipip_decap` then resolves the destination from the
outer address the peer chose, and the traffic is delivered into a tenant the association was
never meant to reach. One association authorised injection into every endpoint on the host.

Nothing refused this, because nothing on the inbound path knew a VNI. `ipsec_decap` keys on the
SPI the frame carries and hands the plaintext on; the VNI is resolved afterwards, by `ipip_decap`,
from an address that arrived unauthenticated.

## Decision

An ingress association records the VNI whose traffic it protects, and the datapath enforces it.

The endpoint lookup that `ipip_decap` performed moves into a helper both nodes call. `ipsec_decap`
calls it on `df->tun_info.ul_dst_addr6`, which `cls` has already filled in before dispatching to
it (`cls_node.c:206`), and drops any frame whose resolved VNI differs from that of the association
that matched. A flag in `struct dp_pkt_mark` records that the lookup ran, so `ipip_decap` does not
repeat it; anything reaching `ipip_decap` without the flag - all unencrypted traffic - resolves as
it always did.

Matching the local underlay address in full, 128 bits rather than 64, was the alternative. It
closes the same hole more strongly: the database itself refuses the frame, with no field anyone
can provision wrongly. It was rejected because it changes what an association is. Cardinality
becomes one per local interface instead of one per VNI, so every interface added to a host would
need its own ingress association created and deleted alongside it, and the two directions of one
tunnel would stop being mirror images - egress remains keyed on the VNI (see ADR 4).

The drop is silent, and happens before the frame is decrypted.

Silence is the same judgement the database miss immediately above it already makes
(`ipsec_decap_node.c:138`). Reaching this check needs only a database hit, which an attacker gets
by spoofing the peer's prefix and naming an SPI this host holds - no key required. A log line
there would be forgeable at line rate, and would say nothing a counter does not.

Placing the check after the integrity check, where RFC 4301 section 5.2 puts the inbound policy
check, was considered for exactly that reason: past the ICV, only a peer that holds the key can
reach it, so a mismatch would mean one specific thing - a legitimate peer provisioned with the
wrong VNI - and would be worth logging. It was not chosen. The drop is the point, the check reads
nothing the association selection did not already read unauthenticated, and refusing before the
crypto is spent is strictly cheaper.

## Consequences

The check is a policy decision made on unauthenticated data, which is a deviation from RFC 4301
and needs to stay a deliberate one. It is safe only because its outcome is always a drop: a
forged frame cannot cause a legitimate one to be discarded.

An ESP frame whose endpoint lookup finds nothing is now dropped by `ipsec_decap` rather than
`ipip_decap`. Same frame, same outcome, a different node's counter.

This is not a security policy database. There is still one rule, applied to everything, with no
way to express bypass and no inspection of the inner packet.
