# 7. Encryption is a property of the interface

Status: accepted

## Context

`--enable-ipsec` did two unrelated jobs. It brought up the crypto device, the session and
operation pools and the Security Association Database, and it decided policy: every packet
leaving towards a PF was handed to `ipsec_encap`, and `cls` refused every unencrypted tunnel
frame outright (`cls_node.c:202`). Policy was therefore an attribute of the whole instance,
settled before any interface existed, and unchangeable without a restart.

That was defensible only while it was total. `docs/concepts/ipsec.md` argued dpservice needs no
security policy database because it already is one, degenerately: in RFC 4301 terms a single
PROTECT rule covering all inter-host overlay traffic, a default of DISCARD, and no BYPASS entry
at all. There is nothing to select between, so there is nothing to look up.

A per-interface flag ends that. The endpoint becomes a selector, BYPASS becomes expressible, and
BYPASS is the entry that can leak. The whole of this decision is about making that safe rather
than merely convenient.

## Decision

An interface carries an `encrypt` flag, default false, settable when it is created and toggled at
runtime. `--enable-ipsec` stays, demoted to a capability gate: it means the crypto subsystem is up
and associations may be provisioned, and nothing more. Requesting encryption without it is
refused; `DP_GRPC_ERR_SA_DISABLED` is renamed `IPSEC_DISABLED`, keeping wire code 466, because the
condition it reports was never specific to associations.

Removing the option entirely, as the feature request asked, was rejected. The production image does
not carry the runtime SSL library, so an unconditional `dp_ipsec_init()` fails its vdev hotplug and
dpservice does not start - a deployment-wide regression bought for a cosmetic simplification. The
gate also keeps the existing startup conflict with hardware offloading (`dp_service.c:275`) where
it is, instead of turning it into a per-`CreateInterface` rejection.

**One invariant governs both directions: cleartext leaves an interface if and only if it is not
encrypting, and cleartext is accepted for an interface if and only if it is not encrypting.**

Egress keeps dropping when the flag is set and no association matches. Falling back to cleartext
was considered and rejected: an interface is created before its association is provisioned, so the
fallback would leak precisely during the window the flag exists to close, silently, and would make
the ordering of two independent control-plane calls security-relevant. The cost is that a flag set
without an association is a silent black hole; that is a diagnosability problem, answered by the
drop counter the nodes already want, not by opening the cleartext path.

Ingress enforces the mirror. Refusing ESP at a non-encrypting interface - what the feature request
asked for - is the lesser half: a peer holding no association is refused by the database anyway.
The half that carries the weight is refusing cleartext at an encrypting one. Without it, injecting
into a protected tenant needs no key, no ICV and no guessed SPI, only an ordinary IPinIP frame
addressed at the endpoint, and the key material would protect confidentiality alone.

Both halves are one comparison in `cls`, on the port `dp_vnf_resolve_tunnel_dst()` resolves from
the outer destination address:

```c
if (unlikely(dst_port->iface.encrypt != (ipv6_hdr->proto == IPPROTO_ESP)))
    return CLS_NEXT_DROP;
```

`cls` is the only node that can make this call, because the destination endpoint is not known
before it and the frame's ESP-ness is not knowable after it: `ipsec_decap` feeds `ipip_decap`, and
`ipsec_decap_restore_flow()` deliberately erases the difference so that a decrypted frame is
indistinguishable from one that arrived in the clear. Splitting the two checks across the decap
nodes would mean re-introducing that difference as a new per-packet mark bit, to undo an erasure
three lines earlier.

Egress branches in `ipip_encap`, which gains a second per-port edge table and chooses between Tx
and `ipsec_encap` on the in-port's flag. Branching inside `ipsec_encap` instead would have kept the
graph wiring unchanged, but that node opens by marking every packet `crypto_failed` and dropping on
a lookup miss; a pass-through path makes that fail-closed default conditional, putting an exception
through the one line that carries the egress half of the invariant. `ipsec_encap` keeps its
contract unqualified: everything it receives leaves encrypted or not at all.

Encryption is not validated for consistency across a VNI. Associations are per VNI and interfaces
are not, so a VNI may hold both kinds. Enforcing uniformity would need a scan per call, would let
the first interface in a VNI silently decide policy for every later one, and would forbid the one
configuration per-interface granularity is genuinely good for: a permanent exemption for a
workload that must stay in the clear.

## Consequences

- **dpservice now has a security policy database.** One selector, the destination or source
  endpoint; three outcomes, PROTECT, BYPASS and DISCARD. What makes BYPASS safe is that the two
  rules *partition* traffic rather than overlapping: a bypassing endpoint cannot receive protected
  traffic and a protecting endpoint cannot receive bypassed traffic. The section of
  `docs/concepts/ipsec.md` claiming there is no policy database is superseded by this one.
- **Both ingress checks are policy decisions made on unauthenticated data**, joining the VNI check
  of ADR 5 and safe for the same reason: the outcome is always a drop, so a forged frame cannot
  cause a legitimate one to be discarded.
- **Enabling encryption on one interface severs it from every peer that has not enabled it, in
  both directions and immediately.** There is no half-migrated state in which a VNI still works.
  Encryption is therefore a property of a tunnel endpoint *pair*, and rolling it out is a
  coordinated change, not an incremental one.
- **An instance upgraded from a previous release stops encrypting.** The flag defaults to false, so
  a deployment that ran with `--enable-ipsec` and provisioned associations carries its traffic in
  the clear until the control plane sets the flag, with no error to say so. This is the real cost
  of defaulting to false and it is not mitigated in code; it is recorded here and in
  `docs/concepts/ipsec.md`.
- **Virtual services are an exception to the invariant.** `virtsvc` is wired straight to PF Tx and
  is matched in `cls` before the ipsec branch, so in an `ENABLE_VIRTSVC` build an encrypting
  interface both sends and accepts virtsvc traffic in the clear. The option is off by default.
  Refusing `--enable-ipsec` in such a build, as the offload check does, was considered and not
  taken.
- **The ADR 5 test depends on the test fixture enabling encryption everywhere.** It asserts that a
  frame encrypted under one VNI's association and aimed at an interface in another is dropped. If
  that target interface were left non-encrypting, the `cls` comparison above would drop the frame
  first, the assertion would still pass, and the inbound VNI check would no longer be covered by
  anything.
