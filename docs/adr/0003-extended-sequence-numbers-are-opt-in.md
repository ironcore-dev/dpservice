# 3. Extended sequence numbers are opt-in, per association

Status: accepted

## Context

An ESP sequence number is 32 bits on the wire. At line rate that space is not comfortable: a
Security Association sending 1.5 Mpps exhausts it in under an hour, and a sender that has run out
must stop, because reusing a sequence number under one key reuses the AES-GCM nonce - the nonce
here is `salt || sequence_number` and nothing else. Reusing a GCM nonce does not merely weaken the
encryption, it forfeits authentication for the key entirely.

RFC 4304 answers this with extended sequence numbers: the association counts to 2^64, transmits
only the lower 32 bits, and authenticates the upper 32 along with the rest of the packet. The
peer reconstructs the upper half from the lower one. `librte_ipsec` implements all of it, and
turning it on is one bit in the transform plus four more bytes of authenticated data.

So the question was not whether to support ESN - clearly yes - but whether an association should
get it by default.

## Decision

ESN is a per-association boolean on `CreateSecurityAssociation`, defaulting to off.

## Consequences

Making it the default was rejected for the same reason ADR 0002 rejected a default anti-replay
window, and for a second reason that is specific to this field.

The first is presence. A proto3 `bool` has no presence: `esn = false` and an omitted `esn` arrive
at the server as the same bytes. If the default were on, a client could not ask for it to be off
without `optional bool`, which this protocol file does not otherwise use.

The second is stronger, and it is why this is not simply a copy of ADR 0002. Anti-replay is a
local decision: a receiver that checks and a sender that does not still interoperate. ESN is
not - it changes what the ICV covers. Two ends that disagree do not degrade, they fail *every*
frame, with an authentication error that names nothing about the cause. Defaulting it on would
therefore silently break interoperability with any peer whose associations were configured
before this field existed, including a Linux XFRM peer configured without `flag esn`. A field
whose wrong value produces a total, undiagnosable outage should be one the operator typed.

The cost is the obvious one: an association created without the field keeps a 32-bit counter, and
a control plane that wants the larger space has to ask for it on both ends. dpservice does not
and cannot check that the two agree - it only ever sees one end.

Nothing else about the association changes. The window and the cipher stay independent of it,
which `xtratest_ipsec_esn.py` asserts by running one combination of all three.
