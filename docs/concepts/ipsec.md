# IPsec

dp-service can encrypt the traffic it sends over the underlay, so that the tunnel between two
instances is not readable by anyone with access to the fabric in-between. This is enabled by
starting dp-service with `--enable-ipsec` and is off by default.

This is a **proof of concept**. It proves the dataplane can carry ESP; it is not yet a usable
IPsec deployment. The limits below are deliberate, not oversights.


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


## Security Association

One hardcoded SA, shared by both directions:

- AES-128-GCM (RFC 4106), a compiled-in key and salt, and a compiled-in SPI.
- The sequence number starts at 1 and doubles as the 8-byte explicit nonce. This makes the one
  thing AES-GCM cannot survive - the same nonce twice under one key - impossible by construction
  rather than merely unlikely.
- The salt is never on the wire; both ends must already have it.

Encryption and decryption are separate AEAD transforms, so the single SA is realised as two
crypto sessions.


## Deliberate limits

- **No security policy database.** The mode is all-or-nothing for the whole instance. Everything
  leaving through the tunnel is encrypted, and unencrypted tunnel traffic arriving on a PF is
  dropped rather than accepted. That strictness is a stand-in for the "no matching inbound policy"
  a real SPD would provide, and it prevents a receiver that silently accepts a downgrade.
- **No SA management.** No gRPC surface, no negotiation or distribution, no rekeying, no lifetime
  limits. Two instances can only talk to each other if they were built from the same source.
- **No anti-replay window.** With one SA shared by both directions and a peer that echoes our own
  sequence numbers, a replay check would reject legitimate traffic. It becomes meaningful only
  once each direction has its own SA.
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

The pytest suite runs `test_vf_to_vf_encap.py` twice: once normally, and once as the `ipsec` suite
with the mode enabled. The test body is identical; only what it observes on the PF differs.

The harness deliberately does **not** hold the key. It reflects the captured ESP frame back after
rewriting only the outer Ethernet and IPv6 headers, which works because the ICV does not cover
them and because `ipip_decap` picks its target port from the outer destination alone. Instead of
reading the payload on the PF it asserts the payload is *not* readable there, which fails loudly
if the cipher ever degrades to doing nothing.

The consequence is that the suite does not independently verify the framing is RFC-correct - a
self-consistent but non-standard layout would pass, since dp-service is both the encryptor and
the decryptor. That was checked once by hand with scapy's `SecurityAssociation` during
development, and should be rechecked by hand if the framing changes.
