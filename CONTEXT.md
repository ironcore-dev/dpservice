# dpservice

dpservice is the DPDK dataplane of an overlay network: it moves tenant traffic between virtual
machines on a host and across hosts, and can protect what crosses between hosts with IPsec. This
glossary fixes the words the codebase uses for that domain.

## Language

### Overlay and underlay

**VNI**:
The 24-bit identifier of one tenant's overlay network. Every interface belongs to exactly one.
_Avoid_: tenant id, network id, segment id

**Underlay address**:
The IPv6 address on the physical network that stands for one overlay endpoint of a host - an
interface, a NAT, a load balancer. Every endpoint on a host has its own, and they all share the
host's prefix.
_Avoid_: tunnel address, outer address

### IPsec

**Security Association**:
A unidirectional agreement to protect traffic between two hosts under one cipher, one key and one
sequence counter (RFC 4301). A protected tunnel is two of them, one per direction.
_Avoid_: tunnel, SA pair, security context

**SA identity**:
The five fields that name one Security Association: VNI, wire SPI, direction, and the source and
destination underlay addresses. What the management API accepts, and what it verifies.
_Avoid_: SA key (collides with the cipher key), selectors

**Lookup SPI**:
The 32-bit value a Security Association is filed and found under: the VNI for an egress
association, the wire SPI for an ingress one.
_Avoid_: selector (this repo uses that for RFC 4301 traffic selectors), SAD key

**Wire SPI**:
The Security Parameter Index carried in the ESP header. Equal to the lookup SPI on ingress,
independent of it on egress.
_Avoid_: an unqualified "SPI" wherever the lookup SPI is also in play
