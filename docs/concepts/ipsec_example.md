# IPsec by hand: an AES-256-GCM walkthrough

A copy-paste run through the IPsec API on a laptop, with no SmartNIC: start dpservice on TAP
devices, make an interface encrypt, install a tunnel's two associations, read one back, and
rotate both directions. Every association here uses **AES-256-GCM with extended sequence
numbers**.

For what the associations *mean* - why they are unidirectional, why an egress one is replaced
rather than edited - see [ipsec.md](ipsec.md). This file is only the commands.

## 1. Start dpservice on TAP devices

Six `net_tap` vdevs stand in for two PFs and four VFs, so no hardware is needed:

```bash
sudo build/src/dpservice-bin -l 0,1 --log-level=user*:8 --huge-unlink --no-pci \
  --vdev=net_tap0,iface=dtap0,mac="22:22:22:22:22:00" \
  --vdev=net_tap1,iface=dtap1,mac="22:22:22:22:22:01" \
  --vdev=net_tap2,iface=dtapvf_0,mac="66:66:66:66:66:00" \
  --vdev=net_tap3,iface=dtapvf_1,mac="66:66:66:66:66:01" \
  --vdev=net_tap4,iface=dtapvf_2,mac="66:66:66:66:66:02" \
  --vdev=net_tap5,iface=dtapvf_3,mac="66:66:66:66:66:03" \
  -- --pf0=dtap0 --pf1=dtap1 --vf-pattern=dtapvf_ --nic-type=tap \
  --ipv6=fc00:1::1 --enable-ipv6-overlay --grpc-port=1337 \
  --no-stats --color=auto --no-offload --enable-ipsec
```

The parts that matter:

| Argument | Why |
| --- | --- |
| `--no-pci` + the `--vdev` list | creates the TAP devices instead of binding a NIC |
| `--nic-type=tap` | tells the service it is not on hardware |
| `--ipv6=fc00:1::1` | **our own** underlay address; the local side of every association is checked against this `/64`, otherwise `SA_BAD_ADDR` (465) |
| `--enable-ipsec` | brings up the crypto subsystem; without it every SA call, and every attempt to make an interface encrypt, returns `IPSEC_DISABLED` (466) |

It is up once the log says:

```
I SERVICE: IPsec enabled, name: crypto_openssl0
I GRPC: Server started and listening, grpc_server_address: [::]:1337
```

Running it a second time fails with `Cannot create lock on '/var/run/dpdk/rte/config'` - one
primary process per machine, unless you give the second one its own `--file-prefix`, `--grpc-port`
and `iface=` names.

## 2. Build the CLI

```bash
cd cli/dpservice-cli && go build -o dpservice-cli .
```

Add `--address=localhost:1337` to every call (or export `DP_GRPC_PORT`), and run
`dpservice-cli init` once before the rest.

## 3. Make the interface encrypt

`--enable-ipsec` is only the capability. Nothing is protected until an interface says so, and the
flag is off by default - either at creation:

```bash
dpservice-cli create interface --id=vm1 --vni=100 --device=net_tap2 \
  --ipv4=10.100.1.1 --ipv6=2000:100:1::1 --encrypt
```

`--device` is the **DPDK device name**, not the TAP interface name. Each `--vdev` above names
both - `--vdev=net_tap2,iface=dtapvf_0` - and this is the first of the two. Passing `dtapvf_0`
gets `NOT_FOUND` (201), because `rte_eth_dev_get_port_by_name()` has never heard of it. With two
PFs taking `net_tap0` and `net_tap1`, the four VFs are `net_tap2` through `net_tap5`.

Encryption can also be turned on afterwards, on an interface that already exists:

```bash
dpservice-cli encryption enable --interface-id=vm1
dpservice-cli encryption get    --interface-id=vm1
```

```
 InterfaceID  Encrypt
 vm1          true
```

`enable` on an interface that already encrypts is `ALREADY_ACTIVE` (210), and `disable` on one
that does not is `NOT_ACTIVE` (211).

From here on `vm1` neither sends nor accepts underlay traffic in the clear. Until step 4 gives it
an egress association, that means everything it sends towards the peer is **dropped** rather than
sent unprotected - which is the intended order, not a race to lose.

## 4. Install the tunnel's two associations

An SA is unidirectional and named by five fields: `vni`, `spi`, `direction`, `src-underlay`,
`dst-underlay`. The underlays are matched on their first 64 bits only, so `fc00:2::` covers the
whole peer host, and they are the addresses **as seen on the wire in that direction** - so they
swap between the two commands.

```bash
# egress - we encrypt, so src is our own underlay
dpservice-cli create securityassociation --vni=100 --spi=43794 --direction=egress \
  --src-underlay=fc00:1:: --dst-underlay=fc00:2:: --algorithm=aes-256-gcm --esn \
  --key=1f6b93d0e58c27a4b0d31e6f95c8a274de03b8615fa29c74e0d61b385caf9027 --salt=d1e60b47

# ingress - addresses reversed; the replay window is ingress-only
dpservice-cli create securityassociation --vni=100 --spi=43795 --direction=ingress \
  --src-underlay=fc00:2:: --dst-underlay=fc00:1:: --algorithm=aes-256-gcm --esn \
  --key=9a2f75c8e01d436bf82ea59c07d13648b5e092af7c31d0685ea4f92c30b871de --salt=68af203c \
  --replay-window=64
```

```
securityassociation/egress/100/43794/fc00:1::-fc00:2:: created, vni: 100, spi: 43794
securityassociation/ingress/100/43795/fc00:2::-fc00:1:: created, vni: 100, spi: 43795
```

`--algorithm=aes-256-gcm` takes a **64**-hex-digit key (the 128-bit default takes 32). The salt is
8 hex digits either way - it is the implicit part of the nonce, not key material. `--esn` and the
cipher have to match on both ends of the tunnel or every frame fails its ICV.

## 5. Read one back

The same five flags name it, nothing else:

```bash
dpservice-cli get securityassociation --vni=100 --spi=43794 --direction=egress \
  --src-underlay=fc00:1:: --dst-underlay=fc00:2::
```

```
 VNI    SPI  Direction  Algorithm    SrcUnderlay  DstUnderlay  ReplayWindow  ESN
 100  43794  egress     aes_256_gcm  fc00:1::     fc00:2::                0  true
```

`-o yaml` (or `-o json`) gives the full record, key and salt included.

## 6. Rotate the egress association

`update` is the gapless replace path, and it is **egress only**. The first five flags name the
association *as it stands now*; `--new-spi` plus a full set of the create's flags say what it
becomes:

```bash
dpservice-cli update securityassociation --vni=100 --spi=43794 --direction=egress \
  --src-underlay=fc00:1:: --dst-underlay=fc00:2:: --new-spi=43796 \
  --algorithm=aes-256-gcm --esn \
  --key=7d2e04b9c1a63f85e0d47b2c98af516309ec4d7b825af0136ed94c25b7a03e18 --salt=7f21c0d3
```

```
securityassociation/egress/100/43796/fc00:1::-fc00:2:: updated, vni: 100, spi: 43796
```

Afterwards `get` on 43796 returns the new key; 43794 returns `SA_NOT_FOUND` (462). The SPI and the
key changed together, between two packets, with no second association left behind.

The replacement starts a sequence number of its own, so it needs key material this association has
never used - reusing it repeats an AES-GCM nonce.

## 7. Rotate the ingress association

An ingress association cannot be updated - it is filed under the SPI its frames carry, and
renumbering it in place would drop whatever is still in flight. `update` on one is refused with
`SA_DIRECTION` (468). Overlap two instead; several ingress associations can serve one VNI and peer
at once:

```bash
# 1. add the new one - the old one keeps working
dpservice-cli create securityassociation --vni=100 --spi=43797 --direction=ingress \
  --src-underlay=fc00:2:: --dst-underlay=fc00:1:: --algorithm=aes-256-gcm --esn \
  --key=b3f81c46e29d0a75c14e83b0d67f2a95104ce7b38fa06d21e59c3b840af71d62 --salt=68af203c \
  --replay-window=64

# 2. once the peer has switched over, drop the old one
dpservice-cli delete securityassociation --vni=100 --spi=43795 --direction=ingress \
  --src-underlay=fc00:2:: --dst-underlay=fc00:1::
```

Rekeying a whole tunnel is therefore three ordered steps, and the order is the caller's to get
right - dpservice cannot see whether the far end is ready:

1. the peer installs its new **ingress** association, beside the one it has;
2. this side **replaces** its egress association (step 6);
3. the peer deletes its old ingress association.

## 8. Delete

Same five naming flags:

```bash
dpservice-cli delete securityassociation --vni=100 --spi=43796 --direction=egress \
  --src-underlay=fc00:1:: --dst-underlay=fc00:2::
```

## Traps worth knowing

**Nothing is carried over by an `update`.** An omitted flag means its *default*, not the value the
association holds right now. Two consequences, and only one of them is loud:

- Omitting `--algorithm` on a 256-bit association falls back to `aes-128-gcm` and the 64-digit key
  is then the wrong length, so the call fails - `code = InvalidArgument desc = Invalid key`. Loud.
- Omitting `--esn` silently turns extended sequence numbers **off**. The update succeeds, `get`
  reports `ESN false`, and the tunnel then fails frame by frame against a peer still using ESN.

So repeat `--algorithm=aes-256-gcm --esn` on every rotation.

**A flag on one side is not a tunnel.** Encryption is symmetric, so turning it on at one endpoint
severs it from every peer that has not turned it on - in both directions, immediately. There is no
half-migrated state in which the VNI still works. Turn it on at both ends, or at neither.

**Other rejections.** `--replay-window` is ingress-only; anything non-zero on egress is
`SA_REPLAY_WINDOW` (467), as is a window above 4096. A second egress association for the same VNI
and peer collides with the first however different the rest of its identity is - `SA_EXISTS` (461);
a new wire SPI does not create a second outbound slot. The full table is in
[ipsec.md](ipsec.md#what-it-rejects).
