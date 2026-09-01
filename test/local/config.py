# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

# Address range convention for better trace/dump readablity
# (see docs/testing/pytest_schema.drawio.png for overview)
#
# Underlay addresses:
#   fc00::
# Overlay addresses change based on VNI and dp-service instance (host machine)
#   2000:vni:machine:: for VM IPv6
#   10.vni.machine.0/24 for VM IPv4
# Virtual addresses:
#   172.2x.x.0/24 per category (vip, nat, lb, ...)
# Private addresses for individual tests:
#   192.168.0.0/16 per test requirements
# Network addresses (TAP devices only):
#   22:22:22:22:22:xx for PFs
#   66:66:66:66:66:xx for VFs

# Virtual network identifiers (shared among dp-service instances)
vni1 = 100
vni2 = 200
vni3 = 300

# Networking layer
pf_tap_pattern = "dtap"
vf_tap_pattern = "dtapvf_"
pci_pattern = "net_tap"
pf_mac_pattern = "22:22:22:22:22:"
vf_mac_pattern = "66:66:66:66:66:"
ipv6_multicast_mac = "33:33:00:00:00:01"

# Overlay IPv4 addresses
gateway_ip = "169.254.0.1"
ov_ip_prefix = "10."

# Overlay IPv6 addresses
gateway_ipv6 = "fe80::1"
ov_ipv6_prefix = "2000:"

# Underlay IPv6 addresses
router_ul_ipv6 = "fc00::ffff"
local_ul_ipv6 = "fc00:1::1"
neigh_ul_ipv6 = "fc00:2::1"

# Neighboring dp-service instance info (normally provided by metalnet)
neigh_vni1_ul_ipv6 = "fc00:2::64:0:1"  # Hardcoded VNI, this would need to correspond to the other instance's config

# IPsec (--ipsec suite only). One Security Association per direction, each with its own key and
# salt: the harness plays the peer and does the crypto for the other side, so the two directions
# are as independent here as they would be between two real hosts.
# The SPI is shared, though, and that part is still a property of the test rather than of the
# design - dpservice derives the egress SPI from the VNI, and the ingress one is kept equal to it.
# See docs/concepts/ipsec.md.
ipsec_spi = vni1
ipsec_key_egress = "247b0ea251c93d6fb84017e59a2cd386"
ipsec_salt_egress = "1bf460a7"
ipsec_key_ingress = "9c3d0b7e4a1f8256d0e4b39f7c15a862"
ipsec_salt_ingress = "5d24c9b1"
# Never given to dpservice, so a frame authenticated with it must fail the ICV check
ipsec_key_wrong = "ffeeddccbbaa99887766554433221100"
# Asked for explicitly, because dpservice leaves anti-replay off unless an association requests
# a window. This is what the whole suite's ingress association runs with.
ipsec_replay_window = 64

# A second ingress association, created by xtratest_ipsec_dataplane.py to prove what an
# association without an anti-replay window does. It can only differ from the one above in its
# SPI - the addresses are pinned by dpservice's local-prefix check on one side and by ipip_decap's
# port lookup on the other - so the "spi is the vni it serves" convention cannot hold for both,
# and this one gives it up. Nothing on the ingress path reads the SPI beyond the lookup.
# It does get its own key and salt: the AES-GCM nonce is salt||sequence_number and the SPI is not
# part of it, so two associations sharing key and salt while both counted from 1 would repeat a
# nonce under one key.
ipsec_spi_unwindowed = vni2
ipsec_key_unwindowed = "3a7f21c85d0e94b6af12c7e0538b6d94"
ipsec_salt_unwindowed = "7e3a91d6"
neigh_vni1_ov_ip_prefix = f"{ov_ip_prefix}{vni1}.2"
neigh_vni1_ov_ip_route = f"{neigh_vni1_ov_ip_prefix}.0/24"
neigh_vni1_ov_ipv6_prefix = f"{ov_ipv6_prefix}{vni1}:2"
neigh_vni1_ov_ipv6_route = f"{neigh_vni1_ov_ipv6_prefix}::/104"

# The Linux peer (xtratest_ipsec_xfrm.py), which is a second neighbour and shares nothing with
# the one IpsecPeer plays. Its own underlay /64, because dpservice tells two associations apart
# by (SPI, source /64, destination /64) and the SPI cannot differ - the egress one is derived
# from the VNI. Its own key material, because AES-GCM builds its nonce from salt||sequence and
# two associations counting from 1 under one key would repeat one.
xfrm_ns = "dp_ipsec_peer"
xfrm_iface = f"ipsec{vni1}"
xfrm_if_id = hex(vni1)
xfrm_peer_ul_ipv6 = "fc00:3::64:0:1"
# where the peer sends its answers, i.e. local_ul_ipv6's prefix
xfrm_local_ul_prefix = "fc00:1::/64"
xfrm_peer_ov_ip = f"{ov_ip_prefix}{vni1}.3.1"
xfrm_peer_ov_ip_route = f"{ov_ip_prefix}{vni1}.3.0/24"
# the VMs' own prefix, which is the inner selector of the peer's associations
xfrm_vm_ov_ip_route = f"{ov_ip_prefix}{vni1}.1.0/24"
xfrm_key_egress = "0f9c1d7a35b8e264c07fa9d1e5386b40"
xfrm_salt_egress = "a1c47e39"
xfrm_key_ingress = "6b2e84f0d915c73a8e40b26fd83a1957"
xfrm_salt_ingress = "3f8b02da"

# The veth carrying ESP between the host and the namespace. Both MACs are fixed because the
# relay writes them into every frame it forwards; nothing on the wire depends on their values.
xfrm_veth_host = "dpsxfrm0"
xfrm_veth_peer = "dpsxfrm1"
xfrm_veth_host_mac = "02:00:00:00:00:01"
xfrm_veth_peer_mac = "02:00:00:00:00:02"

# The echo server the peer answers with. A crashed run leaves it running and holding the
# namespace open, which is why XfrmPeer kills whatever it finds there before reusing the name.
xfrm_echo_script = "xfrm_echo.py"
xfrm_echo_port = 12345
xfrm_echo_timeout = 5

# DHCP response config
dhcp_mtu = 1337
dhcp_dns1 = "8.8.4.4"
dhcp_dns2 = "8.8.8.8"
dhcpv6_dns1 = "2001:4860:4860::6464"
dhcpv6_dns2 = "2002:4861:4861::6464"

# Some "random" IP on the internet
public_ip = "45.86.6.6"
public_ip2 = "45.86.6.106"
public_ip3 = "45.86.6.206"
public_ipv6 = "2001:4860:4860::8888"
public_nat64_ipv6 = "64:ff9b::2d56:0606"

# Virtual IP functionality
vip_vip = "172.20.0.1"
vip_vip2 = "172.20.0.2"

# NAT functionality
nat_vip = "172.21.1.1"
nat_local_min_port = 100
nat_local_max_port = 102
nat_neigh_min_port = 500
nat_neigh_max_port = 520

# Loadbalancer functionality
lb_name = "my_lb"
lb_ip = "172.22.2.1"
lb_pfx = "172.22.2.1/32"
lb_ip6 = "2a10:defe:e01f:f4::2"
lb_ip6_pfx = "2a10:defe:e01f:f4::2/128"

#PXE related
pxe_file_name = "ipxe/x86_64/ipxe.new"
ipxe_file_name = "ipxe"
pxe_server = "2001:dede::1"

# Virtual services functionality
virtsvc_udp_svc_ipv6 = "2a00:da8:fff6::1"
virtsvc_udp_svc_port = 53
virtsvc_udp_virtual_ip = "1.2.3.4"
virtsvc_udp_virtual_port = 5353
virtsvc_tcp_svc_ipv6 = "2a00:da8:fff6::2"
virtsvc_tcp_svc_port = 443
virtsvc_tcp_virtual_ip = "5.6.7.8"
virtsvc_tcp_virtual_port = 4443

# Helper functions config
sniff_timeout = 2
sniff_short_timeout = 1
grpc_port = 1337
exporter_port = 9064

# HA config
grpc_port_b = grpc_port+1
pf_tap_pattern_b = "b_dtap"
vf_tap_pattern_b = "b_dtapvf_"
sync_bridge = "dps_sync_br"
sync_tap_a = "dps_sync_a"
sync_tap_b = "dps_sync_b"
active_lockfile = "/tmp/dpservice_pytest.lock"

# Extra testing options
flow_timeout = 1


class PFSpec:
	_idx = 0
	@staticmethod
	def create():
		pf = PFSpec()
		pf.tap = f"{pf_tap_pattern}{PFSpec._idx}"
		pf.pci = f"{pci_pattern}{PFSpec._idx}"
		pf.mac = f"{pf_mac_pattern}{PFSpec._idx:02}"
		pf.tap_b = f"{pf_tap_pattern_b}{PFSpec._idx}"
		PFSpec._idx += 1
		return pf
	def get_count():
		return PFSpec._idx

class VMSpec:
	_idx = 0
	@staticmethod
	def create(vni):
		vm = VMSpec()
		vm.vni = vni
		vm.name = f"vm{VMSpec._idx+1}"
		vm.tap = f"{vf_tap_pattern}{VMSpec._idx}"
		vm.pci = f"{pci_pattern}{VMSpec._idx+PFSpec.get_count()}"
		vm.mac = f"{vf_mac_pattern}{VMSpec._idx:02}"
		vm.tap_b = f"{vf_tap_pattern_b}{VMSpec._idx}"
		vm.ip = f"{ov_ip_prefix}{vni}.1.{VMSpec._idx+1}"
		vm.ipv6 = f"{ov_ipv6_prefix}{vni}:1::{VMSpec._idx+1}"
		vm.ul_ipv6 = None  # will be assigned dynamically
		vm.hostname = None
		VMSpec._idx += 1
		return vm
	def set_hostname(self, hostname):
		self.hostname = hostname

PF0 = PFSpec.create()
PF1 = PFSpec.create()
# VM1 and VM2 are on the same VNI
VM1 = VMSpec.create(vni1)
VM1.set_hostname("vm1-host")
VM2 = VMSpec.create(vni1)
# VM3 is on the second VNI
VM3 = VMSpec.create(vni2)
# VM4 is for local use
# it is not added anywhere, the interface is not up
# add it and delete manually, note that it is configured for VNI1
VM4 = VMSpec.create(vni1)
