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
neigh_vni1_ov_ip_prefix = f"{ov_ip_prefix}{vni1}.2"
neigh_vni1_ov_ip_range = f"{neigh_vni1_ov_ip_prefix}.0"
neigh_vni1_ov_ip_range_len = 24
neigh_vni1_ov_ipv6_prefix = f"{ov_ipv6_prefix}{vni1}:2"
neigh_vni1_ov_ipv6_range = f"{neigh_vni1_ov_ipv6_prefix}::"
neigh_vni1_ov_ipv6_range_len = 104

# DHCP response config
dhcp_mtu = 1337
dhcp_dns1 = "8.8.4.4"
dhcp_dns2 = "8.8.8.8"

# Some "random" IP on the internet
public_ip = "45.86.6.6"

# Virtual IP functionality
vip_vip = "172.20.0.1"

# NAT functionality
nat_vip = "172.21.1.1"
nat_local_min_port = 100
nat_local_max_port = 102
nat_neigh_min_port = 500
nat_neigh_max_port = 520

# Loadbalancer functionality
lb_name = "my_lb"
lb_ip = "172.22.2.1"
pfx_ip = "172.23.3.0"

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
		vm.ip = f"{ov_ip_prefix}{vni}.1.{VMSpec._idx+1}"
		vm.ipv6 = f"{ov_ipv6_prefix}{vni}:1::{VMSpec._idx+1}"
		vm.ul_ipv6 = None  # will be assigned dynamically
		VMSpec._idx += 1
		return vm

PF0 = PFSpec.create()
PF1 = PFSpec.create()
# VM1 and VM2 are on the same VNI
VM1 = VMSpec.create(vni1)
VM2 = VMSpec.create(vni1)
# VM3 is on the second VNI
VM3 = VMSpec.create(vni2)
# VM4 is for local use
# it is not added anywhere, the interface is not up
# add it and delete manually, note that it is configured for VNI1
VM4 = VMSpec.create(vni1)
