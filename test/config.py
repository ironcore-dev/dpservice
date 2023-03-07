# TODO comments for documenting
# fc00:: - underlay, 2000:: overlay
# 10.0.0.0 overlay
# 172.2x.0.0 virtual
# (mention 192.168.0.0 is free to be used down in tests)
# talk about how vni is mapped into overlay for clarity
# document pf/vf macs

# Virtual network identifiers (ahred among dp-service instances)
vni1 = 100
vni2 = 200

# Networking layer
pf0_tap = "dtap0"
pf1_tap = "dtap1"
vf_patt = "dtapvf_"
vf0_tap = f"{vf_patt}0"
vf1_tap = f"{vf_patt}1"
vf2_tap = f"{vf_patt}2"
vf3_tap = f"{vf_patt}3"
# TODO patterns!
pf0_pci = "net_tap0"
pf1_pci = "net_tap1"
vf0_pci = "net_tap2"
vf1_pci = "net_tap3"
vf2_pci = "net_tap4"
vf3_pci = "net_tap5"
pf0_mac = "22:22:22:22:22:00"
pf1_mac = "22:22:22:22:22:01"
vf0_mac = "66:66:66:66:66:00"
vf1_mac = "66:66:66:66:66:01"
vf2_mac = "66:66:66:66:66:02"
vf3_mac = "66:66:66:66:66:03"
ipv6_multicast_mac = "33:33:00:00:00:01"

# VMs
# TODO maybe make these into objects VM1, VM2, VM3 with fields like VM1.tap, VM1.mac, VM1.ip, etc.
vm1_name = "vm1"
vm2_name = "vm2"
vm3_name = "vm3"
vm4_name = "vm4"  # TODO other name or at least comment to indicate it's for local tests

# Overlay IPv4 addresses
gateway_ip = "169.254.0.1"
ov_ip_prefix = "10"
vni1_ov_ip_prefix = f"{ov_ip_prefix}.{vni1}"
local_vni1_ov_ip_prefix = f"{vni1_ov_ip_prefix}.1"

# Overlay IPv6 addresses
gateway_ipv6 = "fe80::1"
ov_ipv6_prefix = "2000"
vni1_ov_ipv6_prefix = f"{ov_ipv6_prefix}:{vni1}"
local_vni1_ov_ipv6_prefix = f"{vni1_ov_ipv6_prefix}:1"
vf0_ip = f"{local_vni1_ov_ip_prefix}.1"
vf0_ipv6 = f"{local_vni1_ov_ipv6_prefix}::1"
vf1_ip = f"{local_vni1_ov_ip_prefix}.2"
vf1_ipv6 = f"{local_vni1_ov_ipv6_prefix}::2"
vf2_ip = f"{local_vni1_ov_ip_prefix}.3"
vf2_ipv6 = f"{local_vni1_ov_ipv6_prefix}::3"
vf3_ip = f"{local_vni1_ov_ip_prefix}.4"
vf3_ipv6 = f"{local_vni1_ov_ipv6_prefix}::4"

# Underlay IPv6 addresses
router_ul_ipv6 = "fc00::ffff"
local_ul_ipv6 = "fc00:1::1"
neigh_ul_ipv6 = "fc00:2::1"

neigh_vni1_ul_ipv6 = "fc00:2::64:0:1"  # Hardcoded VNI, this would need to correspond to the other instance's config
neigh_vni1_ov_ip_prefix = f"{vni1_ov_ip_prefix}.2"
neigh_vni1_ov_ip_range = f"{neigh_vni1_ov_ip_prefix}.0"
neigh_vni1_ov_ip_range_len = 24
neigh_vni1_ov_ipv6_prefix = f"{vni1_ov_ipv6_prefix}:2"
neigh_vni1_ov_ipv6_range = f"{neigh_vni1_ov_ipv6_prefix}::"
neigh_vni1_ov_ipv6_range_len = 104

# TODO geneve support may be dropped later
tun_type_geneve="geneve"
geneve_vni1 = 0x640000  # 100 in hex, shifted
# t_vni needs to be set programmatically, when we use geneve
t_vni = 0

# DHCP response config
dhcp_mtu = 1337
dhcp_dns1 = "8.8.4.4"
dhcp_dns2 = "8.8.8.8"

# Some "random" IP on the internet
public_ip = "45.86.6.6"
public_server_ip = public_ip
public_server_port = 443

# Virtual IP functionality
vip_vip = "172.20.0.1"

# NAT functionality
nat_vip = "172.21.1.1"
nat_local_min_port = 100
nat_local_max_port = 102
nat_neigh_min_port = 500
nat_neigh_max_port = 520
# TODO this changed
nat_local_single_min_port = 100
nat_local_single_max_port = 101

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
