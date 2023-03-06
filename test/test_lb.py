import pytest

from helpers import *


def test_network_lb_external_icmp_echo(prepare_ipv4, grpc_client):

	ipv6_lb = grpc_client.createlb(lb_name, vni, lb_ip, 80, "tcp")

	icmp_pkt = (Ether(dst=mc_mac, src=pf0_mac, type=0x86DD) /
				IPv6(dst=ipv6_lb, src=ul_actual_src, nh=4) /
				IP(dst=lb_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=pf0_tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

	grpc_client.dellb(lb_name)


def router_loopback(dst_ipv6, check_ipv4_src, check_ipv4_dst):
	pkt = sniff_packet(pf0_tap, is_tcp_pkt)
	assert pkt[IP].dst == check_ipv4_dst, \
		f"Invalid LB->VM destination IP {pkt[IP].dst}"
	assert pkt[IP].src == check_ipv4_src, \
		f"Bad request (src ip: {pkt[IP].src})"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(src=pkt[IP].src, dst=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, pf0_tap)

def communicate_vip_lb(lb_ipv6, src_ipv6, src_ipv4, vf_tap, sport):
	threading.Thread(target=router_loopback, args=(lb_ipv6, src_ipv4, lb_ip)).start()
	# VM3(VIP) HTTP request to LB(VM1,VM2) server
	vm_pkt = (Ether(dst=pf0_mac, src=vf2_mac, type=0x0800) /
			   IP(dst=lb_ip, src=vf2_ip) /
			   TCP(sport=sport, dport=80))
	delayed_sendp(vm_pkt, vf2_tap)
	# LB(VM1,VM2) server request from the router
	srv_pkt = sniff_packet(vf_tap, is_tcp_pkt)
	assert srv_pkt[IP].dst == lb_ip, \
		f"Invalid LB->VM destination IP {srv_pkt[IP].dst}"
	assert srv_pkt[TCP].dport == 80, \
		"Invalid server port"

	threading.Thread(target=router_loopback, args=(src_ipv6, lb_ip, src_ipv4)).start()
	# HTTP response back to VIP(VM3)
	srv_reply = (Ether(dst=srv_pkt[Ether].src, src=srv_pkt[Ether].dst, type=0x0800) /
				 IP(dst=srv_pkt[IP].src, src=srv_pkt[IP].dst) /
				 TCP(sport=srv_pkt[TCP].dport, dport=srv_pkt[TCP].sport))
	delayed_sendp(srv_reply, vf_tap)
	# HTTP response from the router on VM3(VIP)
	vm_reply = sniff_packet(vf2_tap, is_tcp_pkt)
	assert vm_reply[IP].dst == vf2_ip, \
		f"Invalid VIPped destination IP {vm_reply[IP].dst}"
	assert vm_reply[TCP].sport == 80, \
		f"Invalid server reply port {vm_reply[TCP].sport}"

def test_vip_nat_to_lb_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for LB(vni1) <-> VIP/NAT(vni2) test")

	# establish a VM in another VNI on the same host
	vm3_ipv6 = grpc_client.addmachine(vm3_name, "net_tap4", vni2, vf2_ip, vf2_ipv6)
	grpc_client.addroute_ipv4(vni2, "0.0.0.0", 0, vni2, ul_actual_dst)
	request_ip(vf2_tap, vf2_mac, vf2_ip)

	lb_ipv6 = grpc_client.createlb(lb_name, vni, lb_ip, 80, "tcp")
	lb_vm1_ipv6 = grpc_client.addlbpfx(vm1_name, lb_ip)
	grpc_client.addlbvip(lb_name, lb_vm1_ipv6)
	lb_vm2_ipv6 = grpc_client.addlbpfx(vm2_name, lb_ip)
	grpc_client.addlbvip(lb_name, lb_vm2_ipv6)

	vip_ipv6 = grpc_client.addvip(vm3_name, virtual_ip)
	# Also test round-robin
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf1_tap, 1234)
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf1_tap, 1234)
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf0_tap, 1235)
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf1_tap, 1236)
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf0_tap, 1237)
	communicate_vip_lb(lb_ipv6, vip_ipv6, virtual_ip, vf0_tap, 1237)
	grpc_client.delvip(vm3_name)

	# NAT should behave the same, just test once (watch out for round-robin from before)
	nat_ipv6 = grpc_client.addnat(vm3_name, nat_vip, nat_local_min_port, nat_local_max_port)
	communicate_vip_lb(lb_ipv6, nat_ipv6, nat_vip, vf1_tap, 1240)
	grpc_client.delnat(vm3_name)

	grpc_client.dellbvip(vm2_name, lb_vm2_ipv6)
	grpc_client.dellbpfx(vm2_name, lb_ip)
	grpc_client.dellbvip(vm1_name, lb_vm1_ipv6)
	grpc_client.dellbpfx(vm1_name, lb_ip)
	grpc_client.dellb(lb_name)

	grpc_client.delroute_ipv4(vni2, "0.0.0.0", 0)
	grpc_client.delmachine(vm3_name)

	# NOTE: this test, just like in test_pf_to_vf.py
	# cannot be run twice in a row, since the flows need to age-out
