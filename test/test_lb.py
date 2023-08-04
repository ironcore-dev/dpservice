import pytest

from helpers import *


def test_network_lb_external_icmp_echo(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")

	icmp_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=4) /
				IP(dst=lb_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=PF0.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

	grpc_client.dellb(lb_name)


def router_loopback(dst_ipv6, check_ipv4_src, check_ipv4_dst):
	pkt = sniff_packet(PF0.tap, is_tcp_pkt)
	assert pkt[IP].dst == check_ipv4_dst, \
		f"Invalid LB->VM destination IP {pkt[IP].dst}"
	assert pkt[IP].src == check_ipv4_src, \
		f"Bad request (src ip: {pkt[IP].src})"
	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=dst_ipv6, src=pkt[IPv6].dst, nh=4) /
				 IP(src=pkt[IP].src, dst=pkt[IP].dst) /
				 TCP(dport=pkt[TCP].dport, sport=pkt[TCP].sport))
	delayed_sendp(reply_pkt, PF0.tap)

def communicate_vip_lb(vm, lb_ipv6, src_ipv6, src_ipv4, vf_tap, sport):
	threading.Thread(target=router_loopback, args=(lb_ipv6, src_ipv4, lb_ip)).start()
	# vm(VIP) HTTP request to LB(VM1,VM2) server
	vm_pkt = (Ether(dst=PF0.mac, src=vm.mac, type=0x0800) /
			   IP(dst=lb_ip, src=vm.ip) /
			   TCP(sport=sport, dport=80))
	delayed_sendp(vm_pkt, vm.tap)
	# LB(VM1,VM2) server request from the router
	srv_pkt = sniff_packet(vf_tap, is_tcp_pkt)
	assert srv_pkt[IP].dst == lb_ip, \
		f"Invalid LB->VM destination IP {srv_pkt[IP].dst}"
	assert srv_pkt[TCP].dport == 80, \
		"Invalid server port"

	threading.Thread(target=router_loopback, args=(src_ipv6, lb_ip, src_ipv4)).start()
	# HTTP response back to VIP(vm)
	srv_reply = (Ether(dst=srv_pkt[Ether].src, src=srv_pkt[Ether].dst, type=0x0800) /
				 IP(dst=srv_pkt[IP].src, src=srv_pkt[IP].dst) /
				 TCP(sport=srv_pkt[TCP].dport, dport=srv_pkt[TCP].sport))
	delayed_sendp(srv_reply, vf_tap)
	# HTTP response from the router on vm(VIP)
	vm_reply = sniff_packet(vm.tap, is_tcp_pkt)
	assert vm_reply[IP].dst == vm.ip, \
		f"Invalid VIPped destination IP {vm_reply[IP].dst}"
	assert vm_reply[TCP].sport == 80, \
		f"Invalid server reply port {vm_reply[TCP].sport}"

def test_vip_nat_to_lb_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for LB(vni1) <-> VIP/NAT(vni2) test")

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_ip)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)
	lb_vm2_ul_ipv6 = grpc_client.addlbprefix(VM2.name, lb_ip)
	grpc_client.addlbtarget(lb_name, lb_vm2_ul_ipv6)

	vip_ipv6 = grpc_client.addvip(VM3.name, vip_vip)
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", proto="tcp", dst_port_min=80, dst_port_max=80)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)
	# Also test round-robin
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM2.tap, 1234)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM2.tap, 1234)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1235)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM2.tap, 1236)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1237)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1237)
	grpc_client.delvip(VM3.name)

	# NAT should behave the same, just test once (watch out for round-robin from before)
	nat_ipv6 = grpc_client.addnat(VM3.name, nat_vip, nat_local_min_port, nat_local_max_port)
	communicate_vip_lb(VM3, lb_ul_ipv6, nat_ipv6, nat_vip, VM2.tap, 1240)
	grpc_client.delnat(VM3.name)

	grpc_client.dellbtarget(lb_name, lb_vm2_ul_ipv6)
	grpc_client.dellbprefix(VM2.name, lb_ip)
	grpc_client.dellbtarget(lb_name, lb_vm1_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_ip)
	grpc_client.dellb(lb_name)

	grpc_client.delfwallrule(VM2.name, "fw0-vm2")
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")

	# NOTE: this test, just like in test_pf_to_vf.py
	# cannot be run twice in a row, since the flows need to age-out


def test_nat_to_lb_nat(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT <-> LB+NAT test")

	# Create a VM on VNI1 under a loadbalancer and NAT
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_ip)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)
	nat1_ipv6 = grpc_client.addnat(VM1.name, nat_vip, 100, 101)

	# Create another VM on the same VNI behind the same NAT and communicate
	VM4.ul_ipv6 = grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	request_ip(VM4)
	nat3_ipv6 = grpc_client.addnat(VM4.name, nat_vip, 400, 401)
	communicate_vip_lb(VM4, lb_ul_ipv6, nat3_ipv6, nat_vip, VM1.tap, 2400)
	grpc_client.delnat(VM4.name)
	grpc_client.delinterface(VM4.name)

	grpc_client.delnat(VM1.name)
	grpc_client.dellbtarget(lb_name, lb_vm1_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_ip)
	grpc_client.dellb(lb_name)

def send_bounce_pkt_to_pf(ipv6_lb):
	bouce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				 IPv6(dst=ipv6_lb, src=local_ul_ipv6, nh=4) /
				 IP(dst=lb_ip, src=public_ip) /
				 TCP(sport=8989, dport=80))
	delayed_sendp(bouce_pkt, PF0.tap)

def test_external_lb_relay(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.addlbtarget(lb_name, neigh_ul_ipv6)


	threading.Thread(target=send_bounce_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	pkt = sniff_packet(PF0.tap, is_tcp_pkt, skip=1)

	dst_ip = pkt[IPv6].dst
	assert dst_ip == neigh_ul_ipv6, \
		f"Wrong network-lb relayed packet (outer dst ipv6: {dst_ip})"


	grpc_client.dellbtarget(lb_name, neigh_ul_ipv6)
	grpc_client.dellb(lb_name)
