# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from helpers import *


def test_network_lb_external_icmp_echo(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	external_ping(lb_ip, lb_ul_ipv6)
	external_ping(lb_ip, lb_ul_ipv6)
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


def test_nat_to_lb_nat(request, prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT <-> LB+NAT test")

	# Create a VM on VNI1 under a loadbalancer and NAT
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)
	nat1_ipv6 = grpc_client.addnat(VM1.name, nat_vip, 100, 101)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)

	# Create another VM on the same VNI behind the same NAT and communicate
	nat2_ipv6 = grpc_client.addnat(VM2.name, nat_vip, 400, 401)
	communicate_vip_lb(VM2, lb_ul_ipv6, nat2_ipv6, nat_vip, VM1.tap, 2400)
	grpc_client.delnat(VM2.name)

	grpc_client.delfwallrule(VM1.name, "fw0-vm1")
	grpc_client.delnat(VM1.name)
	grpc_client.dellbtarget(lb_name, lb_vm1_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_pfx)
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


def send_bounce_icmp_pkt_to_pf(ipv6_lb):
	bounce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac) /
				IPv6(dst=ipv6_lb, src=local_ul_ipv6, nh=4) /
				IP(dst=lb_ip, src=public_ip) /
				ICMP(type=3, code=4) /  # Type 3: Destination Unreachable, Code 4: fragmentation needed and DF set
				IP(dst=public_ip, src=lb_ip) /
				TCP(sport=8080, dport=8989))

	delayed_sendp(bounce_pkt, PF0.tap)

def test_external_lb_icmp_error_relay(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/8080")
	grpc_client.addlbtarget(lb_name, neigh_ul_ipv6)

	threading.Thread(target=send_bounce_icmp_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	pkt = sniff_packet(PF0.tap, is_icmp_pkt, skip=1)

	dst_ip = pkt[IPv6].dst
	assert dst_ip == neigh_ul_ipv6, \
		f"Wrong network-lb relayed icmp packet (outer dst ipv6: {dst_ip})"

	grpc_client.dellbtarget(lb_name, neigh_ul_ipv6)
	grpc_client.dellb(lb_name)


def test_network_lb_external_icmpv6_echo(prepare_ipv4, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip6, "tcp/443")
	external_ping6(lb_ip6, lb_ul_ipv6)
	external_ping6(lb_ip6, lb_ul_ipv6)
	grpc_client.dellb(lb_name)


def send_bounce_ipv6_pkt_to_pf(ipv6_lb):
	bounce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				 IPv6(dst=ipv6_lb, src=local_ul_ipv6, nh=0x29) /
				 IPv6(dst=lb_ip6, src=public_ipv6) /
				 TCP(sport=8989, dport=8080))
	delayed_sendp(bounce_pkt, PF0.tap)

def test_external_lb_relay_ipv6(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip6, "tcp/8080")
	grpc_client.addlbtarget(lb_name, neigh_ul_ipv6)

	threading.Thread(target=send_bounce_ipv6_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	pkt = sniff_packet(PF0.tap, is_ipv6_tcp_pkt, skip=1)

	dst_ip = pkt.getlayer(IPv6,1).dst
	assert dst_ip == neigh_ul_ipv6, \
		f"Wrong network-lb relayed packet (outer dst ipv6: {dst_ip})"
	grpc_client.dellb(lb_name)


def test_vip_nat_to_lb_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for LB(vni1) <-> VIP/NAT(vni2) test")

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)

	vip_ipv6 = grpc_client.addvip(VM3.name, vip_vip)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)

	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)

	grpc_client.delvip(VM3.name)

	# NAT should behave the same, just test once (watch out for round-robin from before)
	nat_ipv6 = grpc_client.addnat(VM3.name, nat_vip, nat_local_min_port, nat_local_max_port)
	communicate_vip_lb(VM3, lb_ul_ipv6, nat_ipv6, nat_vip, VM1.tap, 1234)
	grpc_client.delnat(VM3.name)

	grpc_client.dellbtarget(lb_name, lb_vm1_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_pfx)
	grpc_client.dellb(lb_name)

	grpc_client.delfwallrule(VM1.name, "fw0-vm1")
