# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from helpers import *

def network_lb_external_icmpv4_ping(lb_ul_ipv6):
	icmp_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=4) /
				IP(dst=lb_ip, src=public_ip) /
				ICMP(type=8, id=0x0040))
	answer = srp1(icmp_pkt, iface=PF0.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmp_pkt(answer), \
		"No ECHO reply"

def test_network_lb_external_icmp_echo(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")

	network_lb_external_icmpv4_ping(lb_ul_ipv6)
	network_lb_external_icmpv4_ping(lb_ul_ipv6)

	grpc_client.dellb(lb_name)

def test_nat_to_lb_nat(request, prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for NAT <-> LB+NAT test")
	if request.config.getoption("--hw"):
		pytest.skip("Hardware testing is not supported for NAT <-> LB+NAT test")

	# Create a VM on VNI1 under a loadbalancer and NAT
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)
	nat1_ipv6 = grpc_client.addnat(VM1.name, nat_vip, 100, 101)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)

	# Create another VM on the same VNI behind the same NAT and communicate
	VM4.ul_ipv6 = grpc_client.addinterface(VM4.name, VM4.pci, VM4.vni, VM4.ip, VM4.ipv6)
	request_ip(VM4)
	nat3_ipv6 = grpc_client.addnat(VM4.name, nat_vip, 400, 401)
	communicate_vip_lb(VM4, lb_ul_ipv6, nat3_ipv6, nat_vip, VM1.tap, 2400)
	grpc_client.delnat(VM4.name)
	grpc_client.delinterface(VM4.name)

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

def network_lb_external_icmpv6_ping(lb_ul_ipv6):
	icmp_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=0x29) /
				IPv6(dst=lb_ip6, src=public_ipv6, nh=58) /
				ICMPv6EchoRequest())
	answer = srp1(icmp_pkt, iface=PF0.tap, timeout=sniff_timeout)
	validate_checksums(answer)
	assert answer and is_icmpv6echo_reply_pkt(answer), \
		"No ECHO reply"

def test_network_lb_external_icmpv6_echo(prepare_ipv4, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip6, "tcp/443")

	network_lb_external_icmpv6_ping(lb_ul_ipv6)
	network_lb_external_icmpv6_ping(lb_ul_ipv6)

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
