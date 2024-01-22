# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

from helpers import *

def send_lb_pkt_to_pf(lb_ul_ipv6):
	lb_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
			  IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=4) /
			  IP(dst=lb_ip, src=public_ip) /
			  TCP(sport=1234, dport=80))
	delayed_sendp(lb_pkt, PF0.tap)

def test_pf_to_vf_lb_tcp(prepare_ifaces, grpc_client):
	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lbpfx_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lbpfx_ul_ipv6)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)

	threading.Thread(target=send_lb_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	pkt = sniff_packet(VM1.tap, is_tcp_pkt)
	dst_ip = pkt[IP].dst
	dport = pkt[TCP].dport
	assert dst_ip == lb_ip and dport == 80, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

	grpc_client.dellbtarget(lb_name, lbpfx_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_pfx)
	grpc_client.dellb(lb_name)
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")
	# TODO: Currently, to use this test again with the same port(s)
	# you need to wait for the used flow to be aged-out (done every 30s)
	# If TCP RST is implemented down the line, this can be overcome

def send_lb_ipv6_pkt_to_pf(lb_ul_ipv6):
	lb_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
			  IPv6(dst=lb_ul_ipv6, src=router_ul_ipv6, nh=0x29) /
			  IPv6(dst=lb_ip6, src=public_ipv6) /
			  TCP(sport=1234, dport=8080))
	delayed_sendp(lb_pkt, PF0.tap)

def test_pf_to_vf_lb_ipv6_tcp(prepare_ifaces, grpc_client):

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip6, "tcp/8080")
	lbpfx_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_ip6_pfx)
	grpc_client.addlbtarget(lb_name, lbpfx_ul_ipv6)
	#grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=8080, dst_port_max=8080)

	threading.Thread(target=send_lb_ipv6_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	pkt = sniff_packet(VM1.tap, is_ipv6_tcp_pkt)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == lb_ip6 and dport == 8080, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

	grpc_client.dellbtarget(lb_name, lbpfx_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_ip6_pfx)
	grpc_client.dellb(lb_name)
	#grpc_client.delfwallrule(VM1.name, "fw0-vm1")
