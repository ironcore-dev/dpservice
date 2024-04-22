# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest

from config import *
from helpers import *
from lb_tester import *
from tcp_tester import TCPTesterPublic
from tcp_tester import TCPTesterVirtsvc


def tcp_server_nat_pkt_check(pkt):
	assert pkt[IPv6].dst == router_ul_ipv6, \
		"Request to the wrong outgoing IPv6 address"
	assert pkt[IP].src == nat_vip, \
		f"Packet not coming from NAT's IP"
	assert pkt[IP].dst == public_ip, \
		"Request to a wrong public server IP"
	assert pkt[TCP].dport == 443, \
		"Request to a wrong TCP port"
	assert pkt[TCP].sport == nat_local_min_port, \
		"Failed to use NAT's only single port"

def test_cntrack_nat_timeout_tcp(request, prepare_ipv4, grpc_client, fast_flow_timeout):
	if not fast_flow_timeout:
		pytest.skip("Fast flow timeout needs to be enabled")

	# Only allow one port for this test, so the next call would normally fail (NAT runs out of free ports)
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_min_port+1)

	tester = TCPTesterPublic(VM1, 12344, nat_ul_ipv6, PF0, public_ip, 443, server_pkt_check=tcp_server_nat_pkt_check)
	tester.communicate()

	age_out_flows()

	# (the only) NAT port should once again be free now
	tester.client_port = 54321
	tester.request_rst()

	# Same test, but after RST, not FIN-FINACK
	age_out_flows()
	tester.client_port = 54320
	tester.request_rst()

	grpc_client.delnat(VM1.name)

def tcp_server_virtsvc_pkt_check(pkt):
	assert pkt[IPv6].dst == virtsvc_tcp_svc_ipv6, \
		"Request to wrong service IPv6 address"
	assert pkt[TCP].dport == virtsvc_tcp_svc_port, \
		"Request to wrong service TCP port"

def tcp_server_virtsvc_pkt_check_first_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1025, \
		"Request from wrong NAT port"

def tcp_server_virtsvc_pkt_check_second_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1026, \
		"Request from wrong NAT port"

def tcp_server_virtsvc_pkt_check_third_port(pkt):
	tcp_server_virtsvc_pkt_check(pkt)
	assert pkt[TCP].sport == 1027, \
		"Request from wrong NAT port"

def test_virtsvc_tcp_timeout(request, prepare_ipv4, fast_flow_timeout):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	if not fast_flow_timeout:
		pytest.skip("Fast flow timeout needs to be enabled")

	tester = TCPTesterVirtsvc(VM1, 12345, PF0, virtsvc_tcp_virtual_ip, virtsvc_tcp_virtual_port,
							  server_pkt_check=tcp_server_virtsvc_pkt_check_first_port)
	tester.communicate()

	# Following connection should be given another port
	tester.client_port = 12346
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_second_port
	tester.leave_open()

	# After aging, this connection should reuse the first port
	age_out_flows()
	tester.client_port = 12348
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_first_port
	tester.request_rst()

	# Second port has been left open, thus aging should not work
	tester.client_port = 12349
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_third_port
	tester.request_rst()

	# Test aging of previous reset
	age_out_flows()
	tester.client_port = 12350
	tester.server_pkt_check = tcp_server_virtsvc_pkt_check_first_port
	tester.request_rst()


def send_bounce_pkt_to_pf(ipv6_lb):
	bouce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				 IPv6(dst=ipv6_lb, src=local_ul_ipv6, nh=4) /
				 IP(dst=lb_ip, src=public_ip) /
				 TCP(sport=8989, dport=80))
	delayed_sendp(bouce_pkt, PF0.tap)

def sniff_lb_pkt(dst_ipv6):
	pkt = sniff_packet(PF0.tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	assert dst_ip == dst_ipv6, \
		f"Wrong network-lb relayed packet (outer dst ipv6: {dst_ip})"

def test_external_lb_relay_timeout(prepare_ipv4, grpc_client, fast_flow_timeout):
	if not fast_flow_timeout:
		pytest.skip("Fast flow timeout needs to be enabled")

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	grpc_client.addlbtarget(lb_name, neigh_ul_ipv6)

	threading.Thread(target=send_bounce_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	sniff_lb_pkt(neigh_ul_ipv6)

	age_out_flows()
	threading.Thread(target=send_bounce_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	sniff_lb_pkt(neigh_ul_ipv6)

	age_out_flows()
	threading.Thread(target=send_bounce_pkt_to_pf, args=(lb_ul_ipv6,)).start()
	sniff_lb_pkt(neigh_ul_ipv6)


	grpc_client.dellbtarget(lb_name, neigh_ul_ipv6)
	grpc_client.dellb(lb_name)

def test_vip_nat_to_lb_on_another_vni(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for LB(vni1) <-> VIP/NAT(vni2) test")

	lb_ul_ipv6 = grpc_client.createlb(lb_name, vni1, lb_ip, "tcp/80")
	lb_vm1_ul_ipv6 = grpc_client.addlbprefix(VM1.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lb_vm1_ul_ipv6)
	lb_vm2_ul_ipv6 = grpc_client.addlbprefix(VM2.name, lb_pfx)
	grpc_client.addlbtarget(lb_name, lb_vm2_ul_ipv6)

	vip_ipv6 = grpc_client.addvip(VM3.name, vip_vip)
	grpc_client.addfwallrule(VM2.name, "fw0-vm2", proto="tcp", dst_port_min=80, dst_port_max=80)
	grpc_client.addfwallrule(VM1.name, "fw0-vm1", proto="tcp", dst_port_min=80, dst_port_max=80)

	# Also test basic maglev behaviour
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)
	age_out_flows()
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM2.tap, 1242)

	# Add/Remove dummy lb targets and the test the traffic againg
	grpc_client.addlbtarget(lb_name, "cafe:dede::1")
	grpc_client.addlbtarget(lb_name, "cafe:dede::ab")
	grpc_client.addlbtarget(lb_name, "cafe:dede::de")
	grpc_client.addlbtarget(lb_name, "cafe:dede::ff")

	grpc_client.dellbtarget(lb_name, "cafe:dede::1")
	grpc_client.dellbtarget(lb_name, "cafe:dede::ab")
	grpc_client.dellbtarget(lb_name, "cafe:dede::de")
	grpc_client.dellbtarget(lb_name, "cafe:dede::ff")

	age_out_flows()
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM1.tap, 1252)
	communicate_vip_lb(VM3, lb_ul_ipv6, vip_ipv6, vip_vip, VM2.tap, 1242)

	grpc_client.delvip(VM3.name)

	# NAT should behave the same, just test once (watch out for round-robin from before)
	nat_ipv6 = grpc_client.addnat(VM3.name, nat_vip, nat_local_min_port, nat_local_max_port)
	communicate_vip_lb(VM3, lb_ul_ipv6, nat_ipv6, nat_vip, VM2.tap, 1234)
	grpc_client.delnat(VM3.name)

	grpc_client.dellbtarget(lb_name, lb_vm2_ul_ipv6)
	grpc_client.dellbprefix(VM2.name, lb_pfx)
	grpc_client.dellbtarget(lb_name, lb_vm1_ul_ipv6)
	grpc_client.dellbprefix(VM1.name, lb_pfx)
	grpc_client.dellb(lb_name)

	grpc_client.delfwallrule(VM2.name, "fw0-vm2")
	grpc_client.delfwallrule(VM1.name, "fw0-vm1")

	# NOTE: this test, just like in test_pf_to_vf.py
	# cannot be run twice in a row, since the flows need to age-out
