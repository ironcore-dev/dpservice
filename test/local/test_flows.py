# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import pytest
import threading
import time

from helpers import *
from tcp_tester import TCPTesterLocal
from tcp_tester import TCPTesterPublic

nat_only_port = 1024

def tcp_server_nat_pkt_check(pkt):
	assert pkt[IPv6].dst == router_ul_ipv6, \
		"Request to the wrong outgoing IPv6 address"
	assert pkt[IP].src == nat_vip, \
		f"Packet not coming from NAT's IP"
	assert pkt[IP].dst == public_ip, \
		"Request to a wrong public server IP"
	assert pkt[TCP].dport == 443, \
		"Request to a wrong TCP port"
	assert pkt[TCP].sport == nat_only_port, \
		"Failed to use NAT's only single port"

def test_nat_table_flush(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for ipv6 in ipv6")

	global nat_only_port

	# NAT with one port
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_only_port, nat_only_port+1)

	tester = TCPTesterPublic(VM1, 12345, nat_ul_ipv6, PF0, public_ip, 443, server_pkt_check=tcp_server_nat_pkt_check)
	tester.communicate()

	# Re-create the NAT with a different port range
	grpc_client.delnat(VM1.name)
	nat_only_port = 1025
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_only_port, nat_only_port+1)
	tester.nat_ul_ipv6 = nat_ul_ipv6

	# Keep the client port the same, this will cause an established flow to re-use the old NAT port
	tester.communicate()

	grpc_client.delnat(VM1.name)


def send_bounce_pkt_to_pf(ipv6_nat):
	bounce_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
				  IPv6(dst=ipv6_nat, src=router_ul_ipv6, nh=4) /
				  IP(dst=nat_vip, src=public_ip) /
				  TCP(sport=8989, dport=510))
	delayed_sendp(bounce_pkt, PF0.tap)

def test_neighnat_table_flush(prepare_ipv4, grpc_client, port_redundancy):

	if port_redundancy:
		pytest.skip("Port redundancy is not supported for ipv6 in ipv6")

	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_local_min_port, nat_local_max_port)

	global nat_only_port
	nat_only_port = nat_local_min_port+1
	tester = TCPTesterPublic(VM1, 12345, nat_ul_ipv6, PF0, public_ip, 443, server_pkt_check=tcp_server_nat_pkt_check)
	tester.communicate()

	grpc_client.addneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port, neigh_vni1_ul_ipv6)

	threading.Thread(target=send_bounce_pkt_to_pf, args=(nat_ul_ipv6,)).start()

	# PF0 receives both the incoming packet and the relayed one, skip the first
	pkt = sniff_packet(PF0.tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == neigh_vni1_ul_ipv6 and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

	# Again, this will re-use flow
	threading.Thread(target=send_bounce_pkt_to_pf, args=(nat_ul_ipv6,)).start()

	# PF0 receives both the incoming packet and the relayed one, skip the first
	pkt = sniff_packet(PF0.tap, is_tcp_pkt, skip=1)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == neigh_vni1_ul_ipv6 and dport == 510, \
		f"Wrong network-nat relayed packet (outer dst ipv6: {dst_ip}, dport: {dport})"

	# What happens if we remove neighnat and put NAT in its place?
	grpc_client.delneighnat(nat_vip, vni1, nat_neigh_min_port, nat_neigh_max_port)
	grpc_client.delnat(VM1.name)
	nat_ul_ipv6 = grpc_client.addnat(VM1.name, nat_vip, nat_neigh_min_port, nat_neigh_min_port+1)

	threading.Thread(target=send_bounce_pkt_to_pf, args=(nat_ul_ipv6,)).start()

	# PF0 receives both the incoming packet and the relayed one, skip the first
	pkt_list = sniff(count=2, lfilter=is_tcp_pkt, iface=PF0.tap, timeout=sniff_timeout)
	assert len(pkt_list) == 1, \
		f"Packet still being relayed!"

	nat_only_port = nat_neigh_min_port
	tester = TCPTesterPublic(VM1, 12345, nat_ul_ipv6, PF0, public_ip, 443, server_pkt_check=tcp_server_nat_pkt_check)
	tester.communicate()

	grpc_client.delnat(VM1.name)
