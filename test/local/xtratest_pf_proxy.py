# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

from helpers import *

def send_tcp_packet_pkt_via_pf1(ipv6_dst):
	tcp_pkt = (Ether(dst=ipv6_multicast_mac, src=PF0.mac, type=0x86DD) /
			  IPv6(dst=ipv6_dst, src=neigh_ul_ipv6) /
			  TCP(sport=1234, dport=80))
	delayed_sendp(tcp_pkt, PF1.tap)

def test_pf_to_vf_lb_tcp(prepare_ifaces, grpc_client):
	threading.Thread(target=send_tcp_packet_pkt_via_pf1, args=(local_ul_ipv6,)).start()
	pkt = sniff_packet(PF1_PROXY.tap, is_tcp_pkt)
	dst_ip = pkt[IPv6].dst
	dport = pkt[TCP].dport
	assert dst_ip == local_ul_ipv6 and dport == 80, \
		f"Wrong packet received (ip: {dst_ip}, dport: {dport})"

