# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading
import pytest

from helpers import *
from tcp_tester import TCPTesterVirtsvc

udp_used_port = 0

def reply_udp(pf_name):
	global udp_used_port

	pkt = sniff_packet(pf_name, is_udp_pkt)
	assert pkt[IPv6].dst == virtsvc_udp_svc_ipv6, \
		"Request to wrong IPv6 address"
	assert pkt[UDP].dport == virtsvc_udp_svc_port, \
		"Request to wrong UDP port"
	assert udp_used_port != pkt[UDP].sport, \
		"UDP port reused over multiple connections"

	udp_used_port = pkt[UDP].sport

	reply_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst, type=0x86DD) /
				 IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst, nh=17) /
				 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport))
	delayed_sendp(reply_pkt, pf_name)

def request_udp(l4_port, pf_name):
	threading.Thread(target=reply_udp, args=(pf_name,)).start()

	udp_pkt = (Ether(dst=PF0.mac, src=VM1.mac, type=0x0800) /
			   IP(dst=virtsvc_udp_virtual_ip, src=VM1.ip) /
			   UDP(dport=virtsvc_udp_virtual_port, sport=l4_port))
	delayed_sendp(udp_pkt, VM1.tap)

	pkt = sniff_packet(VM1.tap, is_udp_pkt)
	assert pkt[IP].src == virtsvc_udp_virtual_ip, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].sport == virtsvc_udp_virtual_port, \
		"Got answer from wrong UDP source port"
	assert pkt[UDP].dport == l4_port, \
		"Got answer to wrong UDP destination port"

def test_virtsvc_udp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")
	# port numbers chosen so that they cause the right redirection
	pf0_ports = [ 12345, 12346, 12347, 12349, 12350 ]
	for port in pf0_ports:
		request_udp(port, PF0.tap)
	if port_redundancy:
		pf1_ports = [ 12348, 12351, 12354, 12355, 12357 ]
		for port in pf1_ports:
			request_udp(port, PF1.tap)


def tcp_server_virtsvc_pkt_check(pkt):
	assert pkt[IPv6].dst == virtsvc_tcp_svc_ipv6, \
		"Request to wrong service IPv6 address"
	assert pkt[TCP].dport == virtsvc_tcp_svc_port, \
		"Request to wrong service TCP port"

def test_virtsvc_tcp(request, prepare_ipv4, port_redundancy):
	if not request.config.getoption("--virtsvc"):
		pytest.skip("Virtual services not enabled")

	port = 12345
	tester = TCPTesterVirtsvc(VM1, port, PF0, virtsvc_tcp_virtual_ip, virtsvc_tcp_virtual_port, server_pkt_check=tcp_server_virtsvc_pkt_check)
	tester.communicate()

	# port number chosen so that they cause the right redirection
	if port_redundancy:
		tester = TCPTesterVirtsvc(VM1, 12348, PF1, virtsvc_tcp_virtual_ip, virtsvc_tcp_virtual_port, server_pkt_check=tcp_server_virtsvc_pkt_check)
		tester.communicate()
