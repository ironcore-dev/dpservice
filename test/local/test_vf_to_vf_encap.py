# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest
from helpers import *

# VM1 and VM2 are both local interfaces in the same VNI, so dpservice switches their
# traffic internally and it never reaches a PF. To get a packet encapsulated, VM1 sends
# to the neighboring dp-service instance's overlay prefix, which init_ifaces() routes to
# neigh_vni1_ul_ipv6. This test then plays the underlay fabric: it catches the encaped
# packet on the PF, redirects it at VM2 and sends it back in, so that dpservice decaps
# it and delivers it to VM2. This way one test covers both encap and decap.

udp_payload = b"hello"
udp_sport = 1234
udp_dport = 12345
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


def udp_encap_loopback_responder(pf_tap):
	pkt = sniff_packet(pf_tap, is_encaped_udp_pkt)
	assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
		"Invalid destination in encaped request"
	assert get_udp_payload(pkt) == udp_payload, \
		"Payload damaged by encapsulation"
	# The outer destination decides the target port, the inner one makes the packet look
	# like it was meant for VM2 all along. Create a new packet instead of changing this
	# one, so that scapy recomputes the lengths and checksums.
	loop_pkt = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
				IPv6(dst=VM2.ul_ipv6, src=pkt[IPv6].dst) /
				IP(dst=VM2.ip, src=pkt[IP].src) /
				UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport) /
				Raw(udp_payload))
	delayed_sendp(loop_pkt, pf_tap)

# vm1 (vf0) -> PF0 (encaped), looped back to PF0 -> vm2 (vf1) (decaped),
# check that the payload survives the whole round trip
def test_vf_to_vf_udp_encap(request, prepare_ipv4):
	if request.config.getoption("--hw"):
		pytest.skip("Loopback is not supported while the packet reflector is running")

	threading.Thread(target=udp_encap_loopback_responder, args=(PF0.tap,)).start()

	udp_pkt = (Ether(dst=PF0.mac, src=VM1.mac) /
			   IP(dst=neigh_ov_ip, src=VM1.ip) /
			   UDP(sport=udp_sport, dport=udp_dport) /
			   Raw(udp_payload))
	delayed_sendp(udp_pkt, VM1.tap)

	pkt = sniff_packet(VM2.tap, is_test_udp_pkt)
	src_ip = pkt[IP].src
	dst_ip = pkt[IP].dst
	assert src_ip == VM1.ip and dst_ip == VM2.ip, \
		f"Wrong packet received (src ip: {src_ip}, dst ip: {dst_ip})"
	assert get_udp_payload(pkt) == udp_payload, \
		"Payload damaged by decapsulation"
