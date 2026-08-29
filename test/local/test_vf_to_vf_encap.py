# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest
from helpers import *

# VM1 and VM2 are both local interfaces in the same VNI, so dpservice switches their
# traffic internally and it never reaches a PF. To get a packet encapsulated, VM1 sends
# to the neighboring dp-service instance's overlay prefix, which init_ifaces() routes to
# neigh_vni1_ul_ipv6. This test then plays the underlay fabric: it catches the encaped
# packets on the PF, redirects them at VM2 and sends them back in, so that dpservice
# decaps them and delivers them to VM2. This way one test covers both encap and decap.
#
# Only the outer headers are rewritten on the way back; everything the outer IPv6 header
# carries is returned byte-for-byte. The outer destination alone decides the target port
# (ipip_decap looks the underlay address up in the VNF table and never inspects the inner
# header), so VM2 receives the inner packet exactly as VM1 sent it - still addressed to
# neigh_ov_ip. Keeping the payload opaque here is what lets the very same responder work
# once the tunnel is encrypted, where the harness cannot read or rebuild the inner packet.
#
# A burst of packets is used rather than a single one, so that the whole path is exercised
# with more than one packet in flight at a time.
#
# With --ipsec the very same test runs against a dpservice that encrypts the tunnel. Only
# what is observed on the PF differs: the harness has no key, so instead of reading the
# payload it asserts that the payload is *not* readable, which fails loudly if the cipher
# ever stops doing anything.

udp_payloads = [f"hello {i}".encode() for i in range(1, 6)]
udp_sport = 1234
udp_dport = 12345
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"
# Has to match DP_IPSEC_SPI in dp_ipsec.h
ipsec_spi = 0xdb5ec001


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


def udp_encap_loopback_responder(pf_tap, ipsec):
	pkts = sniff_packets(pf_tap, is_esp_pkt if ipsec else is_encaped_udp_pkt, len(udp_payloads))
	loop_pkts = []
	for pkt, payload in zip(pkts, udp_payloads):
		assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
			"Invalid destination in encaped request"
		if ipsec:
			assert pkt[ESP].spi == ipsec_spi, \
				"Encrypted request carries an unexpected SPI"
			assert payload not in raw(pkt), \
				"Payload is readable in the encrypted request"
		else:
			assert get_udp_payload(pkt) == payload, \
				"Payload damaged by encapsulation"
		# Swap the outer addresses so the packet is now bound for VM2 and hand the
		# tunneled payload back untouched. Slicing by the payload length field keeps
		# any ethernet padding out of the reconstructed packet.
		loop_pkts.append(Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
						 IPv6(dst=VM2.ul_ipv6, src=pkt[IPv6].dst, nh=pkt[IPv6].nh) /
						 raw(pkt[IPv6].payload)[:pkt[IPv6].plen])
	delayed_sendp(loop_pkts, pf_tap)

# vm1 (vf0) -> PF0 (encaped), looped back to PF0 -> vm2 (vf1) (decaped),
# check that the payloads survive the whole round trip
def test_vf_to_vf_udp_encap(request, prepare_ipv4):
	if request.config.getoption("--hw"):
		pytest.skip("Loopback is not supported while the packet reflector is running")

	ipsec = request.config.getoption("--ipsec")
	threading.Thread(target=udp_encap_loopback_responder, args=(PF0.tap, ipsec)).start()

	udp_pkts = [Ether(dst=PF0.mac, src=VM1.mac) /
				IP(dst=neigh_ov_ip, src=VM1.ip) /
				UDP(sport=udp_sport, dport=udp_dport) /
				Raw(payload)
				for payload in udp_payloads]
	delayed_sendp(udp_pkts, VM1.tap)

	pkts = sniff_packets(VM2.tap, is_test_udp_pkt, len(udp_payloads))
	for pkt, payload in zip(pkts, udp_payloads):
		src_ip = pkt[IP].src
		dst_ip = pkt[IP].dst
		assert src_ip == VM1.ip and dst_ip == neigh_ov_ip, \
			f"Wrong packet received (src ip: {src_ip}, dst ip: {dst_ip})"
		assert get_udp_payload(pkt) == payload, \
			"Payload damaged by decapsulation"
