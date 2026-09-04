# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest
from helpers import *
from ipsec_peer import assert_esp_framing

# VM1 and VM2 are both local interfaces in the same VNI, so dpservice switches their
# traffic internally and it never reaches a PF. To get a packet encapsulated, VM1 sends
# to the neighboring dp-service instance's overlay prefix, which init_ifaces() routes to
# neigh_vni1_ul_ipv6. This test then plays the underlay fabric: it catches the encaped
# packets on the PF, redirects them at VM2 and sends them back in, so that dpservice
# decaps them and delivers them to VM2. This way one test covers both encap and decap.
#
# In plain mode only the outer headers are rewritten on the way back; everything the outer IPv6
# header carries is returned byte-for-byte. The outer destination alone decides the target port
# (ipip_decap looks the underlay address up in the VNF table and never inspects the inner
# header), so VM2 receives the inner packet exactly as VM1 sent it - still addressed to
# neigh_ov_ip.
#
# A burst of packets is used rather than a single one, so that the whole path is exercised
# with more than one packet in flight at a time.
#
# With --ipsec the very same test runs against a dpservice that encrypts the tunnel, using the
# Security Associations dp_service.py installs over gRPC. There the responder cannot reflect
# bytes: the two directions carry different keys, so what goes back has to be decrypted with one
# association and rebuilt with the other. That is deliberate. A responder that echoes our own
# ciphertext only ever proves dpservice can be *read*; one that builds the frame proves dpservice
# accepts ESP it did not produce, which is the half that interoperability actually rests on.
#
# The harness therefore holds both keys and does real crypto in both directions. It cannot pass
# by reimplementing a bug in the code under test, because it shares no code with it: GCM
# authentication fails unless the additional authenticated data, the nonce construction and the
# trailer all match what a second implementation expects. On top of that it asserts the payload
# is *not* readable on the PF, which fails loudly if the cipher ever stops doing anything, and
# it checks the parts of the framing a successful decrypt would silently accept - see
# assert_esp_framing().

udp_payloads = [f"hello {i}".encode() for i in range(1, 6)]
udp_sport = 1234
udp_dport = 12345
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


def udp_encap_loopback_responder(pf_tap, peer):
	pkts = sniff_packets(pf_tap, is_esp_pkt if peer else is_encaped_udp_pkt, len(udp_payloads))
	loop_pkts = []
	for pkt, payload in zip(pkts, udp_payloads):
		assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
			"Invalid destination in encaped request"
		if peer:
			# ipsec_spi is deliberately not a VNI: the association is found under the VNI of the
			# interface this came from, and what it puts on the wire is free of that. See ADR 4.
			assert pkt[ESP].spi == ipsec_spi, \
				"Encrypted request carries an unexpected SPI"
			assert payload not in raw(pkt), \
				"Payload is readable in the encrypted request"
			tunneled = peer.decrypt(pkt)
			assert IP in tunneled and UDP in tunneled[IP], \
				"Decrypted request does not carry the tunneled IPv4 packet"
			assert tunneled[IP].src == VM1.ip and tunneled[IP].dst == neigh_ov_ip, \
				"Decrypted request carries the wrong inner addresses"
			assert get_udp_payload(tunneled[IP]) == payload, \
				"Decrypted request carries the wrong payload"
			assert_esp_framing(pkt[ESP], tunneled)
			# Answer the way the peer would: the tunneled packet goes back untouched, but the
			# frame around it is built again, with this direction's own key.
			tunneled.src, tunneled.dst = tunneled.dst, VM2.ul_ipv6
			reply = peer.encrypt(tunneled)
		else:
			assert get_udp_payload(pkt) == payload, \
				"Payload damaged by encapsulation"
			# Hand the tunneled payload back untouched. Slicing by the payload length field
			# keeps any ethernet padding out of the reconstructed packet.
			reply = IPv6(dst=VM2.ul_ipv6, src=pkt[IPv6].dst, nh=pkt[IPv6].nh) / \
					raw(pkt[IPv6].payload)[:pkt[IPv6].plen]
		# either way the outer addresses now say VM2, which is what picks the target port
		loop_pkts.append(Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / reply)
	delayed_sendp(loop_pkts, pf_tap)

# vm1 (vf0) -> PF0 (encaped), looped back to PF0 -> vm2 (vf1) (decaped),
# check that the payloads survive the whole round trip
def test_vf_to_vf_udp_encap(request, prepare_ipv4, ipsec_peer):
	if request.config.getoption("--hw"):
		pytest.skip("Loopback is not supported while the packet reflector is running")

	threading.Thread(target=udp_encap_loopback_responder, args=(PF0.tap, ipsec_peer)).start()

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
