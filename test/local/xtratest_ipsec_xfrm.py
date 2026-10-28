# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest

from helpers import *
from xfrm_peer import XfrmPeer

# test_vf_to_vf_encap.py already runs a full encrypted round trip, and everything on the far
# side of it is scapy: the harness decrypts what dpservice sent and builds the answer itself.
# That proves dpservice agrees with a second implementation of ESP. It does not prove dpservice
# agrees with the one it would actually meet.
#
# Here the far side is the Linux kernel. The peer is configured the way a real deployment is
# configured - an xfrm interface, a state and a policy per direction, written with iproute2 -
# and nothing in the test participates in the crypto. What comes back has been decrypted by
# xfrm, delivered to an ordinary UDP socket, echoed by a program that has never heard of IPsec,
# and encrypted again on the way out.
#
# That is worth more than a second opinion on the ICV. The kernel enforces what the RFC says
# and refuses frames scapy accepts without comment: a wrong nonce construction, a trailer that
# does not name a tunnelled IP packet, padding that does not add up. And it is the side of the
# claim in docs/concepts/ipsec.md that could not be tested before - that dpservice's ESP, built
# in *transport* mode over an outer header ipip_encap already wrote, is accepted by a peer that
# believes it is speaking tunnel mode.
#
# What is deliberately not here: assertions about the ciphertext on the wire. The relay sees
# every frame and could check that the payload is unreadable and that the SPI is what it should
# be, but udp_encap_loopback_responder already asserts exactly that against exactly this code
# path. A second copy would only cost twice as much to change.
#
# See xfrm_peer.py for how the frames get between the PF and the namespace, and why a bridge
# cannot do it.

udp_payloads = [f"xfrm hello {i}".encode() for i in range(1, 6)]
udp_sport = 1234


def is_echoed_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_sport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


# Module-scoped, because both sides count sequence numbers per association: a peer rebuilt for
# every test would start counting from 1 again, and dpservice's anti-replay window would refuse
# what the previous test had already moved past. The associations dpservice holds for the peer
# are created here rather than in dp_service.py, which describes the topology every test in the
# suite shares - this peer exists for this file.
@pytest.fixture(scope="module")
def xfrm_peer(request, prepare_ipv4, grpc_client):
	skip_reason = XfrmPeer.probe()
	if skip_reason:
		pytest.skip(skip_reason)

	peer = XfrmPeer(VM1)

	# registered before anything is created, so that a setup failing halfway is still cleaned up
	def tear_down():
		print("------ Xfrm peer cleanup -----")
		peer.stop()
		grpc_client.delsa(vni1, xfrm_spi_ingress, "ingress", xfrm_peer_ul_ipv6, local_ul_ipv6)
		grpc_client.delsa(vni1, xfrm_spi_egress, "egress", local_ul_ipv6, xfrm_peer_ul_ipv6)
		grpc_client.delroute(vni1, xfrm_peer_ov_ip_route)
		print("------------------------------")
	request.addfinalizer(tear_down)

	print("------- Xfrm peer init -------")
	# a neighbour like any other, as far as dpservice is concerned: a route to its overlay
	# prefix and one association per direction
	grpc_client.addroute(vni1, xfrm_peer_ov_ip_route, 0, xfrm_peer_ul_ipv6)
	grpc_client.addsa(vni1, xfrm_spi_egress, "egress", local_ul_ipv6, xfrm_peer_ul_ipv6,
					  xfrm_key_egress, xfrm_salt_egress)
	# under the SPI the other peer already sends under, which is the one thing this association
	# shares with it: two ingress associations, one lookup SPI, told apart by the source /64
	grpc_client.addsa(vni1, xfrm_spi_ingress, "ingress", xfrm_peer_ul_ipv6, local_ul_ipv6,
					  xfrm_key_ingress, xfrm_salt_ingress, replay_window=ipsec_replay_window)
	peer.start()
	print("------------------------------")
	return peer


# vm1 (vf0) -> PF0, encaped and encrypted -> the peer namespace, decrypted by xfrm -> the echo
# server -> encrypted by xfrm -> PF0, decrypted and decaped -> vm1 (vf0).
#
# A burst rather than a single packet, so that both sides advance their sequence numbers several
# times inside one test. This is the only place in the suite where the sequence numbers on the
# far side come from a real IPsec implementation rather than from a test harness, and a single
# frame would waste most of what that is for.
def test_ipsec_xfrm_round_trip(prepare_ipv4, xfrm_peer):
	udp_pkts = [Ether(dst=PF0.mac, src=VM1.mac) /
				IP(dst=xfrm_peer_ov_ip, src=VM1.ip) /
				UDP(sport=udp_sport, dport=xfrm_echo_port) /
				Raw(payload)
				for payload in udp_payloads]

	# sending from a thread, so that the sniff below is already listening when the answers
	# arrive - the peer answers as fast as the relay can carry a frame to it
	threading.Thread(target=delayed_sendp, args=(udp_pkts, VM1.tap)).start()

	try:
		pkts = sniff_packets(VM1.tap, is_echoed_pkt, len(udp_payloads))
	finally:
		# even when nothing arrived - especially then. "Expected 5 packets, got 0" says only
		# that something went wrong somewhere along a path with two implementations in it,
		# while the counters name which of them dropped the packet and why.
		errors = xfrm_peer.errors()
		assert not errors, f"The peer's kernel reported IPsec errors: {errors}"

	for pkt, payload in zip(pkts, udp_payloads):
		src_ip = pkt[IP].src
		dst_ip = pkt[IP].dst
		assert src_ip == xfrm_peer_ov_ip and dst_ip == VM1.ip, \
			f"Wrong packet received (src ip: {src_ip}, dst ip: {dst_ip})"
		assert get_udp_payload(pkt) == payload, \
			"Payload damaged on the way through the peer"
