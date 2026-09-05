# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

import threading

import pytest

from helpers import *
from ipsec_peer import IpsecPeer, assert_esp_framing

# xtratest_ipsec_dataplane.py covers extended sequence numbers and the 256-bit cipher on the way
# *in*, by injecting frames the harness built. That leaves the encrypting half untested for both:
# every association dpservice encrypts with in the rest of the suite is a 128-bit one without ESN.
#
# It cannot simply be a second egress association, either. An egress association is found under
# the VNI a packet came in on, so for one VNI and one peer there is exactly one outbound
# association and no way to ask for a different one. Freeing the wire SPI from the VNI did not
# change that, and neither does the replace path: an association can be replaced, it cannot be
# duplicated.
#
# So this replaces it. Each test below deletes the pair dp_service.py installed, creates it again
# with the parameters under test, runs a full round trip through it, and puts the original pair
# back. Deliberately not through UpdateSecurityAssociation, which could do the egress half in one
# request: what these tests are about is what the cipher does, and routing their setup through a
# second feature would let a regression in that feature report itself as an ESN failure.
# Rekeying itself is xtratest_ipsec_rekey.py's subject.
#
# The round trip is the one test_vf_to_vf_encap.py runs, cut down to what is needed here: VM1
# sends to the neighbouring instance's overlay prefix, the harness catches the encrypted frame on
# the PF, decrypts it, rebuilds the answer with the other direction's key and sends it back, and
# VM2 receives what VM1 sent. Nothing in the path is shared with dpservice's own crypto, so a
# frame arriving means two independent implementations agreed on the framing, the nonce and the
# authenticated data.

udp_payloads = [f"esn hello {i}".encode() for i in range(1, 4)]
udp_sport = 1234
udp_dport = 12345
neigh_ov_ip = f"{neigh_vni1_ov_ip_prefix}.147"


def is_test_udp_pkt(pkt):
	return UDP in pkt and pkt[UDP].dport == udp_dport

def get_udp_payload(pkt):
	# Slice by the UDP length field, otherwise ethernet padding would be counted in
	return raw(pkt[UDP])[8:pkt[UDP].len]


# The peer's two associations for one variant. Built from IpsecPeer's own constructor so that the
# nonce construction cannot drift from the one the rest of the suite is checked against.
class SwappedPeer:

	def __init__(self, key_egress, salt_egress, key_ingress, salt_ingress, esn):
		# "egress" is dpservice's direction, so this is the one that *reads* what it sent
		self.egress = IpsecPeer._sa(ipsec_spi, key_egress, salt_egress, esn=esn)
		self.ingress = IpsecPeer._sa(ipsec_spi, key_ingress, salt_ingress, esn=esn)

	def decrypt(self, pkt):
		return self.egress.decrypt(pkt[IPv6].copy())

	def encrypt(self, pkt):
		return self.ingress.encrypt(pkt)


# Replace the session's pair with one built to the given parameters, and put the original back
# afterwards however the test ends. The restore matters more than it looks: every later test in
# the suite - and the package-scoped IpsecPeer that outlives this file - is holding the original
# key material and would fail its ICV against anything else.
def swap_associations(grpc_client, key_egress, salt_egress, key_ingress, salt_ingress,
					  algorithm=None, esn=None):
	grpc_client.delsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)
	grpc_client.delsa(vni1, ipsec_spi, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6)

	grpc_client.addsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6,
					  key_egress, salt_egress, algorithm=algorithm, esn=esn)
	grpc_client.addsa(vni1, ipsec_spi, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  key_ingress, salt_ingress, algorithm=algorithm,
					  replay_window=ipsec_replay_window, esn=esn)

def restore_associations(grpc_client):
	grpc_client.delsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)
	grpc_client.delsa(vni1, ipsec_spi, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6)

	grpc_client.addsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6,
					  ipsec_key_egress, ipsec_salt_egress)
	grpc_client.addsa(vni1, ipsec_spi, "ingress", neigh_vni1_ul_ipv6, local_ul_ipv6,
					  ipsec_key_ingress, ipsec_salt_ingress,
					  replay_window=ipsec_replay_window)


def encrypted_loopback_responder(pf_tap, peer):
	pkts = sniff_packets(pf_tap, is_esp_pkt, len(udp_payloads))
	loop_pkts = []
	for pkt, payload in zip(pkts, udp_payloads):
		assert pkt[IPv6].dst == neigh_vni1_ul_ipv6, \
			"Invalid destination in encaped request"
		assert payload not in raw(pkt), \
			"Payload is readable in the encrypted request"
		tunneled = peer.decrypt(pkt)
		assert IP in tunneled and UDP in tunneled[IP], \
			"Decrypted request does not carry the tunneled IPv4 packet"
		assert get_udp_payload(tunneled[IP]) == payload, \
			"Decrypted request carries the wrong payload"
		assert_esp_framing(pkt[ESP], tunneled)
		# answer the way the peer would, rebuilding the frame with the other direction's key
		tunneled.src, tunneled.dst = tunneled.dst, VM2.ul_ipv6
		reply = peer.encrypt(tunneled)
		loop_pkts.append(Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / reply)
	delayed_sendp(loop_pkts, pf_tap)


def assert_round_trip(peer):
	threading.Thread(target=encrypted_loopback_responder, args=(PF0.tap, peer)).start()

	udp_pkts = [Ether(dst=PF0.mac, src=VM1.mac) /
				IP(dst=neigh_ov_ip, src=VM1.ip) /
				UDP(sport=udp_sport, dport=udp_dport) /
				Raw(payload)
				for payload in udp_payloads]
	delayed_sendp(udp_pkts, VM1.tap)

	pkts = sniff_packets(VM2.tap, is_test_udp_pkt, len(udp_payloads))
	for pkt, payload in zip(pkts, udp_payloads):
		assert pkt[IP].src == VM1.ip and pkt[IP].dst == neigh_ov_ip, \
			f"Wrong packet received (src ip: {pkt[IP].src}, dst ip: {pkt[IP].dst})"
		assert get_udp_payload(pkt) == payload, \
			"Payload damaged by the round trip"


# Both directions with extended sequence numbers. What this adds over the ingress-only test in
# xtratest_ipsec_dataplane.py is the encrypting side: dpservice has to authenticate the upper half
# of a sequence number it never puts in the packet, and the peer has to arrive at the same twelve
# bytes from the four it can see.
def test_ipsec_esn_both_directions(prepare_ipv4, grpc_client):
	swap_associations(grpc_client,
					  ipsec_key_esn_egress, ipsec_salt_esn_egress,
					  ipsec_key_esn_ingress, ipsec_salt_esn_ingress,
					  esn=True)
	try:
		sa = grpc_client.getsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)
		assert sa['esn'] is True, \
			"Egress association was not re-created with extended sequence numbers"

		assert_round_trip(SwappedPeer(ipsec_key_esn_egress, ipsec_salt_esn_egress,
									  ipsec_key_esn_ingress, ipsec_salt_esn_ingress, esn=True))
	finally:
		restore_associations(grpc_client)


# Both directions with the 256-bit cipher, which is the encrypting half of the claim
# test_ipsec_aes256_round_trip() makes about the decrypting one.
def test_ipsec_aes256_both_directions(prepare_ipv4, grpc_client):
	swap_associations(grpc_client,
					  ipsec_key_aes256_egress, ipsec_salt_aes256_egress,
					  ipsec_key_aes256_ingress, ipsec_salt_aes256_ingress,
					  algorithm="aes-256-gcm")
	try:
		sa = grpc_client.getsa(vni1, ipsec_spi, "egress", local_ul_ipv6, neigh_vni1_ul_ipv6)
		assert sa['algorithm'] == "aes_256_gcm", \
			"Egress association was not re-created with the 256-bit cipher"

		assert_round_trip(SwappedPeer(ipsec_key_aes256_egress, ipsec_salt_aes256_egress,
									  ipsec_key_aes256_ingress, ipsec_salt_aes256_ingress,
									  esn=False))
	finally:
		restore_associations(grpc_client)


# The two together, which is the combination a deployment that wants both would actually run.
# They are independent in dpservice - one picks the cipher, the other how the sequence number is
# counted and authenticated - and this is what asserts that nothing couples them.
def test_ipsec_esn_with_aes256(prepare_ipv4, grpc_client):
	swap_associations(grpc_client,
					  ipsec_key_aes256_egress, ipsec_salt_aes256_egress,
					  ipsec_key_aes256_ingress, ipsec_salt_aes256_ingress,
					  algorithm="aes-256-gcm", esn=True)
	try:
		assert_round_trip(SwappedPeer(ipsec_key_aes256_egress, ipsec_salt_aes256_egress,
									  ipsec_key_aes256_ingress, ipsec_salt_aes256_ingress,
									  esn=True))
	finally:
		restore_associations(grpc_client)
